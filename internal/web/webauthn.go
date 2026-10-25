package web

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/session"
	"github.com/mailsvb/openkca/internal/store"
	"github.com/mailsvb/openkca/internal/vault"
)

// WebAuthnConfig configures security keys and passkeys; an empty RPID
// turns them off.
type WebAuthnConfig struct {
	RPID    string
	RPName  string
	Origins []string
}

// ceremonyTTL is how long a started WebAuthn ceremony may take.
const ceremonyTTL = 2 * time.Minute

// prfSaltLen is the length of the salt a security key or passkey
// evaluates its PRF over.
const prfSaltLen = 32

// ceremony is a started WebAuthn ceremony: the library's session data and,
// for a registration, what is being added.
type ceremony struct {
	data    webauthn.SessionData
	expires time.Time

	// registration
	typ, label string
	prfSalt    []byte
	cred       *webauthn.Credential // created, waiting for its PRF output
}

// ceremonies holds the started ceremonies by server session, purpose and
// database: one at a time each.
type ceremonies struct {
	mu sync.Mutex
	m  map[string]*ceremony
}

func ceremonyKey(serverID, purpose, dbName string) string {
	return serverID + "\x00" + purpose + "\x00" + dbName
}

func (c *ceremonies) put(key string, ce *ceremony) {
	ce.expires = time.Now().Add(ceremonyTTL)
	c.mu.Lock()
	if c.m == nil {
		c.m = map[string]*ceremony{}
	}
	c.m[key] = ce
	c.mu.Unlock()
}

// take removes and returns a ceremony that has not expired.
func (c *ceremonies) take(key string) *ceremony {
	c.mu.Lock()
	defer c.mu.Unlock()
	ce, ok := c.m[key]
	delete(c.m, key)
	if !ok || time.Now().After(ce.expires) {
		return nil
	}
	return ce
}

func (c *ceremonies) sweep() {
	c.mu.Lock()
	for k, ce := range c.m {
		if time.Now().After(ce.expires) {
			delete(c.m, k)
		}
	}
	c.mu.Unlock()
}

// dbUser presents one database's security keys and passkeys to the
// WebAuthn library: OpenKCA has no users, the database is the account.
type dbUser struct {
	id      []byte
	name    string
	display string
	creds   []webauthn.Credential
}

func (u *dbUser) WebAuthnID() []byte                         { return u.id }
func (u *dbUser) WebAuthnName() string                       { return u.name }
func (u *dbUser) WebAuthnDisplayName() string                { return u.display }
func (u *dbUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func credentialOf(m *db.UnlockMethod) webauthn.Credential {
	var tr []protocol.AuthenticatorTransport
	for _, t := range strings.Split(m.Transports, ",") {
		if t != "" {
			tr = append(tr, protocol.AuthenticatorTransport(t))
		}
	}
	return webauthn.Credential{
		ID:            m.CredentialID,
		PublicKey:     m.PublicKey,
		Transport:     tr,
		Flags:         webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(m.Flags)),
		Authenticator: webauthn.Authenticator{AAGUID: m.AAGUID, SignCount: m.SignCount},
	}
}

// user builds the WebAuthn user of a database with its credentials.
func (s *Server) user(r *http.Request, h *store.Handle, label string) (*dbUser, []db.UnlockMethod, error) {
	id, err := h.WebAuthnUser(r.Context())
	if err != nil {
		return nil, nil, err
	}
	ms, err := h.Methods(r.Context())
	if err != nil {
		return nil, nil, err
	}
	u := &dbUser{id: id, name: h.Name, display: label}
	var keys []db.UnlockMethod
	for i := range ms {
		if ms[i].WebAuthn() {
			u.creds = append(u.creds, credentialOf(&ms[i]))
			keys = append(keys, ms[i])
		}
	}
	return u, keys, nil
}

// jsonError answers a WebAuthn request with a translated message.
func (s *Server) jsonError(w http.ResponseWriter, r *http.Request, status int, key string) {
	s.writeJSON(w, status, map[string]string{"error": s.printer(r).T(key)})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// readBody reads a WebAuthn response body (at most 64 KiB).
func readBody(r *http.Request) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(http.MaxBytesReader(nil, r.Body, 64<<10)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// prfResult returns the PRF output for the first salt from a ceremony's
// client extension results, nil if the authenticator gave none.
func prfResult(out protocol.AuthenticationExtensionsClientOutputs) []byte {
	if out.PRF == nil || out.PRF.Results == nil || len(out.PRF.Results.First) == 0 {
		return nil
	}
	return out.PRF.Results.First
}

// assertionOptions starts an assertion for u's credentials (keys), with
// each key's PRF salt.
func (s *Server) assertionOptions(u *dbUser, keys []db.UnlockMethod) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	byCred := map[string]protocol.PRFValues{}
	for i := range keys {
		byCred[b64(keys[i].CredentialID)] = protocol.PRFValues{First: keys[i].PRFSalt}
	}
	return s.webauthn.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithAssertionExtensions(webauthn.WithExtensionPRFByCredential(byCred, nil)))
}

// webauthnBegin starts an assertion with every security key and passkey of
// the database: purpose "login" opens it, "confirm" re-confirms an open
// session.
func (s *Server) webauthnBegin(purpose string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.webauthn == nil {
			s.jsonError(w, r, http.StatusNotFound, "methods.error.webauthn_off")
			return
		}
		name := r.PathValue("name")
		var h *store.Handle
		if purpose == "login" {
			if s.dbLimit.Blocked(name) {
				s.jsonError(w, r, http.StatusTooManyRequests, "dblogin.error.ratelimit")
				return
			}
			hd, err := s.store.Acquire(r.Context(), name)
			if err != nil {
				s.jsonError(w, r, http.StatusNotFound, "dblogin.error.unsupported")
				return
			}
			defer hd.Release()
			h = hd
		} else {
			h = dbSession(r).Handle
		}
		u, keys, err := s.user(r, h, name)
		if err != nil {
			s.log.Error("webauthn begin", "db", name, "err", err)
			s.jsonError(w, r, http.StatusInternalServerError, "methods.error.webauthn")
			return
		}
		if len(keys) == 0 {
			s.jsonError(w, r, http.StatusNotFound, "methods.error.nokeys")
			return
		}
		opts, data, err := s.assertionOptions(u, keys)
		if err != nil {
			s.log.Error("webauthn begin", "db", name, "err", err)
			s.jsonError(w, r, http.StatusInternalServerError, "methods.error.webauthn")
			return
		}
		s.ceremonies.put(ceremonyKey(serverSession(r).ID, purpose, name), &ceremony{data: *data})
		s.writeJSON(w, http.StatusOK, opts)
	}
}

// verifyAssertion checks an assertion against the database's keys and
// opens the DEK with the key's PRF output.
func (s *Server) verifyAssertion(r *http.Request, h *store.Handle, ce *ceremony) (*vault.Keyring, *db.UnlockMethod, error) {
	body, err := readBody(r)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, nil, err
	}
	m, err := h.MethodByCredential(r.Context(), parsed.RawID)
	if err != nil {
		return nil, nil, err
	}
	u, _, err := s.user(r, h, h.Name)
	if err != nil {
		return nil, nil, err
	}
	cred, err := s.webauthn.ValidateLogin(u, ce.data, parsed)
	if err != nil {
		return nil, nil, err
	}
	if cred.Authenticator.CloneWarning {
		s.log.Warn("security key signature counter went backwards: the key may be cloned", "db", h.Name, "method", m.Label)
		h.Audit(r.Context(), "method.clone_warning", 0, m.Label)
	}
	prf := prfResult(parsed.ClientExtensionResults)
	if prf == nil {
		return nil, nil, errNoPRF
	}
	defer clear(prf)
	kr, err := h.UnlockSecret(r.Context(), m, prf, cred.Authenticator.SignCount)
	if err != nil {
		return nil, nil, err
	}
	return kr, m, nil
}

var errNoPRF = errors.New("the authenticator returned no PRF output")

// webauthnLoginFinish opens a database session with a security key or
// passkey.
func (s *Server) webauthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ce := s.ceremonies.take(ceremonyKey(serverSession(r).ID, "login", name))
	if ce == nil || s.webauthn == nil {
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.expired")
		return
	}
	if s.dbLimit.Blocked(name) {
		s.jsonError(w, r, http.StatusTooManyRequests, "dblogin.error.ratelimit")
		return
	}
	s.dbLimit.Fail(name)
	h, err := s.store.Acquire(r.Context(), name)
	if err != nil {
		s.jsonError(w, r, http.StatusNotFound, "dblogin.error.unsupported")
		return
	}
	kr, m, err := s.verifyAssertion(r, h, ce)
	if err != nil {
		s.log.Warn("database login with a security key or passkey failed", "db", name, "ip", clientIP(r), "err", err)
		h.Audit(r.Context(), "database.unlock_failed", 0, "security key or passkey")
		h.Release()
		key := "methods.error.assertion"
		if errors.Is(err, errNoPRF) {
			key = "methods.error.noprf"
		}
		s.jsonError(w, r, http.StatusUnauthorized, key)
		return
	}
	s.dbLimit.Reset(name)
	s.openSession(w, r, name, h, kr, m)
	s.writeJSON(w, http.StatusOK, map[string]string{"redirect": dbPath(name)})
}

// openSession starts a database session after a successful login: it owns
// h and kr from here on.
func (s *Server) openSession(w http.ResponseWriter, r *http.Request, name string, h *store.Handle, kr *vault.Keyring, m *db.UnlockMethod) {
	detail := ""
	if m != nil {
		detail = m.Type + " " + m.Label
	}
	h.Audit(r.Context(), "database.unlock", 0, detail)
	if c, err := r.Cookie(dbCookie); err == nil {
		s.dbs.End(c.Value)
	}
	ds := s.dbs.Create(serverSession(r).ID, name, h, kr, nil)
	if m != nil {
		ds.SetMethod(m.UUID)
	}
	ds.Confirm()
	s.setCookie(w, dbCookie, ds.ID, dbPath(name), 0)
	s.log.Info("database opened", "db", name, "ip", clientIP(r), "method", detail)
}

// webauthnConfirmFinish re-confirms an open session with a security key or
// passkey.
func (s *Server) webauthnConfirmFinish(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	ce := s.ceremonies.take(ceremonyKey(serverSession(r).ID, "confirm", ds.DBName))
	if ce == nil || s.webauthn == nil {
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.expired")
		return
	}
	if s.keyLimit.Blocked(ds.ID) {
		s.jsonError(w, r, http.StatusTooManyRequests, "keycheck.ratelimit")
		return
	}
	kr, _, err := s.verifyAssertion(r, ds.Handle, ce)
	if err != nil {
		s.keyLimit.Fail(ds.ID)
		s.log.Warn("re-confirmation with a security key or passkey failed", "db", ds.DBName, "err", err)
		s.jsonError(w, r, http.StatusUnauthorized, "methods.error.assertion")
		return
	}
	kr.Wipe()
	ds.Confirm()
	s.writeJSON(w, http.StatusOK, map[string]string{"redirect": dbPath(ds.DBName) + "methods"})
}

// registerBegin starts adding a security key or passkey.
func (s *Server) registerBegin(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	if s.webauthn == nil {
		s.jsonError(w, r, http.StatusNotFound, "methods.error.webauthn_off")
		return
	}
	if !ds.Confirmed() {
		s.jsonError(w, r, http.StatusForbidden, "methods.error.confirm")
		return
	}
	typ, label := r.PostFormValue("type"), strings.TrimSpace(r.PostFormValue("label"))
	if typ != vault.SlotSecurityKey && typ != vault.SlotPasskey {
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.type")
		return
	}
	if label == "" || len([]rune(label)) > store.MaxLabelLength {
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.label")
		return
	}
	u, keys, err := s.user(r, ds.Handle, s.header(ds).Label)
	if err != nil {
		s.log.Error("webauthn register", "db", ds.DBName, "err", err)
		s.jsonError(w, r, http.StatusInternalServerError, "methods.error.webauthn")
		return
	}
	if len(keys) >= store.MaxWebAuthn {
		s.jsonError(w, r, http.StatusConflict, "methods.error.toomany")
		return
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for i := range u.creds {
		exclude = append(exclude, u.creds[i].Descriptor())
	}
	salt := make([]byte, prfSaltLen)
	rand.Read(salt)
	opts := []webauthn.RegistrationOption{
		webauthn.WithExclusions(exclude),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExtensions(webauthn.WithExtensionPRF(protocol.PRFValues{First: salt})),
	}
	if typ == vault.SlotPasskey {
		opts = append(opts,
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(),
				UserVerification: protocol.VerificationRequired}),
			webauthn.WithPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{
				protocol.PublicKeyCredentialHintClientDevice, protocol.PublicKeyCredentialHintHybrid}))
	} else {
		opts = append(opts,
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				ResidentKey: protocol.ResidentKeyRequirementDiscouraged, RequireResidentKey: protocol.ResidentKeyNotRequired(),
				UserVerification: protocol.VerificationRequired}),
			webauthn.WithPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{protocol.PublicKeyCredentialHintSecurityKey}))
	}
	creation, data, err := s.webauthn.BeginRegistration(u, opts...)
	if err != nil {
		s.log.Error("webauthn register", "db", ds.DBName, "err", err)
		s.jsonError(w, r, http.StatusInternalServerError, "methods.error.webauthn")
		return
	}
	s.ceremonies.put(ceremonyKey(serverSession(r).ID, "register", ds.DBName),
		&ceremony{data: *data, typ: typ, label: label, prfSalt: salt})
	s.writeJSON(w, http.StatusOK, creation)
}

// registerFinish verifies the new credential. When the authenticator
// already evaluated the PRF, the method is stored; otherwise the browser
// gets assertion options for the new credential (a second touch), answered
// at registerPRF.
func (s *Server) registerFinish(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	key := ceremonyKey(serverSession(r).ID, "register", ds.DBName)
	ce := s.ceremonies.take(key)
	if ce == nil || s.webauthn == nil || ce.cred != nil {
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.expired")
		return
	}
	if !ds.Confirmed() {
		s.jsonError(w, r, http.StatusForbidden, "methods.error.confirm")
		return
	}
	body, err := readBody(r)
	if err != nil {
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.webauthn")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		s.log.Warn("webauthn registration response", "db", ds.DBName, "err", err)
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.webauthn")
		return
	}
	u, _, err := s.user(r, ds.Handle, s.header(ds).Label)
	if err != nil {
		s.jsonError(w, r, http.StatusInternalServerError, "methods.error.webauthn")
		return
	}
	cred, err := s.webauthn.CreateCredential(u, ce.data, parsed)
	if err != nil {
		s.log.Warn("webauthn registration failed", "db", ds.DBName, "err", err)
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.webauthn")
		return
	}
	out := parsed.ClientExtensionResults.PRF
	if out == nil || out.Enabled == nil || !*out.Enabled {
		s.jsonError(w, r, http.StatusUnprocessableEntity, "methods.error.noprf")
		return
	}
	if prf := prfResult(parsed.ClientExtensionResults); prf != nil {
		defer clear(prf)
		s.storeKey(w, r, ds, ce, cred, prf, cred.Authenticator.SignCount)
		return
	}
	// A second touch: evaluate the PRF of the new credential.
	m := methodOf(ce, cred)
	opts, data, err := s.assertionOptions(&dbUser{id: u.id, name: u.name, display: u.display,
		creds: []webauthn.Credential{*cred}}, []db.UnlockMethod{m})
	if err != nil {
		s.jsonError(w, r, http.StatusInternalServerError, "methods.error.webauthn")
		return
	}
	ce.data, ce.cred = *data, cred
	s.ceremonies.put(key, ce)
	s.writeJSON(w, http.StatusOK, map[string]any{"assert": opts})
}

// registerPRF takes the second touch of a registration and stores the
// method.
func (s *Server) registerPRF(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	ce := s.ceremonies.take(ceremonyKey(serverSession(r).ID, "register", ds.DBName))
	if ce == nil || s.webauthn == nil || ce.cred == nil {
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.expired")
		return
	}
	if !ds.Confirmed() {
		s.jsonError(w, r, http.StatusForbidden, "methods.error.confirm")
		return
	}
	body, err := readBody(r)
	if err != nil {
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.webauthn")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil || !bytes.Equal(parsed.RawID, ce.cred.ID) {
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.webauthn")
		return
	}
	u, _, err := s.user(r, ds.Handle, s.header(ds).Label)
	if err != nil {
		s.jsonError(w, r, http.StatusInternalServerError, "methods.error.webauthn")
		return
	}
	u.creds = []webauthn.Credential{*ce.cred}
	cred, err := s.webauthn.ValidateLogin(u, ce.data, parsed)
	if err != nil {
		s.log.Warn("webauthn registration assertion failed", "db", ds.DBName, "err", err)
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.assertion")
		return
	}
	prf := prfResult(parsed.ClientExtensionResults)
	if prf == nil {
		s.jsonError(w, r, http.StatusUnprocessableEntity, "methods.error.noprf")
		return
	}
	defer clear(prf)
	s.storeKey(w, r, ds, ce, ce.cred, prf, cred.Authenticator.SignCount)
}

// methodOf turns a verified credential into an unlock method row.
func methodOf(ce *ceremony, cred *webauthn.Credential) db.UnlockMethod {
	var tr []string
	for _, t := range cred.Transport {
		tr = append(tr, string(t))
	}
	return db.UnlockMethod{Type: ce.typ, Label: ce.label, CredentialID: cred.ID, PublicKey: cred.PublicKey,
		SignCount: cred.Authenticator.SignCount, PRFSalt: ce.prfSalt, Transports: strings.Join(tr, ","),
		AAGUID: cred.Authenticator.AAGUID, Flags: byte(cred.Flags.ProtocolValue())}
}

func (s *Server) storeKey(w http.ResponseWriter, r *http.Request, ds *session.Session, ce *ceremony, cred *webauthn.Credential, prf []byte, signCount uint32) {
	m := methodOf(ce, cred)
	m.SignCount = signCount
	if _, err := ds.Handle.AddWebAuthn(r.Context(), ds.Keyring(), m, prf); err != nil {
		key := "methods.error.webauthn"
		switch {
		case errors.Is(err, store.ErrTooManyMethods):
			key = "methods.error.toomany"
		case errors.Is(err, store.ErrBadLabel):
			key = "methods.error.label"
		}
		s.log.Warn("storing a security key or passkey failed", "db", ds.DBName, "err", err)
		s.jsonError(w, r, http.StatusUnprocessableEntity, key)
		return
	}
	s.log.Info("unlock method added", "db", ds.DBName, "type", m.Type, "ip", clientIP(r))
	s.writeJSON(w, http.StatusOK, map[string]string{"redirect": dbPath(ds.DBName) + "methods?notice=added"})
}

// isWrongSecret reports whether err means a wrong password or code.
func isWrongSecret(err error) bool { return errors.Is(err, pki.ErrWrongPassword) }

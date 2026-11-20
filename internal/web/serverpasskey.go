package web

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/mailsvb/openkca/internal/auth"
)

// preCookie names the browser during a passkey login, before it has a
// server session; it only finds the started ceremony again.
const preCookie = "okca_pre"

const preCookiePath = "/login/passkey/"

// serverUser presents the server login to the WebAuthn library: one user,
// with every registered passkey.
type serverUser struct {
	id    []byte
	creds []webauthn.Credential
}

func (u *serverUser) WebAuthnID() []byte                         { return u.id }
func (u *serverUser) WebAuthnName() string                       { return "openkca" }
func (u *serverUser) WebAuthnDisplayName() string                { return "OpenKCA server" }
func (u *serverUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func passkeyCredential(k *auth.Passkey) webauthn.Credential {
	var tr []protocol.AuthenticatorTransport
	for _, t := range k.Transports {
		tr = append(tr, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:            k.CredentialID,
		PublicKey:     k.PublicKey,
		Transport:     tr,
		Flags:         webauthn.NewCredentialFlags(protocol.AuthenticatorFlags(k.Flags)),
		Authenticator: webauthn.Authenticator{AAGUID: k.AAGUID, SignCount: k.SignCount},
	}
}

func (s *Server) serverUser() *serverUser {
	u := &serverUser{id: s.passkeys.UserID()}
	for _, k := range s.passkeys.List() {
		u.creds = append(u.creds, passkeyCredential(&k))
	}
	return u
}

// passkeyLogin reports whether the login page offers passkeys.
func (s *Server) passkeyLogin() bool {
	return s.webauthn != nil && s.passkeys != nil && s.passkeys.Count() > 0
}

// passkeyLoginBegin starts a passkey login: a discoverable assertion, so
// that the browser offers every passkey it has for this server.
func (s *Server) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.passkeyLogin() {
		s.log.Info("server passkey login refused: no passkey is registered or webauthn is off", "ip", ip)
		s.jsonError(w, r, http.StatusNotFound, "passkeys.error.none")
		return
	}
	if s.srvLimit.Blocked(ip) {
		s.log.Info("server passkey login refused: rate limit", "ip", ip)
		s.jsonError(w, r, http.StatusTooManyRequests, "login.error.ratelimit")
		return
	}
	s.checkOrigin(r, "login")
	opts, data, err := s.webauthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.log.Error("server passkey login begin", logAttrs([]any{"ip", ip}, webauthnErrAttrs(err))...)
		s.jsonError(w, r, http.StatusInternalServerError, "passkeys.error.webauthn")
		return
	}
	pre := auth.NewID()
	s.ceremonies.put(ceremonyKey(pre, "server-login", ""), &ceremony{data: *data})
	s.setCookie(w, r, preCookie, pre, preCookiePath, int(ceremonyTTL.Seconds()))
	s.log.Info("server passkey login started", "ip", ip, "origin", r.Header.Get("Origin"),
		"rp_id", s.cfg.WebAuthn.RPID, "passkeys", s.passkeys.Count())
	s.writeJSON(w, http.StatusOK, opts)
}

// passkeyLoginFinish checks the assertion and starts a server session.
func (s *Server) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	var ce *ceremony
	if c, err := r.Cookie(preCookie); err == nil {
		ce = s.ceremonies.take(ceremonyKey(c.Value, "server-login", ""))
	}
	s.setCookie(w, r, preCookie, "", preCookiePath, -1)
	// JSON only: a cross-site form cannot send it without a preflight.
	var reason string
	switch {
	case ce == nil:
		reason = "no pending ceremony (expired, already used or no cookie)"
	case !s.passkeyLogin():
		reason = "no passkey is registered or webauthn is off"
	case !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json"):
		reason = "request is not JSON"
	}
	if reason != "" {
		s.log.Info("server passkey login refused: "+reason, "ip", ip)
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.expired")
		return
	}
	if s.srvLimit.Blocked(ip) {
		s.log.Info("server passkey login refused: rate limit", "ip", ip)
		s.jsonError(w, r, http.StatusTooManyRequests, "login.error.ratelimit")
		return
	}
	s.srvLimit.Fail(ip)
	cred, err := s.verifyServerPasskey(r, ce)
	if err != nil {
		s.log.Warn("server login with a passkey failed", logAttrs([]any{"ip", ip}, webauthnErrAttrs(err))...)
		s.jsonError(w, r, http.StatusUnauthorized, "passkeys.error.assertion")
		return
	}
	k, ok := s.passkeys.ByCredential(cred.ID)
	if !ok {
		// Removed between the check and now.
		s.log.Info("server passkey login refused: the passkey was removed meanwhile", "ip", ip)
		s.jsonError(w, r, http.StatusUnauthorized, "passkeys.error.assertion")
		return
	}
	if cred.Authenticator.CloneWarning {
		s.log.Warn("passkey signature counter went backwards: it may be cloned", "label", k.Label, "ip", ip)
	}
	if err := s.passkeys.Used(cred.ID, cred.Authenticator.SignCount); err != nil {
		s.log.Error("saving the server passkeys", "err", err)
	}
	s.srvLimit.Reset(ip)
	s.startServerSession(w, r, "passkey", k.Label)
	s.writeJSON(w, http.StatusOK, map[string]string{"redirect": "/"})
}

func (s *Server) verifyServerPasskey(r *http.Request, ce *ceremony) (*webauthn.Credential, error) {
	body, err := readBody(r)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, err
	}
	s.log.Info("server passkey login: assertion received", "ip", clientIP(r),
		"credential", b64(parsed.RawID), "user_verified", parsed.Response.AuthenticatorData.Flags.HasUserVerified())
	u := s.serverUser()
	_, cred, err := s.webauthn.ValidatePasskeyLogin(func(_, userHandle []byte) (webauthn.User, error) {
		if subtle.ConstantTimeCompare(userHandle, u.id) != 1 {
			return nil, errors.New("unknown user handle")
		}
		return u, nil
	}, ce.data, parsed)
	return cred, err
}

// passkeysPage lists the server login's passkeys.
func (s *Server) passkeysPage(w http.ResponseWriter, r *http.Request) {
	p := &page{Title: "passkeys.title", Data: map[string]any{
		"WebAuthn": s.webauthn != nil, "MaxLabel": auth.MaxPasskeyLabel,
	}}
	if s.passkeys != nil {
		p.Data["Passkeys"] = s.passkeys.List()
	}
	if n := r.URL.Query().Get("notice"); n == "added" || n == "removed" {
		p.Notice = "passkeys.notice." + n
	}
	s.render(w, r, http.StatusOK, "passkeys", p)
}

// checkServerPassword checks the server password under the login rate
// limit, with at most two Argon2id runs at a time. It returns "" or the
// message key and HTTP status of the failure.
func (s *Server) checkServerPassword(r *http.Request, pw []byte) (string, int) {
	ip := clientIP(r)
	if s.srvLimit.Blocked(ip) {
		return "login.error.ratelimit", http.StatusTooManyRequests
	}
	// Argon2id takes 64 MiB per run: limit the runs in parallel, and count
	// the attempt before hashing so that parallel requests cannot pass the
	// rate limit together.
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		return "login.error.busy", http.StatusTooManyRequests
	}
	s.srvLimit.Fail(ip)
	if !auth.CheckPassword(s.cfg.PasswordHash, pw) {
		return "login.error.password", http.StatusUnauthorized
	}
	s.srvLimit.Reset(ip)
	return "", http.StatusOK
}

// passkeyRegisterBegin starts adding a passkey to the server login. It
// needs the server password every time, also in a session that was
// opened with a passkey.
func (s *Server) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.webauthn == nil || s.passkeys == nil {
		s.log.Info("adding a server passkey refused: webauthn is off (general.webauthn.rp_id not set)", "ip", ip)
		s.jsonError(w, r, http.StatusNotFound, "methods.error.webauthn_off")
		return
	}
	label, ok := auth.ValidPasskeyLabel(r.PostFormValue("label"))
	if !ok {
		s.log.Info("adding a server passkey refused: name missing or too long", "ip", ip)
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.label")
		return
	}
	if s.passkeys.HasLabel(label) {
		s.log.Info("adding a server passkey refused: name already used", "label", label, "ip", ip)
		s.jsonError(w, r, http.StatusConflict, "passkeys.error.duplicate")
		return
	}
	if n := s.passkeys.Count(); n >= auth.MaxPasskeys {
		s.log.Info("adding a server passkey refused: too many passkeys", "label", label, "passkeys", n, "ip", ip)
		s.jsonError(w, r, http.StatusConflict, "passkeys.error.toomany")
		return
	}
	pw := []byte(r.PostFormValue("password"))
	defer clear(pw)
	if key, status := s.checkServerPassword(r, pw); key != "" {
		if key == "login.error.password" {
			s.log.Warn("adding a server passkey: wrong server password", "label", label, "ip", ip)
		} else {
			s.log.Info("adding a server passkey refused", "reason", key, "label", label, "ip", ip)
		}
		s.jsonError(w, r, status, key)
		return
	}
	s.checkOrigin(r, "register")
	u := s.serverUser()
	exclude := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for i := range u.creds {
		exclude = append(exclude, u.creds[i].Descriptor())
	}
	creation, data, err := s.webauthn.BeginRegistration(u,
		webauthn.WithExclusions(exclude),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey: protocol.ResidentKeyRequirementRequired, RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification: protocol.VerificationRequired}))
	if err != nil {
		s.log.Error("server passkey registration begin", logAttrs([]any{"label", label, "ip", ip}, webauthnErrAttrs(err))...)
		s.jsonError(w, r, http.StatusInternalServerError, "passkeys.error.webauthn")
		return
	}
	s.ceremonies.put(ceremonyKey(serverSession(r).ID, "server-register", ""), &ceremony{data: *data, label: label})
	s.log.Info("server passkey registration started", "label", label, "ip", ip, "origin", r.Header.Get("Origin"),
		"host", r.Host, "rp_id", s.cfg.WebAuthn.RPID, "passkeys", len(u.creds))
	s.writeJSON(w, http.StatusOK, creation)
}

// passkeyRegisterFinish verifies the new passkey and stores it.
func (s *Server) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	ce := s.ceremonies.take(ceremonyKey(serverSession(r).ID, "server-register", ""))
	if ce == nil || s.webauthn == nil || s.passkeys == nil {
		s.log.Info("adding a server passkey refused: no pending registration (expired or already used)", "ip", ip)
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.expired")
		return
	}
	body, err := readBody(r)
	if err != nil {
		s.log.Warn("server passkey registration: reading the response failed", "label", ce.label, "ip", ip, "err", err)
		s.jsonError(w, r, http.StatusBadRequest, "passkeys.error.webauthn")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		s.log.Warn("server passkey registration: invalid response", logAttrs([]any{"label", ce.label, "ip", ip}, webauthnErrAttrs(err))...)
		s.jsonError(w, r, http.StatusBadRequest, "passkeys.error.webauthn")
		return
	}
	s.log.Info("server passkey registration: response received", "label", ce.label, "ip", ip,
		"credential", b64(parsed.RawID), "attachment", parsed.AuthenticatorAttachment)
	cred, err := s.webauthn.CreateCredential(s.serverUser(), ce.data, parsed)
	if err != nil {
		s.log.Warn("server passkey registration failed", logAttrs([]any{"label", ce.label, "ip", ip}, webauthnErrAttrs(err))...)
		s.jsonError(w, r, http.StatusBadRequest, "passkeys.error.webauthn")
		return
	}
	var tr []string
	for _, t := range cred.Transport {
		tr = append(tr, string(t))
	}
	k, err := s.passkeys.Add(auth.Passkey{Label: ce.label, CredentialID: cred.ID, PublicKey: cred.PublicKey,
		AAGUID: cred.Authenticator.AAGUID, SignCount: cred.Authenticator.SignCount, Transports: tr,
		Flags: byte(cred.Flags.ProtocolValue())})
	if err != nil {
		key := "passkeys.error.webauthn"
		switch {
		case errors.Is(err, auth.ErrPasskeyDuplicate):
			key = "passkeys.error.duplicate"
		case errors.Is(err, auth.ErrPasskeyKnown):
			key = "passkeys.error.known"
		case errors.Is(err, auth.ErrPasskeyTooMany):
			key = "passkeys.error.toomany"
		case errors.Is(err, auth.ErrPasskeyLabel):
			key = "methods.error.label"
		default:
			s.log.Error("saving the server passkeys", "err", err)
		}
		if key != "passkeys.error.webauthn" {
			s.log.Info("adding a server passkey refused", "reason", err, "label", ce.label, "ip", ip)
		}
		s.jsonError(w, r, http.StatusUnprocessableEntity, key)
		return
	}
	s.log.Info("server passkey added", "label", k.Label, "ip", ip, "aaguid", hex.EncodeToString(k.AAGUID),
		"transports", strings.Join(tr, ","), "backup_eligible", cred.Flags.BackupEligible,
		"backed_up", cred.Flags.BackupState, "passkeys", s.passkeys.Count())
	s.writeJSON(w, http.StatusOK, map[string]string{"redirect": "/passkeys?notice=added"})
}

// passkeyDelete removes a passkey from the server login.
func (s *Server) passkeyDelete(w http.ResponseWriter, r *http.Request) {
	if s.passkeys == nil {
		http.NotFound(w, r)
		return
	}
	k, ok, err := s.passkeys.Remove(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ok {
		s.log.Info("removing a server passkey: not found", "id", r.PathValue("id"), "ip", clientIP(r))
		http.NotFound(w, r)
		return
	}
	s.log.Info("server passkey removed", "label", k.Label, "ip", clientIP(r))
	http.Redirect(w, r, "/passkeys?notice=removed", http.StatusSeeOther)
}

// checkOrigin logs a warning when the browser's origin will not pass the
// WebAuthn checks: the most common reason a passkey cannot be created or
// used. The browser refuses a host outside rp_id itself (SecurityError);
// the server refuses an origin that is not configured.
func (s *Server) checkOrigin(r *http.Request, flow string) {
	origin := strings.ToLower(r.Header.Get("Origin"))
	if origin == "" {
		return
	}
	rpID := s.cfg.WebAuthn.RPID
	origins := s.cfg.WebAuthn.Origins
	if u, err := url.Parse(origin); err == nil {
		if h := u.Hostname(); h != rpID && !strings.HasSuffix(h, "."+rpID) {
			s.log.Warn("server passkey: the browser's host is not general.webauthn.rp_id or below it; the browser will refuse the passkey",
				"flow", flow, "origin", origin, "rp_id", rpID, "ip", clientIP(r))
			return
		}
		if u.Scheme != "https" {
			s.log.Warn("server passkey: the page is not served over HTTPS; passkeys need https:// origins",
				"flow", flow, "origin", origin, "ip", clientIP(r))
		}
	}
	if !slices.Contains(origins, origin) {
		s.log.Warn("server passkey: the browser's origin is not among general.webauthn.origins; the server will refuse the passkey",
			"flow", flow, "origin", origin, "origins", strings.Join(origins, " "), "ip", clientIP(r))
	}
}

// browserFailure is what the browser reports when navigator.credentials
// failed: the DOMException's name and message.
type browserFailure struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

// readBrowserFailure reads a browserFailure; its fields are cut to 200
// characters without control characters, as they go into the log.
func readBrowserFailure(r *http.Request) browserFailure {
	var f browserFailure
	if body, err := readBody(r); err == nil {
		json.Unmarshal(body, &f)
	}
	clean := func(v string) string {
		v = strings.Map(func(c rune) rune {
			if unicode.IsControl(c) {
				return ' '
			}
			return c
		}, v)
		if rs := []rune(v); len(rs) > 200 {
			v = string(rs[:200])
		}
		return strings.TrimSpace(v)
	}
	return browserFailure{Name: clean(f.Name), Message: clean(f.Message)}
}

// passkeyLoginAbort logs a passkey login that failed in the browser. It
// needs the started ceremony, which it ends, so that it cannot fill the log.
func (s *Server) passkeyLoginAbort(w http.ResponseWriter, r *http.Request) {
	var ce *ceremony
	if c, err := r.Cookie(preCookie); err == nil {
		ce = s.ceremonies.take(ceremonyKey(c.Value, "server-login", ""))
	}
	s.setCookie(w, r, preCookie, "", preCookiePath, -1)
	if ce == nil || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		s.jsonError(w, r, http.StatusBadRequest, "methods.error.expired")
		return
	}
	f := readBrowserFailure(r)
	s.log.Info("server passkey login failed in the browser", "ip", clientIP(r), "name", f.Name, "message", f.Message)
	w.WriteHeader(http.StatusNoContent)
}

// passkeyRegisterAbort logs a passkey registration that failed in the
// browser and ends the started ceremony.
func (s *Server) passkeyRegisterAbort(w http.ResponseWriter, r *http.Request) {
	ce := s.ceremonies.take(ceremonyKey(serverSession(r).ID, "server-register", ""))
	f := readBrowserFailure(r)
	label := ""
	if ce != nil {
		label = ce.label
	}
	s.log.Info("server passkey registration failed in the browser", "label", label, "ip", clientIP(r),
		"name", f.Name, "message", f.Message, "pending", ce != nil)
	w.WriteHeader(http.StatusNoContent)
}

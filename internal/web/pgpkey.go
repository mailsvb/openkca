package web

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/session"
	"github.com/mailsvb/go-ca/internal/store"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// pgpKeyChoices are the key types offered for new OpenPGP keys, the usual
// one first. Each gets an encryption subkey of the matching kind.
var pgpKeyChoices = []keyChoice{
	{"Ed25519", "Ed25519 / X25519"},
	{"EC:P-256", "ECDSA / ECDH P-256"}, {"EC:P-384", "ECDSA / ECDH P-384"}, {"EC:P-521", "ECDSA / ECDH P-521"},
	{"RSA:3072", "RSA 3072"}, {"RSA:4096", "RSA 4096"},
}

// pgpVersions and pgpExpiries are the choices of the forms, default first.
var (
	pgpVersions = []string{"4", "6"}
	pgpExpiries = []string{"2y", "1y", "3y", "5y", "never"}
	pgpUsages   = []string{codec.PGPEncrypt, codec.PGPSign, codec.PGPAuth}
	pgpFlavors  = []string{"bundle", "public", "binary", "secret"}
)

// pgpParams reads version, user IDs and expiry of a form.
func pgpParams(r *http.Request) (codec.PGPParams, []string, bool) {
	var uids []string
	for _, l := range strings.Split(r.PostFormValue("uids"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			uids = append(uids, l)
		}
	}
	p := codec.PGPParams{UIDs: uids, Created: time.Now()}
	v := r.PostFormValue("version")
	exp := r.PostFormValue("expiry")
	if !slices.Contains(pgpVersions, v) || !slices.Contains(pgpExpiries, exp) || len(uids) == 0 || len(uids) > 20 {
		return p, uids, false
	}
	for _, u := range uids {
		if !codec.ValidPGPUserID(u) {
			return p, uids, false
		}
	}
	p.Version, _ = strconv.Atoi(v)
	if exp != "never" {
		years, _ := strconv.Atoi(strings.TrimSuffix(exp, "y"))
		p.Lifetime = p.Created.AddDate(years, 0, 0).Sub(p.Created)
	}
	return p, uids, true
}

// encryptionSpec is the encryption subkey generated for a primary key.
func encryptionSpec(pub crypto.PublicKey) *pki.KeySpec {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return &pki.KeySpec{Type: "X25519"}
	case *ecdsa.PublicKey:
		return &pki.KeySpec{Type: "EC", Curve: k.Curve.Params().Name}
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		if !slices.Contains(pki.RSASizes, bits) {
			bits = 3072
		}
		return &pki.KeySpec{Type: "RSA", Bits: bits}
	}
	return nil
}

func (s *Server) newPGPKeyPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "newpgpkey", &page{Title: "newpgpkey.title", Tab: "keys", Data: map[string]any{
		"KeyChoices": pgpKeyChoices, "Type": pgpKeyChoices[0].Value, "Versions": pgpVersions, "Version": pgpVersions[0],
		"Expiries": pgpExpiries, "Expiry": pgpExpiries[0], "Subkey": true}})
}

func (s *Server) newPGPKey(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	name := strings.TrimSpace(r.PostFormValue("name"))
	typ := r.PostFormValue("type")
	p, uids, ok := pgpParams(r)
	subkey := r.PostFormValue("subkey") != ""
	data := map[string]any{"KeyChoices": pgpKeyChoices, "Type": typ, "Versions": pgpVersions, "Version": r.PostFormValue("version"),
		"Expiries": pgpExpiries, "Expiry": r.PostFormValue("expiry"), "Name": name, "UIDs": strings.Join(uids, "\n"), "Subkey": subkey}
	spec, err := parseKeyChoice(typ)
	offered := slices.ContainsFunc(pgpKeyChoices, func(c keyChoice) bool { return c.Value == typ })
	if err != nil || !offered || !ok {
		s.render(w, r, http.StatusUnprocessableEntity, "newpgpkey", &page{Title: "newpgpkey.title", Tab: "keys",
			Error: "newpgpkey.error.input", Data: data})
		return
	}
	if name == "" {
		name = uids[0]
	}
	var subs []store.PGPSubkey
	if subkey {
		sub := *spec // ECDH on the same curve, RSA of the same size
		if spec.Type == "Ed25519" {
			sub = pki.KeySpec{Type: "X25519"}
		}
		subs = append(subs, store.PGPSubkey{Spec: &sub, Name: s.printer(r).T("pgpkey.subkey.name", name), Usage: codec.PGPEncrypt})
	}
	pw := ds.Password()
	defer clear(pw)
	id, err := ds.Handle.GeneratePGPKey(r.Context(), name, "", *spec, subs, p, pw)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("OpenPGP key generated", "db", ds.DBName, "id", id, "type", typ, "version", p.Version)
	http.Redirect(w, r, dbPath(ds.DBName)+"item/"+strconv.FormatInt(id, 10)+"/pgp?notice=created", http.StatusSeeOther)
}

// pgpSubRow is a subkey on a key's PGP page.
type pgpSubRow struct {
	codec.PGPKeyInfo
	Key *xdb.Key // the stored key, nil if not stored
}

// pgpKeyForm is the PGP page of a key.
type pgpKeyForm struct {
	Key         *xdb.Key
	View        *store.PGPView
	Primary     *xdb.Key // when Key is a subkey of another key's certificate
	Fingerprint string
	Public      string // armored
	Subkeys     []pgpSubRow
	Private     bool // the secret key can be exported
	OwnPass     bool // a key of the certificate has its own password
	Expired     bool
	CanCreate   bool   // the key can become an OpenPGP primary key
	SubkeySpec  string // the encryption subkey generated with it
	Eligible    []keyChoice
	Flavors     []string
	Flavor      string
	Versions    []string
	Expiries    []string
	Usages      []string
}

func (s *Server) pgpKeyForm(r *http.Request, snap *xdb.Snapshot) (*pgpKeyForm, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil, false
	}
	var k *xdb.Key
	for _, sk := range snap.Keys {
		if sk.ID == id {
			k = sk
		}
	}
	if k == nil {
		return nil, false
	}
	f := &pgpKeyForm{Key: k, Flavors: pgpFlavors, Flavor: pgpFlavors[0], Versions: pgpVersions, Expiries: pgpExpiries, Usages: pgpUsages}
	byID := map[int64]*xdb.Key{}
	for _, sk := range snap.Keys {
		byID[sk.ID] = sk
	}
	if v := store.PGPOf(snap, id); v != nil {
		f.View = v
		f.Fingerprint = codec.FormatPGPFingerprint(v.Info.Keys[0].Fingerprint)
		if b, err := codec.PGPArmor(codec.PGPPublicBlock, v.Cert.Cert, v.Info.Version); err == nil {
			f.Public = strings.TrimSpace(string(b))
		}
		inCert := map[int64]bool{}
		for i, info := range v.Info.Keys {
			sk := byID[v.KeyIDs[i]]
			if sk != nil {
				inCert[sk.ID] = true
				f.OwnPass = f.OwnPass || sk.OwnPass == xdb.PassPrivate
			}
			if i > 0 {
				f.Subkeys = append(f.Subkeys, pgpSubRow{PGPKeyInfo: info, Key: sk})
			}
		}
		f.Private = k.HasPrivate && !k.Token
		f.Expired = v.Info.Expired(time.Now())
		primaries := map[int64]bool{}
		for _, c := range snap.PGP {
			primaries[c.KeyID] = true
		}
		for _, sk := range snap.Keys {
			if sk.HasPrivate && !sk.Token && !inCert[sk.ID] && !primaries[sk.ID] {
				info := pki.DescribePublicKey(sk.Public)
				f.Eligible = append(f.Eligible, keyChoice{strconv.FormatInt(sk.ID, 10), sk.Name + " (" + info.Algorithm + " " + strconv.Itoa(info.Bits) + ")"})
			}
		}
		return f, true
	}
	if v := store.PGPSubkeyOf(snap, id); v != nil {
		f.View, f.Primary = v, byID[v.Primary()]
		f.Fingerprint = codec.FormatPGPFingerprint(v.Info.Keys[0].Fingerprint)
		return f, true
	}
	pub, err := codec.ParsePublic(k.Public)
	if err != nil {
		return nil, false
	}
	f.CanCreate = k.HasPrivate && !k.Token && codec.PGPCompatible(pub, 4, false)
	f.OwnPass = k.OwnPass == xdb.PassPrivate
	if spec := encryptionSpec(pub); spec != nil {
		f.SubkeySpec = spec.Type
		if spec.Curve != "" {
			f.SubkeySpec += " " + spec.Curve
		} else if spec.Bits != 0 {
			f.SubkeySpec += " " + strconv.Itoa(spec.Bits)
		}
	}
	return f, f.CanCreate
}

func (s *Server) renderPGPKey(w http.ResponseWriter, r *http.Request, status int, f *pgpKeyForm, p *page) {
	if p == nil {
		p = &page{}
	}
	p.Title, p.Tab = "pgpkey.title", "keys"
	p.Data = map[string]any{"F": f}
	s.render(w, r, status, "pgpkey", p)
}

func (s *Server) pgpKeyPage(w http.ResponseWriter, r *http.Request) {
	snap, err := dbSession(r).Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, ok := s.pgpKeyForm(r, snap)
	if !ok {
		s.render(w, r, http.StatusNotFound, "error", &page{Title: "pgpkey.title", Error: "pgpkey.error.notpgp"})
		return
	}
	p := &page{}
	switch n := r.URL.Query().Get("notice"); n {
	case "created", "subkey", "removed":
		p.Notice = "pgpkey.notice." + n
	}
	s.renderPGPKey(w, r, http.StatusOK, f, p)
}

// pgpAction loads the PGP page of a POST and runs fn; fn's error key is
// shown on the page.
func (s *Server) pgpAction(w http.ResponseWriter, r *http.Request, fn func(ds *session.Session, f *pgpKeyForm, snap *xdb.Snapshot) (string, string, error)) {
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, ok := s.pgpKeyForm(r, snap)
	if !ok {
		s.render(w, r, http.StatusNotFound, "error", &page{Title: "pgpkey.title", Error: "pgpkey.error.notpgp"})
		return
	}
	if f.OwnPass && r.PostFormValue("keypass") != "" && s.keyLimit.Blocked(ds.ID) {
		s.renderPGPKey(w, r, http.StatusUnprocessableEntity, f, &page{Error: "export.error.ratelimit"})
		return
	}
	errKey, notice, err := fn(ds, f, snap)
	switch {
	case errors.Is(err, store.ErrNeedKeyPassword):
		if r.PostFormValue("keypass") != "" {
			s.keyLimit.Fail(ds.ID)
		}
		s.renderPGPKey(w, r, http.StatusUnprocessableEntity, f, &page{Error: "export.error.keypass"})
	case err != nil:
		s.log.Warn("OpenPGP action failed", "db", ds.DBName, "id", f.Key.ID, "err", err)
		s.renderPGPKey(w, r, http.StatusUnprocessableEntity, f, &page{Error: "pgpkey.error.failed", ErrorArg: err.Error()})
	case errKey != "":
		s.renderPGPKey(w, r, http.StatusUnprocessableEntity, f, &page{Error: errKey})
	default:
		http.Redirect(w, r, dbPath(ds.DBName)+"item/"+strconv.FormatInt(f.Key.ID, 10)+"/pgp?notice="+notice, http.StatusSeeOther)
	}
}

// pgpCreate turns a stored key into an OpenPGP primary key.
func (s *Server) pgpCreate(w http.ResponseWriter, r *http.Request) {
	s.pgpAction(w, r, func(ds *session.Session, f *pgpKeyForm, snap *xdb.Snapshot) (string, string, error) {
		if !f.CanCreate {
			return "pgpkey.error.notpgp", "", nil
		}
		p, _, ok := pgpParams(r)
		if !ok {
			return "newpgpkey.error.input", "", nil
		}
		var subs []store.PGPSubkey
		if r.PostFormValue("subkey") != "" {
			pub, _ := codec.ParsePublic(f.Key.Public)
			if spec := encryptionSpec(pub); spec != nil {
				subs = append(subs, store.PGPSubkey{Spec: spec, Name: s.printer(r).T("pgpkey.subkey.name", f.Key.Name), Usage: codec.PGPEncrypt})
			}
		}
		pw := ds.Password()
		defer clear(pw)
		if err := ds.Handle.CreatePGP(r.Context(), f.Key.ID, subs, p, pw, keyPasswords(r, snap)); err != nil {
			return "", "", err
		}
		s.log.Info("OpenPGP certificate created", "db", ds.DBName, "id", f.Key.ID, "version", p.Version)
		return "", "created", nil
	})
}

// pgpAddSubkey binds a stored key, or a new encryption key, as subkey.
func (s *Server) pgpAddSubkey(w http.ResponseWriter, r *http.Request) {
	s.pgpAction(w, r, func(ds *session.Session, f *pgpKeyForm, snap *xdb.Snapshot) (string, string, error) {
		if f.View == nil || f.Primary != nil || !f.Private {
			return "pgpkey.error.notpgp", "", nil
		}
		usage := r.PostFormValue("usage")
		if !slices.Contains(pgpUsages, usage) {
			return "pgpkey.error.subkey", "", nil
		}
		sub := store.PGPSubkey{Usage: usage}
		if v := r.PostFormValue("key"); v == "new" {
			pub, _ := codec.ParsePublic(f.Key.Public)
			spec := encryptionSpec(pub)
			if spec == nil || usage != codec.PGPEncrypt {
				return "pgpkey.error.subkey", "", nil
			}
			sub.Spec, sub.Name = spec, s.printer(r).T("pgpkey.subkey.name", f.Key.Name)
		} else {
			id, err := strconv.ParseInt(v, 10, 64)
			if err != nil || !slices.ContainsFunc(f.Eligible, func(c keyChoice) bool { return c.Value == v }) {
				return "pgpkey.error.subkey", "", nil
			}
			k := findSnapKey(snap, id)
			pub, err := codec.ParsePublic(k.Public)
			if err != nil || !codec.PGPCompatible(pub, f.View.Info.Version, usage == codec.PGPEncrypt) {
				return "pgpkey.error.subkey", "", nil
			}
			sub.KeyID = id
		}
		pw := ds.Password()
		defer clear(pw)
		if err := ds.Handle.AddPGPSubkey(r.Context(), f.Key.ID, sub, pw, keyPasswords(r, snap)); err != nil {
			return "", "", err
		}
		s.log.Info("OpenPGP subkey added", "db", ds.DBName, "id", f.Key.ID, "subkey", sub.KeyID, "usage", usage)
		return "", "subkey", nil
	})
}

// pgpRemove deletes a key's certificate; its keys stay.
func (s *Server) pgpRemove(w http.ResponseWriter, r *http.Request) {
	s.pgpAction(w, r, func(ds *session.Session, f *pgpKeyForm, _ *xdb.Snapshot) (string, string, error) {
		if f.View == nil || f.Primary != nil || r.PostFormValue("confirm") == "" {
			return "pgpkey.error.confirm", "", nil
		}
		if err := ds.Handle.DeletePGP(r.Context(), f.Key.ID); err != nil {
			return "", "", err
		}
		s.log.Info("OpenPGP certificate removed", "db", ds.DBName, "id", f.Key.ID)
		return "", "removed", nil
	})
}

func findSnapKey(snap *xdb.Snapshot, id int64) *xdb.Key {
	for _, k := range snap.Keys {
		if k.ID == id {
			return k
		}
	}
	return nil
}

// pgpKeyDownload sends the OpenPGP key: a ZIP of public key, secret key
// and revocation certificate, or one of them.
func (s *Server) pgpKeyDownload(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, ok := s.pgpKeyForm(r, snap)
	if !ok || f.View == nil || f.Primary != nil {
		s.render(w, r, http.StatusNotFound, "error", &page{Title: "pgpkey.title", Error: "pgpkey.error.notpgp"})
		return
	}
	if v := r.PostFormValue("format"); slices.Contains(pgpFlavors, v) {
		f.Flavor = v
	}
	fail := func(key, arg string) {
		s.renderPGPKey(w, r, http.StatusUnprocessableEntity, f, &page{Error: key, ErrorArg: arg})
	}
	secret := f.Flavor == "bundle" || f.Flavor == "secret"
	if secret && !f.Private {
		fail("pgpkey.error.noprivate", "")
		return
	}
	pw, pw2 := []byte(r.PostFormValue("password")), []byte(r.PostFormValue("password2"))
	defer clear(pw)
	defer clear(pw2)
	if !bytes.Equal(pw, pw2) {
		fail("export.error.mismatch", "")
		return
	}
	if secret && f.OwnPass && s.keyLimit.Blocked(ds.ID) {
		fail("export.error.ratelimit", "")
		return
	}
	dbPass := ds.Password()
	defer clear(dbPass)
	req := store.ExportRequest{IDs: []int64{f.Key.ID}, Password: pw, DBPass: dbPass, Keys: keyPasswords(r, snap), T: s.printer(r).T}
	var res *store.ExportResult
	switch f.Flavor {
	case "bundle":
		res, err = ds.Handle.PGPBundle(r.Context(), req)
	default:
		req.Format = map[string]int{"public": 110, "binary": 111, "secret": 112}[f.Flavor]
		if f.Flavor == "secret" && len(pw) > 0 {
			req.Format = 113
		}
		res, err = ds.Handle.Export(r.Context(), req)
	}
	switch {
	case errors.Is(err, store.ErrNeedKeyPassword):
		if r.PostFormValue("keypass") != "" {
			s.keyLimit.Fail(ds.ID)
		}
		fail("export.error.keypass", "")
		return
	case err != nil:
		s.log.Warn("OpenPGP key export failed", "db", ds.DBName, "id", f.Key.ID, "err", err)
		fail("export.error.failed", err.Error())
		return
	}
	if secret {
		s.log.Info("private key exported", "db", ds.DBName, "items", f.View.KeyIDs, "format", "pgp-"+f.Flavor, "ip", clientIP(r))
	}
	w.Header().Set("Content-Type", res.ContentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": res.Filename}))
	w.Header().Set("Content-Length", strconv.Itoa(len(res.Data)))
	w.Write(res.Data)
}

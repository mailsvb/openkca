package web

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/store"
)

// reasonChoice is a revocation reason for select boxes.
type reasonChoice struct {
	Code int
	Name string // message key suffix
}

func reasonChoices() []reasonChoice {
	var out []reasonChoice
	for _, c := range pki.ReasonCodes {
		out = append(out, reasonChoice{c, pki.ReasonNames[c]})
	}
	return out
}

func parseRevocation(r *http.Request) (store.Revocation, error) {
	var rv store.Revocation
	code, err := strconv.Atoi(r.PostFormValue("reason"))
	if err != nil || code < 0 || code >= len(pki.ReasonNames) || pki.ReasonNames[code] == "" {
		return rv, errors.New("invalid reason")
	}
	rv.Reason = code
	if s := r.PostFormValue("invaldate"); s != "" {
		if rv.InvalDate, err = parseLocal(s); err != nil {
			return rv, err
		}
	}
	return rv, nil
}

func nowLocal() string { return time.Now().UTC().Format("2006-01-02T15:04") }

func (s *Server) revokeCert(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	rv, err := parseRevocation(r)
	if err != nil {
		s.toItem(w, r, id, "error=ca.error.revoke")
		return
	}
	if err := dbSession(r).Handle.Revoke(r.Context(), id, rv); err != nil {
		s.log.Warn("revoke failed", "id", id, "err", err)
		s.toItem(w, r, id, "error=ca.error.revoke")
		return
	}
	s.log.Info("certificate revoked", "db", dbSession(r).DBName, "id", id, "reason", rv.Reason)
	s.toItem(w, r, id, "notice=revoked")
}

func (s *Server) unrevokeCert(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := dbSession(r).Handle.Unrevoke(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.toItem(w, r, id, "notice=unrevoked")
}

func (s *Server) caProperties(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	days, err1 := strconv.Atoi(r.PostFormValue("crldays"))
	tmpl, err2 := strconv.ParseInt(r.PostFormValue("template"), 10, 64)
	if err1 != nil || err2 != nil {
		s.toItem(w, r, id, "error=ca.error.properties")
		return
	}
	if err := dbSession(r).Handle.SetCAProperties(r.Context(), id, days, tmpl); err != nil {
		s.toItem(w, r, id, "error=ca.error.properties")
		return
	}
	s.toItem(w, r, id, "notice=saved")
}

// caFor loads a CA certificate for the CA pages.
func (s *Server) caFor(w http.ResponseWriter, r *http.Request) (*gcadb.Snapshot, *gcadb.Cert, bool) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return nil, nil, false
	}
	snap, err := dbSession(r).Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return nil, nil, false
	}
	for _, c := range snap.Certs {
		if c.ID == id && c.CA {
			return snap, c, true
		}
	}
	http.NotFound(w, r)
	return nil, nil, false
}

type revRow struct {
	gcadb.Revocation
	Cert       link
	Reason     string
	InvalLocal string
}

func (s *Server) revocationsPage(w http.ResponseWriter, r *http.Request) {
	snap, ca, ok := s.caFor(w, r)
	if !ok {
		return
	}
	bySerial := map[string]link{}
	for _, c := range snap.Certs {
		if c.IssuerID == ca.ID && c.ID != ca.ID {
			bySerial[c.Serial] = link{c.ID, c.Name}
		}
	}
	var rows []revRow
	for _, rv := range snap.Revocations {
		if rv.CAID != ca.ID {
			continue
		}
		row := revRow{Revocation: *rv, Cert: bySerial[rv.Serial]}
		if rv.ReasonBit >= 0 && rv.ReasonBit < len(pki.ReasonNames) {
			row.Reason = pki.ReasonNames[rv.ReasonBit]
		}
		if !rv.InvalDate.IsZero() && rv.InvalDate.Year() < 9999 {
			row.InvalLocal = rv.InvalDate.UTC().Format("2006-01-02T15:04")
		}
		rows = append(rows, row)
	}
	p := &page{Title: "rev.title", Tab: "certs", Data: map[string]any{"CA": ca, "Rows": rows,
		"Reasons": reasonChoices(), "Now": nowLocal()}}
	switch r.URL.Query().Get("notice") {
	case "saved":
		p.Notice = "item.notice.saved"
	}
	if r.URL.Query().Get("error") == "rev.error.input" {
		p.Error = "rev.error.input"
	}
	s.render(w, r, http.StatusOK, "revocations", p)
}

func (s *Server) revocationsSubmit(w http.ResponseWriter, r *http.Request) {
	_, ca, ok := s.caFor(w, r)
	if !ok {
		return
	}
	h := dbSession(r).Handle
	back := dbPath(dbSession(r).DBName) + "item/" + strconv.FormatInt(ca.ID, 10) + "/revocations"
	serial := r.PostFormValue("serial")
	var err error
	switch r.PostFormValue("action") {
	case "delete":
		err = h.DeleteRevocation(r.Context(), ca.ID, serial)
	default:
		var rv store.Revocation
		if rv, err = parseRevocation(r); err == nil {
			err = h.SetRevocation(r.Context(), ca.ID, serial, rv)
		}
	}
	if err != nil {
		s.log.Warn("revocation change failed", "ca", ca.ID, "err", err)
		http.Redirect(w, r, back+"?error=rev.error.input", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+"?notice=saved", http.StatusSeeOther)
}

func (s *Server) crlPage(w http.ResponseWriter, r *http.Request) {
	snap, ca, ok := s.caFor(w, r)
	if !ok {
		return
	}
	o := store.DefaultCRLOptions(snap, ca)
	s.renderCRL(w, r, http.StatusOK, snap, ca, o, "")
}

func (s *Server) renderCRL(w http.ResponseWriter, r *http.Request, status int, snap *gcadb.Snapshot, ca *gcadb.Cert, o store.CRLOptions, errKey string) {
	hasSAN := false
	for _, e := range pki.DescribeCert(ca.DER).Extensions {
		hasSAN = hasSAN || e.OID == "2.5.29.17"
	}
	var keyOwn bool
	for _, k := range snap.Keys {
		if k.ID == ca.KeyID {
			keyOwn = k.Protection == gcadb.ProtPassword
		}
	}
	n := 0
	for _, rv := range snap.Revocations {
		if rv.CAID == ca.ID {
			n++
		}
	}
	s.render(w, r, status, "crl", &page{Title: "crlgen.title", Tab: "certs", Error: errKey, Data: map[string]any{
		"CA": ca, "O": o, "Hashes": pki.Hashes, "HasSAN": hasSAN, "KeyOwn": keyOwn, "Count": n,
		"This": o.ThisUpdate.UTC().Format("2006-01-02T15:04"), "Next": o.NextUpdate.UTC().Format("2006-01-02T15:04"),
	}})
}

func (s *Server) crlSubmit(w http.ResponseWriter, r *http.Request) {
	snap, ca, ok := s.caFor(w, r)
	if !ok {
		return
	}
	g := r.PostFormValue
	o := store.CRLOptions{Name: g("name"), Hash: g("hash"), SetNumber: g("setnumber") != "",
		WithReason: g("withreason") != "", AuthKeyID: g("authkeyid") != "", IssuerAlt: g("issueralt") != ""}
	var err error
	o.Number, _ = strconv.ParseInt(g("number"), 10, 64)
	if o.ThisUpdate, err = parseLocal(g("thisupdate")); err == nil {
		o.NextUpdate, err = parseLocal(g("nextupdate"))
	}
	if err != nil {
		s.renderCRL(w, r, http.StatusUnprocessableEntity, snap, ca, o, "crlgen.error.input")
		return
	}
	ds := dbSession(r)
	kr := ds.Keyring()
	id, err := ds.Handle.GenerateCRL(r.Context(), ca.ID, o, kr, keyPasswords(r, snap))
	switch {
	case errors.Is(err, store.ErrNeedKeyPassword):
		s.renderCRL(w, r, http.StatusUnprocessableEntity, snap, ca, o, "editor.error.keypass")
		return
	case err != nil:
		s.log.Warn("CRL generation failed", "ca", ca.ID, "err", err)
		s.renderCRL(w, r, http.StatusUnprocessableEntity, snap, ca, o, "crlgen.error.input")
		return
	}
	s.log.Info("CRL generated", "db", ds.DBName, "ca", ca.ID, "crl", id)
	s.toItem(w, r, id, "notice=created")
}

func (s *Server) renewPage(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	snap, err := dbSession(r).Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var c *gcadb.Cert
	for _, x := range snap.Certs {
		if x.ID == id {
			c = x
		}
	}
	if c == nil {
		http.NotFound(w, r)
		return
	}
	info := pki.DescribeCert(c.DER)
	days := int(info.NotAfter.Sub(info.NotBefore).Hours()/24 + 0.5)
	now := time.Now().UTC()
	s.render(w, r, http.StatusOK, "renew", &page{Title: "renew.title", Tab: "certs", Error: r.URL.Query().Get("error"), Data: map[string]any{
		"C": c, "Self": c.IssuerID == c.ID, "Reasons": reasonChoices(), "Now": nowLocal(),
		"NotBefore": now.Format("2006-01-02T15:04"), "NotAfter": now.AddDate(0, 0, days).Format("2006-01-02T15:04"),
		"NoExpiry": info.NoExpiry,
	}})
}

func (s *Server) renewSubmit(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ds := dbSession(r)
	g := r.PostFormValue
	o := store.RenewOptions{NoExpiry: g("noexpiry") != "", KeepSerial: g("keepserial") != "", Replace: g("replace") != ""}
	var err error
	if o.NotBefore, err = parseLocal(g("notbefore")); err == nil {
		o.NotAfter, err = parseLocal(g("notafter"))
	}
	if err == nil && g("revoke") != "" {
		var rv store.Revocation
		if rv, err = parseRevocation(r); err == nil {
			o.Revoke = &rv
		}
	}
	back := dbPath(ds.DBName) + "item/" + strconv.FormatInt(id, 10) + "/renew?error="
	if err != nil {
		http.Redirect(w, r, back+"renew.error.input", http.StatusSeeOther)
		return
	}
	snap, _ := ds.Handle.Snapshot(r.Context())
	kr := ds.Keyring()
	nid, err := ds.Handle.Renew(r.Context(), id, o, kr, keyPasswords(r, snap))
	switch {
	case errors.Is(err, store.ErrNeedKeyPassword):
		http.Redirect(w, r, back+"editor.error.keypass", http.StatusSeeOther)
		return
	case err != nil:
		s.log.Warn("renewal failed", "id", id, "err", err)
		http.Redirect(w, r, back+"renew.error.input", http.StatusSeeOther)
		return
	}
	s.log.Info("certificate renewed", "db", ds.DBName, "old", id, "new", nid)
	s.toItem(w, r, nid, "notice=created")
}

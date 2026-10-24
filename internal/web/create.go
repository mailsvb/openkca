package web

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/store"
)

var (
	oidSKI = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAKI = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// purposeCard is one choice of the "New" page.
type purposeCard struct {
	ID      string // profile ID; "" for a template
	Title   string // message key, or the template's name
	Help    string // message key
	Summary string
	Href    string
}

// purposePage lets the user start from what the certificate or key is
// for: built-in profiles, the database's templates, the full editor.
// Query parameters signer and req (from a CA's or a request's page)
// carry over to the form.
func (s *Server) purposePage(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pr := s.printer(r)
	carry := url.Values{}
	for _, k := range []string{"signer", "req"} {
		if v := r.URL.Query().Get(k); v != "" {
			if _, err := strconv.ParseInt(v, 10, 64); err == nil {
				carry.Set(k, v)
			}
		}
	}
	query := ""
	if len(carry) > 0 {
		query = "?" + carry.Encode()
	}
	base := dbPath(ds.DBName)
	groups := map[string][]purposeCard{}
	for _, p := range profiles {
		c := purposeCard{ID: p.ID, Title: "profile." + p.ID, Help: "profile." + p.ID + ".help", Summary: p.summary(pr.T)}
		switch {
		case p.Link != "":
			c.Href = base + p.Link
		case p.Issuer == "self" && len(carry) > 0:
			continue // a root CA is neither issued by another CA nor made from a request
		default:
			c.Href = base + "create/" + p.ID + query
		}
		groups[p.Group] = append(groups[p.Group], c)
	}
	var templates []purposeCard
	for _, t := range snap.Templates {
		v := url.Values{"template": {strconv.FormatInt(t.ID, 10)}}
		for k := range carry {
			v.Set(k, carry.Get(k))
		}
		templates = append(templates, purposeCard{Title: t.Name, Summary: t.Comment, Href: base + "new/cert?" + v.Encode()})
	}
	s.render(w, r, http.StatusOK, "purpose", &page{Title: "purpose.title", Tab: "certs", Data: map[string]any{
		"CA": groups["ca"], "Cert": groups["cert"], "Keys": groups["keys"], "Templates": templates,
		"Editor": base + "new/cert" + query, "Carry": len(carry) > 0}})
}

// quickForm is the short form of a profile.
type quickForm struct {
	Profile        *profile
	Hosts          string
	CN, Email      string
	Org, Country   string
	Issuer         string // "self" or a CA's item ID
	Validity       string // e.g. "397d"
	KeyMode        string // "new", "existing" or "request"
	NewKey         string
	KeyID, FromReq int64
	NeedPass       bool
}

func parseQuick(r *http.Request, p *profile) *quickForm {
	g := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	q := &quickForm{Profile: p, Hosts: g("hosts"), CN: g("cn"), Email: g("email"), Org: g("org"), Country: g("country"),
		Issuer: g("issuer"), Validity: g("validity"), KeyMode: g("keymode"), NewKey: g("newkey")}
	q.KeyID, _ = strconv.ParseInt(g("keyid"), 10, 64)
	q.FromReq, _ = strconv.ParseInt(g("fromreq"), 10, 64)
	q.normalize()
	return q
}

func (q *quickForm) normalize() {
	p := q.Profile
	if p.Issuer == "self" {
		q.Issuer = "self"
	}
	if _, ok := parseValidity(q.Validity); !ok {
		q.Validity = p.defaultValidity().String()
	}
	if !offeredKey(q.NewKey) {
		q.NewKey = p.Key
	}
	switch q.KeyMode {
	case "existing", "request":
	default:
		q.KeyMode = "new"
	}
	if p.Issuer == "self" && q.KeyMode == "request" {
		q.KeyMode = "new"
	}
}

// splitHosts reads host names and IP addresses separated by lines, commas
// or spaces.
func splitHosts(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
}

// keyAlgorithm is the key type the profile's extensions depend on.
func (q *quickForm) keyAlgorithm(snap *gcadb.Snapshot) string {
	fromReq := int64(0)
	if q.KeyMode == "request" {
		fromReq = q.FromReq
	}
	return keyAlgorithmOf(snap, q.KeyMode == "existing", q.KeyID, fromReq, q.NewKey)
}

// editor turns the short form into the editor's form. With strict set it
// also checks that the profile's fields are filled; the message key of
// the first problem is returned.
func (q *quickForm) editor(snap *gcadb.Snapshot, strict bool) (*editorForm, string) {
	p := q.Profile
	f := defaultEditor("cert", snap)
	f.Profile = p.ID
	f.NewKey = q.NewKey
	f.Signer = q.Issuer
	v, _ := parseValidity(q.Validity)
	f.ValidN, f.ValidUnit = v.N, v.Unit
	f.Ext = p.ext(q.keyAlgorithm(snap))
	switch q.KeyMode {
	case "existing":
		f.KeyMode, f.KeyID = "existing", q.KeyID
	case "request":
		f.FromReq, f.ReqSubject, f.CopyReqExt = q.FromReq, false, false
	}
	problem := ""
	if strict {
		problem = q.check(snap)
	}
	cn := q.CN
	var san []string
	if p.has(fieldHosts) {
		for i, h := range splitHosts(q.Hosts) {
			if i == 0 {
				cn = h
			}
			if net.ParseIP(h) != nil {
				san = append(san, "IP:"+h)
			} else {
				san = append(san, "DNS:"+h)
			}
		}
	}
	if p.has(fieldEmail) && q.Email != "" {
		san = append(san, "email:"+q.Email)
		if cn == "" {
			cn = q.Email
		}
	}
	f.Ext.SubAltName = strings.Join(san, ", ")
	var attrs []pki.DNAttr
	if p.has(fieldOrg) {
		if q.Country != "" {
			attrs = append(attrs, pki.DNAttr{Name: "C", Value: strings.ToUpper(q.Country)})
		}
		if q.Org != "" {
			attrs = append(attrs, pki.DNAttr{Name: "O", Value: q.Org})
		}
	}
	if cn != "" {
		attrs = append(attrs, pki.DNAttr{Name: "CN", Value: cn})
	}
	f.fillSubject(attrs)
	f.Name = cn
	return f, problem
}

func (q *quickForm) check(snap *gcadb.Snapshot) string {
	p := q.Profile
	if p.has(fieldHosts) && len(splitHosts(q.Hosts)) == 0 {
		return "profile.error.hosts"
	}
	if p.has(fieldEmail) && q.Email != "" && (!strings.Contains(q.Email, "@") || strings.ContainsAny(q.Email, " ,;")) {
		return "profile.error.email"
	}
	if p.ID == "smime" && q.Email == "" {
		return "profile.error.email"
	}
	if p.has(fieldCN) && q.CN == "" && !(p.has(fieldEmail) && q.Email != "") {
		return "profile.error.cn"
	}
	if len(q.Country) != 0 && len(q.Country) != 2 {
		return "profile.error.country"
	}
	if q.Issuer != "self" || p.Issuer == "ca" {
		id, _ := strconv.ParseInt(q.Issuer, 10, 64)
		if !isSigner(snap, id) {
			return "profile.error.issuer"
		}
	}
	if q.KeyMode == "existing" && q.KeyID == 0 || q.KeyMode == "request" && q.FromReq == 0 {
		return "profile.error.key"
	}
	return ""
}

func isSigner(snap *gcadb.Snapshot, id int64) bool {
	for _, c := range choices(snap).Signers {
		if c.ID == id {
			return true
		}
	}
	return false
}

// summaryRow is one line of "What you will get".
type summaryRow struct {
	Label string // message key
	Value string
}

// quickSummary describes what the form would create, for the side panel.
func (s *Server) quickSummary(r *http.Request, snap *gcadb.Snapshot, q *quickForm) map[string]any {
	pr := s.printer(r)
	ds := dbSession(r)
	f, _ := q.editor(snap, false)
	if len(f.subject()) == 0 {
		f.fillSubject([]pki.DNAttr{{Name: "CN", Value: "…"}}) // nothing entered yet
	}
	out := map[string]any{}
	var rows []summaryRow
	add := func(label, value string) { rows = append(rows, summaryRow{label, value}) }

	params, err := f.params()
	if err != nil {
		out["Err"] = err.Error()
		return out
	}
	exts, subject, err := ds.Handle.Preview(r.Context(), params)
	if err != nil {
		out["Err"] = err.Error()
		return out
	}
	name := pki.FormatName(subject)
	if name == "" {
		name = "—"
	}
	add("summary.name", name)

	// the key, and the key that signs
	var subjectSPKI []byte
	switch q.KeyMode {
	case "existing":
		for _, k := range snap.Keys {
			if k.ID == q.KeyID {
				subjectSPKI = k.Public
				add("summary.key", pr.T("summary.key.existing", k.Name, describeKey(k.Public)))
			}
		}
	case "request":
		for _, rq := range snap.Requests {
			if rq.ID == q.FromReq {
				if req, err := pki.ParseCertificateRequest(rq.DER); err == nil {
					subjectSPKI = req.RawSubjectPublicKeyInfo
					add("summary.key", pr.T("summary.key.request", rq.Name, describeKey(subjectSPKI)))
				}
			}
		}
	default:
		add("summary.key", pr.T("summary.key.new", keyLabel(q.NewKey)))
	}
	var signerSPKI []byte
	signerName := ""
	var signerCert *gcadb.Cert
	if id, err := strconv.ParseInt(q.Issuer, 10, 64); err == nil {
		for _, c := range snap.Certs {
			if c.ID == id {
				signerCert, signerName = c, c.Name
				for _, k := range snap.Keys {
					if k.ID == c.KeyID {
						signerSPKI = k.Public
					}
				}
			}
		}
	} else {
		signerSPKI = subjectSPKI
	}
	add("summary.signature", s.signatureText(r, f.Hash, signerSPKI, q))
	if signerName != "" {
		add("summary.issuer", signerName)
	} else {
		add("summary.issuer", pr.T("editor.selfsigned"))
	}
	add("summary.serial", pr.T("summary.serial.random", store.SerialLen(snap)))
	if !params.NotBefore.IsZero() {
		add("summary.validity", params.NotBefore.Format("2006-01-02")+" – "+params.NotAfter.Format("2006-01-02"))
	}
	out["Rows"] = rows
	var shown []pkix.Extension
	for _, e := range exts {
		if !e.Id.Equal(oidSKI) && !e.Id.Equal(oidAKI) { // key identifiers: always there, never interesting
			shown = append(shown, e)
		}
	}
	out["Exts"] = pki.DecodeExtensions(shown)

	var warns []string
	v, _ := parseValidity(q.Validity)
	if q.Profile.ID == "tls-server" && v.days() > 825 {
		warns = append(warns, pr.T("summary.warn.apple"))
	}
	if signerCert != nil {
		if info := pki.DescribeCert(signerCert.DER); !info.NoExpiry && info.NotAfter.Before(params.NotAfter) {
			warns = append(warns, pr.T("summary.warn.outlives", info.NotAfter.UTC().Format("2006-01-02")))
		}
	}
	out["Warnings"] = warns
	return out
}

func describeKey(spki []byte) string {
	info := pki.DescribePublicKey(spki)
	switch info.Algorithm {
	case "EC":
		curve := info.Curve // e.g. "prime256v1 (P-256)"
		if _, short, ok := strings.Cut(curve, "("); ok {
			curve = strings.TrimSuffix(short, ")")
		}
		return "ECDSA " + curve
	case "RSA", "RSA-PSS":
		return fmt.Sprintf("%s %d", info.Algorithm, info.Bits)
	}
	return info.Algorithm
}

// signatureText names the signature algorithm a hash choice gives with
// the signer's key (spki; nil: a key still to be generated).
func (s *Server) signatureText(r *http.Request, hash string, spki []byte, q *quickForm) string {
	pr := s.printer(r)
	alg, auto := "", ""
	if spki != nil {
		alg = pki.DescribePublicKey(spki).Algorithm
		auto = pki.AutoHashName(spki)
	} else if spec, err := parseKeyChoice(q.NewKey); err == nil {
		alg = spec.Type
		auto = pki.AutoHashNameForSpec(*spec)
	}
	switch alg {
	case "EC":
		alg = "ECDSA"
	case "":
		alg = "?"
	}
	if hash != pki.HashAuto {
		return pr.T("summary.signature.with", alg, pr.T("hash."+hash))
	}
	if auto == "" {
		return pr.T("summary.signature.own", alg)
	}
	return pr.T("summary.signature.auto", alg, pr.T("hash."+auto))
}

func (s *Server) profileFor(w http.ResponseWriter, r *http.Request) *profile {
	p := profileByID(r.PathValue("profile"))
	if p == nil || p.Link != "" {
		http.NotFound(w, r)
		return nil
	}
	return p
}

// profilePage is the short form of a profile.
func (s *Server) profilePage(w http.ResponseWriter, r *http.Request) {
	p := s.profileFor(w, r)
	if p == nil {
		return
	}
	snap, err := dbSession(r).Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := &quickForm{Profile: p, Issuer: "self"}
	query := r.URL.Query()
	if sg := query.Get("signer"); sg != "" && isSigner(snap, atoi64(sg)) {
		q.Issuer = sg
	} else if p.Issuer != "self" {
		// the newest CA that can sign, as most certificates come from it
		if sg := choices(snap).Signers; len(sg) > 0 {
			q.Issuer = strconv.FormatInt(sg[len(sg)-1].ID, 10)
		}
	}
	if id := atoi64(query.Get("req")); id != 0 {
		for _, rq := range snap.Requests {
			if rq.ID == id {
				q.KeyMode, q.FromReq = "request", id
				if req, err := pki.ParseCertificateRequest(rq.DER); err == nil {
					q.fromRequest(req.Subject.CommonName, req.DNSNames, req.IPAddresses, req.EmailAddresses)
				}
			}
		}
	}
	q.normalize()
	s.renderQuick(w, r, http.StatusOK, snap, q, "")
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// fromRequest fills the profile's fields from a CSR.
func (q *quickForm) fromRequest(cn string, dns []string, ips []net.IP, emails []string) {
	hosts := []string{}
	if cn != "" && q.Profile.has(fieldHosts) && !strings.Contains(cn, " ") {
		hosts = append(hosts, cn)
	}
	for _, d := range dns {
		if d != cn {
			hosts = append(hosts, d)
		}
	}
	for _, ip := range ips {
		hosts = append(hosts, ip.String())
	}
	q.Hosts = strings.Join(hosts, "\n")
	q.CN = cn
	if len(emails) > 0 {
		q.Email = emails[0]
	}
}

func (s *Server) renderQuick(w http.ResponseWriter, r *http.Request, status int, snap *gcadb.Snapshot, q *quickForm, errKey string, errArgs ...any) {
	ds := dbSession(r)
	var vals []map[string]string
	pr := s.printer(r)
	for _, v := range q.Profile.Validity {
		vals = append(vals, map[string]string{"Value": v.String(), "Label": validityText(pr.T, v)})
	}
	pg := &page{Title: "profile." + q.Profile.ID, Tab: "certs", Error: errKey, Data: map[string]any{
		"Q": q, "C": choices(snap), "Validities": vals, "Summary": s.quickSummary(r, snap, q),
		"Picker": newKeyPicker("newkey", q.NewKey, ds.DBName, store.Expert(snap)),
		"Hosts":  q.Profile.has(fieldHosts), "CN": q.Profile.has(fieldCN), "Email": q.Profile.has(fieldEmail),
		"Org": q.Profile.has(fieldOrg), "SelfOnly": q.Profile.Issuer == "self", "CAOnly": q.Profile.Issuer == "ca",
	}}
	if len(errArgs) > 0 {
		pg.ErrorArg = fmt.Sprint(errArgs[0])
	}
	s.render(w, r, status, "profile", pg)
}

// profileSubmit refreshes the summary (htmx), opens the full editor with
// the form's values, or creates the certificate.
func (s *Server) profileSubmit(w http.ResponseWriter, r *http.Request) {
	p := s.profileFor(w, r)
	if p == nil {
		return
	}
	snap, err := dbSession(r).Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := parseQuick(r, p)
	switch r.PostFormValue("action") {
	case "summary":
		s.render(w, r, http.StatusOK, "profile", &page{Data: map[string]any{"fragment": "summary", "Summary": s.quickSummary(r, snap, q)}})
		return
	case "editor":
		f, _ := q.editor(snap, false)
		s.renderEditor(w, r, http.StatusOK, f, snap, "")
		return
	}
	f, problem := q.editor(snap, true)
	if problem != "" {
		s.renderQuick(w, r, http.StatusUnprocessableEntity, snap, q, problem)
		return
	}
	f.NotBefore = time.Now().UTC().Format("2006-01-02T15:04")
	s.issue(w, r, snap, f, func(errKey string, args ...any) {
		q.NeedPass = errKey == "editor.error.keypass"
		s.renderQuick(w, r, http.StatusUnprocessableEntity, snap, q, errKey, args...)
	})
}

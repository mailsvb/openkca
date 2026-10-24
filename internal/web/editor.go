package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/store"
	"github.com/mailsvb/go-ca/internal/tmpl"
)

// Additional subject attributes offered besides the explicit ones.
var extraAttrs = []string{"C", "ST", "L", "O", "OU", "CN", "emailAddress", "serialNumber", "title", "GN", "SN",
	"initials", "pseudonym", "street", "postalCode", "DC", "UID", "description", "businessCategory", "dnQualifier"}

const extraRows = 4

// editorForm is the state of the certificate/request editor.
type editorForm struct {
	Kind       string // "cert" or "request"
	Name       string
	Comment    string
	Explicit   []pki.DNAttr // labelled subject fields (settings explicit_dn)
	Extra      []pki.DNAttr // further rows
	KeyMode    string       // "new" or "existing"
	KeyID      int64
	NewKey     string
	Signer     string // "self" or CA item id
	FromReq    int64
	ReqSubject bool
	CopyReqExt bool
	Hash       string
	NotBefore  string // datetime-local, UTC
	ValidN     int
	ValidUnit  string // "d", "m", "y"
	NotAfter   string // optional explicit end
	Midnight   bool
	NoExpiry   bool
	Ext        pki.ExtSpec
	Source     int
	ID         int64  // template being edited
	TemplateID int64  // template selected for "apply"
	Profile    string // built-in profile the form started from
}

func defaultEditor(kind string, snap *gcadb.Snapshot) *editorForm {
	f := &editorForm{Kind: kind, KeyMode: "new", NewKey: "EC:P-256", Signer: "self", Hash: store.Hash(snap),
		NotBefore: time.Now().UTC().Format("2006-01-02T15:04"), ValidN: 365, ValidUnit: "d",
		ReqSubject: true, CopyReqExt: true, Ext: pki.ExtSpec{SubKey: true, AuthKey: true}}
	explicit := snap.Settings["explicit_dn"]
	if explicit == "" {
		explicit = "C,ST,L,O,OU,CN,emailAddress"
	}
	for _, a := range strings.Split(explicit, ",") {
		if a = strings.TrimSpace(a); a != "" {
			if oid, err := pki.AttrOID(a); err == nil {
				f.Explicit = append(f.Explicit, pki.DNAttr{Name: pki.AttrShortName(oid)})
			}
		}
	}
	f.Extra = make([]pki.DNAttr, extraRows)
	return f
}

// fillSubject distributes existing attributes over explicit and extra rows.
func (f *editorForm) fillSubject(attrs []pki.DNAttr) {
	used := map[int]bool{}
	var extra []pki.DNAttr
	for _, a := range attrs {
		placed := false
		for i := range f.Explicit {
			if !used[i] && f.Explicit[i].Name == a.Name {
				f.Explicit[i].Value, used[i], placed = a.Value, true, true
				break
			}
		}
		if !placed {
			extra = append(extra, a)
		}
	}
	for len(extra) > len(f.Extra) {
		f.Extra = append(f.Extra, pki.DNAttr{})
	}
	copy(f.Extra, extra)
}

func (f *editorForm) subject() []pki.DNAttr {
	var out []pki.DNAttr
	for _, a := range append(append([]pki.DNAttr{}, f.Explicit...), f.Extra...) {
		if a.Name != "" && strings.TrimSpace(a.Value) != "" {
			out = append(out, a)
		}
	}
	return out
}

func bitsFromForm(r *http.Request, prefix string, n int) int {
	v := 0
	for i := 0; i < n; i++ {
		if r.PostFormValue(prefix+strconv.Itoa(i)) != "" {
			v |= 1 << i
		}
	}
	return v
}

// parseEditor reads the editor's form fields.
func parseEditor(r *http.Request, kind string, snap *gcadb.Snapshot) *editorForm {
	f := defaultEditor(kind, snap)
	g := r.PostFormValue
	on := func(k string) bool { return g(k) != "" }
	f.Name, f.Comment = strings.TrimSpace(g("name")), g("comment")
	for i := range f.Explicit {
		f.Explicit[i].Value = g("dn." + f.Explicit[i].Name)
	}
	f.Extra = nil
	for i := 0; i < 32; i++ {
		a, v := g("xattr."+strconv.Itoa(i)), g("xval."+strconv.Itoa(i))
		if a == "" && v == "" && i >= extraRows {
			break
		}
		f.Extra = append(f.Extra, pki.DNAttr{Name: a, Value: v})
	}
	f.KeyMode, f.NewKey = g("keymode"), g("newkey")
	f.KeyID, _ = strconv.ParseInt(g("keyid"), 10, 64)
	f.Signer = g("signer")
	f.FromReq, _ = strconv.ParseInt(g("fromreq"), 10, 64)
	f.ReqSubject, f.CopyReqExt = on("reqsubject"), on("copyreqext")
	f.Hash = g("hash")
	f.NotBefore, f.NotAfter = g("notbefore"), g("notafter")
	f.ValidN, _ = strconv.Atoi(g("validn"))
	f.ValidUnit = g("validunit")
	f.Midnight, f.NoExpiry = on("midnight"), on("noexpiry")
	f.Source, _ = strconv.Atoi(g("source"))
	e := &f.Ext
	e.CA, _ = strconv.Atoi(g("ca"))
	e.BCCritical, e.PathLen = on("bccritical"), strings.TrimSpace(g("pathlen"))
	e.SubKey, e.AuthKey = on("subkey"), on("authkey")
	e.KeyUse, e.KUCritical = bitsFromForm(r, "ku.", len(pki.KeyUsageNames)), on("kucritical")
	for _, n := range pki.EKUNames {
		if on("eku." + n) {
			e.EKU = append(e.EKU, n)
		}
	}
	for _, o := range strings.Split(g("ekuother"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			e.EKU = append(e.EKU, o)
		}
	}
	e.EKUCrit = on("ekucritical")
	e.SubAltName, e.IssAltName, e.CRLDist = g("san"), g("ian"), g("crldist")
	e.AuthInfAcc, e.NameCons, e.OCSPStaple = g("aia"), g("namecons"), on("ocspstaple")
	e.PubCDP, e.PubAIA = on("pubcdp"), on("pubaia")
	e.NSCertType = bitsFromForm(r, "ns.", len(pki.NSCertTypeNames))
	e.NSComment = g("nscomment")
	e.NSBaseURL, e.NSRevocationURL, e.NSCARevocationURL = g("nsbaseurl"), g("nsrevurl"), g("nscarevurl")
	e.NSRenewalURL, e.NSCAPolicyURL, e.NSSSLServerName = g("nsrenewurl"), g("nspolicyurl"), g("nssslname")
	e.AdvExt = strings.ReplaceAll(g("advext"), "\r\n", "\n")
	f.ID, _ = strconv.ParseInt(g("id"), 10, 64)
	if id, ok := strings.CutPrefix(g("template"), "p:"); ok {
		if p := profileByID(id); p != nil && p.Link == "" {
			f.Profile = id
		}
	} else {
		f.TemplateID, _ = strconv.ParseInt(g("template"), 10, 64)
	}
	return f
}

var unitByIndex = []string{"d", "m", "y"}

// applyTemplate copies a template's subject and/or extensions and validity
// into the editor (NewX509::subjectFromTemplate / extensionsFromTemplate).
func (f *editorForm) applyTemplate(d *store.TemplateData, subject, ext bool) {
	if subject {
		for i := range f.Explicit {
			f.Explicit[i].Value = ""
		}
		f.Extra = make([]pki.DNAttr, extraRows)
		f.fillSubject(d.Subject)
	}
	if ext {
		f.Ext = d.Ext
		f.ValidN = d.Validity.N
		if d.Validity.Unit >= 0 && d.Validity.Unit < len(unitByIndex) {
			f.ValidUnit = unitByIndex[d.Validity.Unit]
		}
		f.Midnight, f.NoExpiry = d.Validity.Midnight, d.Validity.NoExpiry
		f.NotAfter = ""
	}
}

// templateData converts the form into a template.
func (f *editorForm) templateData() store.TemplateData {
	unit := 0
	for i, u := range unitByIndex {
		if u == f.ValidUnit {
			unit = i
		}
	}
	return store.TemplateData{ID: f.ID, Name: f.Name, Comment: f.Comment, Subject: f.subject(), Ext: f.Ext,
		Validity: tmpl.Validity{N: f.ValidN, Unit: unit, Midnight: f.Midnight, NoExpiry: f.NoExpiry}}
}

func parseLocal(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty")
	}
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid date %q", s)
}

// params converts the form into store.IssueParams.
func (f *editorForm) params() (store.IssueParams, error) {
	p := store.IssueParams{Request: f.Kind == "request", Name: f.Name, Comment: f.Comment, Subject: f.subject(),
		Hash: f.Hash, Ext: f.Ext, Source: f.Source, FromReqID: f.FromReq, ReqSubject: f.ReqSubject, CopyReqExt: f.CopyReqExt}
	if p.Request {
		p.FromReqID = 0
	}
	if f.KeyMode == "existing" {
		p.KeyID = f.KeyID
	} else if p.FromReqID == 0 {
		spec, err := parseKeyChoice(f.NewKey)
		if err != nil || !offeredKey(f.NewKey) {
			return p, fmt.Errorf("unknown key type %q", f.NewKey)
		}
		p.NewKey = spec
	}
	if !p.Request && f.Signer != "self" && f.Signer != "" {
		id, err := strconv.ParseInt(f.Signer, 10, 64)
		if err != nil {
			return p, err
		}
		p.SignerID = id
	}
	if p.Request {
		return p, nil
	}
	nb, err := parseLocal(f.NotBefore)
	if err != nil {
		return p, fmt.Errorf("not before: %w", err)
	}
	na := nb
	if f.NotAfter != "" {
		if na, err = parseLocal(f.NotAfter); err != nil {
			return p, fmt.Errorf("not after: %w", err)
		}
	} else {
		switch f.ValidUnit {
		case "y":
			na = nb.AddDate(f.ValidN, 0, 0)
		case "m":
			na = nb.AddDate(0, f.ValidN, 0)
		default:
			na = nb.AddDate(0, 0, f.ValidN)
		}
	}
	if f.Midnight { // XCA: 00:00:00 and 23:59:59
		nb = time.Date(nb.Year(), nb.Month(), nb.Day(), 0, 0, 0, 0, time.UTC)
		na = time.Date(na.Year(), na.Month(), na.Day(), 23, 59, 59, 0, time.UTC)
	}
	p.NotBefore, p.NotAfter, p.NoExpiry = nb, na, f.NoExpiry
	return p, nil
}

// editorChoices lists keys, signers and requests for the editor.
type editorChoices struct {
	Keys     []choice
	Signers  []choice
	Requests []choice
}

type choice struct {
	ID    int64
	Label string
	Note  string
}

func choices(snap *gcadb.Snapshot) editorChoices {
	var ch editorChoices
	used := map[int64]bool{}
	keyByID := map[int64]*gcadb.Key{}
	for _, c := range snap.Certs {
		used[c.KeyID] = true
	}
	for _, r := range snap.Requests {
		used[r.KeyID] = true
	}
	var usedKeys []choice
	for _, k := range snap.Keys {
		keyByID[k.ID] = k
		if !k.HasPrivate || k.Protection == gcadb.ProtToken {
			continue
		}
		pk := pki.DescribePublicKey(k.Public)
		if pk.Algorithm == "X25519" {
			continue // cannot sign a certificate or request
		}
		c := choice{ID: k.ID, Label: k.Name, Note: fmt.Sprintf("%s %d", pk.Algorithm, pk.Bits)}
		if used[k.ID] {
			usedKeys = append(usedKeys, c)
		} else {
			ch.Keys = append(ch.Keys, c)
		}
	}
	ch.Keys = append(ch.Keys, usedKeys...) // unused keys first, as XCA
	now := time.Now()
	for _, c := range snap.Certs {
		k := keyByID[c.KeyID]
		if !c.CA || k == nil || !k.HasPrivate {
			continue
		}
		info := pki.DescribeCert(c.DER)
		if !info.NoExpiry && info.NotAfter.Before(now) {
			continue
		}
		note := info.CommonName
		if note == c.Name {
			note = ""
		}
		ch.Signers = append(ch.Signers, choice{ID: c.ID, Label: c.Name, Note: note})
	}
	for _, r := range snap.Requests {
		note := ""
		if r.Signed {
			note = "signed"
		}
		ch.Requests = append(ch.Requests, choice{ID: r.ID, Label: r.Name, Note: note})
	}
	return ch
}

// similar prefills the editor from an existing certificate or request.
func similar(f *editorForm, snap *gcadb.Snapshot, id int64) {
	var der []byte
	for _, c := range snap.Certs {
		if c.ID == id {
			der = c.DER
			f.Name = c.Name
			if c.IssuerID != 0 && c.IssuerID != c.ID {
				f.Signer = strconv.FormatInt(c.IssuerID, 10)
			}
		}
	}
	for _, r := range snap.Requests {
		if r.ID == id {
			der = r.DER
			f.Name = r.Name
		}
	}
	if der == nil {
		return
	}
	var subject []byte
	var keyType string
	if c, err := pki.ParseCertificate(der); err == nil {
		subject = c.RawSubject
		pubCDP, pubAIA := f.Ext.PubCDP, f.Ext.PubAIA
		f.Ext = pki.SpecWithAdvanced(c.Extensions)
		f.Ext.PubCDP, f.Ext.PubAIA = pubCDP, pubAIA
		f.Hash = pki.HashChoice(c.Raw)
		days := int(c.NotAfter.Sub(c.NotBefore).Hours()/24 + 0.5)
		f.ValidN, f.ValidUnit = days, "d"
		f.NoExpiry = c.NotAfter.Year() == 9999
		keyType = pki.DescribePublicKey(c.RawSubjectPublicKeyInfo).Algorithm
		if keyType == "RSA" {
			f.NewKey = fmt.Sprintf("RSA:%d", pki.DescribePublicKey(c.RawSubjectPublicKeyInfo).Bits)
		}
	} else if r, err := pki.ParseCertificateRequest(der); err == nil {
		subject = r.RawSubject
		f.Ext = pki.SpecWithAdvanced(r.Extensions)
		f.Hash = pki.HashChoice(r.Raw)
		keyType = pki.DescribePublicKey(r.RawSubjectPublicKeyInfo).Algorithm
	}
	switch keyType {
	case "EC":
		if info := pki.DescribePublicKey(der); info.Bits == 384 {
			f.NewKey = "EC:P-384"
		}
	case "Ed25519":
		f.NewKey = "Ed25519"
	}
	f.fillSubject(pki.NameAttrs(subject))
}

func (s *Server) editorPage(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if kind != "cert" && kind != "request" && kind != "template" {
		http.NotFound(w, r)
		return
	}
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f := defaultEditor(kind, snap)
	// The issuer's published CRL and certificate are offered, checked;
	// a template applied below decides for itself.
	f.Ext.PubCDP, f.Ext.PubAIA = s.published(), s.published()
	q := r.URL.Query()
	if p := profileByID(q.Get("profile")); p != nil && p.Link == "" {
		f.applyProfile(p, snap)
	}
	// A CA's default template applies when issuing with it, then an
	// explicitly chosen template.
	if sg, err := strconv.ParseInt(q.Get("signer"), 10, 64); err == nil {
		for _, c := range snap.Certs {
			if c.ID == sg && c.Authority != nil && c.Authority.TemplateID != 0 {
				if d, err := ds.Handle.LoadTemplate(r.Context(), c.Authority.TemplateID); err == nil {
					f.applyTemplate(d, true, true)
					f.TemplateID = c.Authority.TemplateID
				}
			}
		}
	}
	if id, err := strconv.ParseInt(q.Get("template"), 10, 64); err == nil {
		if d, err := ds.Handle.LoadTemplate(r.Context(), id); err == nil {
			f.applyTemplate(d, true, true)
			f.TemplateID = id
		}
	}
	if id, err := strconv.ParseInt(q.Get("similar"), 10, 64); err == nil {
		similar(f, snap, id)
	}
	if id, err := strconv.ParseInt(q.Get("req"), 10, 64); err == nil && kind == "cert" {
		f.FromReq = id
		for _, rq := range snap.Requests {
			if rq.ID == id {
				f.Name = rq.Name
				if info := pki.DescribeRequest(rq.DER); info.ParseError == "" {
					f.fillSubject(info.SubjectAttrs())
				}
			}
		}
	}
	if sg := q.Get("signer"); sg != "" {
		f.Signer = sg
	}
	if q.Get("source") == "transformed" {
		f.Source = 3
	}
	s.renderEditor(w, r, http.StatusOK, f, snap, "")
}

// templateEditPage edits an existing template in the editor.
func (s *Server) templateEditPage(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := ds.Handle.LoadTemplate(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f := defaultEditor("template", snap)
	f.applyTemplate(d, true, true)
	f.ID, f.Name, f.Comment = id, d.Name, d.Comment
	s.renderEditor(w, r, http.StatusOK, f, snap, "")
}

func (s *Server) renderEditor(w http.ResponseWriter, r *http.Request, status int, f *editorForm, snap *gcadb.Snapshot, errKey string, errArgs ...any) {
	title := "editor.title." + f.Kind
	tab := "certs"
	switch f.Kind {
	case "request":
		tab = "requests"
	case "template":
		tab = "templates"
	}
	var templates []choice
	for _, t := range snap.Templates {
		templates = append(templates, choice{ID: t.ID, Label: t.Name})
	}
	var profileIDs []string
	for _, p := range profiles {
		if p.Link == "" {
			profileIDs = append(profileIDs, p.ID)
		}
	}
	pr := s.printer(r)
	expert := store.Expert(snap)
	p := &page{Title: title, Tab: tab, Error: errKey, Data: map[string]any{
		"Published": s.published(), "BaseURLs": s.store.BaseURLs,
		"F": f, "C": choices(snap), "Hashes": pki.HashChoices, "ExtraAttrs": extraAttrs,
		"KU": pki.KeyUsageNames, "EKU": pki.EKUNames, "NS": pki.NSCertTypeNames,
		"NoNetscape": snap.Settings["disable_netscape"] == "yes", "ErrArgs": errArgs, "Templates": templates,
		"Profiles": profileIDs, "Expert": expert, "Picker": newKeyPicker("newkey", f.NewKey, dbSession(r).DBName, expert),
		"Sum": f.summaries(pr.T, snap), "Diff": f.profileDiff(pr.T, snap), "ExpertUsed": f.expertUsed(pr.T, snap),
	}}
	if len(errArgs) > 0 {
		p.ErrorArg = fmt.Sprint(errArgs[0])
	}
	s.render(w, r, status, "editor", p)
}

// published reports whether CRLs and CA certificates are published (base
// URLs configured), so that CDP and AIA can point there.
func (s *Server) published() bool { return len(s.store.BaseURLs) > 0 }

func keyPasswords(r *http.Request, snap *gcadb.Snapshot) store.KeyPasswords {
	pw := r.PostFormValue("keypass")
	if pw == "" {
		return nil
	}
	kp := store.KeyPasswords{}
	for _, k := range snap.Keys {
		if k.Protection == gcadb.ProtPassword {
			kp[k.ID] = []byte(pw)
		}
	}
	return kp
}

// editorSubmit validates (htmx preview) or creates.
func (s *Server) editorSubmit(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if kind != "cert" && kind != "request" && kind != "template" {
		http.NotFound(w, r)
		return
	}
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f := parseEditor(r, kind, snap)
	switch action := r.PostFormValue("action"); action {
	case "expert-on", "expert-off":
		v := map[string]string{"expert": "no"}
		if action == "expert-on" {
			v["expert"] = "yes"
		}
		if err := ds.Handle.SetSettings(r.Context(), v); err != nil {
			s.fail(w, r, err)
			return
		}
		if snap, err = ds.Handle.Snapshot(r.Context()); err != nil {
			s.fail(w, r, err)
			return
		}
		s.renderEditor(w, r, http.StatusOK, f, snap, "")
		return
	case "apply-all", "apply-subject", "apply-ext":
		if p := profileByID(f.Profile); p != nil {
			if action != "apply-subject" {
				f.applyProfile(p, snap)
			}
			s.renderEditor(w, r, http.StatusOK, f, snap, "")
			return
		}
		d, err := ds.Handle.LoadTemplate(r.Context(), f.TemplateID)
		if err != nil {
			s.renderEditor(w, r, http.StatusUnprocessableEntity, f, snap, "editor.error.notemplate")
			return
		}
		f.applyTemplate(d, action != "apply-ext", action != "apply-subject")
		s.renderEditor(w, r, http.StatusOK, f, snap, "")
		return
	}
	if kind == "template" && r.PostFormValue("action") != "validate" {
		id, err := ds.Handle.SaveTemplate(r.Context(), f.templateData())
		if err != nil {
			s.renderEditor(w, r, http.StatusUnprocessableEntity, f, snap, "editor.error.input", err.Error())
			return
		}
		s.log.Info("template saved", "db", ds.DBName, "id", id)
		http.Redirect(w, r, dbPath(ds.DBName)+"item/"+strconv.FormatInt(id, 10)+"?notice=saved", http.StatusSeeOther)
		return
	}
	if f.Name == "" && f.FromReq != 0 && kind == "cert" {
		for _, rq := range snap.Requests {
			if rq.ID == f.FromReq {
				f.Name = rq.Name
			}
		}
	}
	if f.Name == "" {
		for _, a := range f.subject() {
			if a.Name == "CN" {
				f.Name = a.Value
			}
		}
	}
	p, perr := f.params()
	if r.PostFormValue("action") == "validate" {
		res := map[string]any{"fragment": "preview"}
		pg := &page{Data: res}
		if kind == "template" {
			p.Request, p.NewKey, p.SignerID = false, &pki.KeySpec{Type: "Ed25519"}, 0
			p.Subject = f.subject()
			if len(p.Subject) == 0 {
				p.Subject = []pki.DNAttr{{Name: "CN", Value: "—"}}
			}
			perr = nil
		}
		if perr != nil {
			res["Err"] = perr.Error()
		} else if exts, subject, err := ds.Handle.Preview(r.Context(), p); err != nil {
			res["Err"] = err.Error()
		} else {
			res["Subject"] = pki.FormatName(subject)
			res["Exts"] = pki.DecodeExtensions(exts)
		}
		s.render(w, r, http.StatusOK, "editor", pg)
		return
	}
	s.issue(w, r, snap, f, func(errKey string, args ...any) {
		s.renderEditor(w, r, http.StatusUnprocessableEntity, f, snap, errKey, args...)
	})
}

// issue creates the certificate or request of a form and redirects to it;
// on failure it calls fail with a message key and its arguments.
func (s *Server) issue(w http.ResponseWriter, r *http.Request, snap *gcadb.Snapshot, f *editorForm, fail func(errKey string, args ...any)) {
	ds := dbSession(r)
	p, err := f.params()
	if err != nil {
		fail("editor.error.input", err.Error())
		return
	}
	p.KeyPass = keyPasswords(r, snap)
	id, err := ds.Handle.Issue(r.Context(), p, ds.Keyring())
	var miss *store.MissingAttrError
	switch {
	case errors.Is(err, store.ErrNeedKeyPassword):
		fail("editor.error.keypass")
		return
	case errors.As(err, &miss):
		fail("editor.error.mandatory", miss.Attr)
		return
	case err != nil:
		fail("editor.error.input", err.Error())
		return
	}
	s.log.Info("created", "db", ds.DBName, "kind", f.Kind, "id", id, "name", p.Name, "profile", f.Profile)
	http.Redirect(w, r, dbPath(ds.DBName)+"item/"+strconv.FormatInt(id, 10)+"?notice=created", http.StatusSeeOther)
}

func (s *Server) newKeyPage(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	typ := "EC:P-256"
	if t := r.URL.Query().Get("type"); offeredKey(t) {
		typ = t
	}
	s.render(w, r, http.StatusOK, "newkey", &page{Title: "newkey.title", Tab: "keys",
		Data: map[string]any{"Picker": newKeyPicker("type", typ, ds.DBName, store.Expert(snap)),
			"Expert": store.Expert(snap), "Back": r.URL.RequestURI()}})
}

func (s *Server) newKey(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	name := strings.TrimSpace(r.PostFormValue("name"))
	typ := r.PostFormValue("type")
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	data := map[string]any{"Picker": newKeyPicker("type", typ, ds.DBName, store.Expert(snap)), "Name": name,
		"Expert": store.Expert(snap), "Back": dbPath(ds.DBName) + "new/key"}
	spec, err := parseKeyChoice(typ)
	if err != nil || !offeredKey(typ) || name == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "newkey", &page{Title: "newkey.title", Tab: "keys",
			Error: "newkey.error.input", Data: data})
		return
	}
	kr := ds.Keyring()
	id, err := ds.Handle.GenerateKey(r.Context(), name, "", *spec, kr)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("key generated", "db", ds.DBName, "id", id, "type", typ)
	http.Redirect(w, r, dbPath(ds.DBName)+"item/"+strconv.FormatInt(id, 10)+"?notice=created", http.StatusSeeOther)
}

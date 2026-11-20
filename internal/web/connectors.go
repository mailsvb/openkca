package web

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mailsvb/openkca/internal/auth"
	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/est"
	"github.com/mailsvb/openkca/internal/estserver"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/store"
)

// connectorRow is a connector in the list.
type connectorRow struct {
	C       *db.Connector
	CA      string // the CA's name
	URL     string // path of the connector
	Problem string // reason code, "" = active
	Issued  int
}

// Subject rule modes in the form.
var ruleModes = []string{est.ModeRequired, est.ModeOptional, est.ModeFixed, est.ModeForbidden}

// connectorRuleRows is how many empty subject rule rows the form offers.
const connectorRuleRows = 3

// connectorForm is the state of the connector form.
type connectorForm struct {
	ID       int64
	Name     string
	Label    string
	Enabled  bool
	CAID     int64
	Password string // typed by hand; "" keeps the current one (generates one for a new connector)
	Cfg      est.Config
	Rules    []est.DNRule // subject rules plus empty rows
}

func (s *Server) connectorPath(r *http.Request, rest string) string {
	return dbPath(dbSession(r).DBName) + "connectors" + rest
}

// connectorProblem is why a connector cannot serve, "" when it can.
func (s *Server) connectorProblem(r *http.Request, snap *db.Snapshot, c *db.Connector) string {
	return s.est.Problem(r.Context(), dbSession(r).DBName, snap, c)
}

func (s *Server) connectorList(w http.ResponseWriter, r *http.Request) {
	snap, err := dbSession(r).Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var rows []connectorRow
	for _, c := range snap.Connectors {
		row := connectorRow{C: c, URL: estserver.PathPrefix + c.Label + "/", Problem: s.connectorProblem(r, snap, c),
			Issued: len(store.IssuedBy(snap, c.ID))}
		if ca := certByID(snap, c.CAID); ca != nil {
			row.CA = ca.Name
		}
		rows = append(rows, row)
	}
	s.render(w, r, http.StatusOK, "connectors", &page{Title: "tab.connectors", Tab: "connectors", Data: map[string]any{
		"Rows": rows, "Served": s.est.Served(dbSession(r).DBName), "CAs": len(store.ConnectorCAs(snap, time.Now())),
	}})
}

func certByID(snap *db.Snapshot, id int64) *db.Cert {
	for _, c := range snap.Certs {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func connectorID(r *http.Request, snap *db.Snapshot) *db.Connector {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil
	}
	return snap.Connector(id)
}

// newConnectorForm starts a connector: the defaults, the newest usable CA
// and its default template's extensions and validity, if it has one.
func newConnectorForm(snap *db.Snapshot) *connectorForm {
	f := &connectorForm{Enabled: true, Cfg: est.Default()}
	cas := store.ConnectorCAs(snap, time.Now())
	if len(cas) > 0 {
		ca := cas[len(cas)-1]
		f.CAID = ca.ID
	}
	f.Cfg.Auth.User = "est"
	return f
}

func formFromConnector(c *db.Connector) (*connectorForm, error) {
	cfg, err := est.Parse([]byte(c.Config))
	if err != nil {
		return nil, err
	}
	return &connectorForm{ID: c.ID, Name: c.Name, Label: c.Label, Enabled: c.Enabled, CAID: c.CAID, Cfg: cfg}, nil
}

// editor returns the certificate properties as the editor's form, which
// renders and parses them (profilefields.html).
func (f *connectorForm) editor(snap *db.Snapshot) *editorForm {
	ef := defaultEditor("template", snap)
	d := f.Cfg.Profile
	ef.applyTemplate(&d, false, true)
	return ef
}

func splitList(v string) []string {
	var out []string
	for _, x := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// parseConnectorForm reads the connector form over the stored settings
// (the password hash stays unless a new password was typed).
func parseConnectorForm(r *http.Request, snap *db.Snapshot, base *connectorForm) *connectorForm {
	g := r.PostFormValue
	on := func(k string) bool { return g(k) != "" }
	f := *base
	f.Name, f.Label = strings.TrimSpace(g("c.name")), strings.ToLower(strings.TrimSpace(g("c.label")))
	f.Enabled = on("c.enabled")
	f.CAID, _ = strconv.ParseInt(g("c.ca"), 10, 64)
	f.Password = g("c.password")
	c := &f.Cfg
	c.Version = est.Version
	c.Auth.User, c.Auth.Reenroll = strings.TrimSpace(g("c.user")), on("c.reenroll")
	k := &c.Keys
	k.RSAMinBits, _ = strconv.Atoi(g("c.rsamin"))
	k.RSAMaxBits, _ = strconv.Atoi(g("c.rsamax"))
	if !on("c.rsa") {
		k.RSAMinBits, k.RSAMaxBits = 0, 0
	}
	pick := func(prefix string, names []string) []string {
		var out []string
		for _, n := range names {
			if on(prefix + n) {
				out = append(out, n)
			}
		}
		return out
	}
	k.ECCurves = pick("c.ec.", curveNames())
	k.EdDSA = pick("c.ed.", []string{"Ed25519", "Ed448"})
	k.MLDSA = pick("c.mldsa.", mldsaNames())
	k.SLHDSA = pick("c.slhdsa.", slhdsaNames())
	k.Composite = pick("c.comp.", compositeNames())
	k.MinCSRHash = g("c.minhash")
	c.Subject.Rules = nil
	for i := 0; i < 64; i++ {
		n := strconv.Itoa(i)
		attr := strings.TrimSpace(g("c.rattr." + n))
		if attr == "" {
			if i >= len(base.Cfg.Subject.Rules)+connectorRuleRows {
				break
			}
			continue
		}
		c.Subject.Rules = append(c.Subject.Rules, est.DNRule{Attr: attr, Mode: g("c.rmode." + n),
			Value: g("c.rvalue." + n), Pattern: strings.TrimSpace(g("c.rpattern." + n))})
	}
	c.Subject.Unlisted = est.UnlistedDrop
	if g("c.unlisted") == est.UnlistedReject {
		c.Subject.Unlisted = est.UnlistedReject
	}
	san := &c.SAN
	san.DNS = est.DNSRule{Enabled: on("c.dns"), Patterns: splitList(g("c.dnspat"))}
	san.IP = est.IPRule{Enabled: on("c.ip"), CIDRs: splitList(g("c.ipcidr"))}
	san.Email = est.EmailRule{Enabled: on("c.email"), Domains: splitList(g("c.emaildom"))}
	san.URI = est.URIRule{Enabled: on("c.uri"), Prefixes: splitList(g("c.uripre"))}
	san.Wildcards, san.CopyCN = on("c.wild"), on("c.copycn")
	san.Max, _ = strconv.Atoi(g("c.max"))
	ef := parseEditor(r, "template", snap)
	ef.Ext.SubAltName = g("san")
	d := ef.templateData()
	d.Subject = nil
	c.Profile = d
	return &f
}

func curveNames() []string {
	var out []string
	for _, c := range pki.ECCurves {
		out = append(out, c.Name)
	}
	return out
}

func mldsaNames() []string {
	var out []string
	for _, p := range pki.MLDSAParamSets {
		out = append(out, p.Name)
	}
	return out
}

func slhdsaNames() []string {
	var out []string
	for _, p := range pki.SLHDSAParamSets {
		out = append(out, p.Name)
	}
	return out
}

func compositeNames() []string {
	var out []string
	for _, a := range pki.CompositeAlgs {
		out = append(out, a.Name)
	}
	return out
}

// randomPassword returns a new connector password: 24 characters.
func randomPassword() string {
	b := make([]byte, 18)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) renderConnectorForm(w http.ResponseWriter, r *http.Request, status int, f *connectorForm, snap *db.Snapshot,
	errKey string, problems []string) {
	rules := append([]est.DNRule{}, f.Cfg.Subject.Rules...)
	for range connectorRuleRows {
		rules = append(rules, est.DNRule{Mode: est.ModeOptional})
	}
	f.Rules = rules
	var cas []choice
	for _, c := range store.ConnectorCAs(snap, time.Now()) {
		cas = append(cas, choice{ID: c.ID, Label: c.Name})
	}
	if f.CAID != 0 && !slices.ContainsFunc(cas, func(c choice) bool { return c.ID == f.CAID }) {
		if ca := certByID(snap, f.CAID); ca != nil {
			cas = append(cas, choice{ID: ca.ID, Label: ca.Name, Note: "unusable"})
		}
	}
	var templates []choice
	for _, t := range snap.Templates {
		templates = append(templates, choice{ID: t.ID, Label: t.Name})
	}
	var profileIDs []string
	for _, p := range profiles {
		if p.Link == "" && p.Group == "cert" {
			profileIDs = append(profileIDs, p.ID)
		}
	}
	pr := s.printer(r)
	ef := f.editor(snap)
	expert := store.Expert(snap)
	action := s.connectorPath(r, "/new/est")
	if f.ID != 0 {
		action = s.connectorPath(r, "/"+strconv.FormatInt(f.ID, 10)+"/edit")
	}
	tab := "connectors"
	s.render(w, r, status, "connectoredit", &page{Title: "connector.title.edit", Tab: tab, Error: errKey, Data: map[string]any{
		"CF": f, "F": ef, "Action": action, "CAs": cas, "Modes": ruleModes, "Templates": templates, "Profiles": profileIDs,
		"Curves": curveNames(), "EdDSA": []string{"Ed25519", "Ed448"}, "MLDSA": mldsaNames(), "SLHDSA": slhdsaNames(), "Composite": compositeNames(),
		"Hashes": []string{"SHA-256", "SHA-384", "SHA-512"}, "Problems": problems, "Served": s.est.Served(dbSession(r).DBName),
		"Published": s.published(), "BaseURLs": s.store.BaseURLs, "KU": pki.KeyUsageNames, "EKU": pki.EKUNames,
		"NS": pki.NSCertTypeNames, "NoNetscape": snap.Settings["disable_netscape"] == "yes", "Expert": expert,
		"Sum": ef.summaries(pr.T, snap), "ExpertUsed": ef.expertUsed(pr.T, snap),
	}})
}

func (s *Server) connectorNew(w http.ResponseWriter, r *http.Request) {
	snap, err := dbSession(r).Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.renderConnectorForm(w, r, http.StatusOK, newConnectorForm(snap), snap, "", nil)
}

func (s *Server) connectorEdit(w http.ResponseWriter, r *http.Request) {
	snap, err := dbSession(r).Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c := connectorID(r, snap)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	f, err := formFromConnector(c)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.renderConnectorForm(w, r, http.StatusOK, f, snap, "", nil)
}

// connectorSave creates or updates a connector; action=apply fills the
// certificate properties from a purpose or template instead.
func (s *Server) connectorSave(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	ctx := r.Context()
	snap, err := ds.Handle.Snapshot(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	base := newConnectorForm(snap)
	var existing *db.Connector
	if r.PathValue("id") != "" {
		if existing = connectorID(r, snap); existing == nil {
			http.NotFound(w, r)
			return
		}
		if base, err = formFromConnector(existing); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	f := parseConnectorForm(r, snap, base)
	if r.PostFormValue("action") == "apply" {
		ef := f.editor(snap)
		sel := r.PostFormValue("template")
		if id, ok := strings.CutPrefix(sel, "p:"); ok {
			if p := profileByID(id); p != nil {
				ef.applyProfile(p, snap)
			}
		} else if id, _ := strconv.ParseInt(sel, 10, 64); id != 0 {
			if d, err := ds.Handle.LoadTemplate(ctx, id); err == nil {
				ef.applyTemplate(d, false, true)
			}
		}
		san := f.Cfg.Profile.Ext.SubAltName
		f.Cfg.Profile = ef.templateData()
		f.Cfg.Profile.Subject, f.Cfg.Profile.Ext.SubAltName = nil, san
		f.Cfg.Profile.Ext.CA = 2
		s.renderConnectorForm(w, r, http.StatusOK, f, snap, "", nil)
		return
	}
	generated := ""
	if f.Password == "" && f.Cfg.Auth.PassHash == "" {
		generated = randomPassword()
		f.Password = generated
	}
	if f.Password != "" {
		if len(f.Password) < 12 {
			s.renderConnectorForm(w, r, http.StatusBadRequest, f, snap, "connector.err.password", nil)
			return
		}
		f.Cfg.Auth.PassHash = auth.HashPassword([]byte(f.Password))
	}
	switch {
	case f.Name == "":
		s.renderConnectorForm(w, r, http.StatusBadRequest, f, snap, "connector.err.name", nil)
		return
	case !store.ValidConnectorLabel(f.Label):
		s.renderConnectorForm(w, r, http.StatusBadRequest, f, snap, "connector.err.label", nil)
		return
	case f.CAID == 0 || store.ConnectorCAProblem(snap, &db.Connector{CAID: f.CAID}, time.Now()) != "":
		s.renderConnectorForm(w, r, http.StatusBadRequest, f, snap, "connector.err.ca", nil)
		return
	}
	if problems := f.Cfg.Validate(); len(problems) > 0 {
		s.renderConnectorForm(w, r, http.StatusBadRequest, f, snap, "connector.err.config", problems)
		return
	}
	// The label names a URL path shared by all databases.
	for _, owner := range s.est.Owners(ctx, f.Label) {
		if owner != ds.DBName {
			s.renderConnectorForm(w, r, http.StatusBadRequest, f, snap, "connector.err.labeltaken", nil)
			return
		}
	}
	cfg, err := f.Cfg.Marshal()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c := &db.Connector{Type: db.ConnectorEST}
	if existing != nil {
		cc := *existing
		c = &cc
	}
	c.Name, c.Label, c.CAID, c.Enabled, c.Config = f.Name, f.Label, f.CAID, f.Enabled, string(cfg)
	action := ""
	if existing != nil && f.Password != "" {
		action = "connector.password"
	}
	if err := ds.Handle.SaveConnector(ctx, c, action); err != nil {
		if errors.Is(err, db.ErrLabelTaken) {
			s.renderConnectorForm(w, r, http.StatusBadRequest, f, snap, "connector.err.labeltaken", nil)
			return
		}
		s.fail(w, r, err)
		return
	}
	if generated != "" {
		s.renderConnector(w, r, c.ID, generated)
		return
	}
	s.redirect(w, r, s.connectorPath(r, "/"+strconv.FormatInt(c.ID, 10)))
}

func (s *Server) connectorView(w http.ResponseWriter, r *http.Request) {
	snap, err := dbSession(r).Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c := connectorID(r, snap)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	s.renderConnector(w, r, c.ID, "")
}

// renderConnector shows a connector; password is a generated password to
// show this once.
func (s *Server) renderConnector(w http.ResponseWriter, r *http.Request, id int64, password string) {
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c := snap.Connector(id)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	cfg, _ := est.Parse([]byte(c.Config))
	issued := store.IssuedBy(snap, c.ID)
	slices.Reverse(issued)
	if len(issued) > 50 {
		issued = issued[:50]
	}
	ca := certByID(snap, c.CAID)
	host := r.Host
	scheme := "https"
	s.render(w, r, http.StatusOK, "connector", &page{Title: "connector.title", Tab: "connectors", Data: map[string]any{
		"C": c, "Cfg": cfg, "CA": ca, "Problem": s.connectorProblem(r, snap, c), "Issued": issued, "Password": password,
		"URL": scheme + "://" + host + estserver.PathPrefix + c.Label + "/",
	}})
}

func (s *Server) connectorToggle(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c := connectorID(r, snap)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	cc := *c
	cc.Enabled = !c.Enabled
	action := "connector.disable"
	if cc.Enabled {
		action = "connector.enable"
	}
	if err := ds.Handle.SaveConnector(r.Context(), &cc, action); err != nil {
		s.fail(w, r, err)
		return
	}
	s.redirect(w, r, s.connectorPath(r, "/"+strconv.FormatInt(c.ID, 10)))
}

// connectorPassword replaces the password with a generated one, shown once.
func (s *Server) connectorPassword(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c := connectorID(r, snap)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	cfg, err := est.Parse([]byte(c.Config))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pw := randomPassword()
	cfg.Auth.PassHash = auth.HashPassword([]byte(pw))
	b, err := cfg.Marshal()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cc := *c
	cc.Config = string(b)
	if err := ds.Handle.SaveConnector(r.Context(), &cc, "connector.password"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.renderConnector(w, r, c.ID, pw)
}

func (s *Server) connectorDelete(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c := connectorID(r, snap)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	if r.PostFormValue("confirm") != c.Label {
		s.renderConnectorTest(w, r, c, nil, nil, "connector.err.confirm")
		return
	}
	if err := ds.Handle.DeleteConnector(r.Context(), c.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.redirect(w, r, s.connectorPath(r, ""))
}

// connectorTest evaluates a pasted CSR against the connector's rules
// without signing anything.
func (s *Server) connectorTest(w http.ResponseWriter, r *http.Request) {
	snap, err := dbSession(r).Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c := connectorID(r, snap)
	if c == nil {
		http.NotFound(w, r)
		return
	}
	cfg, err := est.Parse([]byte(c.Config))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ca := certByID(snap, c.CAID)
	if ca == nil {
		s.renderConnectorTest(w, r, c, nil, nil, "connector.err.ca")
		return
	}
	cc, err := pki.ParseCertificate(ca.DER)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	der := decodeCSR(r.PostFormValue("csr"))
	if der == nil {
		s.renderConnectorTest(w, r, c, nil, nil, "connector.err.csr")
		return
	}
	d, violations := est.Evaluate(cfg, cc, der, time.Now())
	s.renderConnectorTest(w, r, c, &d, violations, "")
}

// decodeCSR reads a pasted CSR: PEM or bare base64.
func decodeCSR(v string) []byte {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "-----BEGIN") {
		lines := strings.Split(v, "\n")
		var body []string
		for _, l := range lines {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "-----") {
				body = append(body, l)
			}
		}
		v = strings.Join(body, "")
	}
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(v), ""))
	if err != nil || len(b) == 0 {
		return nil
	}
	return b
}

func (s *Server) renderConnectorTest(w http.ResponseWriter, r *http.Request, c *db.Connector, d *est.Decision,
	violations []est.Violation, errKey string) {
	data := map[string]any{"C": c, "D": d, "Violations": violations, "fragment": "connectortest"}
	if d != nil && len(violations) == 0 {
		var parts []string
		for _, a := range d.Subject {
			parts = append(parts, a.Name+"="+a.Value)
		}
		data["Subject"] = strings.Join(parts, ", ")
		data["Validity"] = d.NotBefore.UTC().Format("2006-01-02") + " – " + d.NotAfter.UTC().Format("2006-01-02")
	}
	status := http.StatusOK
	if errKey != "" {
		status = http.StatusBadRequest
	}
	if !isHTMX(r) {
		// without htmx: show the result on the connector page
		snap, _ := dbSession(r).Handle.Snapshot(r.Context())
		cfg, _ := est.Parse([]byte(c.Config))
		data["Cfg"], data["CA"], data["Problem"] = cfg, certByID(snap, c.CAID), s.connectorProblem(r, snap, c)
		data["Issued"] = store.IssuedBy(snap, c.ID)
		data["URL"] = "https://" + r.Host + estserver.PathPrefix + c.Label + "/"
		delete(data, "fragment")
	}
	s.render(w, r, status, "connector", &page{Title: "connector.title", Tab: "connectors", Error: errKey, Data: data})
}

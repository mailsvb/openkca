package web

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/store"
	"github.com/mailsvb/go-ca/internal/tmpl"
)

// Column describes a list column; Key doubles as the CSS class suffix used
// to hide it.
type Column struct{ Key, Label string }

var columns = map[string][]Column{
	"keys": {{"name", "col.name"}, {"type", "col.keytype"}, {"size", "col.size"}, {"private", "col.private"},
		{"use", "col.usecount"}, {"date", "col.date"}, {"comment", "col.comment"}},
	"requests": {{"name", "col.name"}, {"cn", "col.cn"}, {"signed", "col.signed"}, {"key", "col.key"},
		{"sigalg", "col.sigalg"}, {"date", "col.date"}, {"comment", "col.comment"}},
	"certs": {{"name", "col.name"}, {"cn", "col.cn"}, {"ca", "col.ca"}, {"serial", "col.serial"},
		{"notbefore", "col.notbefore"}, {"notafter", "col.notafter"}, {"status", "col.status"},
		{"key", "col.key"}, {"crlexpire", "col.crlexpire"}, {"comment", "col.comment"}},
	"templates": {{"name", "col.name"}, {"cn", "col.cn"}, {"date", "col.date"},
		{"comment", "col.comment"}},
	"crls": {{"name", "col.name"}, {"issuer", "col.issuer"}, {"number", "col.crlnumber"},
		{"thisupdate", "col.thisupdate"}, {"nextupdate", "col.nextupdate"}, {"revoked", "col.revokedcount"},
		{"comment", "col.comment"}},
}

// Row is one list row; Cells is keyed by column key.
type Row struct {
	ID       int64
	Depth    int
	Cells    map[string]string
	Classes  map[string]string // per cell CSS class (expiry colours)
	Unusable bool
}

// certStatus classifies a certificate like XCA's list colours.
type certStatus struct {
	Status   string // message key
	Revoked  *gcadb.Revocation
	Unusable bool
	After    string // CSS class of the notAfter cell
	Before   string
}

// expiryWarn parses settings.cert_expiry ("80%", "4W", "30D") and returns
// the warning time for a certificate.
func expiryWarn(setting string, nb, na time.Time) time.Time {
	if setting == "" {
		setting = "80%"
	}
	unit := setting[len(setting)-1:]
	n, err := strconv.Atoi(setting[:len(setting)-1])
	if err != nil {
		n, unit = 80, "%"
	}
	switch unit {
	case "D":
		return na.AddDate(0, 0, -n)
	case "W":
		return na.AddDate(0, 0, -7*n)
	}
	return nb.Add(time.Duration(float64(na.Sub(nb)) * float64(n) / 100))
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "true", "1", "y":
		return true
	}
	return false
}

func statusOf(c *gcadb.Cert, info *pki.CertInfo, revs map[string]*gcadb.Revocation, snap *gcadb.Snapshot, now time.Time) certStatus {
	st := certStatus{Status: "status.valid"}
	if r, ok := revs[revKey(c.IssuerID, c.Serial)]; ok && c.IssuerID != c.ID {
		st.Revoked, st.Status, st.Unusable = r, "status.revoked", true
	}
	colors := !truthy(snap.Settings["no_expire_colors"])
	switch {
	case info.NoExpiry:
		if colors {
			st.After = "exp-none"
		}
	case info.NotAfter.Before(now):
		if st.Revoked == nil {
			st.Status = "status.expired"
		}
		st.Unusable = true
		if colors {
			st.After = "exp-red"
		}
	case expiryWarn(snap.Settings["cert_expiry"], info.NotBefore, info.NotAfter).Before(now):
		if st.Revoked == nil {
			st.Status = "status.expiring"
		}
		if colors {
			st.After = "exp-yellow"
		}
	}
	if info.NotBefore.After(now) {
		if st.Revoked == nil {
			st.Status = "status.notyet"
		}
		if colors {
			st.Before = "exp-red"
		}
	}
	return st
}

func revKey(caID int64, serial string) string { return strconv.FormatInt(caID, 10) + "/" + serial }

// index holds lookups derived from a snapshot.
type index struct {
	snap     *gcadb.Snapshot
	names    map[int64]string
	certs    map[int64]*gcadb.Cert
	keys     map[int64]*gcadb.Key
	revs     map[string]*gcadb.Revocation
	useCount map[int64]int
	children map[int64][]*gcadb.Cert
	info     map[int64]*pki.CertInfo
}

func newIndex(snap *gcadb.Snapshot) *index {
	ix := &index{snap: snap, names: map[int64]string{}, certs: map[int64]*gcadb.Cert{}, keys: map[int64]*gcadb.Key{},
		revs: map[string]*gcadb.Revocation{}, useCount: map[int64]int{}, children: map[int64][]*gcadb.Cert{},
		info: map[int64]*pki.CertInfo{}}
	for _, k := range snap.Keys {
		ix.names[k.ID], ix.keys[k.ID] = k.Name, k
	}
	for _, r := range snap.Requests {
		ix.names[r.ID] = r.Name
		if r.KeyID != 0 {
			ix.useCount[r.KeyID]++
		}
	}
	for _, c := range snap.Certs {
		ix.names[c.ID], ix.certs[c.ID] = c.Name, c
		ix.info[c.ID] = pki.DescribeCert(c.DER)
		if c.KeyID != 0 {
			ix.useCount[c.KeyID]++
		}
	}
	for _, c := range snap.Certs {
		if c.IssuerID != 0 && c.IssuerID != c.ID && ix.certs[c.IssuerID] != nil {
			ix.children[c.IssuerID] = append(ix.children[c.IssuerID], c)
		}
	}
	for _, t := range snap.Templates {
		ix.names[t.ID] = t.Name
	}
	for _, c := range snap.CRLs {
		ix.names[c.ID] = c.Name
	}
	for _, r := range snap.Revocations {
		ix.revs[revKey(r.CAID, r.Serial)] = r
	}
	return ix
}

func matches(q string, fields ...string) bool {
	if q == "" {
		return true
	}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func boolKey(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	tab := r.PathValue("tab")
	cols, ok := columns[tab]
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
	ix := newIndex(snap)
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	plain := r.URL.Query().Get("view") == "plain"
	hideUnusable := r.URL.Query().Get("unusable") == "hide"
	if _, set := r.URL.Query()["unusable"]; !set && r.URL.Query().Get("f") == "" {
		hideUnusable = truthy(snap.Settings["hide_unusable"])
	}
	now := time.Now()
	var rows []Row
	switch tab {
	case "keys":
		onlyLegacy := r.URL.Query().Get("legacy") != ""
		for _, k := range snap.Keys {
			if onlyLegacy && !k.Legacy {
				continue
			}
			pk := pki.DescribePublicKey(k.Public)
			if !matches(q, k.Name, k.Comment, pk.Algorithm, pk.SHA256) {
				continue
			}
			priv := "private.none"
			if k.HasPrivate {
				priv = "private.db"
				switch k.Protection {
				case gcadb.ProtPassword:
					priv = "private.own"
				case gcadb.ProtToken:
					priv = "private.token"
				}
			}
			algo := pk.Algorithm
			if pk.Curve != "" {
				algo += " " + pk.Curve
			}
			rows = append(rows, Row{ID: k.ID, Cells: map[string]string{
				"name": k.Name, "type": algo, "size": strconv.Itoa(pk.Bits), "private": priv,
				"use": strconv.Itoa(ix.useCount[k.ID]), "date": k.Date.UTC().Format("2006-01-02"), "comment": k.Comment,
			}})
		}
	case "requests":
		for _, rq := range snap.Requests {
			info := pki.DescribeRequest(rq.DER)
			if !matches(q, rq.Name, rq.Comment, info.SubjectText) {
				continue
			}
			rows = append(rows, Row{ID: rq.ID, Cells: map[string]string{
				"name": rq.Name, "cn": info.CommonName, "signed": boolKey(rq.Signed), "key": ix.names[rq.KeyID],
				"sigalg": info.SigAlg, "date": rq.Date.UTC().Format("2006-01-02"), "comment": rq.Comment,
			}})
		}
	case "certs":
		var add func(c *gcadb.Cert, depth int)
		seen := map[int64]bool{}
		add = func(c *gcadb.Cert, depth int) {
			if seen[c.ID] {
				return
			}
			seen[c.ID] = true
			info := ix.info[c.ID]
			st := statusOf(c, info, ix.revs, snap, now)
			show := matches(q, c.Name, c.Comment, info.SubjectText, info.Serial, info.Fingerprints.SHA256) &&
				!(hideUnusable && st.Unusable)
			if show {
				notAfter := info.NotAfter.UTC().Format("2006-01-02")
				if info.NoExpiry {
					notAfter = "—"
				}
				row := Row{ID: c.ID, Depth: depth, Unusable: st.Unusable, Cells: map[string]string{
					"name": c.Name, "cn": info.CommonName, "ca": boolKey(c.CA), "serial": c.Serial,
					"notbefore": info.NotBefore.UTC().Format("2006-01-02"), "notafter": notAfter,
					"status": st.Status, "key": ix.names[c.KeyID], "comment": c.Comment,
				}, Classes: map[string]string{"notafter": st.After, "notbefore": st.Before}}
				if c.Authority != nil && c.CA {
					row.Cells["crlexpire"] = c.Authority.CRLExpire.UTC().Format("2006-01-02")
					if c.Authority.CRLExpire.Year() == 9999 {
						row.Cells["crlexpire"] = "—"
					} else if c.Authority.CRLExpire.Before(now) {
						row.Classes["crlexpire"] = "exp-red"
					} else if c.Authority.CRLExpire.Add(-48 * time.Hour).Before(now) {
						row.Classes["crlexpire"] = "exp-yellow"
					}
				}
				rows = append(rows, row)
			}
			if !plain && q == "" {
				for _, ch := range ix.children[c.ID] {
					add(ch, depth+1)
				}
			}
		}
		for _, c := range snap.Certs {
			isRoot := c.IssuerID == 0 || c.IssuerID == c.ID || ix.certs[c.IssuerID] == nil
			if plain || q != "" || isRoot {
				add(c, 0)
			}
		}
		// Issuer cycles would leave certificates unvisited; list them flat.
		for _, c := range snap.Certs {
			add(c, 0)
		}
	case "templates":
		for _, t := range snap.Templates {
			cn := ""
			if t.Data != nil {
				cn = pki.CommonName(t.Data.Subject)
			}
			if !matches(q, t.Name, t.Comment, cn) {
				continue
			}
			rows = append(rows, Row{ID: t.ID, Cells: map[string]string{
				"name": t.Name, "cn": cn,
				"date": t.Date.UTC().Format("2006-01-02"), "comment": t.Comment,
			}})
		}
	case "crls":
		for _, c := range snap.CRLs {
			info := pki.DescribeCRL(c.DER)
			issuer := ix.names[c.IssuerID]
			if issuer == "" {
				issuer = info.IssuerText
			}
			if !matches(q, c.Name, c.Comment, issuer, info.IssuerText) {
				continue
			}
			row := Row{ID: c.ID, Cells: map[string]string{
				"name": c.Name, "issuer": issuer, "number": info.Number,
				"thisupdate": info.ThisUpdate.UTC().Format("2006-01-02"), "nextupdate": info.NextUpdate.UTC().Format("2006-01-02"),
				"revoked": strconv.Itoa(len(info.Entries)), "comment": c.Comment,
			}, Classes: map[string]string{}}
			if !info.NextUpdate.IsZero() && info.NextUpdate.Before(now) {
				row.Classes["nextupdate"] = "exp-red"
			}
			rows = append(rows, row)
		}
	}
	p := &page{Title: "tab." + tab, Tab: tab, Data: map[string]any{
		"Columns": cols, "Rows": rows, "Q": r.URL.Query().Get("q"), "Plain": plain,
		"HideUnusable": hideUnusable, "Trashed": snap.Trashed, "Legacy": legacyKeys(snap, tab), "fragment": "rows",
	}}
	if r.Header.Get("HX-Target") != "rows" {
		delete(p.Data, "fragment")
	}
	switch r.URL.Query().Get("notice") {
	case "imported":
		p.Notice, p.NoticeArg = "importitems.done", r.URL.Query().Get("n")
	case "deleted":
		p.Notice = "list.deleted.notice"
	case "converted":
		p.Notice, p.NoticeArg = "converted.done", r.URL.Query().Get("name")
	case "converted.ownpass":
		p.Notice, p.NoticeArg = "converted.ownpass", r.URL.Query().Get("n")
	}
	s.render(w, r, http.StatusOK, "list", p)
}

// detail is the data for an item page.
type detail struct {
	History  []gcadb.AuditEntry
	Item     gcadb.Item
	Kind     string
	TypeKey  string
	Source   string
	Cert     *gcadb.Cert
	CertInfo *pki.CertInfo
	Status   certStatus
	Key      *gcadb.Key
	KeyInfo  pki.PublicKeyInfo
	Request  *gcadb.Request
	ReqInfo  *pki.RequestInfo
	CRL      *gcadb.CRL
	CRLInfo  *pki.CRLInfo
	Template *tmpl.Template
	TmplKeys []string
	Subject  []pki.NameEntry
	Links    map[string]*link
	Issued   []link
	UsedBy   []link
	CRLs     []link
	Entries  []crlEntry
	// action availability
	SSH        bool // a key SSH can use
	PGP        bool // a key with an OpenPGP certificate, or one that can get one
	HasKey     bool
	KeyPrivate bool
	KeyOwnPass bool
	Self       bool
	HasIssuer  bool
	CanRenew   bool
	Templates  []link
	Reasons    []reasonChoice
	Now        string
	CADir      string // a CA's folder on disk (index files and other data)
}

type link struct {
	ID   int64
	Name string
}

type crlEntry struct {
	pki.RevokedEntry
	Cert link
}

func (s *Server) item(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ix := newIndex(snap)
	d := &detail{Links: map[string]*link{}}
	lk := func(id int64) link { return link{ID: id, Name: ix.names[id]} }
	plk := func(id int64) *link { l := lk(id); return &l }
	tab := ""
	for _, k := range snap.Keys {
		if k.ID == id {
			d.Item, d.Kind, d.Key, tab = k.Item, "key", k, "keys"
			d.KeyInfo = pki.DescribePublicKey(k.Public)
			if pub, err := codec.ParsePublic(k.Public); err == nil {
				d.SSH = codec.SSHCompatible(pub)
				d.PGP = k.HasPrivate && !k.Token && (codec.PGPCompatible(pub, 4, false) || codec.PGPCompatible(pub, 6, false))
			}
			d.PGP = d.PGP || store.PGPOf(snap, id) != nil || store.PGPSubkeyOf(snap, id) != nil
			for _, c := range snap.Certs {
				if c.KeyID == id {
					d.UsedBy = append(d.UsedBy, lk(c.ID))
				}
			}
			for _, rq := range snap.Requests {
				if rq.KeyID == id {
					d.UsedBy = append(d.UsedBy, lk(rq.ID))
				}
			}
		}
	}
	for _, c := range snap.Certs {
		if c.ID == id {
			d.Item, d.Kind, d.Cert, tab = c.Item, "cert", c, "certs"
			d.CertInfo = ix.info[c.ID]
			d.Subject = d.CertInfo.Subject
			d.Status = statusOf(c, d.CertInfo, ix.revs, snap, time.Now())
			if c.IssuerID != 0 && c.IssuerID != c.ID {
				d.Links["issuer"] = plk(c.IssuerID)
			}
			if c.KeyID != 0 {
				d.Links["key"] = plk(c.KeyID)
			}
			if c.Authority != nil && c.Authority.TemplateID != 0 {
				d.Links["template"] = plk(c.Authority.TemplateID)
			}
			if c.CA && c.Authority != nil {
				d.CADir, _ = ds.Handle.CADir(c.Authority.UUID)
			}
			for _, ch := range ix.children[c.ID] {
				d.Issued = append(d.Issued, lk(ch.ID))
			}
			for _, crl := range snap.CRLs {
				if crl.IssuerID == c.ID {
					d.CRLs = append(d.CRLs, lk(crl.ID))
				}
			}
		}
	}
	for _, rq := range snap.Requests {
		if rq.ID == id {
			d.Item, d.Kind, d.Request, tab = rq.Item, "request", rq, "requests"
			d.ReqInfo = pki.DescribeRequest(rq.DER)
			d.Subject = d.ReqInfo.Subject
			if rq.KeyID != 0 {
				d.Links["key"] = plk(rq.KeyID)
			}
		}
	}
	for _, c := range snap.CRLs {
		if c.ID == id {
			d.Item, d.Kind, d.CRL, tab = c.Item, "crl", c, "crls"
			d.CRLInfo = pki.DescribeCRL(c.DER)
			if c.IssuerID != 0 {
				d.Links["issuer"] = plk(c.IssuerID)
			}
			bySerial := map[string]int64{}
			for _, cert := range snap.Certs {
				if cert.IssuerID == c.IssuerID {
					bySerial[cert.Serial] = cert.ID
				}
			}
			for _, e := range d.CRLInfo.Entries {
				ce := crlEntry{RevokedEntry: e}
				if cid, ok := bySerial[e.Serial]; ok {
					ce.Cert = lk(cid)
				}
				d.Entries = append(d.Entries, ce)
			}
		}
	}
	for _, t := range snap.Templates {
		if t.ID == id {
			d.Item, d.Kind, tab = t.Item, "template", "templates"
			if tp := t.Data; tp != nil {
				d.Template = tp
				d.Subject, _ = pki.ParseName(tp.Subject)
				for k := range tp.Settings {
					d.TmplKeys = append(d.TmplKeys, k)
				}
				sort.Strings(d.TmplKeys)
			}
		}
	}
	if d.Kind == "" {
		s.render(w, r, http.StatusNotFound, "error", &page{Title: "error.title", Error: "error.notfound"})
		return
	}
	d.Source = "source." + gcadb.SourceName(d.Item.Source)
	if d.Cert != nil && d.Cert.KeyID != 0 {
		d.HasKey = true
		if k := ix.keys[d.Cert.KeyID]; k != nil {
			d.KeyPrivate = k.HasPrivate
			d.KeyOwnPass = k.Protection == gcadb.ProtPassword
		}
	}
	if d.Request != nil && d.Request.KeyID != 0 {
		d.HasKey = true
	}
	if d.Cert != nil {
		signer := d.Cert
		if d.Cert.IssuerID != d.Cert.ID {
			signer = ix.certs[d.Cert.IssuerID]
		}
		d.Self = d.Cert.IssuerID == d.Cert.ID
		d.HasIssuer = d.Cert.IssuerID != 0 && !d.Self && signer != nil
		if signer != nil {
			if k := ix.keys[signer.KeyID]; k != nil && k.HasPrivate {
				d.CanRenew = true
			}
		}
		for _, t := range snap.Templates {
			d.Templates = append(d.Templates, link{t.ID, t.Name})
		}
		d.Reasons = reasonChoices()
		d.Now = nowLocal()
	}
	if d.Item.ID != 0 {
		d.History, _ = ds.Handle.AuditLog(r.Context(), d.Item.ID, 0, 50)
	}
	p := &page{Title: "tab." + tab, Tab: tab, Data: map[string]any{"D": d}}
	q := r.URL.Query()
	if n := q.Get("notice"); n == "created" || n == "saved" || n == "keypw" || n == "revoked" || n == "unrevoked" {
		p.Notice = "item.notice." + n
	}
	if e := q.Get("error"); strings.HasPrefix(e, "item.error.") || strings.HasPrefix(e, "keypw.error.") || strings.HasPrefix(e, "ca.error.") {
		p.Error = e
	}
	s.render(w, r, http.StatusOK, "item", p)
}

// checkKey decrypts a private key in memory and checks it against the
// public key. Keys with their own password take a password from the form;
// it is used once and never stored.
func (s *Server) checkKey(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var key *gcadb.Key
	for _, k := range snap.Keys {
		if k.ID == id && k.HasPrivate {
			key = k
		}
	}
	res := map[string]any{"ID": id, "fragment": "keycheck"}
	p := &page{Data: res}
	if key == nil {
		res["Result"] = "keycheck.nokey"
		s.render(w, r, http.StatusOK, "item", p)
		return
	}
	res["OwnPass"] = key.Protection == gcadb.ProtPassword
	limitKey := ds.ID
	if s.keyLimit.Blocked(limitKey) {
		res["Result"] = "keycheck.ratelimit"
		s.render(w, r, http.StatusTooManyRequests, "item", p)
		return
	}
	if key.Protection == gcadb.ProtToken {
		res["Result"] = "keycheck.token"
		s.render(w, r, http.StatusOK, "item", p)
		return
	}
	var pw []byte
	if key.Protection == gcadb.ProtPassword {
		pw = []byte(r.PostFormValue("password"))
		defer clear(pw)
	}
	algo, ok, err := ds.Handle.CheckKey(r.Context(), key, ds.Keyring(), pw)
	switch {
	case errors.Is(err, store.ErrNeedKeyPassword):
		s.keyLimit.Fail(limitKey)
		res["Result"] = "keycheck.wrongpass"
	case err != nil:
		res["Result"] = "keycheck.error"
		res["Detail"] = err.Error()
	default:
		if ok {
			res["Result"] = "keycheck.ok"
		} else {
			res["Result"] = "keycheck.mismatch"
		}
		res["Algorithm"] = algo
	}
	s.render(w, r, http.StatusOK, "item", p)
}

// optionRow is one entry of the options page.
type optionRow struct {
	Key, Label, Value, Kind string
	Default                 bool
	Choices                 []string
	Labels                  map[string]string // message keys of choices shown translated
	Units                   []string
	Min, Max                int    // number: bounds
	Num                     string // expiry: number part
	Unit                    string // expiry: unit part
}

// hashLabels are the message keys of the hash choices.
var hashLabels = func() map[string]string {
	m := map[string]string{}
	for _, h := range pki.HashChoices {
		m[h] = "hash." + h
	}
	return m
}()

var serialLens = []string{"64", "72", "80", "88", "96", "104", "112", "120", "128", "136", "144", "152", "160"}

var optionKeys = []struct {
	key, label, def, kind string
	choices               []string
	units                 string
}{
	{"expert", "opt.expert", "no", "bool", nil, ""},
	{"default_hash", "opt.default_hash", store.DefaultHash, "select", pki.HashChoices, ""},
	{"mandatory_dn", "opt.mandatory_dn", "", "text", nil, ""},
	{"explicit_dn", "opt.explicit_dn", "C,ST,L,O,OU,CN,emailAddress", "text", nil, ""},
	{"adapt_explicit_subj", "opt.adapt_explicit_subj", "no", "bool", nil, ""},
	{"string_opt", "opt.string_opt", "MASK:0x2002", "select", []string{"MASK:0x2002", "utf8only", "pkix", "nombstr", "default"}, ""},
	{"serial_len", "opt.serial_len", strconv.Itoa(store.DefaultSerialLen), "select", serialLens, ""},
	{"cert_expiry", "opt.cert_expiry", "80%", "expiry", nil, "%DW"},
	{"ical_expiry", "opt.ical_expiry", "1W", "expiry", nil, "DW"},
	{"pkcs12_enc_algo", "opt.pkcs12_enc_algo", codec.PKCS12Algorithms[0], "select", codec.PKCS12Algorithms, ""},
	{"pkcs12_iterations", "opt.pkcs12_iterations", strconv.Itoa(codec.PKCS12Iterations), "number", nil, ""},
	{"disable_netscape", "opt.disable_netscape", "no", "bool", nil, ""},
	{"no_expire_colors", "opt.no_expire_colors", "no", "bool", nil, ""},
	{"backup_keep", "opt.backup_keep", strconv.Itoa(store.DefaultBackupKeep), "number", nil, ""},
	{"backup_days", "opt.backup_days", strconv.Itoa(store.DefaultBackupDays), "number", nil, ""},
	{"hide_unusable", "opt.hide_unusable", "no", "bool", nil, ""},
	{"translate_dn", "opt.translate_dn", "no", "bool", nil, ""},
	{"suppress_messages", "opt.suppress_messages", "no", "bool", nil, ""},
}

// optionRanges are the bounds of the "number" options.
var optionRanges = map[string][2]int{
	"pkcs12_iterations": {codec.PKCS12MinIterations, codec.PKCS12MaxIterations},
	"backup_keep":       {1, store.MaxBackupKeep},
	"backup_days":       {0, store.MaxBackupDays},
}

func (s *Server) options(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var rows []optionRow
	for _, o := range optionKeys {
		v, ok := snap.Settings[o.key]
		if !ok {
			v = o.def
		}
		row := optionRow{Key: o.key, Label: o.label, Value: v, Default: !ok, Kind: o.kind, Choices: o.choices}
		if o.key == "default_hash" {
			row.Labels = hashLabels
		}
		if rg, ok := optionRanges[o.key]; ok {
			row.Min, row.Max = rg[0], rg[1]
		}
		if o.kind == "select" && !contains(row.Choices, v) {
			row.Choices = append([]string{v}, row.Choices...)
		}
		if o.kind == "expiry" && v != "" {
			row.Num, row.Unit = v[:len(v)-1], v[len(v)-1:]
			for _, u := range o.units {
				row.Units = append(row.Units, string(u))
			}
		}
		rows = append(rows, row)
	}
	p := &page{Title: "options.title", Tab: "options", Data: map[string]any{"Options": rows, "Schema": snap.Schema}}
	switch q := r.URL.Query(); {
	case q.Get("notice") == "saved":
		p.Notice = "options.saved"
	case q.Get("error") == "options.error.value":
		p.Error, p.ErrorArg = "options.error.value", q.Get("key")
	case q.Get("error") == "dump.error.password":
		p.Error = "dump.error.password"
	}
	s.render(w, r, http.StatusOK, "options", p)
}

// tabOf returns the list tab an item belongs to.
func tabOf(snap *gcadb.Snapshot, id int64) string {
	for _, k := range snap.Keys {
		if k.ID == id {
			return "keys"
		}
	}
	for _, r := range snap.Requests {
		if r.ID == id {
			return "requests"
		}
	}
	for _, c := range snap.CRLs {
		if c.ID == id {
			return "crls"
		}
	}
	for _, t := range snap.Templates {
		if t.ID == id {
			return "templates"
		}
	}
	return "certs"
}

// legacyKeys counts the keys with their own password still in an XCA
// form, shown on the key list.
func legacyKeys(snap *gcadb.Snapshot, tab string) int {
	if tab != "keys" {
		return 0
	}
	n := 0
	for _, k := range snap.Keys {
		if k.Legacy {
			n++
		}
	}
	return n
}

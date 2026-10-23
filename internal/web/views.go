package web

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/tmpl"
	"github.com/mailsvb/go-ca/internal/xdb"
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
	"templates": {{"name", "col.name"}, {"cn", "col.cn"}, {"version", "col.version"}, {"date", "col.date"},
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
	Revoked  *xdb.Revocation
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

func statusOf(c *xdb.Cert, info *pki.CertInfo, revs map[string]*xdb.Revocation, snap *xdb.Snapshot, now time.Time) certStatus {
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
	snap     *xdb.Snapshot
	names    map[int64]string
	certs    map[int64]*xdb.Cert
	keys     map[int64]*xdb.Key
	revs     map[string]*xdb.Revocation
	useCount map[int64]int
	children map[int64][]*xdb.Cert
	info     map[int64]*pki.CertInfo
}

func newIndex(snap *xdb.Snapshot) *index {
	ix := &index{snap: snap, names: map[int64]string{}, certs: map[int64]*xdb.Cert{}, keys: map[int64]*xdb.Key{},
		revs: map[string]*xdb.Revocation{}, useCount: map[int64]int{}, children: map[int64][]*xdb.Cert{},
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
		for _, k := range snap.Keys {
			pk := pki.DescribePublicKey(k.Public)
			if !matches(q, k.Name, k.Comment, pk.Algorithm, pk.SHA256) {
				continue
			}
			priv := "private.none"
			if k.HasPrivate {
				priv = "private.db"
				switch k.OwnPass {
				case xdb.PassPrivate:
					priv = "private.own"
				case xdb.PassBogus:
					priv = "private.bogus"
				case xdb.PassPIN:
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
		var add func(c *xdb.Cert, depth int)
		seen := map[int64]bool{}
		add = func(c *xdb.Cert, depth int) {
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
			if d, err := tmpl.Decode(t.Blob, t.Version); err == nil {
				cn = pki.CommonName(d.Subject)
			}
			if !matches(q, t.Name, t.Comment, cn) {
				continue
			}
			rows = append(rows, Row{ID: t.ID, Cells: map[string]string{
				"name": t.Name, "cn": cn, "version": strconv.Itoa(t.Version),
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
		"HideUnusable": hideUnusable, "Deleted": snap.Deleted, "fragment": "rows",
	}}
	if r.Header.Get("HX-Target") != "rows" {
		delete(p.Data, "fragment")
	}
	s.render(w, r, http.StatusOK, "list", p)
}

// detail is the data for an item page.
type detail struct {
	Item     xdb.Item
	Kind     string
	TypeKey  string
	Source   string
	Cert     *xdb.Cert
	CertInfo *pki.CertInfo
	Status   certStatus
	Key      *xdb.Key
	KeyInfo  pki.PublicKeyInfo
	Request  *xdb.Request
	ReqInfo  *pki.RequestInfo
	CRL      *xdb.CRL
	CRLInfo  *pki.CRLInfo
	Template *tmpl.Template
	TmplErr  string
	TmplKeys []string
	TmplVer  int
	Subject  []pki.NameEntry
	Links    map[string]*link
	Issued   []link
	UsedBy   []link
	CRLs     []link
	Entries  []crlEntry
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
			d.Item, d.Kind, tab, d.TmplVer = t.Item, "template", "templates", t.Version
			tp, err := tmpl.Decode(t.Blob, t.Version)
			if err != nil {
				d.TmplErr = err.Error()
			}
			if tp != nil {
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
	d.Source = "source." + xdb.SourceName(d.Item.Source)
	s.render(w, r, http.StatusOK, "item", &page{Title: "tab." + tab, Tab: tab, Data: map[string]any{"D": d}})
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
	var key *xdb.Key
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
	res["OwnPass"] = key.OwnPass == xdb.PassPrivate
	limitKey := ds.ID
	if s.keyLimit.Blocked(limitKey) {
		res["Result"] = "keycheck.ratelimit"
		s.render(w, r, http.StatusTooManyRequests, "item", p)
		return
	}
	blob, own, err := ds.Handle.DB.PrivateKey(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var pw []byte
	switch own {
	case xdb.PassPrivate:
		pw = []byte(r.PostFormValue("password"))
	case xdb.PassBogus:
		pw = []byte("Bogus")
	case xdb.PassPIN:
		res["Result"] = "keycheck.token"
		s.render(w, r, http.StatusOK, "item", p)
		return
	default:
		pw = ds.Password()
	}
	defer clear(pw)
	priv, legacy, err := pki.DecryptPrivateKey(blob, key.KeyType, pw)
	switch {
	case errors.Is(err, pki.ErrWrongPassword):
		s.keyLimit.Fail(limitKey)
		res["Result"] = "keycheck.wrongpass"
	case err != nil:
		res["Result"] = "keycheck.error"
		res["Detail"] = err.Error()
	default:
		ok, _ := pki.MatchesPublic(priv, key.Public)
		if ok {
			res["Result"] = "keycheck.ok"
		} else {
			res["Result"] = "keycheck.mismatch"
		}
		res["Legacy"] = legacy
		res["Algorithm"] = pki.KeyAlgorithm(priv)
	}
	s.render(w, r, http.StatusOK, "item", p)
}

// optionRow is one entry of the options page.
type optionRow struct {
	Key, Label, Value string
	Default           bool
}

var optionKeys = []struct{ key, label, def string }{
	{"default_hash", "opt.default_hash", "sha256"},
	{"mandatory_dn", "opt.mandatory_dn", ""},
	{"explicit_dn", "opt.explicit_dn", "C,ST,L,O,OU,CN,emailAddress"},
	{"adapt_explicit_subj", "opt.adapt_explicit_subj", "no"},
	{"string_opt", "opt.string_opt", "MASK:0x2002"},
	{"serial_len", "opt.serial_len", "64"},
	{"cert_expiry", "opt.cert_expiry", "80%"},
	{"ical_expiry", "opt.ical_expiry", "1W"},
	{"pkcs12_enc_algo", "opt.pkcs12_enc_algo", "aes256"},
	{"disable_netscape", "opt.disable_netscape", "no"},
	{"no_expire_colors", "opt.no_expire_colors", "no"},
	{"hide_unusable", "opt.hide_unusable", "no"},
	{"translate_dn", "opt.translate_dn", "no"},
	{"suppress_messages", "opt.suppress_messages", "no"},
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
		rows = append(rows, optionRow{Key: o.key, Label: o.label, Value: v, Default: !ok})
		if !ok {
			rows[len(rows)-1].Value = o.def
		}
	}
	s.render(w, r, http.StatusOK, "options", &page{Title: "options.title", Tab: "options",
		Data: map[string]any{"Options": rows, "Schema": snap.Schema}})
}

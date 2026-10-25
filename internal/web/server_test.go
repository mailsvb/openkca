package web

import (
	"context"
	"html"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/mailsvb/openkca/internal/auth"
	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/i18n"
	"github.com/mailsvb/openkca/internal/store"
)

const serverPassword = "serverpass1"

func newTestServer(t *testing.T, opts ...func(*Config)) (*httptest.Server, *Server) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"sample.xdb", "variants.xdb", "legacy.xdb"} {
		b, err := os.ReadFile(filepath.Join("../../testdata/xdb", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Store: st, PasswordHash: auth.HashPassword([]byte(serverPassword)), Catalog: cat,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, o := range opts {
		o(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(srv)
	t.Cleanup(func() { ts.Close(); srv.dbs.CloseAll() })
	return ts, srv
}

func client(t *testing.T, ts *httptest.Server) *http.Client {
	c := ts.Client()
	c.Jar, _ = cookiejar.New(nil)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func body(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// methodIDRE finds the unlock methods on the methods page by their rename form.
var methodIDRE = regexp.MustCompile(`/methods/([0-9a-f-]{36})/rename`)

func login(t *testing.T, ts *httptest.Server, c *http.Client) string {
	t.Helper()
	r, err := c.PostForm(ts.URL+"/login", url.Values{"password": {serverPassword}})
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status %d", r.StatusCode)
	}
	r, _ = c.Get(ts.URL + "/")
	m := csrfRE.FindStringSubmatch(body(t, r))
	if m == nil {
		t.Fatal("no CSRF token on the databases page")
	}
	return m[1]
}

// finishConversion polls the progress page until the conversion of name
// has finished and returns where it sends the browser.
func finishConversion(t *testing.T, ts *httptest.Server, c *http.Client, name string) string {
	t.Helper()
	for range 50 {
		r, err := c.Get(ts.URL + "/db/" + name + "/converting")
		if err != nil {
			t.Fatal(err)
		}
		body(t, r)
		if r.StatusCode == http.StatusSeeOther {
			return r.Header.Get("Location")
		}
	}
	t.Fatalf("%s: the conversion does not finish", name)
	return ""
}

func TestServerLoginFlow(t *testing.T) {
	ts, srv := newTestServer(t)
	c := client(t, ts)
	r, _ := c.Get(ts.URL + "/")
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/login" {
		t.Fatalf("unauthenticated: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"} {
		if r.Header.Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
	r, _ = c.PostForm(ts.URL+"/login", url.Values{"password": {"wrong"}})
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", r.StatusCode)
	}
	// Server password checks run at most two at a time; a third is
	// turned away instead of allocating another 64 MiB.
	srv.loginSlots <- struct{}{}
	srv.loginSlots <- struct{}{}
	if r, _ := c.PostForm(ts.URL+"/login", url.Values{"password": {serverPassword}}); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("login with all slots busy: %d", r.StatusCode)
	}
	<-srv.loginSlots
	<-srv.loginSlots
	csrf := login(t, ts, c)

	// Database login without the CSRF token is refused.
	r, _ = c.PostForm(ts.URL+"/db/sample.xdb/login", url.Values{"password": {"secret"}})
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("db login without CSRF: %d", r.StatusCode)
	}
	r, _ = c.PostForm(ts.URL+"/db/sample.xdb/login", url.Values{"password": {"bad"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "dblogin.error.password") {
		t.Fatalf("wrong db password: %s", loc)
	}
	// An XCA database is converted first; the session waits for it.
	r, _ = c.PostForm(ts.URL+"/db/sample.xdb/login", url.Values{"password": {"secret"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); loc != "/db/sample.xdb/converting" {
		t.Fatalf("db login redirect %q", loc)
	}
	var sess *http.Cookie
	for _, ck := range r.Cookies() {
		if ck.Name == dbCookie {
			sess = ck
		}
	}
	if sess == nil || sess.Path != "/db/sample.xdb/" || !sess.Secure || !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode {
		t.Fatalf("database cookie %+v", sess)
	}
	r2, _ := c.Get(ts.URL + "/db/sample.xdb/certs")
	if loc := r2.Header.Get("Location"); loc != "/db/sample.xdb/converting" {
		t.Fatalf("before the import has been picked up: %q", loc)
	}
	// The import ends in a session on the new OpenKCA database.
	if loc := finishConversion(t, ts, c, "sample.xdb"); loc != "/db/sample/keys?notice=converted&name=sample.xdb" {
		t.Fatalf("after the import: %q", loc)
	}
	r2, _ = c.Get(ts.URL + "/db/sample/keys?notice=converted&name=sample.xdb")
	if b := body(t, r2); r2.StatusCode != http.StatusOK || !strings.Contains(b, "sample.xdb was imported") {
		t.Fatalf("keys after the import: %d", r2.StatusCode)
	}

	// A second database in parallel.
	r, _ = c.PostForm(ts.URL+"/db/variants.xdb/login", url.Values{"password": {"secret"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); loc != "/db/variants.xdb/converting" {
		t.Fatalf("second db login redirect %q", loc)
	}
	// variants has a key with its own password still in XCA's form
	if loc := finishConversion(t, ts, c, "variants.xdb"); loc != "/db/variants/keys?notice=converted.ownpass&n=1" {
		t.Fatalf("variants conversion: %q", loc)
	}
	for _, dbName := range []string{"sample", "variants"} {
		for _, tab := range append(tabs, "options") {
			r, _ = c.Get(ts.URL + "/db/" + dbName + "/" + tab)
			b := body(t, r)
			if r.StatusCode != http.StatusOK || strings.Contains(b, "[") && regexp.MustCompile(`\[[a-z]+\.[a-z.]+\]`).MatchString(b) {
				t.Errorf("%s/%s: status %d or untranslated key", dbName, tab, r.StatusCode)
			}
		}
	}
	// Every item page renders.
	for id := 1; id <= 23; id++ {
		r, _ = c.Get(ts.URL + "/db/sample/item/" + itoa(id))
		if r.StatusCode != http.StatusOK {
			t.Errorf("item %d: status %d", id, r.StatusCode)
		}
		body(t, r)
	}
	// htmx search returns only rows.
	req, _ := http.NewRequest("GET", ts.URL+"/db/sample/certs?q=alice", nil)
	req.Header.Set("HX-Request", "true")
	req.Header.Set("HX-Target", "rows")
	r, _ = c.Do(req)
	b := body(t, r)
	if strings.Contains(b, "<html") || !strings.Contains(b, "Alice") || strings.Contains(b, "www.example.org") {
		t.Fatalf("htmx fragment: %s", b)
	}
	// Private key check with the database password.
	req, _ = http.NewRequest("POST", ts.URL+"/db/sample/item/4/check-key", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("HX-Request", "true")
	r, _ = c.Do(req)
	if b := body(t, r); !strings.Contains(b, "decrypts and matches") {
		t.Fatalf("key check: %s", b)
	}
	// Server logout ends the database sessions.
	r, _ = c.PostForm(ts.URL+"/logout", url.Values{"csrf": {csrf}})
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout %d", r.StatusCode)
	}
	login(t, ts, c)
	r, _ = c.Get(ts.URL + "/db/sample/certs")
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("database still open after server logout: %d", r.StatusCode)
	}
}

func TestLegacyRefused(t *testing.T) {
	ts, _ := newTestServer(t)
	c := client(t, ts)
	csrf := login(t, ts, c)
	r, _ := c.PostForm(ts.URL+"/db/legacy.xdb/login", url.Values{"password": {"x"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "dblogin.error.unsupported") {
		t.Fatalf("legacy login: %s", loc)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestCreateImportUpgrade(t *testing.T) {
	ts, srv := newTestServer(t)
	c := client(t, ts)
	csrf := login(t, ts, c)

	// Create
	r, _ := c.PostForm(ts.URL+"/", url.Values{"name": {"fresh"}, "password": {"password1"}, "password2": {"password2"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "create.error.mismatch") {
		t.Fatalf("mismatch: %s", loc)
	}
	r, _ = c.PostForm(ts.URL+"/", url.Values{"name": {"fresh"}, "password": {"password1"}, "password2": {"password1"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "notice=created") {
		t.Fatalf("create: %s", loc)
	}
	r, _ = c.PostForm(ts.URL+"/", url.Values{"name": {"fresh"}, "password": {"password1"}, "password2": {"password1"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "create.error.exists") {
		t.Fatalf("duplicate: %s", loc)
	}
	r, _ = c.PostForm(ts.URL+"/db/fresh/login", url.Values{"password": {"password1"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); loc != "/db/fresh/" {
		t.Fatalf("login to new db: %s", loc)
	}

	// Import: the multipart body needs the CSRF header.
	data, _ := os.ReadFile("../../testdata/xdb/sample.xdb")
	upload := func(withToken bool, filename string, content []byte) *http.Response {
		var buf strings.Builder
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("file", filename)
		fw.Write(content)
		mw.Close()
		req, _ := http.NewRequest("POST", ts.URL+"/import", strings.NewReader(buf.String()))
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("HX-Request", "true")
		if withToken {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if r := upload(false, "x.xdb", data); r.StatusCode != http.StatusForbidden {
		t.Fatalf("import without CSRF header: %d", r.StatusCode)
	}
	if r := upload(true, "uploaded.xdb", data); !strings.Contains(r.Header.Get("HX-Redirect"), "notice=imported&name=uploaded") {
		t.Fatalf("import: %s", r.Header.Get("HX-Redirect"))
	}
	legacy, _ := os.ReadFile("../../testdata/xdb/legacy.xdb")
	if r := upload(true, "old.xdb", legacy); !strings.Contains(r.Header.Get("HX-Redirect"), "import.error.legacy") {
		t.Fatalf("legacy import: %s", r.Header.Get("HX-Redirect"))
	}

	// Login to the uploaded XCA file imports it and deletes the .xdb.
	r, _ = c.PostForm(ts.URL+"/db/uploaded.xdb/login", url.Values{"password": {"secret"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); loc != "/db/uploaded.xdb/converting" {
		t.Fatalf("login to imported db: %s", loc)
	}
	finishConversion(t, ts, c, "uploaded.xdb")
	info, _ := srv.store.Lookup(context.Background(), "uploaded")
	if info.Status != store.Supported || info.Schema != db.Schema || info.XCA {
		t.Fatalf("after login: %+v", info)
	}
	if _, err := srv.store.Lookup(context.Background(), "uploaded.xdb"); err == nil {
		t.Fatal("the .xdb file is still there")
	}
}

func TestEditorFlow(t *testing.T) {
	ts, srv := newTestServer(t)
	c := client(t, ts)
	csrf := login(t, ts, c)
	post := func(path string, v url.Values) *http.Response {
		t.Helper()
		v.Set("csrf", csrf)
		r, err := c.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	post("/", url.Values{"name": {"ed"}, "password": {"password1"}, "password2": {"password1"}})
	post("/db/ed/login", url.Values{"password": {"password1"}})
	itemFrom := func(r *http.Response) string {
		t.Helper()
		loc := r.Header.Get("Location")
		if !strings.Contains(loc, "/item/") {
			b := body(t, r)
			if m := regexp.MustCompile(`class="error"[^>]*>([^<]*)`).FindStringSubmatch(b); m != nil {
				t.Fatalf("no redirect to an item: %d %s", r.StatusCode, m[1])
			}
			t.Fatalf("no redirect to an item: %d %q", r.StatusCode, loc)
		}
		return strings.TrimSuffix(strings.Split(strings.Split(loc, "/item/")[1], "?")[0], "/")
	}
	ca := url.Values{"name": {"Web Root"}, "dn.C": {"DE"}, "dn.O": {"Web"}, "dn.CN": {"Web Root"},
		"keymode": {"new"}, "newkey": {"EC:P-256"}, "signer": {"self"}, "hash": {"sha256"},
		"notbefore": {"2026-01-01T00:00"}, "validn": {"10"}, "validunit": {"y"},
		"ca": {"1"}, "bccritical": {"1"}, "subkey": {"1"}, "ku.5": {"1"}, "ku.6": {"1"}, "kucritical": {"1"}}
	// Validate shows a preview without storing anything.
	req, _ := http.NewRequest("POST", ts.URL+"/db/ed/new/cert", strings.NewReader(func() string {
		v := url.Values{}
		for k, x := range ca {
			v[k] = x
		}
		v.Set("action", "validate")
		return v.Encode()
	}()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.Header.Set("X-CSRF-Token", csrf)
	r, _ := c.Do(req)
	if b := body(t, r); !strings.Contains(b, "Basic Constraints") || strings.Contains(b, "<html") {
		t.Fatalf("preview: %s", b)
	}
	rootID := itemFrom(post("/db/ed/new/cert", ca))

	// CSR with a new key, then signed by the root from the request.
	csr := url.Values{"dn.CN": {"svc.example.org"}, "keymode": {"new"}, "newkey": {"RSA:2048"}, "hash": {"sha256"},
		"san": {"DNS:copycn"}, "ku.0": {"1"}, "eku.serverAuth": {"1"}}
	reqID := itemFrom(post("/db/ed/new/request", csr))
	leaf := url.Values{"fromreq": {reqID}, "reqsubject": {"1"}, "copyreqext": {"1"}, "signer": {rootID}, "hash": {"sha256"},
		"notbefore": {"2026-06-01T12:00"}, "validn": {"90"}, "validunit": {"d"}, "ca": {"2"}, "subkey": {"1"}, "authkey": {"1"}}
	leafID := itemFrom(post("/db/ed/new/cert", leaf))
	r, _ = c.Get(ts.URL + "/db/ed/item/" + leafID)
	if b := body(t, r); !strings.Contains(b, "DNS:svc.example.org") || !strings.Contains(b, "Web Root") {
		t.Fatal("leaf page lacks SAN or issuer")
	}

	// Similar certificate page is prefilled.
	r, _ = c.Get(ts.URL + "/db/ed/new/cert?similar=" + rootID)
	if b := body(t, r); !strings.Contains(b, `value="Web Root"`) {
		t.Fatal("similar not prefilled")
	}
	// New key, rename, delete.
	keyID := itemFrom(post("/db/ed/new/key", url.Values{"name": {"spare"}, "type": {"Ed25519"}}))
	post("/db/ed/item/"+keyID+"/rename", url.Values{"name": {"spare2"}, "comment": {"hello"}})
	r = post("/db/ed/item/"+keyID+"/delete", url.Values{"confirm": {"1"}})
	if loc := r.Header.Get("Location"); !strings.HasSuffix(loc, "/keys?notice=deleted") {
		t.Fatalf("delete redirect %s", loc)
	}
	// Mandatory subject entry from the options.
	opts := url.Values{"default_hash": {"sha384"}, "mandatory_dn": {"O"}, "explicit_dn": {"C,O,CN"}, "string_opt": {"MASK:0x2002"},
		"serial_len": {"128"}, "cert_expiry.n": {"30"}, "cert_expiry.u": {"D"}, "ical_expiry.n": {"1"}, "ical_expiry.u": {"W"},
		"pkcs12_enc_algo": {"AES-256-CBC"}, "pkcs12_iterations": {"1000"}, "backup_keep": {"5"}, "backup_days": {"30"},
		"crl_days_root": {"180"}, "crl_days_sub": {"7"}}
	if loc := post("/db/ed/options", opts).Header.Get("Location"); !strings.Contains(loc, "error=options.error.value&key=pkcs12_iterations") {
		t.Fatalf("pkcs12_iterations below the minimum: %s", loc)
	}
	opts.Set("pkcs12_iterations", "300000")
	opts.Set("backup_keep", "0")
	if loc := post("/db/ed/options", opts).Header.Get("Location"); !strings.Contains(loc, "key=backup_keep") {
		t.Fatalf("backup_keep 0: %s", loc)
	}
	opts.Set("backup_keep", "5")
	if loc := post("/db/ed/options", opts).Header.Get("Location"); !strings.Contains(loc, "notice=saved") {
		t.Fatalf("options: %s", loc)
	}
	if r, _ := c.Get(ts.URL + "/db/ed/options"); !strings.Contains(body(t, r), `name="pkcs12_iterations" value="300000" min="2048" max="10000000"`) {
		t.Fatal("pkcs12_iterations not shown")
	}
	r = post("/db/ed/new/cert", url.Values{"dn.CN": {"no org"}, "keymode": {"new"}, "newkey": {"EC:P-256"}, "signer": {rootID},
		"hash": {"sha384"}, "notbefore": {"2026-01-01T00:00"}, "validn": {"1"}, "validunit": {"y"}})
	if r.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body(t, r), "mandatory subject entry O") {
		t.Fatal("mandatory_dn not enforced")
	}
	// Unlock methods: a second password, a change, a removal, the cost.
	if loc := post("/db/ed/methods/password", url.Values{"label": {"Second"}, "password": {"short"}, "password2": {"short"}}).Header.Get("Location"); !strings.Contains(loc, "error=short") {
		t.Fatalf("short password: %s", loc)
	}
	if loc := post("/db/ed/methods/password", url.Values{"label": {"Second"}, "password": {"password2"}, "password2": {"password3"}}).Header.Get("Location"); !strings.Contains(loc, "error=mismatch") {
		t.Fatalf("mismatch: %s", loc)
	}
	if loc := post("/db/ed/methods/password", url.Values{"label": {"Second"}, "password": {"password2"}, "password2": {"password2"}}).Header.Get("Location"); !strings.Contains(loc, "notice=added") {
		t.Fatalf("add password: %s", loc)
	}
	r, _ = c.Get(ts.URL + "/db/ed/methods")
	ids := methodIDRE.FindAllStringSubmatch(body(t, r), -1)
	if len(ids) != 2 {
		t.Fatalf("methods on the page: %v", ids)
	}
	if loc := post("/db/ed/methods/"+ids[0][1]+"/password", url.Values{"password": {"password4"}, "password2": {"password4"}}).Header.Get("Location"); !strings.Contains(loc, "notice=password") {
		t.Fatalf("change password: %s", loc)
	}
	if loc := post("/db/ed/methods/"+ids[1][1]+"/remove", url.Values{}).Header.Get("Location"); !strings.Contains(loc, "notice=removed") {
		t.Fatalf("remove: %s", loc)
	}
	if loc := post("/db/ed/methods/"+ids[0][1]+"/remove", url.Values{}).Header.Get("Location"); !strings.Contains(loc, "error=last") {
		t.Fatalf("remove the last password: %s", loc)
	}
	if loc := post("/db/ed/methods/kdf", url.Values{"kdf_memory": {"100"}, "kdf_time": {"1"}}).Header.Get("Location"); !strings.Contains(loc, "error=kdf") {
		t.Fatalf("unoffered memory cost: %s", loc)
	}
	if loc := post("/db/ed/methods/kdf", url.Values{"kdf_memory": {"64"}, "kdf_time": {"1"}}).Header.Get("Location"); !strings.Contains(loc, "notice=kdf") {
		t.Fatalf("cost: %s", loc)
	}
	r, _ = c.Get(ts.URL + "/db/ed/methods")
	if b := body(t, r); !strings.Contains(b, `<option value="64" selected>`) || !strings.Contains(b, "no backup code yet") {
		t.Fatal("methods page after the changes")
	}
	if r, _ := c.Get(ts.URL + "/db/ed/password"); r.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("old password page: %d", r.StatusCode)
	}
	r = post("/db/ed/item/"+rootID+"/to-request", url.Values{})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "notice=created") {
		t.Fatalf("to-request after password change: %s", loc)
	}
	// after a password change and a removal only the backup of the new state remains
	if b, _ := srv.store.Backups("ed"); len(b) != 1 {
		t.Fatalf("backups after the changes: %v", b)
	}
}

func TestCAPages(t *testing.T) {
	ts, srv := newTestServer(t)
	c := client(t, ts)
	csrf := login(t, ts, c)
	post := func(path string, v url.Values) *http.Response {
		t.Helper()
		v.Set("csrf", csrf)
		r, err := c.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	post("/db/sample.xdb/login", url.Values{"password": {"secret"}})
	finishConversion(t, ts, c, "sample.xdb")
	// www.example.org is item 7, issued by Example Issuing CA (item 5)
	if loc := post("/db/sample/item/7/revoke", url.Values{"reason": {"1"}, "invaldate": {"2026-10-01T00:00"}}).Header.Get("Location"); !strings.Contains(loc, "notice=revoked") {
		t.Fatalf("revoke: %s", loc)
	}
	r, _ := c.Get(ts.URL + "/db/sample/item/5/revocations")
	if b := body(t, r); !strings.Contains(b, "www.example.org") || !strings.Contains(b, "2001") {
		t.Fatal("revocation list")
	}
	if loc := post("/db/sample/item/5/revocations", url.Values{"action": {"add"}, "serial": {"DEAD"}, "reason": {"5"}, "invaldate": {""}}).Header.Get("Location"); !strings.Contains(loc, "rev.error.unknown") {
		t.Fatalf("unknown serial: %s", loc)
	}
	post("/db/sample/item/5/revocations", url.Values{"action": {"delete"}, "serial": {"DEAD"}})
	r, _ = c.Get(ts.URL + "/db/sample/item/5/revocations")
	if b := body(t, r); !strings.Contains(b, "on the CRL") {
		t.Fatal("no CRL status on the revocations page")
	}
	r, _ = c.Get(ts.URL + "/db/sample/item/5/crl")
	if b := body(t, r); !strings.Contains(b, `name="number" value="1"`) {
		t.Fatal("CRL form defaults")
	}
	r = post("/db/sample/item/5/crl", url.Values{"name": {"web CRL"}, "thisupdate": {"2026-10-23T00:00"}, "nextupdate": {"2026-11-23T00:00"},
		"hash": {"sha256"}, "number": {"1"}, "setnumber": {"1"}, "withreason": {"1"}, "authkeyid": {"1"}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "notice=created") {
		t.Fatalf("CRL: %d %s", r.StatusCode, loc)
	}
	post("/db/sample/item/5/ca-properties", url.Values{"crldays": {"14"}, "template": {"21"}})
	r, _ = c.Get(ts.URL + "/db/sample/item/5")
	if b := body(t, r); !strings.Contains(b, `value="14"`) || !strings.Contains(b, ">TLS_server</a>") {
		t.Fatal("CA properties not shown")
	}
	r = post("/db/sample/item/9/renew", url.Values{"notbefore": {"2026-10-23T00:00"}, "notafter": {"2027-10-23T00:00"},
		"revoke": {"1"}, "reason": {"4"}, "invaldate": {"2026-10-23T00:00"}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "notice=created") {
		t.Fatalf("renew: %s", loc)
	}
	r, _ = c.Get(ts.URL + "/db/sample/item/5")
	m := regexp.MustCompile(`class="mono small">([^<]+/ca/sample/[0-9a-f-]{36})</dd>`).FindStringSubmatch(body(t, r))
	if m == nil || !strings.HasPrefix(html.UnescapeString(m[1]), filepath.Join(srv.store.Dir, "ca", "sample")) {
		t.Fatalf("CA folder not shown: %v", m)
	}
	idx, err := os.ReadFile(filepath.Join(html.UnescapeString(m[1]), "index.txt"))
	if err != nil || strings.Count(string(idx), "\nR\t")+boolInt(strings.HasPrefix(string(idx), "R\t")) != 3 {
		t.Fatalf("index file:\n%s %v", idx, err)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestTemplatePages(t *testing.T) {
	ts, _ := newTestServer(t)
	c := client(t, ts)
	csrf := login(t, ts, c)
	post := func(path string, v url.Values) *http.Response {
		t.Helper()
		v.Set("csrf", csrf)
		r, err := c.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	post("/db/sample.xdb/login", url.Values{"password": {"secret"}})
	finishConversion(t, ts, c, "sample.xdb")
	r := post("/db/sample/new/template", url.Values{"name": {"web tmpl"}, "dn.O": {"Web Org"}, "ca": {"2"}, "subkey": {"1"},
		"ku.0": {"1"}, "eku.clientAuth": {"1"}, "san": {"email:copy"}, "validn": {"2"}, "validunit": {"y"},
		"advext": {"certificatePolicies = 1.2.3.4"}})
	loc := r.Header.Get("Location")
	if !strings.Contains(loc, "notice=saved") {
		t.Fatalf("save template: %d %s", r.StatusCode, loc)
	}
	tid := strings.Split(strings.Split(loc, "/item/")[1], "?")[0]
	// Edit page shows the stored values.
	r, _ = c.Get(ts.URL + "/db/sample/item/" + tid + "/edit")
	if b := body(t, r); !strings.Contains(b, `value="Web Org"`) || !strings.Contains(b, "certificatePolicies = 1.2.3.4") {
		t.Fatal("edit page not filled")
	}
	// Applying the template in the certificate editor fills the form.
	r = post("/db/sample/new/cert", url.Values{"action": {"apply-all"}, "template": {tid}, "dn.CN": {"kept?"}})
	b := body(t, r)
	if !strings.Contains(b, `value="Web Org"`) || !strings.Contains(b, `name="eku.clientAuth" value="1" checked`) {
		t.Fatal("apply-all did not fill the editor")
	}
	// The template page links to creating a certificate from it.
	r, _ = c.Get(ts.URL + "/db/sample/new/cert?template=" + tid)
	if b := body(t, r); !strings.Contains(b, "certificatePolicies = 1.2.3.4") {
		t.Fatal("editor from template")
	}
	// Transform a certificate into a template, duplicate it.
	if loc := post("/db/sample/item/7/to-template", url.Values{}).Header.Get("Location"); !strings.Contains(loc, "notice=created") {
		t.Fatalf("to-template: %s", loc)
	}
	if loc := post("/db/sample/item/"+tid+"/duplicate", url.Values{}).Header.Get("Location"); !strings.Contains(loc, "notice=created") {
		t.Fatalf("duplicate: %s", loc)
	}
	// Invalid advanced extensions are reported with their line.
	r = post("/db/sample/new/template", url.Values{"name": {"bad"}, "advext": {"\nfoo = bar"}})
	if r.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body(t, r), "line 2") {
		t.Fatal("bad adv_ext not reported")
	}
	r, _ = c.Get(ts.URL + "/oid?q=2.5.29.17")
	if b := body(t, r); !strings.Contains(b, "subjectAltName") {
		t.Fatal("OID resolver")
	}
}

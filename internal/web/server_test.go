package web

import (
	"context"
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

	"github.com/mailsvb/go-ca/internal/auth"
	"github.com/mailsvb/go-ca/internal/i18n"
	"github.com/mailsvb/go-ca/internal/store"
)

const serverPassword = "serverpass1"

func newTestServer(t *testing.T) (*httptest.Server, *Server) {
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
	srv, err := New(Config{Store: st, PasswordHash: auth.HashPassword([]byte(serverPassword)), Catalog: cat,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
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

func TestServerLoginFlow(t *testing.T) {
	ts, _ := newTestServer(t)
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
	csrf := login(t, ts, c)

	// Database login without the CSRF token is refused.
	r, _ = c.PostForm(ts.URL+"/db/sample/login", url.Values{"password": {"secret"}})
	if r.StatusCode != http.StatusForbidden {
		t.Fatalf("db login without CSRF: %d", r.StatusCode)
	}
	r, _ = c.PostForm(ts.URL+"/db/sample/login", url.Values{"password": {"bad"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "dblogin.error.password") {
		t.Fatalf("wrong db password: %s", loc)
	}
	r, _ = c.PostForm(ts.URL+"/db/sample/login", url.Values{"password": {"secret"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); loc != "/db/sample/" {
		t.Fatalf("db login redirect %q", loc)
	}
	var sess *http.Cookie
	for _, ck := range r.Cookies() {
		if ck.Name == dbCookie {
			sess = ck
		}
	}
	if sess == nil || sess.Path != "/db/sample/" || !sess.Secure || !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode {
		t.Fatalf("database cookie %+v", sess)
	}

	// A second database in parallel.
	r, _ = c.PostForm(ts.URL+"/db/variants/login", url.Values{"password": {"secret"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); loc != "/db/variants/" {
		t.Fatalf("second db login redirect %q", loc)
	}
	for _, db := range []string{"sample", "variants"} {
		for _, tab := range append(tabs, "options") {
			r, _ = c.Get(ts.URL + "/db/" + db + "/" + tab)
			b := body(t, r)
			if r.StatusCode != http.StatusOK || strings.Contains(b, "[") && regexp.MustCompile(`\[[a-z]+\.[a-z.]+\]`).MatchString(b) {
				t.Errorf("%s/%s: status %d or untranslated key", db, tab, r.StatusCode)
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
	r, _ := c.PostForm(ts.URL+"/db/legacy/login", url.Values{"password": {"x"}, "csrf": {csrf}})
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
	r, _ := c.PostForm(ts.URL+"/", url.Values{"name": {"fresh"}, "password": {"pw1"}, "password2": {"pw2"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "create.error.mismatch") {
		t.Fatalf("mismatch: %s", loc)
	}
	r, _ = c.PostForm(ts.URL+"/", url.Values{"name": {"fresh"}, "password": {"pw1"}, "password2": {"pw1"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "notice=created") {
		t.Fatalf("create: %s", loc)
	}
	r, _ = c.PostForm(ts.URL+"/", url.Values{"name": {"fresh"}, "password": {"pw1"}, "password2": {"pw1"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "create.error.exists") {
		t.Fatalf("duplicate: %s", loc)
	}
	r, _ = c.PostForm(ts.URL+"/db/fresh/login", url.Values{"password": {"pw1"}, "csrf": {csrf}})
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

	// Login to the schema 7 import upgrades it after a backup.
	r, _ = c.PostForm(ts.URL+"/db/uploaded/login", url.Values{"password": {"secret"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); loc != "/db/uploaded/" {
		t.Fatalf("login to imported db: %s", loc)
	}
	info, _ := srv.store.Lookup(context.Background(), "uploaded")
	if info.Status != store.Supported || info.Schema != 8 {
		t.Fatalf("after login: %+v", info)
	}
	if b, _ := srv.store.Backups("uploaded"); len(b) != 1 {
		t.Fatalf("backups: %v", b)
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
	post("/", url.Values{"name": {"ed"}, "password": {"pw"}, "password2": {"pw"}})
	post("/db/ed/login", url.Values{"password": {"pw"}})
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
		"pkcs12_enc_algo": {"aes256"}}
	if loc := post("/db/ed/options", opts).Header.Get("Location"); !strings.Contains(loc, "notice=saved") {
		t.Fatalf("options: %s", loc)
	}
	r = post("/db/ed/new/cert", url.Values{"dn.CN": {"no org"}, "keymode": {"new"}, "newkey": {"EC:P-256"}, "signer": {rootID},
		"hash": {"sha384"}, "notbefore": {"2026-01-01T00:00"}, "validn": {"1"}, "validunit": {"y"}})
	if r.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body(t, r), "mandatory subject entry O") {
		t.Fatal("mandatory_dn not enforced")
	}
	// Database password change keeps this session working.
	r = post("/db/ed/password", url.Values{"old": {"pw"}, "new": {"pw2"}, "new2": {"pw2"}})
	if !strings.Contains(body(t, r), "was changed") {
		t.Fatal("password change")
	}
	r = post("/db/ed/item/"+rootID+"/to-request", url.Values{})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "notice=created") {
		t.Fatalf("to-request after password change: %s", loc)
	}
	if b, _ := srv.store.Backups("ed"); len(b) != 1 {
		t.Fatalf("backup before password change: %v", b)
	}
}

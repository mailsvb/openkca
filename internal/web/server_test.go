package web

import (
	"io"
	"log/slog"
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

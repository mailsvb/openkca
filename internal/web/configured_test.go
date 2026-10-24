package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mailsvb/openkca/internal/background"
	"github.com/mailsvb/openkca/internal/store"
	"github.com/mailsvb/openkca/internal/vault"
)

// TestConfiguredDatabases covers databases from the configuration file:
// listed under their name, one held open in the background (whose
// password cannot be changed in the UI) and one web-only in a subfolder.
func TestConfiguredDatabases(t *testing.T) {
	ctx := context.Background()
	ts, srv := newTestServer(t)
	st := srv.store
	for _, n := range []string{"lab", "archive"} {
		if err := st.Create(ctx, n, []byte("password-"+n), vault.Default); err != nil {
			t.Fatal(err)
		}
	}
	sub := filepath.Join(st.Dir, "old")
	os.MkdirAll(sub, 0o700)
	if err := os.Rename(filepath.Join(st.Dir, "archive.gca"), filepath.Join(sub, "archive.gca")); err != nil {
		t.Fatal(err)
	}
	names, err := st.Configure(ctx, []store.Configured{
		{Label: "Home Lab CA", Path: filepath.Join(st.Dir, "lab.gca"), Background: true},
		{Label: "Old Archive", Path: filepath.Join(sub, "archive.gca")},
	})
	if err != nil {
		t.Fatal(err)
	}
	bg, err := background.Open(ctx, st, names, map[string][]byte{"lab": []byte("password-lab")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bg.Close)

	c := client(t, ts)
	csrf := login(t, ts, c)
	r, _ := c.Get(ts.URL + "/")
	page := body(t, r)
	for _, want := range []string{"Home Lab CA", "Old Archive", "badge-background", "/db/lab/login", "/db/archive/login"} {
		if !strings.Contains(page, want) {
			t.Errorf("databases page lacks %q", want)
		}
	}
	if strings.Index(page, "Home Lab CA") > strings.Index(page, "sample.xdb") {
		t.Error("configured databases are not listed first")
	}

	// The web login still needs the database password.
	r, _ = c.PostForm(ts.URL+"/db/lab/login", url.Values{"password": {"wrong"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "dblogin.error.password") {
		t.Fatalf("wrong password: %s", loc)
	}
	r, _ = c.PostForm(ts.URL+"/db/lab/login", url.Values{"password": {"password-lab"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); loc != "/db/lab/" {
		t.Fatalf("login: %s", loc)
	}
	r, _ = c.Get(ts.URL + "/db/lab/certs")
	if p := body(t, r); !strings.Contains(p, `class="dbname" title="lab">Home Lab CA<`) {
		t.Fatal("the header does not show the configured name")
	}
	r, _ = c.Get(ts.URL + "/db/lab/options")
	if p := body(t, r); strings.Contains(p, "/db/lab/password") {
		t.Fatal("options link to the password page")
	}
	r, _ = c.Get(ts.URL + "/db/lab/password")
	if p := body(t, r); strings.Contains(p, `name="new"`) || !strings.Contains(p, "configuration file") {
		t.Fatal("the password page offers a change")
	}
	r, _ = c.PostForm(ts.URL+"/db/lab/password", url.Values{"old": {"password-lab"}, "new": {"password-new"},
		"new2": {"password-new"}, "csrf": {csrf}})
	body(t, r)
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("password change: %d", r.StatusCode)
	}
	if _, err := bg.Get("lab").Handle.Unlock(ctx, []byte("password-lab")); err != nil {
		t.Fatalf("the password changed: %v", err)
	}
	// Logging out of the web session leaves the background database open.
	r, _ = c.PostForm(ts.URL+"/db/lab/logout", url.Values{"csrf": {csrf}})
	body(t, r)
	if bg.Get("lab").Keyring() == nil {
		t.Fatal("logout closed the background database")
	}
	if _, err := bg.Get("lab").Handle.Snapshot(ctx); err != nil {
		t.Fatalf("background handle after logout: %v", err)
	}

	// A web-only configured database in a subfolder: password change allowed.
	r, _ = c.PostForm(ts.URL+"/db/archive/login", url.Values{"password": {"password-archive"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); loc != "/db/archive/" {
		t.Fatalf("login archive: %s", loc)
	}
	r, _ = c.Get(ts.URL + "/db/archive/options")
	if p := body(t, r); !strings.Contains(p, "/db/archive/password") {
		t.Fatal("no password link for a web-only database")
	}
	// Its name is taken for new databases.
	r, _ = c.PostForm(ts.URL+"/", url.Values{"name": {"archive"}, "password": {"password1"}, "password2": {"password1"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "create.error.exists") {
		t.Fatalf("create over configured name: %s", loc)
	}
}

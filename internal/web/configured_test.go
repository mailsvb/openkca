package web

import (
	"context"
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
	if err := os.Rename(filepath.Join(st.Dir, "archive.okca"), filepath.Join(sub, "archive.okca")); err != nil {
		t.Fatal(err)
	}
	names, err := st.Configure(ctx, []store.Configured{
		{Label: "Home Lab CA", Path: filepath.Join(st.Dir, "lab.okca"), Background: true},
		{Label: "Old Archive", Path: filepath.Join(sub, "archive.okca")},
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
	if p := body(t, r); !strings.Contains(p, "/db/lab/methods") {
		t.Fatal("options do not link to the unlock methods")
	}
	// The password the configuration file uses can be neither changed nor
	// removed, and the data key not replaced.
	cfgID := bg.Get("lab").Handle.ConfiguredMethod()
	r, _ = c.Get(ts.URL + "/db/lab/methods")
	if p := body(t, r); cfgID == "" || strings.Contains(p, "/methods/"+cfgID+"/password") ||
		strings.Contains(p, "/methods/"+cfgID+"/remove") || !strings.Contains(p, "configuration file") ||
		strings.Contains(p, "/db/lab/methods/rekey") {
		t.Fatal("the configured password can be changed")
	}
	r, _ = c.PostForm(ts.URL+"/db/lab/methods/"+cfgID+"/password", url.Values{"password": {"password-new"},
		"password2": {"password-new"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "error=configured") {
		t.Fatalf("password change: %s", loc)
	}
	r, _ = c.PostForm(ts.URL+"/db/lab/methods/rekey", url.Values{"password": {"password-lab"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "error=background") {
		t.Fatalf("data key replaced: %s", loc)
	}
	if _, err := bg.Get("lab").Handle.Unlock(ctx, []byte("password-lab")); err != nil {
		t.Fatalf("the password changed: %v", err)
	}
	// Another password can still be added and removed.
	r, _ = c.PostForm(ts.URL+"/db/lab/methods/password", url.Values{"label": {"Second"}, "password": {"password-two"},
		"password2": {"password-two"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "notice=added") {
		t.Fatalf("add password: %s", loc)
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
	r, _ = c.Get(ts.URL + "/db/archive/methods")
	if p := body(t, r); !strings.Contains(p, "/db/archive/methods/rekey") {
		t.Fatal("no data key replacement for a web-only database")
	}
	// Its name is taken for new databases.
	r, _ = c.PostForm(ts.URL+"/", url.Values{"name": {"archive"}, "password": {"password1"}, "password2": {"password1"}, "csrf": {csrf}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "create.error.exists") {
		t.Fatalf("create over configured name: %s", loc)
	}
}

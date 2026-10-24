package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestTrashAuditPages(t *testing.T) {
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
	get := func(path string) string {
		t.Helper()
		r, err := c.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b := body(t, r)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", path, r.StatusCode)
		}
		if regexp.MustCompile(`\[[a-z]+\.[a-z_.]+\]`).MatchString(b) {
			t.Fatalf("%s: untranslated key in %s", path, regexp.MustCompile(`\[[a-z]+\.[a-z_.]+\]`).FindString(b))
		}
		return b
	}
	post("/", url.Values{"name": {"tr"}, "password": {"password1"}, "password2": {"password1"}})
	post("/db/tr/login", url.Values{"password": {"password1"}})
	r := post("/db/tr/new/key", url.Values{"name": {"spare"}, "type": {"EC:P-256"}})
	loc := r.Header.Get("Location")
	id := loc[strings.LastIndex(loc, "/")+1:]
	if i := strings.Index(id, "?"); i >= 0 {
		id = id[:i]
	}
	if b := get("/db/tr/trash"); !strings.Contains(b, "The trash is empty") {
		t.Fatal("trash not empty")
	}
	r = post("/db/tr/item/"+id+"/delete", url.Values{"confirm": {"1"}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "notice=deleted") {
		t.Fatalf("delete: %s", loc)
	}
	if b := get("/db/tr/keys"); strings.Contains(b, ">spare<") || !strings.Contains(b, "1 item in the trash") {
		t.Fatal("trashed key still listed, or no trash line")
	}
	if b := get("/db/tr/trash"); !strings.Contains(b, "spare") {
		t.Fatal("key not in the trash")
	}
	r = post("/db/tr/trash/"+id+"/restore", url.Values{})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "notice=restored") {
		t.Fatalf("restore: %s", loc)
	}
	if b := get("/db/tr/keys"); !strings.Contains(b, "spare") {
		t.Fatal("restored key not listed")
	}
	post("/db/tr/item/"+id+"/delete", url.Values{"confirm": {"1"}})
	r = post("/db/tr/trash/empty", url.Values{"confirm": {"1"}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "notice=purged&n=1") {
		t.Fatalf("empty: %s", loc)
	}
	b := get("/db/tr/audit")
	for _, a := range []string{"Database created", "Database opened", "Key generated", "Moved to the trash", "Restored from the trash", "Deleted for good", "127.0.0.1"} {
		if !strings.Contains(b, a) {
			t.Errorf("log lacks %q", a)
		}
	}
	// a wrong database password is logged too
	post("/db/tr/logout", url.Values{})
	post("/db/tr/login", url.Values{"password": {"wrong password"}})
	post("/db/tr/login", url.Values{"password": {"password1"}})
	if b := get("/db/tr/audit"); !strings.Contains(b, "Wrong database password") {
		t.Error("failed login not logged")
	}
}

// Keys with their own password still in XCA's form are pointed out.
func TestLegacyKeyBanner(t *testing.T) {
	ts, _ := newTestServer(t)
	c := client(t, ts)
	csrf := login(t, ts, c)
	c.PostForm(ts.URL+"/db/variants.xdb/login", url.Values{"password": {"secret"}, "csrf": {csrf}})
	finishConversion(t, ts, c, "variants.xdb")
	r, _ := c.Get(ts.URL + "/db/variants/keys")
	b := body(t, r)
	if !strings.Contains(b, "1 key with its own password is still encrypted as XCA stored it") {
		t.Fatal("no banner")
	}
	r, _ = c.Get(ts.URL + "/db/variants/keys?legacy=1")
	b = body(t, r)
	if !strings.Contains(b, ">mail<") || strings.Contains(b, ">root<") {
		t.Fatal("legacy filter")
	}
	// checking the key with its password re-encrypts it
	req, _ := http.NewRequest("POST", ts.URL+"/db/variants/item/10/check-key", strings.NewReader(url.Values{"password": {"mailpass"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.Header.Set("X-CSRF-Token", csrf)
	r, _ = c.Do(req)
	if b := body(t, r); !strings.Contains(b, "decrypts and matches") {
		t.Fatalf("check: %s", b)
	}
	r, _ = c.Get(ts.URL + "/db/variants/keys")
	if b := body(t, r); strings.Contains(b, "still encrypted as XCA stored") {
		t.Fatal("banner after the upgrade")
	}
	r, _ = c.Get(ts.URL + "/db/variants/item/10")
	if b := body(t, r); !strings.Contains(b, "Key re-encrypted") {
		t.Fatal("item history lacks the upgrade")
	}
}

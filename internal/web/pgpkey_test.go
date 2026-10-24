package web

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/mailsvb/go-ca/internal/codec"
)

func TestPGPKeyPages(t *testing.T) {
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
	post("/", url.Values{"name": {"pk"}, "password": {"password1"}, "password2": {"password1"}})
	post("/db/pk/login", url.Values{"password": {"password1"}})
	r, _ := c.Get(ts.URL + "/db/pk/keys")
	if b := body(t, r); !strings.Contains(b, `href="/db/pk/new/pgpkey"`) {
		t.Fatal("no New OpenPGP key button")
	}
	r, _ = c.Get(ts.URL + "/db/pk/new/pgpkey")
	if b := body(t, r); r.StatusCode != 200 || !strings.Contains(b, `value="Ed25519" selected`) {
		t.Fatalf("new OpenPGP key page: %d", r.StatusCode)
	}
	form := url.Values{"type": {"Ed25519"}, "version": {"4"}, "expiry": {"2y"}, "subkey": {"1"}}
	bad := url.Values{"type": {"Ed25519"}, "version": {"5"}, "expiry": {"2y"}, "uids": {"A <a@x>"}}
	if r := post("/db/pk/new/pgpkey", bad); r.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("version 5 accepted: %d", r.StatusCode)
	}
	if r := post("/db/pk/new/pgpkey", form); r.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("no user ID accepted: %d", r.StatusCode)
	}
	form.Set("uids", "Alice <alice@example.org>\n\nAlice (work) <a@example.com>\n")
	r = post("/db/pk/new/pgpkey", form)
	loc := r.Header.Get("Location")
	if !strings.HasSuffix(loc, "/pgp?notice=created") {
		t.Fatalf("create: %d %s", r.StatusCode, loc)
	}
	page := strings.TrimSuffix(loc, "?notice=created")
	r, _ = c.Get(ts.URL + loc)
	b := body(t, r)
	for _, want := range []string{"BEGIN PGP PUBLIC KEY BLOCK", "Alice (work) &lt;a@example.com&gt;", "EdDSA Ed25519", "ECDH Curve25519",
		"Alice &lt;alice@example.org&gt; (encryption)", "The OpenPGP key was created."} {
		if !strings.Contains(b, want) {
			t.Fatalf("PGP page lacks %q:\n%s", want, b)
		}
	}
	item := strings.TrimSuffix(page, "/pgp")
	r, _ = c.Get(ts.URL + item)
	if b := body(t, r); !strings.Contains(b, `href="`+page+`"`) {
		t.Fatal("no OpenPGP key action on the item page")
	}

	download := func(v url.Values) []byte {
		t.Helper()
		r := post(page, v)
		data, _ := io.ReadAll(r.Body)
		if r.StatusCode != 200 {
			t.Fatalf("download %v: %d\n%s", v, r.StatusCode, data)
		}
		return data
	}
	data := download(url.Values{"format": {"bundle"}, "password": {"pp"}, "password2": {"pp"}})
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range z.File {
		rc, _ := f.Open()
		files[f.Name], _ = io.ReadAll(rc)
		rc.Close()
	}
	sec := files["Alice_alice@example.org_.secret.asc"]
	ents, _, _, wrong := codec.ReadPGP(sec, func() ([]byte, bool) { return []byte("pp"), true })
	if len(ents) != 1 || wrong || ents[0].Private[0] == nil || ents[0].Private[1] == nil || len(files) != 3 {
		t.Fatalf("bundle of %d files: %d keys", len(files), len(ents))
	}
	if pub := download(url.Values{"format": {"public"}}); !bytes.HasPrefix(pub, []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		t.Fatalf("public: %q", pub)
	}
	if r := post(page, url.Values{"format": {"secret"}, "password": {"a"}, "password2": {"b"}}); r.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("passphrase mismatch: %d", r.StatusCode)
	}

	// an SSH key becomes a v6 OpenPGP key and gets another SSH key as
	// authentication subkey
	r = post("/db/pk/new/sshkey", url.Values{"name": {"laptop"}, "type": {"Ed25519"}})
	sshItem := strings.TrimSuffix(r.Header.Get("Location"), "/ssh?notice=created")
	r = post("/db/pk/new/sshkey", url.Values{"name": {"auth"}, "type": {"EC:P-256"}})
	authItem := strings.TrimSuffix(r.Header.Get("Location"), "/ssh?notice=created")
	authID := authItem[strings.LastIndexByte(authItem, '/')+1:]
	r, _ = c.Get(ts.URL + sshItem + "/pgp")
	if b := body(t, r); !strings.Contains(b, "Create OpenPGP key") {
		t.Fatalf("no create form:\n%s", b)
	}
	r = post(sshItem+"/pgp/create", url.Values{"uids": {"Laptop <me@laptop>"}, "version": {"6"}, "expiry": {"never"}})
	if loc := r.Header.Get("Location"); !strings.HasSuffix(loc, "/pgp?notice=created") {
		t.Fatalf("create from SSH key: %d %s", r.StatusCode, loc)
	}
	r = post(sshItem+"/pgp/subkey", url.Values{"key": {authID}, "usage": {"A"}})
	if loc := r.Header.Get("Location"); !strings.HasSuffix(loc, "/pgp?notice=subkey") {
		t.Fatalf("add subkey: %d %s %s", r.StatusCode, loc, body(t, r))
	}
	r, _ = c.Get(ts.URL + sshItem + "/pgp")
	if b := body(t, r); !strings.Contains(b, "authenticate") || !strings.Contains(b, "Ed25519 · OpenPGP v6") || !strings.Contains(b, ">auth</a>") {
		t.Fatalf("v6 page:\n%s", b)
	}
	r, _ = c.Get(ts.URL + authItem + "/pgp")
	if b := body(t, r); !strings.Contains(b, "This key is a subkey of the OpenPGP key") {
		t.Fatalf("subkey page:\n%s", b)
	}
	if r := post(sshItem+"/pgp/subkey", url.Values{"key": {authID}, "usage": {"A"}}); r.StatusCode != http.StatusNotFound &&
		r.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("same subkey twice: %d", r.StatusCode)
	}
	if r := post(sshItem+"/pgp/remove", url.Values{}); r.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("remove without confirmation: %d", r.StatusCode)
	}
	r = post(sshItem+"/pgp/remove", url.Values{"confirm": {"1"}})
	if loc := r.Header.Get("Location"); !strings.HasSuffix(loc, "/pgp?notice=removed") {
		t.Fatalf("remove: %d %s", r.StatusCode, loc)
	}
	if r, _ := c.Get(ts.URL + "/db/pk/item/999/pgp"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown key: %d", r.StatusCode)
	}
}

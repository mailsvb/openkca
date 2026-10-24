package web

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHKeyPages(t *testing.T) {
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
	post("/", url.Values{"name": {"sk"}, "password": {"password1"}, "password2": {"password1"}})
	post("/db/sk/login", url.Values{"password": {"password1"}})
	r, _ := c.Get(ts.URL + "/db/sk/keys")
	if b := body(t, r); !strings.Contains(b, `href="/db/sk/new/sshkey"`) {
		t.Fatal("no New SSH key button")
	}
	r, _ = c.Get(ts.URL + "/db/sk/new/sshkey")
	if b := body(t, r); r.StatusCode != 200 || !strings.Contains(b, `value="Ed25519" selected`) {
		t.Fatalf("new SSH key page: %d", r.StatusCode)
	}
	if r := post("/db/sk/new/sshkey", url.Values{"name": {"x"}, "type": {"RSA:2048"}}); r.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("type not offered for SSH keys: %d", r.StatusCode)
	}
	r = post("/db/sk/new/sshkey", url.Values{"name": {"laptop"}, "type": {"Ed25519"}, "comment": {" me@laptop "}})
	loc := r.Header.Get("Location")
	if !strings.HasSuffix(loc, "/ssh?notice=created") {
		t.Fatalf("create: %d %s", r.StatusCode, loc)
	}
	page := strings.TrimSuffix(loc, "?notice=created")
	r, _ = c.Get(ts.URL + loc)
	b := body(t, r)
	if !strings.Contains(b, "ssh-ed25519 AAAA") || !strings.Contains(b, " me@laptop</textarea>") || !strings.Contains(b, "SHA256:") || !strings.Contains(b, "Created.") {
		t.Fatalf("SSH page:\n%s", b)
	}
	item := strings.TrimSuffix(page, "/ssh")
	r, _ = c.Get(ts.URL + item)
	if b := body(t, r); !strings.Contains(b, `href="`+page+`"`) {
		t.Fatal("no SSH key action on the item page")
	}

	unzip := func(r *http.Response) map[string][]byte {
		t.Helper()
		data, _ := io.ReadAll(r.Body)
		if ct := r.Header.Get("Content-Type"); ct != "application/zip" {
			t.Fatalf("download: %d %s\n%s", r.StatusCode, ct, data)
		}
		z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string][]byte{}
		for _, f := range z.File {
			rc, _ := f.Open()
			out[f.Name], _ = io.ReadAll(rc)
			rc.Close()
		}
		return out
	}
	files := unzip(post(page, url.Values{"format": {"openssh"}}))
	if _, err := ssh.ParseRawPrivateKey(files["laptop"]); err != nil {
		t.Fatalf("OpenSSH private: %v %v", err, files)
	}
	if pub, comment, _, _, err := ssh.ParseAuthorizedKey(files["laptop.pub"]); err != nil || comment != "me@laptop" || pub.Type() != "ssh-ed25519" {
		t.Fatalf("OpenSSH public: %v %q", err, comment)
	}
	files = unzip(post(page, url.Values{"format": {"putty"}, "password": {"pp"}, "password2": {"pp"}}))
	if !bytes.HasPrefix(files["laptop.ppk"], []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: me@laptop\n")) ||
		!bytes.HasPrefix(files["laptop.pub"], []byte("---- BEGIN SSH2 PUBLIC KEY ----\n")) {
		t.Fatalf("PuTTY pair: %q", files)
	}
	files = unzip(post(page, url.Values{"format": {"putty2"}}))
	if !bytes.HasPrefix(files["laptop.ppk"], []byte("PuTTY-User-Key-File-2: ssh-ed25519\nEncryption: none\n")) {
		t.Fatalf("PuTTY 2: %q", files["laptop.ppk"])
	}
	if r := post(page, url.Values{"format": {"openssh"}, "password": {"a"}, "password2": {"b"}}); r.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("passphrase mismatch: %d", r.StatusCode)
	}
	// only one key was created
	r, _ = c.Get(ts.URL + "/db/sk/keys")
	if b := body(t, r); strings.Count(b, ">laptop<") != 1 {
		t.Fatalf("keys list:\n%s", b)
	}
	if r, _ := c.Get(ts.URL + "/db/sk/item/999/ssh"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown key: %d", r.StatusCode)
	}
}

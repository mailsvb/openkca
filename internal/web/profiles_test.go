package web

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// TestProfiles creates a hierarchy through the purpose forms and checks
// what the profiles put into the certificates.
func TestProfiles(t *testing.T) {
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
		if r.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d", path, r.StatusCode)
		}
		return html.UnescapeString(body(t, r))
	}
	created := func(r *http.Response) string {
		t.Helper()
		loc := r.Header.Get("Location")
		if !strings.Contains(loc, "/item/") {
			t.Fatalf("not created: %d %q %s", r.StatusCode, loc, body(t, r))
		}
		return strings.Split(strings.Split(loc, "/item/")[1], "?")[0]
	}
	post("/", url.Values{"name": {"p"}, "password": {"password1"}, "password2": {"password1"}})
	post("/db/p/login", url.Values{"password": {"password1"}})

	page := get("/db/p/new")
	for _, want := range []string{"/db/p/create/root-ca", "/db/p/create/tls-server", "/db/p/new/sshkey", "/db/p/new/pgpkey",
		"ECDSA P-384 · 20 years · CA, pathlen 1", "ECDSA P-256 · 397 days · serverAuth"} {
		if !strings.Contains(page, want) {
			t.Errorf("purpose page lacks %q", want)
		}
	}

	// the summary follows the form
	r := post("/db/p/create/tls-server", url.Values{"action": {"summary"}, "hosts": {"a.example.org 10.1.2.3"}, "issuer": {"self"}})
	sum := html.UnescapeString(body(t, r))
	for _, want := range []string{"CN=a.example.org", "DNS:a.example.org", "IP:10.1.2.3", "random, 128 bit", "ECDSA with SHA-256 (from the key)"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary lacks %q", want)
		}
	}

	root := created(post("/db/p/create/root-ca", url.Values{"action": {"create"}, "cn": {"P Root"}, "org": {"P GmbH"}, "country": {"de"}}))
	b := get("/db/p/item/" + root)
	for _, want := range []string{"ECDSA-SHA384", "CA:TRUE", "pathlen:1", "Certificate Sign", "C=DE"} {
		if !strings.Contains(b, want) {
			t.Errorf("root lacks %q", want)
		}
	}
	if serial := regexp.MustCompile(`[0-9A-F]{32}`).FindString(b); serial == "" {
		t.Error("root has no 128 bit serial")
	}

	// an intermediate needs a CA
	if r := post("/db/p/create/intermediate-ca", url.Values{"action": {"create"}, "cn": {"Sub"}, "issuer": {"self"}}); r.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("self-signed intermediate: %d", r.StatusCode)
	}
	sub := created(post("/db/p/create/intermediate-ca", url.Values{"action": {"create"}, "cn": {"P Sub"}, "issuer": {root}}))
	if b := get("/db/p/item/" + sub); !strings.Contains(b, "pathlen:0") || !strings.Contains(b, "ECDSA-SHA384") {
		t.Error("intermediate lacks pathlen 0 or the root's SHA-384 signature")
	}

	// required fields
	if r := post("/db/p/create/tls-server", url.Values{"action": {"create"}, "issuer": {sub}}); r.StatusCode != http.StatusUnprocessableEntity ||
		!strings.Contains(body(t, r), "Enter at least one host name") {
		t.Error("TLS server without host names accepted")
	}
	if r := post("/db/p/create/smime", url.Values{"action": {"create"}, "email": {"no address"}, "issuer": {sub}}); r.StatusCode != http.StatusUnprocessableEntity {
		t.Error("S/MIME with a bad address accepted")
	}

	// RSA keys also encipher
	tls := created(post("/db/p/create/tls-server", url.Values{"action": {"create"}, "hosts": {"www.example.org\nexample.org"},
		"issuer": {sub}, "validity": {"90d"}, "newkey": {"RSA:2048"}}))
	b = get("/db/p/item/" + tls)
	for _, want := range []string{"TLS Web Server Authentication", "Key Encipherment", "DNS:example.org", "ECDSA-SHA256", "CA:FALSE"} {
		if !strings.Contains(b, want) {
			t.Errorf("TLS server lacks %q", want)
		}
	}
	mail := created(post("/db/p/create/smime", url.Values{"action": {"create"}, "email": {"a@example.org"}, "issuer": {sub}}))
	if b := get("/db/p/item/" + mail); !strings.Contains(b, "email:a@example.org") || !strings.Contains(b, "E-mail Protection") {
		t.Error("S/MIME certificate lacks address or usage")
	}

	// the full editor takes the form over, with its purpose
	r = post("/db/p/create/tls-server", url.Values{"action": {"editor"}, "hosts": {"x.example.org"}, "issuer": {sub}, "validity": {"90d"}})
	ed := html.UnescapeString(body(t, r))
	for _, want := range []string{`value="p:tls-server" selected`, `value="DNS:x.example.org"`, "validity (purpose: 397 days)", `name="hash"`} {
		if !strings.Contains(ed, want) {
			t.Errorf("editor from the form lacks %q", want)
		}
	}
	if !strings.Contains(ed, `class="card expert" hidden`) {
		t.Error("expert fields shown without the option")
	}
	// applying a purpose keeps the subject
	r = post("/db/p/new/cert", url.Values{"action": {"apply-ext"}, "template": {"p:code-signing"}, "dn.CN": {"kept"}, "keymode": {"new"}})
	ed = html.UnescapeString(body(t, r))
	if !strings.Contains(ed, `value="kept"`) || !strings.Contains(ed, `name="eku.codeSigning" value="1" checked`) {
		t.Error("applying a purpose lost the subject or did not set the usage")
	}
	// the expert switch in the editor keeps the form
	r = post("/db/p/new/cert", url.Values{"action": {"expert-on"}, "dn.CN": {"still"}})
	ed = html.UnescapeString(body(t, r))
	if !strings.Contains(ed, `value="still"`) || strings.Contains(ed, `class="card expert" hidden`) {
		t.Error("expert switch lost the form or did not show the fields")
	}

	// CA and request pages lead to the purposes
	if b := get("/db/p/new?signer=" + sub); strings.Contains(b, "create/root-ca") || !strings.Contains(b, "create/tls-server?signer="+sub) {
		t.Error("issuing from a CA offers a root CA or loses the CA")
	}
}

func TestBackPath(t *testing.T) {
	for in, want := range map[string]string{
		"/db/x/new/key":       "/db/x/new/key",
		"https://evil/db/x/":  "/db/x/",
		"/db/x//evil.example": "/db/x/",
		"/db/y/new":           "/db/x/",
	} {
		if got := backPath(in, "x"); got != want {
			t.Errorf("backPath(%q) = %q, want %q", in, got, want)
		}
	}
}

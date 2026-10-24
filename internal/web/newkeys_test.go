package web

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestNewKeyTypesUI generates keys of the new types through the forms: a
// composite CA, an ML-KEM certificate it signs, an RSA certificate signed
// with PSS, and key pages that show the new attributes.
func TestNewKeyTypesUI(t *testing.T) {
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
		return html.UnescapeString(body(t, r))
	}
	itemFrom := func(r *http.Response) string {
		t.Helper()
		loc := r.Header.Get("Location")
		if !strings.Contains(loc, "/item/") {
			t.Fatalf("no redirect to an item: %d %q %s", r.StatusCode, loc, body(t, r))
		}
		return strings.TrimSuffix(strings.Split(strings.Split(loc, "/item/")[1], "?")[0], "/")
	}
	post("/", url.Values{"name": {"pq"}, "password": {"password1"}, "password2": {"password1"}})
	post("/db/pq/login", url.Values{"password": {"password1"}})

	page := get("/db/pq/new/key")
	for _, want := range []string{`<optgroup label="ML-DSA (post-quantum)">`, `value="Composite:MLDSA87-Ed448-SHAKE256"`,
		`value="EC:brainpoolP512r1"`, `value="ML-KEM:ML-KEM-1024"`, `value="X448"`, `value="RSA-PSS:3072"`} {
		if !strings.Contains(page, want) {
			t.Errorf("new key page lacks %s", want)
		}
	}
	if page := get("/db/pq/new/cert"); !strings.Contains(page, ">SHA-384, RSA keys with PSS<") {
		t.Error("editor lacks the PSS hash choices")
	}
	if page := get("/db/pq/options"); !strings.Contains(page, ">SHA-512, RSA keys with PSS<") {
		t.Error("options lack the PSS hash choices")
	}

	ca := url.Values{"name": {"PQ Root"}, "dn.CN": {"PQ Root"}, "keymode": {"new"}, "newkey": {"Composite:MLDSA65-Ed25519-SHA512"},
		"signer": {"self"}, "hash": {"sha256"}, "notbefore": {"2026-01-01T00:00"}, "validn": {"10"}, "validunit": {"y"},
		"ca": {"1"}, "bccritical": {"1"}, "subkey": {"1"}, "ku.5": {"1"}, "ku.6": {"1"}}
	rootID := itemFrom(post("/db/pq/new/cert", ca))
	root := get("/db/pq/item/" + rootID)
	for _, want := range []string{"MLDSA65-Ed25519-SHA512", "ML-DSA-65 + Ed25519"} {
		if !strings.Contains(root, want) {
			t.Errorf("root page lacks %q", want)
		}
	}

	kem := url.Values{"name": {"kem"}, "dn.CN": {"kem"}, "keymode": {"new"}, "newkey": {"ML-KEM:ML-KEM-768"},
		"signer": {rootID}, "hash": {"sha256"}, "notbefore": {"2026-01-01T00:00"}, "validn": {"1"}, "validunit": {"y"},
		"ca": {"2"}, "subkey": {"1"}, "authkey": {"1"}, "ku.4": {"1"}}
	kemID := itemFrom(post("/db/pq/new/cert", kem))
	if b := get("/db/pq/item/" + kemID); !strings.Contains(b, "ML-KEM-768") || !strings.Contains(b, "PQ Root") {
		t.Error("ML-KEM certificate page lacks key or issuer")
	}

	// a key that cannot sign cannot make a self-signed certificate
	self := url.Values{}
	for k, v := range kem {
		self[k] = v
	}
	self.Set("name", "x448 self")
	self.Set("newkey", "X448")
	self.Set("signer", "self")
	if r := post("/db/pq/new/cert", self); r.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("self-signed X448 certificate: %d", r.StatusCode)
	}

	rsa := url.Values{"name": {"pss"}, "dn.CN": {"pss"}, "keymode": {"new"}, "newkey": {"RSA:2048"}, "signer": {"self"},
		"hash": {"sha384-pss"}, "notbefore": {"2026-01-01T00:00"}, "validn": {"1"}, "validunit": {"y"}}
	rsaID := itemFrom(post("/db/pq/new/cert", rsa))
	if b := get("/db/pq/item/" + rsaID); !strings.Contains(b, "SHA384-RSAPSS") {
		t.Error("RSA certificate not signed with PSS")
	}
	// "Similar" keeps the PSS choice
	if b := get("/db/pq/new/cert?similar=" + rsaID); !strings.Contains(b, `value="sha384-pss" selected`) {
		t.Error("similar certificate lost the PSS hash")
	}

	pssKey := itemFrom(post("/db/pq/new/key", url.Values{"name": {"pss key"}, "type": {"RSA-PSS:2048"}}))
	slhKey := itemFrom(post("/db/pq/new/key", url.Values{"name": {"slh key"}, "type": {"SLH-DSA:SLH-DSA-SHAKE-128f"}}))
	if b := get("/db/pq/item/" + pssKey); !strings.Contains(b, "RSA-PSS") {
		t.Error("RSA-PSS key page")
	}
	if b := get("/db/pq/item/" + slhKey); !strings.Contains(b, "SLH-DSA-SHAKE-128f") {
		t.Error("SLH-DSA key page")
	}
	keys := get("/db/pq/keys")
	for _, want := range []string{"ML-KEM-768", "MLDSA65-Ed25519-SHA512", "SLH-DSA-SHAKE-128f", "RSA-PSS"} {
		if !strings.Contains(keys, want) {
			t.Errorf("key list lacks %s", want)
		}
	}
	for _, bad := range []string{"Foo:1", "RSA:1024", "ML-DSA:ML-DSA-99", "EC:P-224"} {
		if r := post("/db/pq/new/key", url.Values{"name": {"bad"}, "type": {bad}}); r.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("key type %s accepted: %d", bad, r.StatusCode)
		}
	}
}

// TestNewPGPKeyTypes creates OpenPGP keys of the new types through the
// form: Ed448, Brainpool and the v6-only ML-DSA composite.
func TestNewPGPKeyTypes(t *testing.T) {
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
	post("/", url.Values{"name": {"pg"}, "password": {"password1"}, "password2": {"password1"}})
	post("/db/pg/login", url.Values{"password": {"password1"}})
	for _, tc := range []struct {
		typ, version string
		want         []string
	}{
		{"Ed448", "4", []string{"Ed448", "X448"}},
		{"EC:brainpoolP384r1", "4", []string{"ECDSA BrainpoolP384", "ECDH BrainpoolP384"}},
		{"Composite:MLDSA65-Ed25519-SHA512", "6", []string{"ML-DSA-65+Ed25519", "ML-KEM-768+X25519"}},
		{"Composite:MLDSA87-Ed448-SHAKE256", "6", []string{"ML-DSA-87+Ed448", "ML-KEM-1024+X448"}},
	} {
		form := url.Values{"name": {tc.typ}, "type": {tc.typ}, "version": {tc.version}, "expiry": {"2y"}, "subkey": {"1"},
			"uids": {"New <new@example.org>"}}
		r := post("/db/pg/new/pgpkey", form)
		loc := r.Header.Get("Location")
		if !strings.HasSuffix(loc, "/pgp?notice=created") {
			t.Fatalf("%s: %d %s %s", tc.typ, r.StatusCode, loc, body(t, r))
		}
		r, _ = c.Get(ts.URL + loc)
		b := html.UnescapeString(body(t, r))
		for _, w := range tc.want {
			if !strings.Contains(b, w) {
				t.Errorf("%s: PGP page lacks %q", tc.typ, w)
			}
		}
	}
	// the composites exist as v6 keys only
	form := url.Values{"name": {"v4"}, "type": {"Composite:MLDSA65-Ed25519-SHA512"}, "version": {"4"}, "expiry": {"2y"},
		"uids": {"New <new@example.org>"}}
	r := post("/db/pg/new/pgpkey", form)
	if b := body(t, r); r.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(b, "version 6") {
		t.Errorf("v4 composite: %d", r.StatusCode)
	}
}

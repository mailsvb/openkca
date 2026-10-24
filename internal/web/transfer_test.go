package web

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTransferPages(t *testing.T) {
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
	post("/", url.Values{"name": {"tx"}, "password": {"password1"}, "password2": {"password1"}})
	post("/db/tx/login", url.Values{"password": {"password1"}})
	ca := url.Values{"name": {"Root"}, "dn.O": {"Web"}, "dn.CN": {"Root"}, "keymode": {"new"}, "newkey": {"EC:P-256"}, "signer": {"self"},
		"hash": {"sha256"}, "notbefore": {"2026-01-01T00:00"}, "validn": {"10"}, "validunit": {"y"}, "ca": {"1"}, "subkey": {"1"}, "ku.5": {"1"}}
	r := post("/db/tx/new/cert", ca)
	loc := r.Header.Get("Location")
	if !strings.Contains(loc, "/item/") {
		t.Fatalf("create root: %d %s", r.StatusCode, loc)
	}
	root := strings.Split(strings.Split(loc, "/item/")[1], "?")[0]

	r, _ = c.Get(ts.URL + "/db/tx/export?id=" + root)
	if b := body(t, r); r.StatusCode != 200 || !strings.Contains(b, "PKCS #12 chain") && !strings.Contains(b, "PKCS #12") {
		t.Fatalf("export page: %d", r.StatusCode)
	}
	r = post("/db/tx/export", url.Values{"id": {root}, "format": {"1"}, "action": {"download"}})
	if cd := r.Header.Get("Content-Disposition"); !strings.Contains(cd, `filename=Root.crt`) || !strings.Contains(body(t, r), "BEGIN CERTIFICATE") {
		t.Fatalf("PEM download: %q", cd)
	}
	r = post("/db/tx/export", url.Values{"id": {root}, "format": {"1"}, "action": {"show"}})
	if b := body(t, r); !strings.Contains(b, "data-copy") || !strings.Contains(b, "BEGIN CERTIFICATE") {
		t.Fatal("show as text")
	}
	r = post("/db/tx/export", url.Values{"id": {root}, "format": {"15"}})
	if r.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body(t, r), "enter an export password") {
		t.Fatalf("PKCS#12 without password: %d", r.StatusCode)
	}
	r = post("/db/tx/export", url.Values{"id": {root}, "format": {"15"}, "password": {"x"}, "password2": {"x"}})
	if ct := r.Header.Get("Content-Type"); ct != "application/x-pkcs12" {
		t.Fatalf("PKCS#12: %s %s", ct, body(t, r))
	}
	p12, _ := io.ReadAll(r.Body)
	r, _ = c.Get(ts.URL + "/db/tx/certs")
	if b := body(t, r); !strings.Contains(b, `form="selform"`) {
		t.Fatal("no selection checkboxes")
	}

	upload := func(files map[string][]byte, fields map[string]string) *http.Response {
		t.Helper()
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for name, data := range files {
			fw, _ := mw.CreateFormFile("file", name)
			fw.Write(data)
		}
		for k, v := range fields {
			mw.WriteField(k, v)
		}
		mw.Close()
		req, _ := http.NewRequest("POST", ts.URL+"/db/tx/import", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("HX-Request", "true")
		req.Header.Set("X-CSRF-Token", csrf)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	// a foreign certificate as pasted text, and the root again as a file
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Foreign"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	foreign := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if r := upload(map[string][]byte{"root.p12": p12}, map[string]string{"pem": string(foreign)}); r.Header.Get("HX-Redirect") != "/db/tx/import" {
		t.Fatalf("upload: %d %s", r.StatusCode, r.Header.Get("HX-Redirect"))
	}
	r, _ = c.Get(ts.URL + "/db/tx/import")
	b := body(t, r)
	if !strings.Contains(b, "password required") || !strings.Contains(b, `value="Foreign"`) {
		t.Fatalf("review page:\n%s", b)
	}
	post("/db/tx/import/password", url.Values{"password": {"x"}})
	r, _ = c.Get(ts.URL + "/db/tx/import")
	b = body(t, r)
	if !strings.Contains(b, "Already in the database as &#39;Root&#39;") {
		t.Fatalf("review after password:\n%s", b)
	}
	r = post("/db/tx/import/commit", url.Values{"sel": {"0", "1", "2"}, "name.2": {"Foreign renamed"}})
	if loc := r.Header.Get("Location"); loc != "/db/tx/certs?notice=imported&n=1" {
		t.Fatalf("commit: %s", loc)
	}
	r, _ = c.Get(ts.URL + "/db/tx/certs")
	if b := body(t, r); !strings.Contains(b, "Foreign renamed") {
		t.Fatal("imported certificate not listed")
	}

	// Dump
	r = post("/db/tx/dump", url.Values{"password": {"a"}, "password2": {"b"}})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "dump.error.password") {
		t.Fatalf("dump with mismatched passwords: %q", loc)
	}
	r = post("/db/tx/dump", url.Values{"password": {"dump pass"}, "password2": {"dump pass"}})
	if ct := r.Header.Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("dump: %s", ct)
	}

	// DH parameters
	r = post("/dh", url.Values{"bits": {"1024"}})
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("dh start: %d", r.StatusCode)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		r, _ = c.Get(ts.URL + "/dh?part=status")
		if strings.Contains(body(t, r), "Download PEM") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DH generation did not finish")
		}
		time.Sleep(100 * time.Millisecond)
	}
	r, _ = c.Get(ts.URL + "/dh/download")
	if b := body(t, r); !strings.Contains(b, "BEGIN DH PARAMETERS") {
		t.Fatalf("dh download: %s", b)
	}
}

func TestImportDuplicateInBatch(t *testing.T) {
	ts, _ := newTestServer(t)
	c := client(t, ts)
	csrf := login(t, ts, c)
	c.PostForm(ts.URL+"/", url.Values{"name": {"dup"}, "password": {"password1"}, "password2": {"password1"}, "csrf": {csrf}})
	c.PostForm(ts.URL+"/db/dup/login", url.Values{"password": {"password1"}, "csrf": {csrf}})
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Twice"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	p := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("pem", string(p)+string(p))
	mw.Close()
	req, _ := http.NewRequest("POST", ts.URL+"/db/dup/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", csrf)
	c.Do(req)
	r, _ := c.Get(ts.URL + "/db/dup/import")
	if b := body(t, r); r.StatusCode != 200 || !strings.Contains(b, "Found more than once") {
		t.Fatalf("review: %d\n%s", r.StatusCode, b)
	}
}

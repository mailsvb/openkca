package pubserve

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/publish"
)

const id1 = "1111aaaa-2222-4333-8444-55555555bbbb"

func fixture(t *testing.T, next time.Time) (dir string, cert, crl []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(cert)
	crl, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: next}, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	folder := filepath.Join(dir, "ca", "lab", id1)
	os.MkdirAll(folder, 0o700)
	os.WriteFile(filepath.Join(folder, publish.CertFile), cert, 0o644)
	os.WriteFile(filepath.Join(folder, publish.CRLFile), crl, 0o644)
	return dir, cert, crl
}

func TestHandler(t *testing.T) {
	dir, cert, crl := fixture(t, time.Now().Add(48*time.Hour))
	ts := httptest.NewServer(&Handler{Dir: dir, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	defer ts.Close()
	get := func(method, p string, hdr ...string) (*http.Response, []byte) {
		req, _ := http.NewRequest(method, ts.URL+p, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r, b
	}
	r, b := get("GET", "/"+id1+".crl")
	if r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/pkix-crl" || string(b) != string(crl) {
		t.Fatalf("crl: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
	if r.Header.Get("Cache-Control") != "public, max-age=300" || r.Header.Get("ETag") == "" || r.Header.Get("Last-Modified") == "" {
		t.Fatalf("caching headers %v", r.Header)
	}
	etag := r.Header.Get("ETag")
	if r, _ := get("GET", "/"+id1+".crl", "If-None-Match", etag); r.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional GET: %d", r.StatusCode)
	}
	if r, b := get("GET", "/pki/sub/"+id1+".crt"); r.StatusCode != 200 || r.Header.Get("Content-Type") != "application/pkix-cert" || string(b) != string(cert) {
		t.Fatalf("crt below a path: %d", r.StatusCode)
	}
	r, b = get("GET", "/"+id1+".pem")
	if blk, _ := pem.Decode(b); r.StatusCode != 200 || blk == nil || blk.Type != "CERTIFICATE" || string(blk.Bytes) != string(cert) {
		t.Fatalf("pem: %d %q", r.StatusCode, b)
	}
	if r, b := get("HEAD", "/"+id1+".crl"); r.StatusCode != 200 || len(b) != 0 || r.ContentLength != int64(len(crl)) {
		t.Fatalf("HEAD: %d %d", r.StatusCode, r.ContentLength)
	}
	for _, p := range []string{"/", "/index.html", "/" + id1, "/" + id1 + ".der", "/" + id1 + ".crl/x",
		"/1111aaaa-2222-4333-8444-55555555bbbc.crl", "/" + strings.ToUpper(id1) + ".crl",
		"/" + id1 + ".crl.bak"} {
		if r, _ := get("GET", p); r.StatusCode != 404 {
			t.Errorf("%s: %d", p, r.StatusCode)
		}
	}
	if r, _ := get("POST", "/"+id1+".crl"); r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", r.StatusCode)
	}
}

func TestMonitor(t *testing.T) {
	dir, _, _ := fixture(t, time.Now().Add(48*time.Hour))
	m := &Monitor{Dir: dir, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	a := m.Check(time.Now())
	if len(a) != 1 || a[0].Expired || a[0].DB != "lab" || a[0].AuthorityID != id1 || !strings.Contains(a[0].Issuer, "Test CA") {
		t.Fatalf("expiring: %+v", a)
	}
	if a := m.Check(time.Now().Add(72 * time.Hour)); len(a) != 1 || !a[0].Expired {
		t.Fatalf("expired: %+v", a)
	}
	if a := m.Check(time.Now().Add(-8 * 24 * time.Hour)); len(a) != 0 {
		t.Fatalf("far from expiry: %+v", a)
	}
	if len(m.Alerts()) != 0 {
		t.Fatal("Alerts does not keep the last check")
	}
}

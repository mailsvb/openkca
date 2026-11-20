package web

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/background"
	"github.com/mailsvb/openkca/internal/codec"
	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/store"
	"github.com/mailsvb/openkca/internal/vault"
)

var passwordRE = regexp.MustCompile(`<code class="mono">([^<]+)</code>`)

// estFixture is a server whose database "dev" is open in the background
// with a root CA.
type estFixture struct {
	ts    *httptest.Server
	srv   *Server
	bg    *background.Holder
	caID  int64
	label string
}

func newESTFixture(t *testing.T, opts ...func(*Config)) *estFixture {
	t.Helper()
	ctx := context.Background()
	fx := &estFixture{label: "devices"}
	pw := []byte("password1")
	ts, srv := newTestServer(t, append([]func(*Config){func(cfg *Config) {
		if err := cfg.Store.Create(ctx, "dev", pw, vault.Default); err != nil {
			t.Fatal(err)
		}
		bg, err := background.Open(ctx, cfg.Store, []string{"dev"}, map[string][]byte{"dev": pw})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(bg.Close)
		d := bg.Get("dev")
		root := store.IssueParams{Name: "Device CA", Subject: []pki.DNAttr{{Name: "CN", Value: "Device CA"}},
			NewKey: &pki.KeySpec{Type: "EC", Curve: "P-256"}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().AddDate(2, 0, 0), Hash: "sha256",
			Ext: pki.ExtSpec{CA: 1, BCCritical: true, SubKey: true, AuthKey: true, KeyUse: 1<<5 | 1<<6, KUCritical: true}}
		if fx.caID, err = d.Handle.Issue(ctx, root, d.Keyring()); err != nil {
			t.Fatal(err)
		}
		cfg.Background, fx.bg = bg, bg
	}}, opts...)...)
	fx.ts, fx.srv = ts, srv
	return fx
}

func newCSR(t *testing.T, spec pki.KeySpec, cn string, dns ...string) ([]byte, crypto.Signer) {
	t.Helper()
	key, err := pki.GenerateKey(spec)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{DNSNames: dns}
	tmpl.Subject.CommonName = cn
	der, err := x509.CreateCertificateRequest(nil, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func estPost(t *testing.T, c *http.Client, u, user, pass string, csr []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(base64.StdEncoding.EncodeToString(csr)))
	req.Header.Set("Content-Type", "application/pkcs10")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func p7Certs(t *testing.T, b64 string) []*x509.Certificate {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
	if err != nil {
		t.Fatal(err)
	}
	ders, _, err := codec.ParsePKCS7(der)
	if err != nil {
		t.Fatal(err)
	}
	var out []*x509.Certificate
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// createConnector sets up an EST connector through the web form and
// returns its generated password.
func (fx *estFixture) createConnector(t *testing.T, extra url.Values) string {
	t.Helper()
	c := client(t, fx.ts)
	csrf := login(t, fx.ts, c)
	post := func(path string, v url.Values) *http.Response {
		t.Helper()
		v.Set("csrf", csrf)
		r, err := c.PostForm(fx.ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := post("/db/dev/login", url.Values{"password": {"password1"}}); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("db login %d", r.StatusCode)
	}
	r, _ := c.Get(fx.ts.URL + "/db/dev/connectors/new/est")
	if b := body(t, r); r.StatusCode != http.StatusOK || !strings.Contains(b, "Device CA") {
		t.Fatalf("new connector page %d", r.StatusCode)
	}
	v := url.Values{"c.name": {"Devices"}, "c.label": {fx.label}, "c.enabled": {"1"}, "c.ca": {strconv.FormatInt(fx.caID, 10)},
		"c.user": {"est"}, "c.ec.P-256": {"1"}, "c.minhash": {"SHA-256"},
		"c.rattr.0": {"CN"}, "c.rmode.0": {"required"}, "c.rpattern.0": {`[a-z0-9.-]+\.example\.com`},
		"c.dns": {"1"}, "c.dnspat": {"*.example.com"}, "c.copycn": {"1"}, "c.max": {"5"},
		"validn": {"90"}, "validunit": {"d"}, "ca": {"2"}, "ku.0": {"1"}, "eku.clientAuth": {"1"}, "subkey": {"1"}, "authkey": {"1"},
		"action": {"save"}}
	for k, vs := range extra {
		v[k] = vs
	}
	r = post("/db/dev/connectors/new/est", v)
	b := body(t, r)
	m := passwordRE.FindStringSubmatch(b)
	if r.StatusCode != http.StatusOK || m == nil {
		e := regexp.MustCompile(`class="error"[^>]*>([^<]*)`).FindStringSubmatch(b)
		t.Fatalf("create connector: %d %v", r.StatusCode, e)
	}
	r, _ = c.Get(fx.ts.URL + "/db/dev/connectors")
	if b := body(t, r); !strings.Contains(b, "/.well-known/est/devices/") || strings.Contains(b, "Inactive") {
		t.Fatal("connector not listed as active")
	}
	return m[1]
}

func TestESTEnroll(t *testing.T) {
	fx := newESTFixture(t)
	pass := fx.createConnector(t, nil)
	base := fx.ts.URL + "/.well-known/est/" + fx.label + "/"
	c := fx.ts.Client()

	// cacerts: the CA, without authentication.
	r, _ := c.Get(base + "cacerts")
	if b := body(t, r); r.StatusCode != http.StatusOK || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/pkcs7-mime") {
		t.Fatalf("cacerts %d %s", r.StatusCode, b)
	} else if certs := p7Certs(t, b); len(certs) != 1 || certs[0].Subject.CommonName != "Device CA" {
		t.Fatalf("cacerts: %v", certs)
	}
	r, _ = c.Get(base + "csrattrs")
	if body(t, r); r.StatusCode != http.StatusOK {
		t.Fatalf("csrattrs %d", r.StatusCode)
	}

	// Enrollment needs the password.
	csr, key := newCSR(t, pki.KeySpec{Type: "EC", Curve: "P-256"}, "dev1.example.com")
	if r := estPost(t, c, base+"simpleenroll", "", "", csr); r.StatusCode != http.StatusUnauthorized || r.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("no auth: %d", r.StatusCode)
	}
	r = estPost(t, c, base+"simpleenroll", "est", pass, csr)
	b := body(t, r)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("simpleenroll %d %s", r.StatusCode, b)
	}
	issued := p7Certs(t, b)[0]
	if issued.Subject.CommonName != "dev1.example.com" || len(issued.DNSNames) != 1 || issued.DNSNames[0] != "dev1.example.com" ||
		issued.IsCA || issued.NotAfter.After(time.Now().AddDate(0, 0, 91)) || len(issued.ExtKeyUsage) != 1 {
		t.Fatalf("issued %v %v %v %v", issued.Subject, issued.DNSNames, issued.NotAfter, issued.ExtKeyUsage)
	}
	snap, _ := fx.bg.Get("dev").Handle.Snapshot(context.Background())
	var stored *db.Cert
	for _, sc := range snap.Certs {
		if string(sc.DER) == string(issued.Raw) {
			stored = sc
		}
	}
	if stored == nil || stored.KeyID != 0 || stored.IssuerID != fx.caID || stored.ConnectorID == 0 {
		t.Fatalf("stored certificate %+v", stored)
	}

	// Policy: a curve the connector does not allow, a name outside the pattern.
	p521, _ := newCSR(t, pki.KeySpec{Type: "EC", Curve: "P-521"}, "dev2.example.com")
	if r := estPost(t, c, base+"simpleenroll", "est", pass, p521); r.StatusCode != http.StatusForbidden {
		t.Fatalf("P-521: %d", r.StatusCode)
	}
	other, _ := newCSR(t, pki.KeySpec{Type: "EC", Curve: "P-256"}, "dev2.example.org")
	if r := estPost(t, c, base+"simpleenroll", "est", pass, other); r.StatusCode != http.StatusForbidden {
		t.Fatalf("CN outside the pattern: %d", r.StatusCode)
	}
	if r := estPost(t, c, fx.ts.URL+"/.well-known/est/nothing/simpleenroll", "est", pass, csr); r.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown label: %d", r.StatusCode)
	}

	// Re-enrollment is off for this connector.
	if r := estPost(t, c, base+"simplereenroll", "", "", csr); r.StatusCode != http.StatusForbidden {
		t.Fatalf("reenroll while off: %d", r.StatusCode)
	}
	_ = key

	// Plain HTTP is refused, even with a forged X-Forwarded-Proto.
	plain := httptest.NewServer(fx.srv)
	defer plain.Close()
	req, _ := http.NewRequest(http.MethodGet, plain.URL+"/.well-known/est/"+fx.label+"/cacerts", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != http.StatusForbidden {
		t.Fatalf("plain HTTP: %v %v", r, err)
	}

	// Wrong passwords: refused, then rate limited.
	for range 5 {
		if r := estPost(t, c, base+"simpleenroll", "est", "wrong-password", csr); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d", r.StatusCode)
		}
	}
	if r := estPost(t, c, base+"simpleenroll", "est", pass, csr); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after failures: %d", r.StatusCode)
	}

	// Every refusal is in the audit log.
	var rejected, enrolled int
	entries, _ := fx.bg.Get("dev").Handle.AuditLog(context.Background(), 0, 0, 1000)
	for _, e := range entries {
		switch e.Action {
		case "est.rejected":
			rejected++
		case "est.enroll":
			enrolled++
		}
	}
	if enrolled != 1 || rejected < 7 {
		t.Fatalf("audit: %d enrolled, %d rejected", enrolled, rejected)
	}
}

func TestESTReenroll(t *testing.T) {
	fx := newESTFixture(t, func(cfg *Config) {
		cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
		cfg.ClientCertHeader = "X-SSL-Client-Cert"
	})
	pass := fx.createConnector(t, url.Values{"c.reenroll": {"1"}})
	path := "/.well-known/est/" + fx.label + "/"
	csr, key := newCSR(t, pki.KeySpec{Type: "EC", Curve: "P-256"}, "dev1.example.com")
	r := estPost(t, fx.ts.Client(), fx.ts.URL+path+"simpleenroll", "est", pass, csr)
	b := body(t, r)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("simpleenroll %d %s", r.StatusCode, b)
	}
	current := p7Certs(t, b)[0]

	// On an EST listener that asks for client certificates.
	ests := httptest.NewUnstartedServer(fx.srv.ESTHandler())
	ests.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	ests.StartTLS()
	defer ests.Close()
	tr := ests.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{current.Raw}, PrivateKey: key}}
	withCert := &http.Client{Transport: tr}
	renew, _ := newCSR(t, pki.KeySpec{Type: "EC", Curve: "P-256"}, "dev1.example.com")
	r = estPost(t, withCert, ests.URL+path+"simplereenroll", "", "", renew)
	if b := body(t, r); r.StatusCode != http.StatusOK {
		t.Fatalf("simplereenroll %d %s", r.StatusCode, b)
	}
	// The subject must stay.
	renamed, _ := newCSR(t, pki.KeySpec{Type: "EC", Curve: "P-256"}, "dev9.example.com")
	if r := estPost(t, withCert, ests.URL+path+"simplereenroll", "", "", renamed); r.StatusCode != http.StatusForbidden {
		t.Fatalf("reenroll with another subject: %d", r.StatusCode)
	}
	// Without a certificate there is nothing to renew; the EST listener
	// serves nothing else.
	if r := estPost(t, ests.Client(), ests.URL+path+"simplereenroll", "", "", renew); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reenroll without a certificate: %d", r.StatusCode)
	}
	if r, _ := ests.Client().Get(ests.URL + "/login"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("EST listener serves the UI: %d", r.StatusCode)
	}

	// Behind a trusted TLS proxy that passes the certificate in a header.
	plain := httptest.NewServer(fx.srv)
	defer plain.Close()
	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: current.Raw}))
	req, _ := http.NewRequest(http.MethodPost, plain.URL+path+"simplereenroll", strings.NewReader(base64.StdEncoding.EncodeToString(renew)))
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-SSL-Client-Cert", url.QueryEscape(pemCert))
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != http.StatusOK {
		t.Fatalf("reenroll through the proxy: %v %v", r.StatusCode, err)
	}
}

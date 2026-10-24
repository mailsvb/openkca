package web

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/pubserve"
	"github.com/mailsvb/openkca/internal/vault"
)

var itemIDRE = regexp.MustCompile(`/item/(\d+)`)

// TestPublishedCDPAndAIA: the editor, profiles and the renew dialog offer
// the issuer's published CRL and certificate, checked; templates decide
// for themselves; the CA page shows the URLs and re-signs on a click.
func TestPublishedCDPAndAIA(t *testing.T) {
	ctx := context.Background()
	ts, srv := newTestServer(t)
	srv.store.BaseURLs = []string{"http://ext.example", "http://int.lan:8080"}
	srv.cfg.CRLAlerts = func() []pubserve.Alert {
		return []pubserve.Alert{{DB: "pki", Issuer: "CN=Old CA", NextUpdate: time.Now().Add(-time.Hour), Expired: true}}
	}
	if err := srv.store.Create(ctx, "pki", []byte("password1"), vault.Default); err != nil {
		t.Fatal(err)
	}
	c := client(t, ts)
	csrf := login(t, ts, c)
	r, _ := c.Get(ts.URL + "/")
	if b := body(t, r); !strings.Contains(b, "CN=Old CA") || !strings.Contains(b, `class="error"`) {
		t.Fatal("no CRL alert on the databases page")
	}
	r, _ = c.PostForm(ts.URL+"/db/pki/login", url.Values{"password": {"password1"}, "csrf": {csrf}})
	body(t, r)
	post := func(path string, v url.Values) *http.Response {
		v.Set("csrf", csrf)
		r, err := c.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		body(t, r)
		return r
	}
	get := func(path string) string {
		r, err := c.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		return body(t, r)
	}

	// Root CA through its profile: self-signed, no boxes.
	if b := get("/db/pki/create/root-ca"); strings.Contains(b, `name="pubcdp"`) {
		t.Fatal("root CA profile offers CDP")
	}
	r = post("/db/pki/create/root-ca", url.Values{"action": {"create"}, "cn": {"Lab Root"}, "validity": {"20y"}, "keymode": {"new"}, "newkey": {"EC:P-256"}})
	m := itemIDRE.FindStringSubmatch(r.Header.Get("Location"))
	if m == nil {
		t.Fatalf("root: %s", r.Header.Get("Location"))
	}
	rootID := m[1]

	// The editor offers both boxes, checked.
	b := get("/db/pki/new/cert?signer=" + rootID)
	if !strings.Contains(b, `name="pubcdp" value="1" checked`) || !strings.Contains(b, `name="pubaia" value="1" checked`) ||
		!strings.Contains(b, "http://ext.example, http://int.lan:8080") {
		t.Fatal("editor does not pre-select the published CDP/AIA")
	}
	// The TLS server profile too.
	b = get("/db/pki/create/tls-server?signer=" + rootID)
	if !strings.Contains(b, `name="pubcdp" value="1" checked`) {
		t.Fatal("profile does not pre-select the published CDP")
	}
	r = post("/db/pki/create/tls-server", url.Values{"action": {"create"}, "hosts": {"www.example.org"}, "issuer": {rootID},
		"validity": {"397d"}, "keymode": {"new"}, "newkey": {"EC:P-256"}, "pubcdp": {"1"}})
	m = itemIDRE.FindStringSubmatch(r.Header.Get("Location"))
	if m == nil {
		t.Fatalf("leaf: %s", r.Header.Get("Location"))
	}
	h, _ := srv.store.Acquire(ctx, "pki")
	defer h.Release()
	snap, _ := h.Snapshot(ctx)
	var leaf, root *x509.Certificate
	var authID string
	for _, ce := range snap.Certs {
		switch {
		case ce.Name == "www.example.org":
			leaf, _ = x509.ParseCertificate(ce.DER)
		case ce.Authority != nil:
			root, _ = x509.ParseCertificate(ce.DER)
			authID = ce.Authority.UUID
		}
	}
	if leaf == nil || root == nil {
		t.Fatal("certificates missing")
	}
	if got := strings.Join(leaf.CRLDistributionPoints, " "); got != "http://ext.example/"+authID+".crl http://int.lan:8080/"+authID+".crl" {
		t.Fatalf("leaf CDP %s", got)
	}
	if len(leaf.IssuingCertificateURL) != 0 {
		t.Fatal("AIA added although unchecked")
	}

	// A template without the flags unchecks them when applied.
	r = post("/db/pki/new/template", url.Values{"action": {"create"}, "name": {"no urls"}, "ca": {"2"}})
	b = get("/db/pki/new/template")
	if !strings.Contains(b, `name="pubcdp" value="1" checked`) {
		t.Fatal("new template does not pre-select")
	}
	var tmplID int64
	snap, _ = h.Snapshot(ctx)
	for _, tp := range snap.Templates {
		if tp.Name == "no urls" {
			tmplID = tp.ID
			if tp.Data.Spec().PubCDP {
				t.Fatal("template saved the unchecked flag")
			}
		}
	}
	if tmplID == 0 {
		t.Fatal("template not saved")
	}
	b = get("/db/pki/new/cert?template=" + itoa(int(tmplID)))
	if strings.Contains(b, `name="pubcdp" value="1" checked`) {
		t.Fatal("template without flags left the box checked")
	}

	// The CA page lists the URLs, the automatic signing state and re-signs.
	b = get("/db/pki/item/" + rootID)
	for _, want := range []string{"http://ext.example/" + authID + ".crl", "http://int.lan:8080/" + authID + ".crt",
		"/crl/now", "not kept open in the background"} {
		if !strings.Contains(b, want) {
			t.Errorf("CA page lacks %q", want)
		}
	}
	r = post("/db/pki/item/"+rootID+"/crl/now", url.Values{})
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "notice=crlsigned") {
		t.Fatalf("re-sign: %s", loc)
	}
	snap, _ = h.Snapshot(ctx)
	if len(snap.CRLs) != 1 {
		t.Fatalf("%d CRLs", len(snap.CRLs))
	}

	// The renew dialog pre-selects and the renewal gets both.
	leafItem := m[1]
	if b := get("/db/pki/item/" + leafItem + "/renew"); !strings.Contains(b, `name="pubaia" value="1" checked`) {
		t.Fatal("renew dialog does not pre-select")
	}
	now := time.Now().UTC()
	r = post("/db/pki/item/"+leafItem+"/renew", url.Values{"notbefore": {now.Format("2006-01-02T15:04")},
		"notafter": {now.AddDate(1, 0, 0).Format("2006-01-02T15:04")}, "pubcdp": {"1"}, "pubaia": {"1"}})
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("renew: %d", r.StatusCode)
	}
	snap, _ = h.Snapshot(ctx)
	n := 0
	for _, ce := range snap.Certs {
		if ce.Name == "www.example.org" {
			if c, _ := x509.ParseCertificate(ce.DER); len(c.IssuingCertificateURL) == 2 {
				n++
			}
		}
	}
	if n != 1 {
		t.Fatal("renewal without AIA")
	}
}

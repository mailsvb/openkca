package store

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/tmpl"
)

func extOrder(c *x509.Certificate) string {
	var names []string
	for _, e := range c.Extensions {
		names = append(names, e.Id.String())
	}
	return strings.Join(names, " ")
}

// TestXCATemplatesApply issues certificates from the three templates XCA
// ships (stored in the fixture by XCA itself) and checks the resulting
// extensions against what XCA's NewX509 produces from the same template.
func TestXCATemplatesApply(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	h, _ := load(t, s, "schema8")
	want := map[string]struct {
		order string
		check func(*x509.Certificate) bool
	}{
		// BC(critical, CA), SKI, KU keyCertSign+cRLSign, nsCertType sslCA/emailCA/objCA, nsComment
		"CA": {"2.5.29.19 2.5.29.14 2.5.29.15 2.16.840.1.113730.1.1 2.16.840.1.113730.1.13", func(c *x509.Certificate) bool {
			return c.IsCA && c.KeyUsage == x509.KeyUsageCertSign|x509.KeyUsageCRLSign
		}},
		// BC(critical, end entity), SKI, KU, EKU serverAuth, SAN DNS:copycn, nsCertType server, nsComment
		"TLS_server": {"2.5.29.19 2.5.29.14 2.5.29.15 2.5.29.37 2.5.29.17 2.16.840.1.113730.1.1 2.16.840.1.113730.1.13", func(c *x509.Certificate) bool {
			return !c.IsCA && c.ExtKeyUsage[0] == x509.ExtKeyUsageServerAuth && c.DNSNames[0] == "tmpl.example.org" &&
				c.KeyUsage == x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment|x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement
		}},
		"TLS_client": {"", func(c *x509.Certificate) bool { return !c.IsCA && c.ExtKeyUsage[0] == x509.ExtKeyUsageClientAuth }},
	}
	snap, _ := h.Snapshot(ctx)
	if len(snap.Templates) != 3 {
		t.Fatalf("%d templates", len(snap.Templates))
	}
	for _, st := range snap.Templates {
		d, err := h.LoadTemplate(ctx, st.ID)
		if err != nil {
			t.Fatal(err)
		}
		p := IssueParams{Name: "from " + st.Name, Subject: []pki.DNAttr{{Name: "CN", Value: "tmpl.example.org"}},
			NewKey: &pki.KeySpec{Type: "EC", Curve: "P-256"}, NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
			Hash: "sha256", Ext: d.Ext}
		id, err := h.Issue(ctx, p, krOf(t, h))
		if err != nil {
			t.Fatalf("%s: %v", st.Name, err)
		}
		sn, _ := h.Snapshot(ctx)
		c, _ := x509.ParseCertificate(findCert(sn, id).DER)
		w := want[st.Name]
		if w.order != "" && extOrder(c) != w.order {
			t.Errorf("%s: extensions %s\nwant %s", st.Name, extOrder(c), w.order)
		}
		if !w.check(c) {
			t.Errorf("%s: unexpected content", st.Name)
		}
		for _, e := range c.Extensions {
			if e.Id.String() == "2.16.840.1.113730.1.13" && !strings.Contains(string(e.Value), "xca certificate") {
				t.Errorf("%s: nsComment", st.Name)
			}
		}
	}
}

func TestTemplateLifecycle(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	h, _ := load(t, s, "schema8")
	d := TemplateData{Name: "My server", Subject: []pki.DNAttr{{Name: "O", Value: "Org"}, {Name: "C", Value: "DE"}},
		Ext: pki.ExtSpec{CA: 2, SubKey: true, AuthKey: true, KeyUse: 1 | 4, EKU: []string{"serverAuth", "secureShellClient"},
			SubAltName: "DNS:copycn, UPN:admin@example.org", AdvExt: "certificatePolicies = 1.2.3.4\n"},
		Validity: tmpl.Validity{N: 2, Unit: 2, Midnight: true}}
	id, err := h.SaveTemplate(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	back, err := h.LoadTemplate(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if back.Ext.SubAltName != d.Ext.SubAltName || len(back.Ext.EKU) != 2 || back.Ext.AdvExt != d.Ext.AdvExt ||
		back.Validity != d.Validity || len(back.Subject) != 2 {
		t.Fatalf("round trip %+v", back)
	}
	back.Name, back.Ext.KeyUse = "My server v2", 1
	if _, err := h.SaveTemplate(ctx, *back); err != nil {
		t.Fatal(err)
	}
	if again, _ := h.LoadTemplate(ctx, id); again.Name != "My server v2" || again.Ext.KeyUse != 1 {
		t.Fatal("update")
	}
	if _, err := h.SaveTemplate(ctx, TemplateData{Name: "bad", Ext: pki.ExtSpec{AdvExt: "nonsense = 1"}}); err == nil {
		t.Fatal("invalid adv_ext accepted")
	}
	dup, err := h.DuplicateTemplate(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if dd, _ := h.LoadTemplate(ctx, dup); dd.Name != "My server v2 copy" {
		t.Fatalf("duplicate name %q", dd.Name)
	}
	// Certificate to template: www.example.org (item 7) from the XCA fixture
	tid, err := h.TemplateFromItem(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	td, _ := h.LoadTemplate(ctx, tid)
	if td.Ext.CA != 2 || td.Ext.SubAltName != "DNS:www.example.org, DNS:example.org" || td.Ext.EKU[0] != "serverAuth" ||
		!td.Ext.AuthKey || td.Validity.N != 13 || td.Validity.Unit != 1 || td.Subject[0].Name != "C" {
		t.Fatalf("template from certificate %+v", td)
	}
}

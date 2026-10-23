package pki

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func mustName(t *testing.T, attrs ...string) []byte {
	t.Helper()
	var a []DNAttr
	for i := 0; i+1 < len(attrs); i += 2 {
		a = append(a, DNAttr{attrs[i], attrs[i+1]})
	}
	der, err := BuildName(a, "MASK:0x2002")
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestBuildNameTypes(t *testing.T) {
	der := mustName(t, "C", "DE", "O", "Müller & Co", "OU", "IT", "CN", "www.example.org", "emailAddress", "a@example.org")
	got := map[string]string{}
	for _, e := range mustParse(t, der) {
		got[e.Short] = e.Type
	}
	want := map[string]string{"C": "PrintableString", "O": "UTF8String", "OU": "PrintableString",
		"CN": "PrintableString", "emailAddress": "IA5String"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("types %v", got)
	}
	if FormatName(der) != "C=DE, O=Müller & Co, OU=IT, CN=www.example.org, emailAddress=a@example.org" {
		t.Fatalf("order: %s", FormatName(der))
	}
	if _, err := BuildName([]DNAttr{{"C", "Germany"}}, ""); err == nil {
		t.Fatal("three-letter country accepted")
	}
	utf, _ := BuildName([]DNAttr{{"CN", "plain"}}, "utf8only")
	if mustParse(t, utf)[0].Type != "UTF8String" {
		t.Fatal("utf8only")
	}
}

func mustParse(t *testing.T, der []byte) []NameEntry {
	e, err := ParseName(der)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func issue(t *testing.T, subject []byte, key crypto.Signer, spec ExtSpec, issuer *x509.Certificate, issuerKey crypto.Signer) *x509.Certificate {
	t.Helper()
	spki, _ := x509.MarshalPKIXPublicKey(key.Public())
	ctx := ExtContext{SubjectSPKI: spki, Subject: subject, SelfSigned: issuer == nil}
	signer := key
	if issuer != nil {
		ctx.IssuerSPKI, ctx.IssuerSKI = issuer.RawSubjectPublicKeyInfo, issuer.SubjectKeyId
		signer = issuerKey
	}
	exts, err := BuildExtensions(spec, ctx)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := RandomSerial(64)
	der, err := CreateCertificate(CertRequest{Subject: subject, PublicKey: key.Public(), Serial: serial,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), Extensions: exts,
		Hash: "sha256", Issuer: issuer, SignerKey: signer})
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIssueChain(t *testing.T) {
	rootKey, _ := GenerateKey(KeySpec{Type: "RSA", Bits: 2048})
	interKey, _ := GenerateKey(KeySpec{Type: "EC", Curve: "P-384"})
	leafKey, _ := GenerateKey(KeySpec{Type: "Ed25519"})
	caSpec := ExtSpec{CA: 1, BCCritical: true, SubKey: true, AuthKey: true, KeyUse: 1<<5 | 1<<6, KUCritical: true}
	root := issue(t, mustName(t, "CN", "Root"), rootKey, caSpec, nil, nil)
	interSpec := caSpec
	interSpec.PathLen = "0"
	interSpec.NameCons = "permitted;DNS:.example.org, excluded;IP:10.0.0.0/255.0.0.0"
	interSpec.CRLDist = "URI:http://crl.example.org/root.crl"
	interSpec.AuthInfAcc = "OCSP;URI:http://ocsp.example.org, caIssuers;URI:http://example.org/root.crt"
	inter := issue(t, mustName(t, "CN", "Inter"), interKey, interSpec, root, rootKey)
	leafSpec := ExtSpec{CA: 2, BCCritical: true, SubKey: true, AuthKey: true, KeyUse: 1, EKU: []string{"serverAuth", "clientAuth"},
		SubAltName: "DNS:copycn, DNS:alt.example.org, IP:192.0.2.1, email:copy", NSCertType: 1 << 1, NSComment: "go-ca", OCSPStaple: true}
	leaf := issue(t, mustName(t, "CN", "www.example.org", "emailAddress", "hostmaster@example.org"), leafKey, leafSpec, inter, interKey)

	if len(root.AuthorityKeyId) != 0 {
		t.Error("self-signed certificate has an AKI")
	}
	if !root.IsCA || root.MaxPathLen != -1 || !inter.IsCA || inter.MaxPathLen != 0 || !inter.MaxPathLenZero {
		t.Errorf("basic constraints root %v/%d inter %v/%d", root.IsCA, root.MaxPathLen, inter.IsCA, inter.MaxPathLen)
	}
	if string(inter.AuthorityKeyId) != string(root.SubjectKeyId) || string(leaf.AuthorityKeyId) != string(inter.SubjectKeyId) {
		t.Error("AKI does not match the issuer's SKI")
	}
	if !reflect.DeepEqual(leaf.DNSNames, []string{"www.example.org", "alt.example.org"}) || len(leaf.IPAddresses) != 1 ||
		!reflect.DeepEqual(leaf.EmailAddresses, []string{"hostmaster@example.org"}) {
		t.Errorf("SAN %v %v %v", leaf.DNSNames, leaf.IPAddresses, leaf.EmailAddresses)
	}
	if inter.PermittedDNSDomains[0] != ".example.org" || len(inter.ExcludedIPRanges) != 1 || inter.OCSPServer[0] != "http://ocsp.example.org" ||
		inter.CRLDistributionPoints[0] != "http://crl.example.org/root.crl" {
		t.Errorf("CA extensions: %v %v %v %v", inter.PermittedDNSDomains, inter.ExcludedIPRanges, inter.OCSPServer, inter.CRLDistributionPoints)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	ip := x509.NewCertPool()
	ip.AddCert(inter)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: ip, DNSName: "alt.example.org"}); err != nil {
		t.Fatalf("Go verify: %v", err)
	}
	// Extension order as XCA writes it.
	var order []string
	for _, e := range leaf.Extensions {
		order = append(order, extNames[e.Id.String()])
	}
	want := "Basic Constraints,Subject Key Identifier,Authority Key Identifier,Key Usage,Extended Key Usage,Subject Alternative Name,TLS Feature,Netscape Cert Type,Netscape Comment"
	if strings.Join(order, ",") != want {
		t.Errorf("order %v", order)
	}
	// Similar: spec round trip
	back, rest := SpecFromExtensions(leaf.Extensions)
	if len(rest) != 0 || back.KeyUse != leafSpec.KeyUse || back.NSCertType != leafSpec.NSCertType || !back.OCSPStaple ||
		back.SubAltName != "DNS:www.example.org, DNS:alt.example.org, IP:192.0.2.1, email:hostmaster@example.org" {
		t.Errorf("spec round trip %+v rest %v", back, rest)
	}
	iback, _ := SpecFromExtensions(inter.Extensions)
	if iback.NameCons != "permitted;DNS:.example.org, excluded;IP:10.0.0.0/8" || iback.AuthInfAcc != interSpec.AuthInfAcc || iback.CRLDist != interSpec.CRLDist {
		t.Errorf("CA spec round trip %+v", iback)
	}
	// OpenSSL agrees.
	if _, err := exec.LookPath("openssl"); err == nil {
		dir := t.TempDir()
		w := func(n string, c *x509.Certificate) string {
			p := filepath.Join(dir, n)
			os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}), 0o644)
			return p
		}
		out, err := exec.Command("openssl", "verify", "-CAfile", w("root.pem", root), "-untrusted", w("inter.pem", inter), w("leaf.pem", leaf)).CombinedOutput()
		if err != nil {
			t.Fatalf("openssl verify: %v\n%s", err, out)
		}
	}
	// CSR
	csrDER, err := CreateRequest(mustName(t, "CN", "req"), nil, leafKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if r, err := x509.ParseCertificateRequest(csrDER); err != nil || r.CheckSignature() != nil {
		t.Fatalf("CSR: %v", err)
	}
}

func TestSerial(t *testing.T) {
	for i := 0; i < 50; i++ {
		s, _ := RandomSerial(64)
		if s.Sign() <= 0 || s.BitLen() > 63 || s.BitLen() < 57 {
			t.Fatalf("serial %x", s)
		}
	}
}

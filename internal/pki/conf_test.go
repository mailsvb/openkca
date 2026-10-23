package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
)

func TestBuildAdvanced(t *testing.T) {
	key, _ := GenerateKey(KeySpec{Type: "EC", Curve: "P-256"})
	adv := `
# comment
subjectAltName = DNS:a.example.org, UPN:user@example.org, @alt
certificatePolicies = ia5org, 1.2.3.4, @pol
policyConstraints = critical, requireExplicitPolicy:0
inhibitAnyPolicy = 2
noCheck = ignored
1.2.3.5 = ASN1:UTF8String:hello
1.2.3.6 = critical,DER:05:00
extendedKeyUsage = serverAuth, secureShellClient

[alt]
DNS.1 = b.example.org
dirName.1 = dir
[dir]
C = DE
CN = Dir Name
[pol]
policyIdentifier = 1.3.6.1.4.1.99999.1
CPS.1 = http://example.org/cps
userNotice.1 = @notice
[notice]
explicitText = Explicit text
organization = Org
noticeNumbers = 1, 2
`
	cert := issue(t, mustName(t, "CN", "adv"), key, ExtSpec{AdvExt: adv, SubKey: true}, nil, nil)
	if !strings.Contains(strings.Join(cert.DNSNames, ","), "b.example.org") || len(cert.DNSNames) != 2 {
		t.Fatalf("SAN %v", cert.DNSNames)
	}
	got := map[string]bool{}
	for _, e := range cert.Extensions {
		got[e.Id.String()] = e.Critical
	}
	for _, oid := range []string{"2.5.29.17", "2.5.29.32", "2.5.29.36", "2.5.29.54", "1.3.6.1.5.5.7.48.1.5", "1.2.3.5", "1.2.3.6", "2.5.29.37"} {
		if _, ok := got[oid]; !ok {
			t.Errorf("missing %s", oid)
		}
	}
	if !got["1.2.3.6"] || !got["2.5.29.36"] {
		t.Error("critical flag lost")
	}
	if len(cert.PolicyIdentifiers) != 2 {
		t.Errorf("policies %v", cert.PolicyIdentifiers)
	}
	// Errors name the line
	var ce *ConfError
	for _, bad := range []string{"foo = bar", "keyUsage = digitalSignature\nkeyUsage = cRLSign", "subjectAltName = @missing", "1.2.3 = ASN1:SEQUENCE:x"} {
		_, err := BuildExtensions(ExtSpec{AdvExt: bad}, ExtContext{})
		if err == nil {
			t.Errorf("%q accepted", bad)
		} else if !errors.As(err, &ce) && !strings.Contains(err.Error(), "twice") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// Generic DER round trip (GenConf output parses back to the same bytes)
	exts := []pkix.Extension{{Id: []int{1, 2, 3, 9}, Critical: true, Value: []byte{0x0c, 0x01, 0x41}}}
	back, err := BuildAdvanced(GenConf(exts), ExtContext{})
	if err != nil || len(back) != 1 || !back[0].Critical || string(back[0].Value) != string(exts[0].Value) {
		t.Fatalf("GenConf round trip %q: %v %v", GenConf(exts), back, err)
	}
	// SpecWithAdvanced keeps what the fields cannot hold
	s := SpecWithAdvanced(cert.Extensions)
	if !strings.Contains(s.AdvExt, "certificatePolicies=") || !strings.Contains(s.AdvExt, "subjectAltName=") || s.SubAltName != "" {
		t.Fatalf("advanced split %+v", s)
	}
	again := issue(t, mustName(t, "CN", "adv"), key, s, nil, nil)
	if len(again.Extensions) != len(cert.Extensions) {
		t.Fatalf("re-issued with %d extensions, want %d", len(again.Extensions), len(cert.Extensions))
	}
	_ = x509.Certificate{}
}

func TestResolveOID(t *testing.T) {
	if r := ResolveOID("2.5.29.17"); len(r) != 1 || r[0].Short != "subjectAltName" {
		t.Fatalf("%+v", r)
	}
	if r := ResolveOID("bitlocker"); len(r) != 2 {
		t.Fatalf("%+v", r)
	}
	if o, ok := OIDByName("secureShellClient"); !ok || o.String() != "1.3.6.1.5.5.7.3.21" {
		t.Fatal("OIDByName")
	}
}

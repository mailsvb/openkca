package est

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/tmpl"
)

var (
	keyMu    sync.Mutex
	keyCache = map[pki.KeySpec]crypto.Signer{}
)

// testKey generates a key once per spec.
func testKey(t *testing.T, spec pki.KeySpec) crypto.Signer {
	t.Helper()
	keyMu.Lock()
	defer keyMu.Unlock()
	if k, ok := keyCache[spec]; ok {
		return k
	}
	k, err := pki.GenerateKey(spec)
	if err != nil {
		t.Fatalf("GenerateKey(%+v): %v", spec, err)
	}
	keyCache[spec] = k
	return k
}

var (
	rsa2048 = pki.KeySpec{Type: "RSA", Bits: 2048}
	rsa3072 = pki.KeySpec{Type: "RSA", Bits: 3072}
	ecP256  = pki.KeySpec{Type: "EC", Curve: "P-256"}
	ecP521  = pki.KeySpec{Type: "EC", Curve: "P-521"}
	ed25519 = pki.KeySpec{Type: "Ed25519"}
	mldsa65 = pki.KeySpec{Type: "ML-DSA", Param: "ML-DSA-65"}
)

func hashFor(spec pki.KeySpec) string {
	if spec.Type == "RSA" || spec.Type == "EC" {
		return "sha256"
	}
	return ""
}

// testCSR builds a DER CSR for subject and SANs in the one-line syntax.
func testCSR(t *testing.T, spec pki.KeySpec, subject []pki.DNAttr, sans string) []byte {
	t.Helper()
	key := testKey(t, spec)
	return csrWith(t, key, subject, sans, hashFor(spec))
}

func csrWith(t *testing.T, key crypto.Signer, subject []pki.DNAttr, sans, hash string) []byte {
	t.Helper()
	name := []byte{0x30, 0x00}
	if len(subject) > 0 {
		var err error
		if name, err = pki.BuildName(subject, ""); err != nil {
			t.Fatal(err)
		}
	}
	var exts []pkix.Extension
	if sans != "" {
		spki, err := pki.MarshalPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		if exts, err = pki.BuildExtensions(pki.ExtSpec{SubAltName: sans}, pki.ExtContext{SubjectSPKI: spki, Request: true}); err != nil {
			t.Fatal(err)
		}
	}
	der, err := pki.CreateRequest(name, exts, key, hash)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// sha1CSR re-signs a CSR's body with SHA-1.
func sha1CSR(t *testing.T, subject []pki.DNAttr) []byte {
	t.Helper()
	key := testKey(t, rsa2048).(*rsa.PrivateKey)
	r, err := x509.ParseCertificateRequest(csrWith(t, key, subject, "", "sha256"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(r.RawTBSCertificateRequest)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{
		asn1.RawValue{FullBytes: r.RawTBSCertificateRequest},
		pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}, Parameters: asn1.NullRawValue},
		asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

var (
	caOnce sync.Once
	caKey  *ecdsa.PrivateKey
)

// testCA is a P-256 CA valid from notBefore to notAfter.
func testCA(t *testing.T, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	caOnce.Do(func() { caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader) })
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// testConfig is the default with credentials and DNS names below
// example.com.
func testConfig() Config {
	c := Default()
	c.Auth = Auth{User: "device", PassHash: "$argon2id$placeholder"}
	c.SAN.DNS = DNSRule{Enabled: true, Patterns: []string{"*.example.com"}}
	return c
}

func cn(v string) []pki.DNAttr { return []pki.DNAttr{{Name: "CN", Value: v}} }

func TestEvaluate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := testCA(t, now.Add(-time.Hour), now.AddDate(5, 0, 0))

	type tc struct {
		name    string
		key     pki.KeySpec
		subject []pki.DNAttr
		sans    string
		csr     func(t *testing.T) []byte // overrides key/subject/sans
		cfg     func(c *Config)
		ca      *x509.Certificate
		noCA    bool
		want    []string // "field: reason substring"; none means accepted
		check   func(t *testing.T, d Decision)
	}
	subjectIs := func(want ...pki.DNAttr) func(*testing.T, Decision) {
		return func(t *testing.T, d Decision) {
			t.Helper()
			if !reflect.DeepEqual(d.Subject, want) {
				t.Errorf("subject = %v, want %v", d.Subject, want)
			}
		}
	}
	sansAre := func(want string) func(*testing.T, Decision) {
		return func(t *testing.T, d Decision) {
			t.Helper()
			if d.Ext.SubAltName != want {
				t.Errorf("SAN = %q, want %q", d.Ext.SubAltName, want)
			}
		}
	}
	kuIs := func(want int) func(*testing.T, Decision) {
		return func(t *testing.T, d Decision) {
			t.Helper()
			if d.Ext.KeyUse != want {
				t.Errorf("key usage = %#x, want %#x", d.Ext.KeyUse, want)
			}
		}
	}
	keyAlgIs := func(want string) func(*testing.T, Decision) {
		return func(t *testing.T, d Decision) {
			t.Helper()
			if d.KeyAlg != want {
				t.Errorf("KeyAlg = %q, want %q", d.KeyAlg, want)
			}
		}
	}

	tests := []tc{
		// Keys.
		{name: "RSA 2048 accepted", key: rsa2048, subject: cn("dev1"),
			check: func(t *testing.T, d Decision) {
				keyAlgIs("RSA:2048")(t, d)
				kuIs(kuDigitalSignature|kuKeyEncipherment)(t, d)
				if d.Hash != "sha256" {
					t.Errorf("hash = %q", d.Hash)
				}
				if !reflect.DeepEqual(d.Ext.EKU, []string{"clientAuth"}) || d.Ext.CA != 2 {
					t.Errorf("ext = %+v", d.Ext)
				}
			}},
		{name: "RSA below minimum", key: rsa2048, subject: cn("dev1"), cfg: func(c *Config) { c.Keys.RSAMinBits = 3072 },
			want: []string{"key: at least 3072"}},
		{name: "RSA 3072 accepted", key: rsa3072, subject: cn("dev1"), cfg: func(c *Config) { c.Keys.RSAMinBits = 3072 },
			check: keyAlgIs("RSA:3072")},
		{name: "RSA above maximum", key: rsa3072, subject: cn("dev1"), cfg: func(c *Config) { c.Keys.RSAMaxBits = 2048 },
			want: []string{"key: at most 2048"}},
		{name: "RSA not allowed", key: rsa2048, subject: cn("dev1"), cfg: func(c *Config) { c.Keys.RSAMinBits = 0 },
			want: []string{"key: RSA keys are not allowed"}},
		{name: "EC P-256 accepted", key: ecP256, subject: cn("dev1"),
			check: func(t *testing.T, d Decision) {
				keyAlgIs("EC:P-256")(t, d)
				kuIs(kuDigitalSignature|kuKeyAgreement)(t, d)
			}},
		{name: "EC P-521 refused", key: ecP521, subject: cn("dev1"), want: []string{"key: EC keys on P-521"}},
		{name: "EC P-521 allowed", key: ecP521, subject: cn("dev1"), cfg: func(c *Config) { c.Keys.ECCurves = []string{"P-521"} },
			check: keyAlgIs("EC:P-521")},
		{name: "Ed25519 refused", key: ed25519, subject: cn("dev1"), want: []string{"key: Ed25519 keys are not allowed"}},
		{name: "Ed25519 allowed", key: ed25519, subject: cn("dev1"), cfg: func(c *Config) { c.Keys.EdDSA = []string{"Ed25519"} },
			check: func(t *testing.T, d Decision) {
				keyAlgIs("Ed25519")(t, d)
				kuIs(kuDigitalSignature)(t, d)
			}},
		{name: "ML-DSA-65 refused", key: mldsa65, subject: cn("dev1"), want: []string{"key: ML-DSA-65 keys are not allowed"}},
		{name: "ML-DSA-65 allowed", key: mldsa65, subject: cn("dev1"), cfg: func(c *Config) { c.Keys.MLDSA = []string{"ML-DSA-65"} },
			check: func(t *testing.T, d Decision) {
				keyAlgIs("ML-DSA:ML-DSA-65")(t, d)
				kuIs(kuDigitalSignature)(t, d)
			}},
		{name: "KU emptied by key falls back to digitalSignature", key: ed25519, subject: cn("dev1"),
			cfg:   func(c *Config) { c.Keys.EdDSA = []string{"Ed25519"}; c.Profile.Ext.KeyUse = kuKeyEncipherment },
			check: kuIs(kuDigitalSignature)},

		// Signatures.
		{name: "bad CSR signature", csr: func(t *testing.T) []byte {
			der := testCSR(t, ecP256, cn("dev1"), "")
			der = append([]byte(nil), der...)
			der[len(der)-1] ^= 0xff
			return der
		}, want: []string{"signature: invalid"}},
		{name: "SHA-1 CSR", csr: func(t *testing.T) []byte { return sha1CSR(t, cn("dev1")) },
			want: []string{"signature: signed with SHA-1"}},
		{name: "hash below minimum", key: ecP256, subject: cn("dev1"), cfg: func(c *Config) { c.Keys.MinCSRHash = "SHA-384" },
			want: []string{"signature: at least SHA-384"}},
		{name: "garbage", csr: func(*testing.T) []byte { return []byte("not a csr") }, want: []string{"csr: cannot parse"}},

		// Subject.
		{name: "CN required", key: ecP256, subject: []pki.DNAttr{{Name: "O", Value: "Acme"}},
			want: []string{"subject.CN: CN is required", "subject: empty"}},
		{name: "CN pattern", key: ecP256, subject: cn("printer-7"),
			cfg:  func(c *Config) { c.Subject.Rules[0].Pattern = `dev[0-9]+` },
			want: []string{`subject.CN: "printer-7" does not match`}},
		{name: "CN pattern is anchored", key: ecP256, subject: cn("xdev1x"),
			cfg:  func(c *Config) { c.Subject.Rules[0].Pattern = `dev[0-9]+` },
			want: []string{`subject.CN: "xdev1x" does not match`}},
		{name: "CN pattern matches", key: ecP256, subject: cn("dev12"),
			cfg:   func(c *Config) { c.Subject.Rules[0].Pattern = `dev[0-9]+` },
			check: subjectIs(pki.DNAttr{Name: "CN", Value: "dev12"})},
		{name: "unlisted dropped", key: ecP256,
			subject: []pki.DNAttr{{Name: "C", Value: "DE"}, {Name: "O", Value: "Acme"}, {Name: "CN", Value: "dev1"}},
			check:   subjectIs(pki.DNAttr{Name: "CN", Value: "dev1"})},
		{name: "unlisted rejected", key: ecP256,
			subject: []pki.DNAttr{{Name: "C", Value: "DE"}, {Name: "CN", Value: "dev1"}},
			cfg:     func(c *Config) { c.Subject.Unlisted = UnlistedReject },
			want:    []string{"subject.C: not allowed"}},
		{name: "optional present and absent", key: ecP256,
			subject: []pki.DNAttr{{Name: "OU", Value: "Lab"}, {Name: "CN", Value: "dev1"}},
			cfg: func(c *Config) {
				c.Subject.Rules = append(c.Subject.Rules, DNRule{Attr: "O", Mode: ModeOptional}, DNRule{Attr: "OU", Mode: ModeOptional, Pattern: "Lab|Ops"})
			},
			check: subjectIs(pki.DNAttr{Name: "CN", Value: "dev1"}, pki.DNAttr{Name: "OU", Value: "Lab"})},
		{name: "optional pattern", key: ecP256,
			subject: []pki.DNAttr{{Name: "OU", Value: "Sales"}, {Name: "CN", Value: "dev1"}},
			cfg: func(c *Config) {
				c.Subject.Rules = append(c.Subject.Rules, DNRule{Attr: "OU", Mode: ModeOptional, Pattern: "Lab|Ops"})
			},
			want: []string{`subject.OU: "Sales" does not match`}},
		{name: "fixed overrides CSR", key: ecP256,
			subject: []pki.DNAttr{{Name: "O", Value: "Evil"}, {Name: "CN", Value: "dev1"}},
			cfg: func(c *Config) {
				c.Subject.Rules = append([]DNRule{{Attr: "O", Mode: ModeFixed, Value: "Acme"}}, c.Subject.Rules...)
			},
			check: subjectIs(pki.DNAttr{Name: "O", Value: "Acme"}, pki.DNAttr{Name: "CN", Value: "dev1"})},
		{name: "fixed from profile subject", key: ecP256,
			subject: []pki.DNAttr{{Name: "C", Value: "US"}, {Name: "CN", Value: "dev1"}},
			cfg:     func(c *Config) { c.Profile.Subject = []pki.DNAttr{{Name: "countryName", Value: "DE"}} },
			check:   subjectIs(pki.DNAttr{Name: "CN", Value: "dev1"}, pki.DNAttr{Name: "C", Value: "DE"})},
		{name: "forbidden", key: ecP256,
			subject: []pki.DNAttr{{Name: "emailAddress", Value: "a@example.com"}, {Name: "CN", Value: "dev1"}},
			cfg: func(c *Config) {
				c.Subject.Rules = append(c.Subject.Rules, DNRule{Attr: "emailAddress", Mode: ModeForbidden})
			},
			want: []string{"subject.emailAddress: emailAddress is not allowed"}},
		{name: "long attribute names match", key: ecP256, subject: cn("dev1"),
			cfg:   func(c *Config) { c.Subject.Rules = []DNRule{{Attr: "commonName", Mode: ModeRequired}} },
			check: subjectIs(pki.DNAttr{Name: "CN", Value: "dev1"})},

		// SANs.
		{name: "DNS suffix", key: ecP256, subject: cn("dev1"), sans: "DNS:a.example.com, DNS:B.c.Example.com",
			check: sansAre("DNS:a.example.com, DNS:b.c.example.com")},
		{name: "DNS apex not below suffix", key: ecP256, subject: cn("dev1"), sans: "DNS:example.com",
			want: []string{`san.DNS: "example.com" is not an allowed`}},
		{name: "DNS lookalike", key: ecP256, subject: cn("dev1"), sans: "DNS:evilexample.com",
			want: []string{`san.DNS: "evilexample.com" is not an allowed`}},
		{name: "DNS exact", key: ecP256, subject: cn("dev1"), sans: "DNS:example.com",
			cfg:   func(c *Config) { c.SAN.DNS.Patterns = []string{"example.com"} },
			check: sansAre("DNS:example.com")},
		{name: "DNS disabled", key: ecP256, subject: cn("dev1"), sans: "DNS:a.example.com",
			cfg:  func(c *Config) { c.SAN.DNS.Enabled = false },
			want: []string{"san.DNS: DNS names are not allowed"}},
		{name: "DNS invalid host name", key: ecP256, subject: cn("dev1"), sans: "DNS:a_b.example.com",
			want: []string{"san.DNS: \"a_b.example.com\" is not a valid host name"}},
		{name: "wildcard refused", key: ecP256, subject: cn("dev1"), sans: "DNS:*.a.example.com",
			want: []string{"san.DNS: the wildcard name"}},
		{name: "wildcard allowed", key: ecP256, subject: cn("dev1"), sans: "DNS:*.a.example.com",
			cfg:   func(c *Config) { c.SAN.Wildcards = true },
			check: sansAre("DNS:*.a.example.com")},
		{name: "wildcard of the suffix itself", key: ecP256, subject: cn("dev1"), sans: "DNS:*.example.com",
			cfg:   func(c *Config) { c.SAN.Wildcards = true },
			check: sansAre("DNS:*.example.com")},
		{name: "wildcard outside the suffix", key: ecP256, subject: cn("dev1"), sans: "DNS:*.com",
			cfg:  func(c *Config) { c.SAN.Wildcards = true },
			want: []string{`san.DNS: "*.com" is not an allowed`}},
		{name: "IP in CIDR", key: ecP256, subject: cn("dev1"), sans: "IP:10.1.2.3, IP:2001:db8::1",
			cfg:   func(c *Config) { c.SAN.IP = IPRule{Enabled: true, CIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}} },
			check: sansAre("IP:10.1.2.3, IP:2001:db8::1")},
		{name: "IP outside CIDR", key: ecP256, subject: cn("dev1"), sans: "IP:192.168.1.1",
			cfg:  func(c *Config) { c.SAN.IP = IPRule{Enabled: true, CIDRs: []string{"10.0.0.0/8"}} },
			want: []string{"san.IP: 192.168.1.1 is not in an allowed network"}},
		{name: "IP disabled", key: ecP256, subject: cn("dev1"), sans: "IP:10.1.2.3",
			want: []string{"san.IP: IP addresses are not allowed"}},
		{name: "email domain", key: ecP256, subject: cn("dev1"), sans: "email:alice@Example.COM",
			cfg:   func(c *Config) { c.SAN.Email = EmailRule{Enabled: true, Domains: []string{"example.com"}} },
			check: sansAre("email:alice@example.com")},
		{name: "email wrong domain", key: ecP256, subject: cn("dev1"), sans: "email:alice@example.org",
			cfg:  func(c *Config) { c.SAN.Email = EmailRule{Enabled: true, Domains: []string{"example.com"}} },
			want: []string{"san.email: the domain of"}},
		{name: "URI prefix", key: ecP256, subject: cn("dev1"), sans: "URI:spiffe://example.com/dev1",
			cfg:   func(c *Config) { c.SAN.URI = URIRule{Enabled: true, Prefixes: []string{"spiffe://example.com/"}} },
			check: sansAre("URI:spiffe://example.com/dev1")},
		{name: "URI wrong prefix", key: ecP256, subject: cn("dev1"), sans: "URI:spiffe://evil.com/dev1",
			cfg:  func(c *Config) { c.SAN.URI = URIRule{Enabled: true, Prefixes: []string{"spiffe://example.com/"}} },
			want: []string{"san.URI: \"spiffe://evil.com/dev1\" does not start"}},
		{name: "unsupported SAN type", key: ecP256, subject: cn("dev1"), sans: "RID:1.2.3.4",
			want: []string{"san: RID names are not supported"}},
		{name: "too many SANs", key: ecP256, subject: cn("dev1"), sans: "DNS:a.example.com, DNS:b.example.com, DNS:c.example.com",
			cfg:  func(c *Config) { c.SAN.Max = 2 },
			want: []string{"san: the request has 3 SANs, at most 2"}},
		{name: "CopyCN", key: ecP256, subject: cn("dev1.example.com"), sans: "DNS:a.example.com",
			cfg:   func(c *Config) { c.SAN.CopyCN = true },
			check: sansAre("DNS:a.example.com, DNS:dev1.example.com")},
		{name: "CopyCN does not duplicate", key: ecP256, subject: cn("Dev1.example.com"), sans: "DNS:dev1.example.com",
			cfg:   func(c *Config) { c.SAN.CopyCN = true },
			check: sansAre("DNS:dev1.example.com")},
		{name: "CopyCN skips names failing the DNS rules", key: ecP256, subject: cn("dev1.example.org"),
			cfg:   func(c *Config) { c.SAN.CopyCN = true },
			check: sansAre("")},
		{name: "CopyCN skips non host names", key: ecP256, subject: cn("Device 1"),
			cfg:   func(c *Config) { c.SAN.CopyCN = true },
			check: sansAre("")},
		{name: "fixed SANs appended", key: ecP256, subject: cn("dev1"), sans: "DNS:a.example.com",
			cfg:   func(c *Config) { c.Profile.Ext.SubAltName = "DNS:static.example.net, DNS:a.example.com, DNS:copycn" },
			check: sansAre("DNS:a.example.com, DNS:static.example.net")},

		// Validity.
		{name: "validity from profile", key: ecP256, subject: cn("dev1"),
			check: func(t *testing.T, d Decision) {
				if !d.NotBefore.Equal(now) || !d.NotAfter.Equal(now.AddDate(1, 0, 0)) {
					t.Errorf("validity = %s .. %s", d.NotBefore, d.NotAfter)
				}
			}},
		{name: "validity in days at midnight", key: ecP256, subject: cn("dev1"),
			cfg: func(c *Config) { c.Profile.Validity = tmpl.Validity{N: 30, Unit: 0, Midnight: true} },
			check: func(t *testing.T, d Decision) {
				na := now.AddDate(0, 0, 30)
				if d.NotBefore.Hour() != 0 || d.NotBefore.Minute() != 0 ||
					!d.NotAfter.Equal(time.Date(na.Year(), na.Month(), na.Day(), 23, 59, 59, 0, time.UTC)) {
					t.Errorf("validity = %s .. %s", d.NotBefore, d.NotAfter)
				}
			}},
		{name: "validity capped at CA", key: ecP256, subject: cn("dev1"), ca: testCA(t, now.Add(-time.Hour), now.AddDate(0, 0, 30)),
			check: func(t *testing.T, d Decision) {
				if !d.NotAfter.Equal(now.AddDate(0, 0, 30)) {
					t.Errorf("not after = %s, want the CA's", d.NotAfter)
				}
			}},
		{name: "no expiry capped at CA", key: ecP256, subject: cn("dev1"),
			cfg: func(c *Config) { c.Profile.Validity = tmpl.Validity{NoExpiry: true} },
			check: func(t *testing.T, d Decision) {
				if !d.NotAfter.Equal(ca.NotAfter) {
					t.Errorf("not after = %s, want %s", d.NotAfter, ca.NotAfter)
				}
			}},
		{name: "CA expired", key: ecP256, subject: cn("dev1"), ca: testCA(t, now.AddDate(-2, 0, 0), now.AddDate(0, 0, -1)),
			want: []string{"validity: the CA expired"}},
		{name: "no CA", key: ecP256, subject: cn("dev1"), noCA: true, want: []string{"ca: no issuing CA"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			if tt.cfg != nil {
				tt.cfg(&cfg)
			}
			var der []byte
			if tt.csr != nil {
				der = tt.csr(t)
			} else {
				der = testCSR(t, tt.key, tt.subject, tt.sans)
			}
			useCA := ca
			if tt.ca != nil {
				useCA = tt.ca
			}
			if tt.noCA {
				useCA = nil
			}
			d, vs := Evaluate(cfg, useCA, der, now)
			if len(tt.want) == 0 {
				if len(vs) > 0 {
					t.Fatalf("refused: %v", vs)
				}
				if tt.check != nil {
					tt.check(t, d)
				}
				return
			}
			if !reflect.DeepEqual(d, Decision{}) {
				t.Errorf("decision set despite violations: %+v", d)
			}
			for _, w := range tt.want {
				field, reason, _ := strings.Cut(w, ": ")
				found := false
				for _, v := range vs {
					found = found || v.Field == field && strings.Contains(v.Reason, reason)
				}
				if !found {
					t.Errorf("want violation %q, got %v", w, vs)
				}
			}
		})
	}
}

func TestCheckKeyExponent(t *testing.T) {
	key := testKey(t, rsa2048).(*rsa.PrivateKey)
	k := Default().Keys
	for _, e := range []int{3, 65538, 65537, 65539} {
		spki, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: key.N, E: e})
		if err != nil {
			t.Fatal(err)
		}
		_, reason := checkKey(k, spki)
		ok := e == 65537 || e == 65539
		if ok != (reason == "") {
			t.Errorf("exponent %d: reason %q", e, reason)
		}
	}
}

func TestRequestHash(t *testing.T) {
	for _, tt := range []struct {
		spec pki.KeySpec
		hash string
		want string
	}{
		{rsa2048, "sha256", "SHA-256"},
		{rsa2048, "sha512-pss", "SHA-512"},
		{ecP256, "sha384", "SHA-384"},
		{ed25519, "", ""},
		{mldsa65, "", ""},
	} {
		der := csrWith(t, testKey(t, tt.spec), cn("x"), "", tt.hash)
		got, err := requestHash(der)
		if err != nil || got != tt.want {
			t.Errorf("%v %s: %q, %v; want %q", tt.spec, tt.hash, got, err, tt.want)
		}
	}
	if got, _ := requestHash(sha1CSR(t, cn("x"))); got != "SHA-1" {
		t.Errorf("SHA-1 CSR: %q", got)
	}
}

func TestValidate(t *testing.T) {
	if r := testConfig().Validate(); len(r) > 0 {
		t.Fatalf("test config: %v", r)
	}
	if r := Default().Validate(); len(r) != 2 {
		t.Errorf("default without credentials: %v", r)
	}
	for _, tt := range []struct {
		name string
		mod  func(c *Config)
		want string
	}{
		{"version", func(c *Config) { c.Version = 7 }, "version 7"},
		{"user", func(c *Config) { c.Auth.User = " " }, "no user name"},
		{"password", func(c *Config) { c.Auth.PassHash = "" }, "no password"},
		{"no key type", func(c *Config) { c.Keys = KeyRules{} }, "no key type"},
		{"RSA min above max", func(c *Config) { c.Keys.RSAMinBits, c.Keys.RSAMaxBits = 4096, 2048 }, "above the maximum"},
		{"RSA too small", func(c *Config) { c.Keys.RSAMinBits = 1024 }, "below 2048"},
		{"unknown curve", func(c *Config) { c.Keys.ECCurves = []string{"P-192"} }, `unknown EC curve "P-192"`},
		{"unknown EdDSA", func(c *Config) { c.Keys.EdDSA = []string{"X25519"} }, `unknown EdDSA algorithm "X25519"`},
		{"unknown ML-DSA", func(c *Config) { c.Keys.MLDSA = []string{"ML-KEM-768"} }, "unknown ML-DSA parameter set"},
		{"unknown SLH-DSA", func(c *Config) { c.Keys.SLHDSA = []string{"SHA2-128s"} }, "unknown SLH-DSA parameter set"},
		{"unknown composite", func(c *Config) { c.Keys.Composite = []string{"MLKEM768-X25519-SHA3-256"} }, "unknown composite"},
		{"weak hash", func(c *Config) { c.Keys.MinCSRHash = "SHA-1" }, "minimum CSR hash"},
		{"unlisted", func(c *Config) { c.Subject.Unlisted = "keep" }, "unlisted"},
		{"bad regex", func(c *Config) { c.Subject.Rules[0].Pattern = "(" }, "bad pattern"},
		{"bad mode", func(c *Config) { c.Subject.Rules[0].Mode = "maybe" }, "unknown mode"},
		{"unknown attr", func(c *Config) { c.Subject.Rules[0].Attr = "favouriteColour" }, "unknown subject attribute"},
		{"duplicate rule", func(c *Config) {
			c.Subject.Rules = append(c.Subject.Rules, DNRule{Attr: "commonName", Mode: ModeOptional})
		}, "more than one rule"},
		{"fixed without value", func(c *Config) { c.Subject.Rules[0].Mode = ModeFixed }, "no value"},
		{"bad DNS pattern", func(c *Config) { c.SAN.DNS.Patterns = []string{"*.exa mple.com"} }, "bad DNS pattern"},
		{"DNS without patterns", func(c *Config) { c.SAN.DNS.Patterns = nil }, "without patterns"},
		{"bad CIDR", func(c *Config) { c.SAN.IP = IPRule{Enabled: true, CIDRs: []string{"10.0.0.0/33"}} }, "bad CIDR"},
		{"bad email domain", func(c *Config) { c.SAN.Email = EmailRule{Enabled: true, Domains: []string{"@example.com"}} }, "bad e-mail domain"},
		{"bad URI prefix", func(c *Config) { c.SAN.URI = URIRule{Enabled: true, Prefixes: []string{"example.com"}} }, "bad URI prefix"},
		{"negative max", func(c *Config) { c.SAN.Max = -1 }, "must not be negative"},
		{"CA profile", func(c *Config) { c.Profile.Ext.CA = 1 }, "CA certificates"},
		{"cert signing", func(c *Config) { c.Profile.Ext.KeyUse |= kuKeyCertSign }, "signing certificates"},
		{"copycn in profile", func(c *Config) { c.Profile.Ext.SubAltName = "DNS:copycn" }, "CN copy option"},
		{"no validity", func(c *Config) { c.Profile.Validity = tmpl.Validity{} }, "no validity"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := testConfig()
			tt.mod(&c)
			r := c.Validate()
			if !strings.Contains(strings.Join(r, "\n"), tt.want) {
				t.Errorf("want %q in %q", tt.want, r)
			}
		})
	}
	// Every name the key picker offers for signatures validates.
	c := testConfig()
	c.Keys.ECCurves, c.Keys.EdDSA, c.Keys.MLDSA, c.Keys.SLHDSA, c.Keys.Composite = validCurves, validEdDSA, validMLDSA, validSLHDSA, validComposite
	if r := c.Validate(); len(r) > 0 {
		t.Errorf("all key names: %v", r)
	}
}

func TestConfigJSON(t *testing.T) {
	c := testConfig()
	c.Version = 0
	c.SAN.IP = IPRule{Enabled: true, CIDRs: []string{"10.0.0.0/8"}}
	c.Subject.Rules = append(c.Subject.Rules, DNRule{Attr: "O", Mode: ModeFixed, Value: "Acme"})
	b, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	c.Version = Version
	if !reflect.DeepEqual(got, c) {
		t.Errorf("round trip:\n got %+v\nwant %+v", got, c)
	}
	if _, err := Parse([]byte(`{"version":2}`)); err == nil {
		t.Error("version 2 accepted")
	}
	if _, err := Parse([]byte(`{`)); err == nil {
		t.Error("bad JSON accepted")
	}
}

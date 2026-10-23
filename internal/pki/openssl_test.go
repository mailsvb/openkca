package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The example SLH-DSA-SHA2-128s key of RFC 9909, Appendix C.
const (
	rfc9909Public = `-----BEGIN PUBLIC KEY-----
MDAwCwYJYIZIAWUDBAMUAyEAK4EJ7Hd8qk4fAkzPz5SX2ZGAUJKA9CVq8rB6+AKJ
tJQ=
-----END PUBLIC KEY-----`
	rfc9909Private = `-----BEGIN PRIVATE KEY-----
MFICAQAwCwYJYIZIAWUDBAMUBECiJjvKRYYINlIxYASVI9YhZ3+tkNUetgZ6Mn4N
HmSlASuBCex3fKpOHwJMz8+Ul9mRgFCSgPQlavKwevgCibSU
-----END PRIVATE KEY-----`
)

func pemBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		t.Fatal("bad PEM")
	}
	return b.Bytes
}

// TestSLHDSARFC9909 checks the SLH-DSA private key form (the raw octets in
// privateKey) against the RFC's example; OpenSSL 3.0 has no SLH-DSA.
func TestSLHDSARFC9909(t *testing.T) {
	spkiDER, skDER := pemBytes(t, rfc9909Public), pemBytes(t, rfc9909Private)
	sk, err := ParsePKCS8(skDER)
	if err != nil {
		t.Fatal(err)
	}
	if KeyAlgorithm(sk) != "SLH-DSA-SHA2-128s" {
		t.Fatalf("parameter set %s", KeyAlgorithm(sk))
	}
	if back, err := MarshalPKCS8(sk); err != nil || !bytes.Equal(back, skDER) {
		t.Fatalf("PKCS#8 round trip: %v", err)
	}
	if spki, err := MarshalPublicKey(sk.Public()); err != nil || !bytes.Equal(spki, spkiDER) {
		t.Fatalf("public key: %v", err)
	}
	pub, err := ParsePublicKey(spkiDER)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("RFC 9909")
	sig, err := sk.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(pub, pkix.AlgorithmIdentifier{Algorithm: SLHDSAParamSets[0].OID}, msg, sig); err != nil {
		t.Fatal(err)
	}
}

type openssl struct {
	t   *testing.T
	dir string
}

func needOpenSSL(t *testing.T) *openssl {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("no openssl")
	}
	return &openssl{t, t.TempDir()}
}

func (o *openssl) run(args ...string) []byte {
	o.t.Helper()
	cmd := exec.Command("openssl", args...)
	cmd.Dir = o.dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if e, ok := err.(*exec.ExitError); ok {
			stderr = string(e.Stderr)
		}
		o.t.Fatalf("openssl %v: %v\n%s%s", args, err, out, stderr)
	}
	return out
}

func (o *openssl) write(name, typ string, der []byte) string {
	o.t.Helper()
	if err := os.WriteFile(filepath.Join(o.dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		o.t.Fatal(err)
	}
	return name
}

// TestOpenSSLKeys reads keys OpenSSL generates and has OpenSSL read ours,
// for the new types OpenSSL 3.0 knows.
func TestOpenSSLKeys(t *testing.T) {
	o := needOpenSSL(t)
	cases := []struct {
		name string
		gen  []string
		spec KeySpec
	}{
		{"Ed448", []string{"-algorithm", "ed448"}, KeySpec{Type: "Ed448"}},
		{"X448", []string{"-algorithm", "x448"}, KeySpec{Type: "X448"}},
		{"RSA-PSS", []string{"-algorithm", "RSA-PSS", "-pkeyopt", "rsa_keygen_bits:2048"}, KeySpec{Type: "RSA-PSS", Bits: 2048}},
		{"RSA-PSS-SHA256", []string{"-algorithm", "RSA-PSS", "-pkeyopt", "rsa_keygen_bits:2048",
			"-pkeyopt", "rsa_pss_keygen_md:sha256", "-pkeyopt", "rsa_pss_keygen_mgf1_md:sha256", "-pkeyopt", "rsa_pss_keygen_saltlen:32"}, KeySpec{}},
		{"brainpoolP256r1", []string{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP256r1"}, KeySpec{Type: "EC", Curve: "brainpoolP256r1"}},
		{"brainpoolP384r1", []string{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP384r1"}, KeySpec{Type: "EC", Curve: "brainpoolP384r1"}},
		{"brainpoolP512r1", []string{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP512r1"}, KeySpec{Type: "EC", Curve: "brainpoolP512r1"}},
		{"secp256k1", []string{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:secp256k1"}, KeySpec{Type: "EC", Curve: "secp256k1"}},
	}
	for _, c := range cases {
		// OpenSSL's key: we read it, re-encode it unchanged and derive
		// the same public key
		o.run(append([]string{"genpkey", "-out", "k.pem"}, c.gen...)...)
		der := o.run("pkcs8", "-topk8", "-nocrypt", "-in", "k.pem", "-outform", "DER")
		key, err := ParsePKCS8(der)
		if err != nil {
			t.Fatalf("%s: parse OpenSSL's key: %v", c.name, err)
		}
		if back, err := MarshalPKCS8(key); err != nil || !bytes.Equal(back, der) {
			t.Errorf("%s: PKCS#8 differs from OpenSSL's: %v", c.name, err)
		}
		spki := o.run("pkey", "-in", "k.pem", "-pubout", "-outform", "DER")
		if mine, err := MarshalPublicKey(key.Public()); err != nil || !bytes.Equal(mine, spki) {
			t.Errorf("%s: public key differs from OpenSSL's: %v", c.name, err)
		}
		if _, err := ParsePublicKey(spki); err != nil {
			t.Errorf("%s: parse OpenSSL's public key: %v", c.name, err)
		}
		if c.name == "RSA-PSS-SHA256" {
			if p := key.(RSAPSSKey).Params; p == nil || *p != (PSSParams{crypto.SHA256, 32}) {
				t.Errorf("%s: parameters %v", c.name, p)
			}
		}
		if c.spec.Type == "" {
			continue
		}

		// our key: OpenSSL reads it and derives the same public key
		mine, err := GenerateKey(c.spec)
		if err != nil {
			t.Fatal(err)
		}
		pk8, _ := MarshalPKCS8(mine)
		o.write("mine.pem", "PRIVATE KEY", pk8)
		spki = o.run("pkey", "-in", "mine.pem", "-pubout", "-outform", "DER")
		if want, _ := MarshalPublicKey(mine.Public()); !bytes.Equal(spki, want) {
			t.Errorf("%s: OpenSSL derives another public key from ours", c.name)
		}
	}
}

// TestOpenSSLVerifies has OpenSSL verify certificates, requests and CRLs
// signed with the new key types and the PSS hash choices.
func TestOpenSSLVerifies(t *testing.T) {
	o := needOpenSSL(t)
	restricted, _ := GenerateKey(KeySpec{Type: "RSA-PSS", Bits: 2048})
	rk := restricted.(RSAPSSKey)
	rk.Params = &PSSParams{crypto.SHA384, 48}
	rsaKey, _ := GenerateKey(KeySpec{Type: "RSA", Bits: 2048})
	cases := []struct {
		name string
		key  crypto.Signer
		hash string
	}{
		{"rsa-pss-hash", rsaKey, "sha512-pss"},
		{"rsa-pss-key", nil, "sha256"},
		{"rsa-pss-restricted", rk, "sha256"},
		{"ed448", nil, ""},
		{"bp256", nil, "sha256"},
		{"bp384", nil, "sha384"},
		{"bp512", nil, "sha512"},
		{"k256", nil, "sha256"},
	}
	specs := map[string]KeySpec{"rsa-pss-key": {Type: "RSA-PSS", Bits: 2048}, "ed448": {Type: "Ed448"},
		"bp256": {Type: "EC", Curve: "brainpoolP256r1"}, "bp384": {Type: "EC", Curve: "brainpoolP384r1"},
		"bp512": {Type: "EC", Curve: "brainpoolP512r1"}, "k256": {Type: "EC", Curve: "secp256k1"}}
	x448, _ := GenerateKey(KeySpec{Type: "X448"})
	x448SPKI, _ := MarshalPublicKey(x448.Public())
	for _, c := range cases {
		key := c.key
		if key == nil {
			key, _ = GenerateKey(specs[c.name])
		}
		ca, _ := selfSigned(t, key, c.name, c.hash)
		caFile := o.write(c.name+".crt", "CERTIFICATE", ca.Raw)
		o.run("verify", "-CAfile", caFile, caFile)

		leaf := issueFromSPKI(t, x448SPKI, ca, key, c.hash)
		o.run("verify", "-CAfile", caFile, o.write(c.name+"-leaf.crt", "CERTIFICATE", leaf.Raw))

		csr, err := CreateRequest(mustName(t, "CN", c.name), nil, key, c.hash)
		if err != nil {
			t.Fatal(err)
		}
		o.run("req", "-verify", "-noout", "-in", o.write(c.name+".csr", "CERTIFICATE REQUEST", csr))

		now := time.Now().Truncate(time.Second)
		crl, err := CreateCRL(CRLParams{Issuer: ca, Key: key, Hash: c.hash, ThisUpdate: now, NextUpdate: now.Add(time.Hour),
			Number: big.NewInt(3), AuthKeyID: true, Revoked: []Revoked{{Serial: big.NewInt(2), Date: now}}})
		if err != nil {
			t.Fatal(err)
		}
		o.run("crl", "-noout", "-CAfile", caFile, "-in", o.write(c.name+".crl", "X509 CRL", crl))
	}

	// a certificate OpenSSL signs with an RSA-PSS key and a Brainpool key
	// verifies here
	for _, gen := range [][]string{
		{"-algorithm", "RSA-PSS", "-pkeyopt", "rsa_keygen_bits:2048"},
		{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP384r1"},
		{"-algorithm", "ed448"},
	} {
		o.run(append([]string{"genpkey", "-out", "o.key"}, gen...)...)
		o.run("req", "-x509", "-new", "-key", "o.key", "-subj", "/CN=openssl", "-days", "1", "-out", "o.crt")
		b, _ := os.ReadFile(filepath.Join(o.dir, "o.crt"))
		p, _ := pem.Decode(b)
		c, err := ParseCertificate(p.Bytes)
		if err != nil {
			t.Fatalf("%v: %v", gen, err)
		}
		if err := CheckCertSignature(c, c); err != nil {
			t.Fatalf("%v: OpenSSL's signature: %v", gen, err)
		}
		if _, err := x509.ParseCertificate(p.Bytes); err != nil && DescribeCert(p.Bytes).ParseError != "" {
			t.Errorf("%v: not described: %s", gen, DescribeCert(p.Bytes).ParseError)
		}
	}
}

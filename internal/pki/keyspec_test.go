package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"
)

// allKeySpecs lists one KeySpec per algorithm and parameter set. The slow
// SLH-DSA "s" sets and the larger RSA sizes are left to short mode's
// absence.
func allKeySpecs(t *testing.T) []KeySpec {
	specs := []KeySpec{
		{Type: "RSA", Bits: 2048}, {Type: "RSA-PSS", Bits: 2048},
		{Type: "Ed25519"}, {Type: "Ed448"}, {Type: "X25519"}, {Type: "X448"},
	}
	for _, c := range ECCurves {
		specs = append(specs, KeySpec{Type: "EC", Curve: c.Name})
	}
	for _, p := range MLDSAParamSets {
		specs = append(specs, KeySpec{Type: "ML-DSA", Param: p.Name})
	}
	for _, p := range SLHDSAParamSets {
		if testing.Short() && strings.HasSuffix(p.Name, "s") {
			continue
		}
		specs = append(specs, KeySpec{Type: "SLH-DSA", Param: p.Name})
	}
	for _, p := range MLKEMParamSets {
		specs = append(specs, KeySpec{Type: "ML-KEM", Param: p.Name})
	}
	for _, a := range CompositeAlgs {
		specs = append(specs, KeySpec{Type: "Composite", Param: a.Name})
	}
	for _, a := range CompositeKEMAlgs {
		specs = append(specs, KeySpec{Type: "CompositeKEM", Param: a.Name})
	}
	return specs
}

func specName(s KeySpec) string {
	switch {
	case s.Param != "":
		return s.Type + "/" + s.Param
	case s.Curve != "":
		return s.Type + "/" + s.Curve
	case s.Bits != 0:
		return s.Type + "/" + big.NewInt(int64(s.Bits)).String()
	}
	return s.Type
}

// testCA is an RSA CA that certifies keys which cannot sign themselves.
var testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func caForTest(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	if testCA.cert == nil {
		key, err := GenerateKey(KeySpec{Type: "RSA", Bits: 2048})
		if err != nil {
			t.Fatal(err)
		}
		testCA.cert, testCA.key = selfSigned(t, key, "Test CA", "sha256")
	}
	return testCA.cert, testCA.key
}

func selfSigned(t *testing.T, key crypto.Signer, cn, hash string) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	subject := mustName(t, "CN", cn)
	spki, err := MarshalPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	exts, err := BuildExtensions(ExtSpec{CA: 1, BCCritical: true, SubKey: true, KeyUse: 1<<5 | 1<<6},
		ExtContext{SubjectSPKI: spki, Subject: subject, SelfSigned: true})
	if err != nil {
		t.Fatal(err)
	}
	der, err := CreateCertificate(CertRequest{Subject: subject, PublicKey: key.Public(), Serial: big.NewInt(1),
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), Extensions: exts,
		Hash: hash, SignerKey: key})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// issueFromSPKI has the issuer certify a public key given only as its
// SubjectPublicKeyInfo.
func issueFromSPKI(t *testing.T, spki []byte, issuer *x509.Certificate, key crypto.Signer, hash string) *x509.Certificate {
	t.Helper()
	subject := mustName(t, "CN", "leaf")
	exts, err := BuildExtensions(ExtSpec{CA: 2, SubKey: true, AuthKey: true, KeyUse: 1 << 2},
		ExtContext{SubjectSPKI: spki, Subject: subject, IssuerSPKI: issuer.RawSubjectPublicKeyInfo, IssuerSKI: issuer.SubjectKeyId})
	if err != nil {
		t.Fatal(err)
	}
	der, err := CreateCertificate(CertRequest{Subject: subject, SPKI: spki, Serial: big.NewInt(2),
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), Extensions: exts,
		Hash: hash, Issuer: issuer, SignerKey: key})
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.RawSubjectPublicKeyInfo, spki) {
		t.Fatal("the certificate holds another public key")
	}
	if err := CheckCertSignature(issuer, c); err != nil {
		t.Fatalf("issued certificate: %v", err)
	}
	return c
}

func TestKeySpecs(t *testing.T) {
	caForTest(t) // before the parallel subtests use it
	for _, spec := range allKeySpecs(t) {
		t.Run(specName(spec), func(t *testing.T) {
			t.Parallel()
			key, err := GenerateKey(spec)
			if err != nil {
				t.Fatal(err)
			}
			if a := KeyAlgorithm(key); strings.HasPrefix(a, "pki.") || strings.HasPrefix(a, "*") {
				t.Errorf("KeyAlgorithm %q", a)
			}

			// PKCS#8 round trip, byte for byte
			der, err := MarshalPKCS8(key)
			if err != nil {
				t.Fatal(err)
			}
			back, err := ParsePKCS8(der)
			if err != nil {
				t.Fatal(err)
			}
			if again, err := MarshalPKCS8(back); err != nil || !bytes.Equal(again, der) {
				t.Fatalf("PKCS#8 round trip: %v", err)
			}

			// SPKI round trip, byte for byte
			spki, err := MarshalPublicKey(key.Public())
			if err != nil {
				t.Fatal(err)
			}
			pub, err := ParsePublicKey(spki)
			if err != nil {
				t.Fatal(err)
			}
			if again, err := MarshalPublicKey(pub); err != nil || !bytes.Equal(again, spki) {
				t.Fatalf("SPKI round trip: %v", err)
			}
			if ok, err := MatchesPublic(back, spki); err != nil || !ok {
				t.Fatalf("the parsed private key does not match: %v", err)
			}
			if !publicEqual(back.Public(), pub) {
				t.Fatal("public keys differ")
			}

			// display
			info := DescribePublicKey(spki)
			if info.Algorithm == "" || strings.Contains(info.Algorithm, ".") || info.Bits == 0 {
				t.Errorf("described as %+v", info)
			}
			if typ, bits := StoredKeyType(spki); typ == "" || len(typ) > 4 || bits != info.Bits {
				t.Errorf("stored as %q %d", typ, bits)
			} else if KeyTypeText(typ) == "" {
				t.Error("no type text")
			}

			// the encrypted form XCA stores
			blob, err := EncryptPrivateKey(key, []byte("pw"))
			if err != nil {
				t.Fatal(err)
			}
			if dec, _, err := DecryptPrivateKey(blob, "", []byte("pw")); err != nil || !publicEqual(dec.Public(), pub) {
				t.Fatalf("encrypted round trip: %v", err)
			}

			if !CanSign(key) {
				if _, err := CreateRequest(mustName(t, "CN", "x"), nil, key, ""); err == nil {
					t.Fatal("a key that cannot sign signed a request")
				}
				ca, caKey := caForTest(t)
				issueFromSPKI(t, spki, ca, caKey, "sha256")
				return
			}

			// certificate, request and CRL, each verified
			hash := "sha384"
			if spec.Type == "RSA" {
				hash = "sha384-pss"
			}
			cert, _ := selfSigned(t, key, "self", hash)
			if err := CheckCertSignature(cert, cert); err != nil {
				t.Fatalf("certificate: %v", err)
			}
			if !bytes.Equal(cert.RawSubjectPublicKeyInfo, spki) {
				t.Fatal("certificate SPKI differs")
			}
			if spec.Type == "SLH-DSA" && strings.HasSuffix(spec.Param, "s") {
				return // slow to sign; the "f" sets take the same path below
			}
			if d := DescribeCert(cert.Raw); d.ParseError != "" || d.SigAlg == "" || d.PublicKey.Algorithm != info.Algorithm {
				t.Errorf("described certificate %q %q %q", d.ParseError, d.SigAlg, d.PublicKey.Algorithm)
			}
			issueFromSPKI(t, spki, cert, key, hash)

			csrDER, err := CreateRequest(mustName(t, "CN", "req"), nil, key, hash)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckRequestSignature(csr); err != nil {
				t.Fatalf("request: %v", err)
			}
			if d := DescribeRequest(csrDER); !d.SignatureOK || d.PublicKey.Algorithm != info.Algorithm {
				t.Errorf("described request %+v", d)
			}

			now := time.Now().Truncate(time.Second)
			crlDER, err := CreateCRL(CRLParams{Issuer: cert, Key: key, Hash: hash, ThisUpdate: now, NextUpdate: now.Add(time.Hour),
				Number: big.NewInt(1), AuthKeyID: true, Revoked: []Revoked{{Serial: big.NewInt(7), Date: now}}})
			if err != nil {
				t.Fatal(err)
			}
			crl, err := x509.ParseRevocationList(crlDER)
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckCRLSignature(cert, crl); err != nil {
				t.Fatalf("CRL: %v", err)
			}
			if d := DescribeCRL(crlDER); d.ParseError != "" || len(d.Entries) != 1 || d.SigAlg == "" {
				t.Errorf("described CRL %+v", d)
			}

			// another key's signature is rejected
			other, _ := caForTest(t)
			if CheckCertSignature(other, cert) == nil {
				t.Fatal("certificate verifies with another key")
			}
		})
	}
}

// TestPSSHashes checks the "-pss" hash choices: RSA keys sign with PSS,
// RSA-PSS keys always do, other keys ignore the suffix.
func TestPSSHashes(t *testing.T) {
	rsaKey, _ := GenerateKey(KeySpec{Type: "RSA", Bits: 2048})
	for _, h := range Hashes {
		c, _ := selfSigned(t, rsaKey, "rsa "+h, h)
		pss := strings.HasSuffix(h, "-pss")
		if got := c.SignatureAlgorithm; pss != (got == x509.SHA256WithRSAPSS || got == x509.SHA384WithRSAPSS || got == x509.SHA512WithRSAPSS) {
			t.Errorf("%s: signed with %v", h, got)
		}
		if HashName(c.SignatureAlgorithm) != h {
			t.Errorf("%s: HashName %q", h, HashName(c.SignatureAlgorithm))
		}
		if err := c.CheckSignatureFrom(c); err != nil {
			t.Errorf("%s: crypto/x509 rejects the signature: %v", h, err)
		}
	}

	pssKey, _ := GenerateKey(KeySpec{Type: "RSA-PSS", Bits: 2048})
	c, _ := selfSigned(t, pssKey, "pss", "sha512")
	if !strings.HasPrefix(SignatureAlgorithmName(c.Raw), "RSASSA-PSS (SHA-512, salt 64)") {
		t.Errorf("RSA-PSS key signed with %s", SignatureAlgorithmName(c.Raw))
	}

	// a key restricted to SHA-256 signs with its parameters whatever is asked
	k := pssKey.(RSAPSSKey)
	k.Params = &PSSParams{Hash: crypto.SHA256, SaltLength: 32}
	c, _ = selfSigned(t, k, "restricted", "sha512")
	if got := SignatureAlgorithmName(c.Raw); got != "RSASSA-PSS (SHA-256, salt 32)" {
		t.Errorf("restricted key signed with %s", got)
	}
	if info := DescribePublicKey(c.RawSubjectPublicKeyInfo); info.Algorithm != "RSA-PSS" || info.PSS != "SHA-256, salt 32" {
		t.Errorf("restricted key described as %+v", info)
	}
	pub, _ := ParsePublicKey(c.RawSubjectPublicKeyInfo)
	if !pub.(*RSAPSSPublicKey).Equal(k.Public()) {
		t.Error("restriction lost")
	}

	ecKey, _ := GenerateKey(KeySpec{Type: "EC", Curve: "P-256"})
	c, _ = selfSigned(t, ecKey, "ec", "sha384-pss")
	if c.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("EC key with sha384-pss signed with %v", c.SignatureAlgorithm)
	}
}

// TestParseLenient checks that certificates with keys crypto/x509 refuses
// keep their raw fields.
func TestParseLenient(t *testing.T) {
	key, _ := GenerateKey(KeySpec{Type: "EC", Curve: "brainpoolP384r1"})
	c, _ := selfSigned(t, key, "bp", "sha384")
	if _, err := x509.ParseCertificate(c.Raw); err == nil {
		t.Skip("crypto/x509 reads Brainpool keys now")
	}
	if c.PublicKeyAlgorithm != x509.ECDSA || !publicEqual(key.Public(), c.PublicKey) {
		t.Errorf("public key %v %T", c.PublicKeyAlgorithm, c.PublicKey)
	}
	if FormatName(c.RawSubject) != "CN=bp" || c.SerialNumber.Int64() != 1 || !c.IsCA {
		t.Errorf("fields lost: %s %v %v", FormatName(c.RawSubject), c.SerialNumber, c.IsCA)
	}
	tbs, _ := elements(c.Raw)
	if !bytes.Equal(tbs[0], c.RawTBSCertificate) {
		t.Error("RawTBSCertificate is not the original")
	}
}

// TestAutoHash checks that "auto" picks the hash from the signing key.
func TestAutoHash(t *testing.T) {
	cases := []struct {
		spec KeySpec
		want x509.SignatureAlgorithm
		name string
	}{
		{KeySpec{Type: "EC", Curve: "P-256"}, x509.ECDSAWithSHA256, "sha256"},
		{KeySpec{Type: "EC", Curve: "P-384"}, x509.ECDSAWithSHA384, "sha384"},
		{KeySpec{Type: "EC", Curve: "P-521"}, x509.ECDSAWithSHA512, "sha512"},
		{KeySpec{Type: "RSA", Bits: 2048}, x509.SHA256WithRSA, "sha256"},
		{KeySpec{Type: "Ed25519"}, x509.PureEd25519, ""},
	}
	for _, c := range cases {
		key, err := GenerateKey(c.spec)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := selfSigned(t, key, "auto", HashAuto)
		if cert.SignatureAlgorithm != c.want {
			t.Errorf("%+v: signed with %v, want %v", c.spec, cert.SignatureAlgorithm, c.want)
		}
		if got := AutoHashName(cert.RawSubjectPublicKeyInfo); got != c.name {
			t.Errorf("%+v: AutoHashName %q, want %q", c.spec, got, c.name)
		}
		if got := AutoHashNameForSpec(c.spec); got != c.name {
			t.Errorf("%+v: AutoHashNameForSpec %q, want %q", c.spec, got, c.name)
		}
	}
	if AutoHash("RSA", 8192) != crypto.SHA384 || AutoHash("RSA", 3072) != crypto.SHA256 {
		t.Error("RSA sizes map to the wrong hash")
	}
}

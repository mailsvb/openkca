package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The official test vectors of draft-ietf-lamps-pq-composite-sigs and
// draft-ietf-lamps-pq-composite-kem (trimmed to the fields used here).

type lampsSigVectors struct {
	M     string `json:"m"`
	Tests []struct {
		TcID    string `json:"tcId"`
		PK      string `json:"pk"`
		X5C     string `json:"x5c"`
		SKPKCS8 string `json:"sk_pkcs8"`
		S       string `json:"s"`
	} `json:"tests"`
}

type lampsKEMVectors struct {
	CACert string `json:"cacert"`
	Tests  []struct {
		TcID    string `json:"tcId"`
		EK      string `json:"ek"`
		X5C     string `json:"x5c"`
		DKPKCS8 string `json:"dk_pkcs8"`
	} `json:"tests"`
}

func loadJSON(t *testing.T, file string, v any) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// spkiParts returns the algorithm and the raw key bits of a DER
// SubjectPublicKeyInfo.
func spkiParts(t *testing.T, der []byte) (asn1.ObjectIdentifier, []byte) {
	t.Helper()
	var s spki
	if _, err := asn1.Unmarshal(der, &s); err != nil {
		t.Fatal(err)
	}
	return s.Algo.Algorithm, s.PublicKey.RightAlign()
}

func TestLAMPSCompositeSignatures(t *testing.T) {
	var v lampsSigVectors
	loadJSON(t, "testdata/composite-sigs.json", &v)
	msg := b64(t, v.M)
	if len(v.Tests) != len(CompositeAlgs)+len(MLDSAParamSets) {
		t.Fatalf("%d vectors", len(v.Tests))
	}
	for _, tc := range v.Tests {
		t.Run(tc.TcID, func(t *testing.T) {
			name := strings.TrimPrefix(tc.TcID, "id-")
			cert, err := ParseCertificate(b64(t, tc.X5C))
			if err != nil {
				t.Fatal(err)
			}
			oid, bits := spkiParts(t, cert.RawSubjectPublicKeyInfo)
			if !bytes.Equal(bits, b64(t, tc.PK)) {
				t.Fatal("pk is not the certificate's public key")
			}
			if a := compositeByName(name); a != nil && !a.OID.Equal(oid) {
				t.Fatalf("OID %v, want %v", oid, a.OID)
			} else if p := mldsaByName(name); a == nil && (p == nil || !p.OID.Equal(oid)) {
				t.Fatalf("unknown algorithm %s %v", name, oid)
			}
			if info := DescribePublicKey(cert.RawSubjectPublicKeyInfo); info.Algorithm != name {
				t.Errorf("described as %q", info.Algorithm)
			}

			// the private key: parse, re-encode byte for byte, matches
			skDER := b64(t, tc.SKPKCS8)
			sk, err := ParsePKCS8(skDER)
			if err != nil {
				t.Fatal(err)
			}
			if back, err := MarshalPKCS8(sk); err != nil || !bytes.Equal(back, skDER) {
				t.Fatalf("PKCS#8 round trip: %v", err)
			}
			if ok, err := MatchesPublic(sk, cert.RawSubjectPublicKeyInfo); err != nil || !ok {
				t.Fatalf("private key does not match the certificate: %v", err)
			}
			if KeyAlgorithm(sk) != name {
				t.Errorf("KeyAlgorithm %q", KeyAlgorithm(sk))
			}

			// the public key: parse and re-encode byte for byte
			pub, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
			if err != nil {
				t.Fatal(err)
			}
			if back, err := MarshalPublicKey(pub); err != nil || !bytes.Equal(back, cert.RawSubjectPublicKeyInfo) {
				t.Fatalf("SPKI round trip: %v", err)
			}

			// the signature s over m, and a forged one
			algo := pkix.AlgorithmIdentifier{Algorithm: oid}
			sig := b64(t, tc.S)
			if err := VerifySignature(pub, algo, msg, sig); err != nil {
				t.Fatalf("signature: %v", err)
			}
			bad := append([]byte(nil), sig...)
			bad[len(bad)-1] ^= 1
			if VerifySignature(pub, algo, msg, bad) == nil {
				t.Fatal("altered signature verifies")
			}
			if VerifySignature(pub, algo, append(msg, '!'), sig) == nil {
				t.Fatal("signature verifies for another message")
			}

			// the certificate is self-signed
			if err := CheckCertSignature(cert, cert); err != nil {
				t.Fatalf("self-signature: %v", err)
			}
			if got := SignatureAlgorithmName(cert.Raw); got != name {
				t.Errorf("signature algorithm %q", got)
			}

			// our own signature verifies
			var opts crypto.SignerOpts = crypto.Hash(0)
			if _, ok := sk.(CompositeKey); ok {
				opts = &CompositeOptions{}
			}
			own, err := sk.Sign(rand.Reader, msg, opts)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifySignature(pub, algo, msg, own); err != nil {
				t.Fatalf("own signature: %v", err)
			}
		})
	}
}

func TestLAMPSCompositeKEM(t *testing.T) {
	var v lampsKEMVectors
	loadJSON(t, "testdata/composite-kem.json", &v)
	ca, err := ParseCertificate(b64(t, v.CACert))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCertSignature(ca, ca); err != nil {
		t.Fatalf("CA self-signature: %v", err)
	}
	if len(v.Tests) != len(CompositeKEMAlgs)+2 {
		t.Fatalf("%d vectors", len(v.Tests))
	}
	for _, tc := range v.Tests {
		t.Run(tc.TcID, func(t *testing.T) {
			name := strings.TrimPrefix(tc.TcID, "id-")
			name = strings.Replace(name, "alg-ml-kem-", "ML-KEM-", 1)
			cert, err := ParseCertificate(b64(t, tc.X5C))
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckCertSignature(ca, cert); err != nil {
				t.Fatalf("signature by the CA: %v", err)
			}
			oid, bits := spkiParts(t, cert.RawSubjectPublicKeyInfo)
			ek := b64(t, tc.EK)
			if !bytes.Equal(bits, ek) {
				t.Fatal("ek is not the certificate's public key")
			}
			if a := compositeKEMByName(name); a != nil && !a.OID.Equal(oid) {
				t.Fatalf("OID %v, want %v", oid, a.OID)
			} else if p := mlkemByName(name); a == nil && (p == nil || !p.OID.Equal(oid)) {
				t.Fatalf("unknown algorithm %s %v", name, oid)
			}
			if info := DescribePublicKey(cert.RawSubjectPublicKeyInfo); info.Algorithm != name {
				t.Errorf("described as %q", info.Algorithm)
			}
			pub, err := ParsePublicKey(cert.RawSubjectPublicKeyInfo)
			if err != nil {
				t.Fatal(err)
			}
			if back, err := MarshalPublicKey(pub); err != nil || !bytes.Equal(back, cert.RawSubjectPublicKeyInfo) {
				t.Fatalf("SPKI round trip: %v", err)
			}

			// the private key re-encodes byte for byte, and its seed
			// derives ek
			dkDER := b64(t, tc.DKPKCS8)
			dk, err := ParsePKCS8(dkDER)
			if err != nil {
				t.Fatal(err)
			}
			if back, err := MarshalPKCS8(dk); err != nil || !bytes.Equal(back, dkDER) {
				t.Fatalf("PKCS#8 round trip: %v", err)
			}
			if !publicEqual(dk.Public(), pub) {
				t.Fatal("the private key does not derive ek")
			}
			if CanSign(dk) {
				t.Error("a KEM key can sign")
			}
			if KeyAlgorithm(dk) != name {
				t.Errorf("KeyAlgorithm %q", KeyAlgorithm(dk))
			}
		})
	}
}

package codec

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"github.com/mailsvb/go-ca/internal/pki"
)

// TestPGPUseNewAlgorithms signs and encrypts with keys of the algorithms
// GnuPG 2.4 does not know, through go-crypto: a secret key go-ca exports
// signs a message the certificate verifies, and decrypts a message
// encrypted to the certificate.
func TestPGPUseNewAlgorithms(t *testing.T) {
	for _, c := range pgpCases {
		if c.gnupg {
			continue
		}
		primary, sub := genKey(t, c.primary), genKey(t, c.sub)
		for _, v := range c.versions {
			cert, err := NewPGPCert(primary, []PGPSubkey{{Key: sub, Usage: PGPEncrypt}},
				PGPParams{Version: v, UIDs: []string{"New <new@example.org>"}, Created: time.Now().Add(-time.Hour)})
			if err != nil {
				t.Fatalf("%s v%d: %v", c.name, v, err)
			}
			sec, err := PGPSecret(cert, []crypto.Signer{primary, sub}, nil)
			if err != nil {
				t.Fatalf("%s v%d: secret: %v", c.name, v, err)
			}
			public, err := openpgp.ReadKeyRing(bytes.NewReader(cert))
			if err != nil {
				t.Fatalf("%s v%d: go-crypto reads the certificate: %v", c.name, v, err)
			}
			secret, err := openpgp.ReadKeyRing(bytes.NewReader(sec))
			if err != nil {
				t.Fatalf("%s v%d: go-crypto reads the secret key: %v", c.name, v, err)
			}
			msg := []byte("signed and sealed by go-ca")

			var sig bytes.Buffer
			if err := openpgp.DetachSign(&sig, secret, bytes.NewReader(msg), nil); err != nil {
				t.Fatalf("%s v%d: sign: %v", c.name, v, err)
			}
			if _, _, err := openpgp.VerifyDetachedSignature(public, bytes.NewReader(msg), &sig, nil); err != nil {
				t.Fatalf("%s v%d: verify: %v", c.name, v, err)
			}

			var enc bytes.Buffer
			w, err := openpgp.Encrypt(&enc, public, nil, nil, nil, &packet.Config{}) // nil panics on v6 recipients
			if err != nil {
				t.Fatalf("%s v%d: encrypt: %v", c.name, v, err)
			}
			w.Write(msg)
			w.Close()
			md, err := openpgp.ReadMessage(&enc, secret, nil, nil)
			if err != nil {
				t.Fatalf("%s v%d: decrypt: %v", c.name, v, err)
			}
			if got, _ := io.ReadAll(md.UnverifiedBody); !bytes.Equal(got, msg) {
				t.Fatalf("%s v%d: decrypted %q", c.name, v, got)
			}

			// import as key items: the SPKI and PKCS#8 of both keys
			r := Probe("k.gpg", sec, ProbeOptions{})
			if len(r.Objects) != 2 {
				t.Fatalf("%s v%d: imported %d objects, skipped %v", c.name, v, len(r.Objects), r.Unrecognized)
			}
			for i, k := range []crypto.Signer{primary, sub} {
				spki, _ := pki.MarshalPublicKey(k.Public())
				back, err := pki.ParsePKCS8(r.Objects[i].Private)
				if !bytes.Equal(r.Objects[i].DER, spki) || err != nil || !sameKey(back, k) {
					t.Errorf("%s v%d: imported key %d differs: %v", c.name, v, i, err)
				}
			}

			info, _ := ParsePGPCert(cert)
			for i, k := range info.Keys {
				if k.Public == nil || k.Algorithm == "" || strings.HasPrefix(k.Algorithm, "algorithm") {
					t.Errorf("%s v%d: key %d described as %q %T", c.name, v, i, k.Algorithm, k.Public)
				}
			}
		}
	}
	// the composites are v6 only, ML-KEM-1024+X448 too
	mldsa := genKey(t, pki.KeySpec{Type: "Composite", Param: "MLDSA65-Ed25519-SHA512"})
	kem1024 := genKey(t, pki.KeySpec{Type: "CompositeKEM", Param: "MLKEM1024-X448-SHA3-256"})
	if PGPCompatible(mldsa.Public(), 4, false) || !PGPCompatible(mldsa.Public(), 6, false) || PGPCompatible(mldsa.Public(), 6, true) {
		t.Error("ML-DSA composite compatibility")
	}
	if PGPCompatible(kem1024.Public(), 4, true) || !PGPCompatible(kem1024.Public(), 6, true) {
		t.Error("ML-KEM-1024+X448 compatibility")
	}
	other := genKey(t, pki.KeySpec{Type: "Composite", Param: "MLDSA44-Ed25519-SHA512"})
	if PGPCompatible(other.Public(), 6, false) {
		t.Error("a composite without an OpenPGP algorithm is compatible")
	}
}

// TestPGPRSAPrimeOrder exports an RSA key whose primes Go holds in the
// order OpenPGP forbids: the secret key must have p < q, and GnuPG must
// make good signatures with it.
func TestPGPRSAPrimeOrder(t *testing.T) {
	var key *rsa.PrivateKey
	for key == nil {
		k := genKey(t, pki.KeySpec{Type: "RSA", Bits: 2048}).(*rsa.PrivateKey)
		if k.Primes[1].Cmp(k.Primes[0]) > 0 { // written as p > q without the fix
			key = k
		}
	}
	cert, err := NewPGPCert(key, nil, PGPParams{Version: 4, UIDs: []string{"RSA <rsa@example.org>"}, Created: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	sec, err := PGPSecret(cert, []crypto.Signer{key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	el, err := openpgp.ReadKeyRing(bytes.NewReader(sec))
	if err != nil {
		t.Fatal(err)
	}
	// go-crypto reads p into Primes[1] and q into Primes[0]
	back := el[0].PrivateKey.PrivateKey.(*rsa.PrivateKey)
	if back.Primes[1].Cmp(back.Primes[0]) >= 0 {
		t.Fatal("the secret key has p > q")
	}
	if !sameKey(back, key) || back.D.Cmp(key.D) != 0 {
		t.Fatal("the secret key changed")
	}

	g := newGnuPG(t)
	g.must(sec, "--import")
	info, _ := ParsePGPCert(cert)
	msg := []byte("RSA prime order")
	sig := g.must(msg, "--local-user", info.Keys[0].Fingerprint, "--detach-sign")
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "msg"), msg, 0o600)
	os.WriteFile(filepath.Join(dir, "msg.sig"), sig, 0o600)
	g.must(nil, "--verify", filepath.Join(dir, "msg.sig"), filepath.Join(dir, "msg"))
}

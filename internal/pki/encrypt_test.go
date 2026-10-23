package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestEncryptRoundTripAndOpenSSL(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	xKey, _ := GenerateKey(KeySpec{Type: "X25519"})
	pw := []byte("pässwörd")
	for name, s := range map[string]crypto.Signer{"rsa": rsaKey, "ec": ecKey, "ed25519": edKey, "x25519": xKey} {
		blob, err := EncryptPrivateKey(s, pw)
		if err != nil {
			t.Fatal(err)
		}
		back, legacy, err := DecryptPrivateKey(blob, "", pw)
		if err != nil || legacy {
			t.Fatalf("%s: decrypt %v legacy=%v", name, err, legacy)
		}
		pub, _ := x509.MarshalPKIXPublicKey(s.Public())
		if ok, _ := MatchesPublic(back, pub); !ok {
			t.Fatalf("%s: round trip mismatch", name)
		}
		if _, _, err := DecryptPrivateKey(blob, "", []byte("wrong")); err != ErrWrongPassword {
			t.Fatalf("%s: wrong password: %v", name, err)
		}
		// OpenSSL must read what we write.
		if _, err := exec.LookPath("openssl"); err != nil {
			continue
		}
		f := filepath.Join(t.TempDir(), "k.der")
		os.WriteFile(f, blob, 0o600)
		out, err := exec.Command("openssl", "pkey", "-inform", "DER", "-in", f, "-passin", "pass:"+string(pw), "-outform", "DER").Output()
		if err != nil {
			t.Fatalf("%s: openssl pkey: %v", name, err)
		}
		k, err := parseAnyDER(out)
		if err != nil {
			t.Fatalf("%s: parse openssl output: %v", name, err)
		}
		if ok, _ := MatchesPublic(k, pub); !ok {
			t.Fatalf("%s: openssl decrypted a different key", name)
		}
	}
}

// parseAnyDER accepts the encodings openssl pkey writes for each key type.
func parseAnyDER(der []byte) (crypto.Signer, error) {
	if k, err := ParsePKCS8(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return x509.ParseECPrivateKey(der)
}

func TestX25519Key(t *testing.T) {
	k, err := GenerateKey(KeySpec{Type: "X25519"})
	if err != nil {
		t.Fatal(err)
	}
	if CanSign(k) || KeyAlgorithm(k) != "X25519" {
		t.Fatalf("CanSign %v, algorithm %s", CanSign(k), KeyAlgorithm(k))
	}
	if _, err := k.Sign(rand.Reader, make([]byte, 32), crypto.Hash(0)); err == nil {
		t.Fatal("X25519 key signed")
	}
	spki, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	if typ, bits := StoredKeyType(spki); typ != "X255" || bits != 256 {
		t.Fatalf("stored type %s %d", typ, bits)
	}
	der, err := MarshalPKCS8(k)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePKCS8(der)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := MatchesPublic(back, spki); !ok {
		t.Fatal("PKCS#8 round trip changed the key")
	}
}

package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// KeySpec describes a key to generate. Only key types Go can sign with are
// offered (Agreed decisions: DSA and non-NIST curves are display-only).
type KeySpec struct {
	Type  string // "RSA", "EC" or "Ed25519"
	Bits  int    // RSA modulus size
	Curve string // "P-256", "P-384" or "P-521"
}

// RSASizes are the sizes offered for new RSA keys (XCA offers the same,
// plus 1024 which is too weak today; 3072 is added).
var RSASizes = []int{2048, 3072, 4096, 8192}

// Curves are the EC curves offered for new keys.
var Curves = []string{"P-256", "P-384", "P-521"}

// GenerateKey creates a new private key.
func GenerateKey(spec KeySpec) (crypto.Signer, error) {
	switch spec.Type {
	case "RSA":
		ok := false
		for _, s := range RSASizes {
			ok = ok || s == spec.Bits
		}
		if !ok {
			return nil, fmt.Errorf("unsupported RSA size %d", spec.Bits)
		}
		return rsa.GenerateKey(rand.Reader, spec.Bits)
	case "EC":
		var c elliptic.Curve
		switch spec.Curve {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		case "P-521":
			c = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", spec.Curve)
		}
		return ecdsa.GenerateKey(c, rand.Reader)
	case "Ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	}
	return nil, fmt.Errorf("unsupported key type %q", spec.Type)
}

// StoredKeyType returns public_keys.type (EVP key type name cut to 4
// characters, as XCA stores it) and public_keys.len for a public key.
func StoredKeyType(spki []byte) (string, int) {
	info := DescribePublicKey(spki)
	switch info.Algorithm {
	case "Ed25519":
		return "ED25", info.Bits
	case "Ed448":
		return "ED44", info.Bits
	}
	t := info.Algorithm
	if len(t) > 4 {
		t = t[:4]
	}
	return t, info.Bits
}

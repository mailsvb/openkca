package pki

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// KeySpec describes a key to generate.
type KeySpec struct {
	// "RSA", "RSA-PSS", "EC", "Ed25519", "Ed448", "ML-DSA", "SLH-DSA",
	// "Composite" (ML-DSA with a traditional key) or the encryption only
	// "X25519", "X448", "ML-KEM" and "CompositeKEM"
	Type  string
	Bits  int    // RSA modulus size
	Curve string // EC: a name of ECCurves
	Param string // ML-DSA, SLH-DSA, ML-KEM: the parameter set; composites: the algorithm name
}

// RSASizes are the sizes offered for new RSA keys (XCA offers the same,
// plus 1024 which is too weak today; 3072 is added).
var RSASizes = []int{2048, 3072, 4096, 8192}

// Curves are the EC curves offered for new keys.
var Curves = func() []string {
	var out []string
	for _, c := range ECCurves {
		out = append(out, c.Name)
	}
	return out
}()

// GenerateKey creates a new private key.
func GenerateKey(spec KeySpec) (crypto.Signer, error) {
	switch spec.Type {
	case "RSA", "RSA-PSS":
		ok := false
		for _, s := range RSASizes {
			ok = ok || s == spec.Bits
		}
		if !ok {
			return nil, fmt.Errorf("unsupported RSA size %d", spec.Bits)
		}
		k, err := rsa.GenerateKey(rand.Reader, spec.Bits)
		if err != nil || spec.Type == "RSA" {
			return k, err
		}
		return RSAPSSKey{PrivateKey: k}, nil
	case "EC":
		c := curveByName(spec.Curve)
		if c == nil {
			return nil, fmt.Errorf("unsupported curve %q", spec.Curve)
		}
		return ecdsa.GenerateKey(c.Curve(), rand.Reader)
	case "Ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	case "Ed448":
		_, k, err := ed448.GenerateKey(rand.Reader)
		return k, err
	case "X25519":
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return X25519Key{k}, nil
	case "X448":
		secret := make([]byte, 56)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
		return NewX448Key(secret)
	case "ML-DSA":
		p := mldsaByName(spec.Param)
		if p == nil {
			return nil, fmt.Errorf("unsupported ML-DSA parameter set %q", spec.Param)
		}
		return mldsa.GenerateKey(p.Params())
	case "SLH-DSA":
		p := slhdsaByName(spec.Param)
		if p == nil {
			return nil, fmt.Errorf("unsupported SLH-DSA parameter set %q", spec.Param)
		}
		_, k, err := slhdsa.GenerateKey(rand.Reader, p.ID)
		return k, err
	case "ML-KEM":
		p := mlkemByName(spec.Param)
		if p == nil {
			return nil, fmt.Errorf("unsupported ML-KEM parameter set %q", spec.Param)
		}
		seed := make([]byte, MLKEMSeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		return NewMLKEMKey(p, seed)
	case "Composite":
		a := compositeByName(spec.Param)
		if a == nil {
			return nil, fmt.Errorf("unsupported composite algorithm %q", spec.Param)
		}
		m, err := mldsa.GenerateKey(a.MLDSA.Params())
		if err != nil {
			return nil, err
		}
		trad, err := generateTrad(a.Trad, a.RSABits, a.Curve)
		if err != nil {
			return nil, err
		}
		return CompositeKey{a, m, trad}, nil
	case "CompositeKEM":
		a := compositeKEMByName(spec.Param)
		if a == nil {
			return nil, fmt.Errorf("unsupported composite algorithm %q", spec.Param)
		}
		seed := make([]byte, MLKEMSeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		m, err := NewMLKEMKey(a.MLKEM, seed)
		if err != nil {
			return nil, err
		}
		trad, err := generateTrad(a.Trad, a.RSABits, a.Curve)
		if err != nil {
			return nil, err
		}
		return CompositeKEMKey{a, m, trad}, nil
	}
	return nil, fmt.Errorf("unsupported key type %q", spec.Type)
}

// StoredKeyType returns public_keys.type (the OpenSSL short name of the
// key type cut to 4 characters, as XCA stores it) and public_keys.len for
// a public key. Composite keys, which OpenSSL does not name, are "CMLD"
// and "CMLK".
func StoredKeyType(spki []byte) (string, int) {
	info := DescribePublicKey(spki)
	switch {
	case info.Algorithm == "Ed25519":
		return "ED25", info.Bits
	case info.Algorithm == "Ed448":
		return "ED44", info.Bits
	case info.Algorithm == "X25519":
		return "X255", info.Bits
	case info.Algorithm == "RSA-PSS":
		return "RSAS", info.Bits // RSASSA-PSS
	case info.Composite == "ML-DSA":
		return "CMLD", info.Bits
	case info.Composite == "ML-KEM":
		return "CMLK", info.Bits
	}
	t := info.Algorithm
	if len(t) > 4 {
		t = t[:4]
	}
	return t, info.Bits
}

// KeyTypeText names a public_keys.type for display.
func KeyTypeText(t string) string {
	switch t {
	case "ED25":
		return "ED25519"
	case "ED44":
		return "ED448"
	case "X255":
		return "X25519"
	case "RSAS":
		return "RSA-PSS"
	case "ML-D":
		return "ML-DSA"
	case "ML-K":
		return "ML-KEM"
	case "SLH-":
		return "SLH-DSA"
	case "CMLD":
		return "Composite ML-DSA"
	case "CMLK":
		return "Composite ML-KEM"
	}
	return t
}

// Package pki handles keys, certificates, requests and CRLs as XCA stores
// them: decrypting private keys and describing objects for display.
package pki

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys exist in old databases; display only
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var oidDSA = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}

type privateKeyInfo struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type dsaParams struct{ P, Q, G *big.Int }

type dsaLegacy struct {
	Version       int
	P, Q, G, Y, X *big.Int
}

// DecryptPrivateKey decrypts a private_keys.private blob with password,
// handling both the current PKCS#8 form and XCA's legacy 3DES form. keyType
// is public_keys.type (RSA, DSA, EC, ED25), needed for the legacy form.
// legacy reports which form the blob had.
func DecryptPrivateKey(blob []byte, keyType string, password []byte) (key crypto.Signer, legacy bool, err error) {
	if IsEncryptedPKCS8(blob) {
		der, err := DecryptPKCS8(blob, password)
		if err != nil {
			return nil, false, err
		}
		defer clear(der)
		key, err := ParsePKCS8(der)
		return key, false, err
	}
	der, err := DecryptLegacy(blob, password)
	if err != nil {
		return nil, true, err
	}
	defer clear(der)
	switch keyType {
	case "RSA":
		key, err = x509.ParsePKCS1PrivateKey(der)
	case "EC":
		key, err = x509.ParseECPrivateKey(der)
	case "DSA":
		var k dsaLegacy
		if _, err = asn1.Unmarshal(der, &k); err == nil {
			key = dsaKey(k.P, k.Q, k.G, k.Y, k.X)
		}
	default:
		err = fmt.Errorf("legacy key of type %q", keyType)
	}
	return key, true, err
}

// ParsePKCS8 parses an unencrypted PrivateKeyInfo, including DSA keys which
// crypto/x509 no longer supports.
func ParsePKCS8(der []byte) (crypto.Signer, error) {
	var pki privateKeyInfo
	if _, err := asn1.Unmarshal(der, &pki); err != nil {
		return nil, err
	}
	if pki.Algo.Algorithm.Equal(oidDSA) {
		var p dsaParams
		if _, err := asn1.Unmarshal(pki.Algo.Parameters.FullBytes, &p); err != nil {
			return nil, err
		}
		x := new(big.Int)
		if _, err := asn1.Unmarshal(pki.PrivateKey, &x); err != nil {
			return nil, err
		}
		y := new(big.Int).Exp(p.G, x, p.P)
		return dsaKey(p.P, p.Q, p.G, y, x), nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key %T", k)
	}
	return s, nil
}

// DSAKey wraps a DSA key so it satisfies crypto.Signer for type handling.
// Signing is not supported: Go dropped DSA signing for new code.
type DSAKey struct{ *dsa.PrivateKey }

func (k DSAKey) Public() crypto.PublicKey { return &k.PublicKey }

func (k DSAKey) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("DSA keys cannot sign in go-ca")
}

func dsaKey(p, q, g, y, x *big.Int) DSAKey {
	return DSAKey{&dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: dsa.Parameters{P: p, Q: q, G: g}, Y: y}, X: x}}
}

type spki struct {
	Algo      pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// MatchesPublic reports whether priv belongs to the DER SubjectPublicKeyInfo.
func MatchesPublic(priv crypto.Signer, spkiDER []byte) (bool, error) {
	if k, ok := priv.(DSAKey); ok {
		var s spki
		if _, err := asn1.Unmarshal(spkiDER, &s); err != nil {
			return false, err
		}
		y := new(big.Int)
		if _, err := asn1.Unmarshal(s.PublicKey.Bytes, &y); err != nil {
			return false, err
		}
		return y.Cmp(k.Y) == 0, nil
	}
	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return false, err
	}
	if bytes.Equal(der, spkiDER) {
		return true, nil
	}
	// Encodings can differ (explicit EC parameters); compare parsed keys.
	pub, err := x509.ParsePKIXPublicKey(spkiDER)
	if err != nil {
		return false, nil
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := priv.Public().(equaler); ok {
		return e.Equal(pub), nil
	}
	return false, nil
}

// KeyAlgorithm names the algorithm of a private key for display.
func KeyAlgorithm(k crypto.Signer) string {
	switch k.(type) {
	case *rsa.PrivateKey:
		return "RSA"
	case *ecdsa.PrivateKey:
		return "EC"
	case ed25519.PrivateKey:
		return "Ed25519"
	case DSAKey:
		return "DSA"
	}
	return fmt.Sprintf("%T", k)
}

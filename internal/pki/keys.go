// Package pki handles keys, certificates, requests and CRLs as XCA stores
// them: decrypting private keys and describing objects for display.
package pki

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys exist in old databases; display only
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/slhdsa"
)

var oidDSA = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}

type dsaParams struct{ P, Q, G *big.Int }

type dsaLegacy struct {
	Version       int
	P, Q, G, Y, X *big.Int
}

// DecryptPrivateKey decrypts a private_keys.private blob with password,
// handling both the current PKCS#8 form and XCA's legacy 3DES form. keyType
// is public_keys.type (RSA, DSA, EC, ED25, X255), needed for the legacy form.
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

// DSAKey wraps a DSA key so it satisfies crypto.Signer for type handling.
// Signing is not supported: Go dropped DSA signing for new code.
type DSAKey struct{ *dsa.PrivateKey }

func (k DSAKey) Public() crypto.PublicKey { return &k.PublicKey }

func (k DSAKey) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("DSA keys cannot sign in go-ca")
}

// X25519Key wraps an X25519 key (an OpenPGP encryption subkey) so it
// satisfies crypto.Signer for type handling. It cannot sign.
type X25519Key struct{ *ecdh.PrivateKey }

func (k X25519Key) Public() crypto.PublicKey { return k.PrivateKey.PublicKey() }

func (k X25519Key) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("X25519 keys cannot sign")
}

// CanSign reports whether a key can make signatures in go-ca.
func CanSign(k crypto.Signer) bool {
	switch k.(type) {
	case DSAKey, X25519Key, X448Key, MLKEMKey, CompositeKEMKey:
		return false
	}
	return true
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
	der, err := MarshalPublicKey(priv.Public())
	if err != nil {
		return false, err
	}
	if bytes.Equal(der, spkiDER) {
		return true, nil
	}
	// Encodings can differ (explicit EC parameters); compare parsed keys.
	pub, err := ParsePublicKey(spkiDER)
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
	switch k := k.(type) {
	case *rsa.PrivateKey:
		return "RSA"
	case *ecdsa.PrivateKey:
		return "EC"
	case ed25519.PrivateKey:
		return "Ed25519"
	case DSAKey:
		return "DSA"
	case X25519Key:
		return "X25519"
	case RSAPSSKey:
		return "RSA-PSS"
	case ed448.PrivateKey:
		return "Ed448"
	case X448Key:
		return "X448"
	case *mldsa.PrivateKey:
		return mldsaOf(k.PublicKey().Parameters()).Name
	case slhdsa.PrivateKey:
		return slhdsaByID(k.ID).Name
	case MLKEMKey:
		return k.pub.Params.Name
	case CompositeKey:
		return k.Alg.Name
	case CompositeKEMKey:
		return k.Alg.Name
	}
	return fmt.Sprintf("%T", k)
}

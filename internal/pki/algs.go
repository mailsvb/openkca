package pki

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/ProtonMail/go-crypto/bitcurves"
	"github.com/ProtonMail/go-crypto/brainpool"
	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// Algorithm identifiers of keys beyond those crypto/x509 knows.
var (
	oidRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSAPSS   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidECPublic = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidEd25519  = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidEd448    = asn1.ObjectIdentifier{1, 3, 101, 113}
	oidX25519   = asn1.ObjectIdentifier{1, 3, 101, 110}
	oidX448     = asn1.ObjectIdentifier{1, 3, 101, 111}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
)

// ECCurve is an elliptic curve go-ca can compute with: the NIST curves
// natively, Brainpool and secp256k1 through crypto/ecdsa's generic code.
type ECCurve struct {
	Name  string // as offered and in KeySpec.Curve, e.g. "brainpoolP256r1"
	OID   asn1.ObjectIdentifier
	Curve func() elliptic.Curve
	NIST  bool
}

// ECCurves lists the curves in the order they are offered.
var ECCurves = []ECCurve{
	{"P-256", asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, elliptic.P256, true},
	{"P-384", asn1.ObjectIdentifier{1, 3, 132, 0, 34}, elliptic.P384, true},
	{"P-521", asn1.ObjectIdentifier{1, 3, 132, 0, 35}, elliptic.P521, true},
	{"brainpoolP256r1", asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}, brainpool.P256r1, false},
	{"brainpoolP384r1", asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}, brainpool.P384r1, false},
	{"brainpoolP512r1", asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}, brainpool.P512r1, false},
	{"secp256k1", asn1.ObjectIdentifier{1, 3, 132, 0, 10}, func() elliptic.Curve { return bitcurves.S256() }, false},
}

func curveByOID(oid asn1.ObjectIdentifier) *ECCurve {
	for i := range ECCurves {
		if ECCurves[i].OID.Equal(oid) {
			return &ECCurves[i]
		}
	}
	return nil
}

func curveByName(name string) *ECCurve {
	for i := range ECCurves {
		if ECCurves[i].Name == name {
			return &ECCurves[i]
		}
	}
	return nil
}

// CurveOf finds the entry of an elliptic.Curve, nil if go-ca does not
// know it.
func CurveOf(c elliptic.Curve) *ECCurve {
	for i := range ECCurves {
		if ECCurves[i].Curve() == c {
			return &ECCurves[i]
		}
	}
	return nil
}

// ecSize is the length of a coordinate or scalar of the curve.
func ecSize(c elliptic.Curve) int { return (c.Params().BitSize + 7) / 8 }

// ECPoint encodes an ECDSA public key as an uncompressed point; unlike
// PublicKey.Bytes it works for every curve.
func ECPoint(k *ecdsa.PublicKey) []byte {
	n := ecSize(k.Curve)
	out := make([]byte, 1+2*n)
	out[0] = 4
	k.X.FillBytes(out[1 : 1+n]) //nolint:staticcheck // the generic curves have no other accessor
	k.Y.FillBytes(out[1+n:])    //nolint:staticcheck
	return out
}

// parseECPoint decodes an uncompressed point on c.
func parseECPoint(c elliptic.Curve, b []byte) (*ecdsa.PublicKey, error) {
	n := ecSize(c)
	if len(b) != 1+2*n || b[0] != 4 {
		return nil, errors.New("ec: unsupported point encoding")
	}
	x, y := new(big.Int).SetBytes(b[1:1+n]), new(big.Int).SetBytes(b[1+n:])
	p := c.Params().P
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 || !c.IsOnCurve(x, y) {
		return nil, errors.New("ec: point not on the curve")
	}
	return &ecdsa.PublicKey{Curve: c, X: x, Y: y}, nil
}

// ecPrivateFromScalar builds an ECDSA key from its scalar on any curve.
func ecPrivateFromScalar(c elliptic.Curve, d []byte) (*ecdsa.PrivateKey, error) {
	if CurveOf(c) != nil && CurveOf(c).NIST {
		if len(d) < ecSize(c) {
			d = append(make([]byte, ecSize(c)-len(d)), d...)
		}
		return ecdsa.ParseRawPrivateKey(c, d)
	}
	k := new(big.Int).SetBytes(d)
	if k.Sign() == 0 || k.Cmp(c.Params().N) >= 0 {
		return nil, errors.New("ec: invalid private key")
	}
	x, y := c.ScalarBaseMult(k.FillBytes(make([]byte, ecSize(c))))
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: x, Y: y}, D: k}, nil //nolint:staticcheck
}

// PSSParams restricts an RSASSA-PSS key or describes a PSS signature:
// the hash (also used for MGF1) and the salt length.
type PSSParams struct {
	Hash       crypto.Hash
	SaltLength int
}

// RSAPSSPublicKey is an RSA key with the id-RSASSA-PSS algorithm (RFC
// 4055): usable for PSS signatures only, optionally with fixed
// parameters.
type RSAPSSPublicKey struct {
	*rsa.PublicKey
	Params *PSSParams // nil: any PSS parameters
}

// Equal reports whether x is the same key with the same restriction.
func (k *RSAPSSPublicKey) Equal(x crypto.PublicKey) bool {
	o, ok := x.(*RSAPSSPublicKey)
	if !ok || !k.PublicKey.Equal(o.PublicKey) || (k.Params == nil) != (o.Params == nil) {
		return false
	}
	return k.Params == nil || *k.Params == *o.Params
}

// RSAPSSKey is the private key of an RSAPSSPublicKey. It signs with PSS
// whatever the options ask for.
type RSAPSSKey struct {
	*rsa.PrivateKey
	Params *PSSParams
}

func (k RSAPSSKey) Public() crypto.PublicKey {
	return &RSAPSSPublicKey{&k.PrivateKey.PublicKey, k.Params}
}

func (k RSAPSSKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	po, ok := opts.(*rsa.PSSOptions)
	if !ok {
		po = &rsa.PSSOptions{Hash: opts.HashFunc(), SaltLength: rsa.PSSSaltLengthEqualsHash}
	}
	if k.Params != nil && (po.HashFunc() != k.Params.Hash || po.SaltLength != k.Params.SaltLength &&
		!(po.SaltLength == rsa.PSSSaltLengthEqualsHash && k.Params.SaltLength == k.Params.Hash.Size())) {
		return nil, errors.New("rsa-pss: the key is restricted to other parameters")
	}
	return k.PrivateKey.Sign(r, digest, po)
}

// X448PublicKey is an X448 key (RFC 7748).
type X448PublicKey []byte

func (k X448PublicKey) Equal(x crypto.PublicKey) bool {
	o, ok := x.(X448PublicKey)
	return ok && subtle.ConstantTimeCompare(k, o) == 1
}

// X448Key is an X448 private key; like X25519Key it satisfies
// crypto.Signer for type handling but cannot sign.
type X448Key struct{ secret, public x448.Key }

// NewX448Key derives the key from its 56 secret bytes.
func NewX448Key(secret []byte) (X448Key, error) {
	var k X448Key
	if len(secret) != x448.Size {
		return k, errors.New("x448: bad private key length")
	}
	copy(k.secret[:], secret)
	x448.KeyGen(&k.public, &k.secret)
	return k, nil
}

// Bytes returns the secret.
func (k X448Key) Bytes() []byte { return append([]byte(nil), k.secret[:]...) }

func (k X448Key) Public() crypto.PublicKey { return X448PublicKey(append([]byte(nil), k.public[:]...)) }

func (k X448Key) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("X448 keys cannot sign")
}

// MLKEMParams is an ML-KEM parameter set (FIPS 203).
type MLKEMParams struct {
	Name   string
	OID    asn1.ObjectIdentifier
	scheme kem.Scheme
}

// MLKEMParamSets lists the ML-KEM parameter sets.
var MLKEMParamSets = []*MLKEMParams{
	{"ML-KEM-512", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}, mlkem512.Scheme()},
	{"ML-KEM-768", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}, mlkem768.Scheme()},
	{"ML-KEM-1024", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}, mlkem1024.Scheme()},
}

// MLKEMSeedSize is the size of an ML-KEM private key seed (d || z).
const MLKEMSeedSize = 64

func mlkemByOID(oid asn1.ObjectIdentifier) *MLKEMParams {
	for _, p := range MLKEMParamSets {
		if p.OID.Equal(oid) {
			return p
		}
	}
	return nil
}

func mlkemByName(name string) *MLKEMParams {
	for _, p := range MLKEMParamSets {
		if p.Name == name {
			return p
		}
	}
	return nil
}

// MLKEMPublicKey is an ML-KEM encapsulation key.
type MLKEMPublicKey struct {
	Params *MLKEMParams
	key    []byte
}

func newMLKEMPublicKey(p *MLKEMParams, b []byte) (*MLKEMPublicKey, error) {
	if _, err := p.scheme.UnmarshalBinaryPublicKey(b); err != nil {
		return nil, err
	}
	return &MLKEMPublicKey{p, append([]byte(nil), b...)}, nil
}

// Bytes returns the encoded encapsulation key.
func (k *MLKEMPublicKey) Bytes() []byte { return append([]byte(nil), k.key...) }

func (k *MLKEMPublicKey) Equal(x crypto.PublicKey) bool {
	o, ok := x.(*MLKEMPublicKey)
	return ok && o.Params == k.Params && subtle.ConstantTimeCompare(k.key, o.key) == 1
}

// MLKEMKey is an ML-KEM decapsulation key, held as its seed. It satisfies
// crypto.Signer for type handling but cannot sign.
type MLKEMKey struct {
	seed []byte
	pub  *MLKEMPublicKey
}

// NewMLKEMKey derives the key pair from a 64 byte seed.
func NewMLKEMKey(p *MLKEMParams, seed []byte) (MLKEMKey, error) {
	if len(seed) != MLKEMSeedSize {
		return MLKEMKey{}, errors.New("ml-kem: bad seed length")
	}
	pk, _ := p.scheme.DeriveKeyPair(seed)
	b, err := pk.MarshalBinary()
	if err != nil {
		return MLKEMKey{}, err
	}
	return MLKEMKey{append([]byte(nil), seed...), &MLKEMPublicKey{p, b}}, nil
}

// Seed returns the private key seed.
func (k MLKEMKey) Seed() []byte { return append([]byte(nil), k.seed...) }

func (k MLKEMKey) Public() crypto.PublicKey { return k.pub }

func (k MLKEMKey) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("ML-KEM keys cannot sign")
}

// MLDSAParams names an ML-DSA parameter set (FIPS 204).
type MLDSAParams struct {
	Name   string
	OID    asn1.ObjectIdentifier
	Params func() mldsa.Parameters
}

// MLDSAParamSets lists the ML-DSA parameter sets.
var MLDSAParamSets = []MLDSAParams{
	{"ML-DSA-44", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, mldsa.MLDSA44},
	{"ML-DSA-65", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, mldsa.MLDSA65},
	{"ML-DSA-87", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, mldsa.MLDSA87},
}

func mldsaByOID(oid asn1.ObjectIdentifier) *MLDSAParams {
	for i := range MLDSAParamSets {
		if MLDSAParamSets[i].OID.Equal(oid) {
			return &MLDSAParamSets[i]
		}
	}
	return nil
}

func mldsaByName(name string) *MLDSAParams {
	for i := range MLDSAParamSets {
		if MLDSAParamSets[i].Name == name {
			return &MLDSAParamSets[i]
		}
	}
	return nil
}

func mldsaOf(p mldsa.Parameters) *MLDSAParams {
	for i := range MLDSAParamSets {
		if MLDSAParamSets[i].Params() == p {
			return &MLDSAParamSets[i]
		}
	}
	return nil
}

// SLHDSAParams names an SLH-DSA parameter set (FIPS 205, RFC 9909).
type SLHDSAParams struct {
	Name string
	OID  asn1.ObjectIdentifier
	ID   slhdsa.ID
}

// SLHDSAParamSets lists the SLH-DSA parameter sets.
var SLHDSAParamSets = func() []SLHDSAParams {
	var out []SLHDSAParams
	for i, n := range []string{"SHA2-128s", "SHA2-128f", "SHA2-192s", "SHA2-192f", "SHA2-256s", "SHA2-256f",
		"SHAKE-128s", "SHAKE-128f", "SHAKE-192s", "SHAKE-192f", "SHAKE-256s", "SHAKE-256f"} {
		id, err := slhdsa.IDByName("SLH-DSA-" + n)
		if err != nil {
			panic(err)
		}
		out = append(out, SLHDSAParams{"SLH-DSA-" + n, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20 + i}, id})
	}
	return out
}()

func slhdsaByOID(oid asn1.ObjectIdentifier) *SLHDSAParams {
	for i := range SLHDSAParamSets {
		if SLHDSAParamSets[i].OID.Equal(oid) {
			return &SLHDSAParamSets[i]
		}
	}
	return nil
}

func slhdsaByID(id slhdsa.ID) *SLHDSAParams {
	for i := range SLHDSAParamSets {
		if SLHDSAParamSets[i].ID == id {
			return &SLHDSAParamSets[i]
		}
	}
	return nil
}

func slhdsaByName(name string) *SLHDSAParams {
	for i := range SLHDSAParamSets {
		if SLHDSAParamSets[i].Name == name {
			return &SLHDSAParamSets[i]
		}
	}
	return nil
}

// isX25519 reports whether pub is an X25519 key.
func isX25519(pub crypto.PublicKey) bool {
	k, ok := pub.(*ecdh.PublicKey)
	return ok && k.Curve() == ecdh.X25519()
}

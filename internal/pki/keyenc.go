package pki

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys exist in old databases; display only
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// ParsePublicKey parses a DER SubjectPublicKeyInfo. Besides what
// crypto/x509 returns (RSA, NIST ECDSA, Ed25519, X25519, ML-DSA, DSA) it
// knows RSASSA-PSS (*RSAPSSPublicKey), ECDSA on Brainpool curves and
// secp256k1, Ed448 (ed448.PublicKey), X448 (X448PublicKey), ML-KEM
// (*MLKEMPublicKey), SLH-DSA (slhdsa.PublicKey) and the composite
// algorithms (*CompositePublicKey, *CompositeKEMPublicKey).
func ParsePublicKey(der []byte) (crypto.PublicKey, error) {
	var s spki
	if rest, err := asn1.Unmarshal(der, &s); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errors.New("trailing data after the public key")
	}
	oid, key := s.Algo.Algorithm, s.PublicKey.RightAlign()
	switch {
	case oid.Equal(oidRSAPSS):
		pub, err := x509.ParsePKCS1PublicKey(key)
		if err != nil {
			return nil, err
		}
		params, err := parsePSSKeyParams(s.Algo.Parameters)
		if err != nil {
			return nil, err
		}
		return &RSAPSSPublicKey{pub, params}, nil
	case oid.Equal(oidECPublic):
		var curve asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(s.Algo.Parameters.FullBytes, &curve); err != nil {
			break // explicit parameters: leave it to crypto/x509
		}
		if c := curveByOID(curve); c != nil && !c.NIST {
			return parseECPoint(c.Curve(), key)
		}
	case oid.Equal(oidEd448):
		if len(key) != ed448.PublicKeySize {
			return nil, errors.New("ed448: bad public key length")
		}
		return ed448.PublicKey(key), nil
	case oid.Equal(oidX448):
		if len(key) != 56 {
			return nil, errors.New("x448: bad public key length")
		}
		return X448PublicKey(key), nil
	}
	if p := mlkemByOID(oid); p != nil {
		return newMLKEMPublicKey(p, key)
	}
	if p := slhdsaByOID(oid); p != nil {
		pub := slhdsa.PublicKey{ID: p.ID}
		if err := pub.UnmarshalBinary(key); err != nil {
			return nil, err
		}
		return pub, nil
	}
	if a := compositeByOID(oid); a != nil {
		n := mldsaPublicSize(a.MLDSA)
		if len(key) <= n {
			return nil, errors.New("composite: public key too short")
		}
		m, err := mldsa.NewPublicKey(a.MLDSA.Params(), key[:n])
		if err != nil {
			return nil, err
		}
		trad, err := parseTradPublic(a.Trad, a.Curve, key[n:])
		if err != nil {
			return nil, err
		}
		return &CompositePublicKey{a, m, trad}, nil
	}
	if a := compositeKEMByOID(oid); a != nil {
		n := a.MLKEM.scheme.PublicKeySize()
		if len(key) <= n {
			return nil, errors.New("composite: public key too short")
		}
		m, err := newMLKEMPublicKey(a.MLKEM, key[:n])
		if err != nil {
			return nil, err
		}
		trad, err := parseTradPublic(a.Trad, a.Curve, key[n:])
		if err != nil {
			return nil, err
		}
		return &CompositeKEMPublicKey{a, m, trad}, nil
	}
	return x509.ParsePKIXPublicKey(der)
}

// MarshalPublicKey encodes any key ParsePublicKey returns as
// SubjectPublicKeyInfo.
func MarshalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	var algo pkix.AlgorithmIdentifier
	var key []byte
	switch k := pub.(type) {
	case *dsa.PublicKey:
		params, err := asn1.Marshal(dsaParams{P: k.P, Q: k.Q, G: k.G})
		if err != nil {
			return nil, err
		}
		if key, err = asn1.Marshal(k.Y); err != nil {
			return nil, err
		}
		algo = pkix.AlgorithmIdentifier{Algorithm: oidDSA, Parameters: asn1.RawValue{FullBytes: params}}
	case *RSAPSSPublicKey:
		algo = pkix.AlgorithmIdentifier{Algorithm: oidRSAPSS}
		if k.Params != nil {
			b, err := marshalPSSParams(*k.Params)
			if err != nil {
				return nil, err
			}
			algo.Parameters = asn1.RawValue{FullBytes: b}
		}
		key = x509.MarshalPKCS1PublicKey(k.PublicKey)
	case *ecdsa.PublicKey:
		c := CurveOf(k.Curve)
		if c == nil || c.NIST {
			return x509.MarshalPKIXPublicKey(pub)
		}
		params, _ := asn1.Marshal(c.OID)
		algo = pkix.AlgorithmIdentifier{Algorithm: oidECPublic, Parameters: asn1.RawValue{FullBytes: params}}
		key = ECPoint(k)
	case ed448.PublicKey:
		algo, key = pkix.AlgorithmIdentifier{Algorithm: oidEd448}, k
	case X448PublicKey:
		algo, key = pkix.AlgorithmIdentifier{Algorithm: oidX448}, k
	case *MLKEMPublicKey:
		algo, key = pkix.AlgorithmIdentifier{Algorithm: k.Params.OID}, k.key
	case slhdsa.PublicKey:
		p := slhdsaByID(k.ID)
		if p == nil {
			return nil, errors.New("slh-dsa: unknown parameter set")
		}
		b, err := k.MarshalBinary()
		if err != nil {
			return nil, err
		}
		algo, key = pkix.AlgorithmIdentifier{Algorithm: p.OID}, b
	case *CompositePublicKey:
		t, err := tradPublicBytes(k.Trad)
		if err != nil {
			return nil, err
		}
		algo, key = pkix.AlgorithmIdentifier{Algorithm: k.Alg.OID}, append(k.MLDSA.Bytes(), t...)
	case *CompositeKEMPublicKey:
		t, err := tradPublicBytes(k.Trad)
		if err != nil {
			return nil, err
		}
		algo, key = pkix.AlgorithmIdentifier{Algorithm: k.Alg.OID}, append(k.MLKEM.Bytes(), t...)
	default:
		return x509.MarshalPKIXPublicKey(pub)
	}
	return asn1.Marshal(spki{algo, asn1.BitString{Bytes: key, BitLength: 8 * len(key)}})
}

// oneAsymmetricKey is PKCS#8's PrivateKeyInfo, also in its version 2 form
// with a public key (RFC 5958).
type oneAsymmetricKey struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes asn1.RawValue  `asn1:"optional,tag:0"`
	PublicKey  asn1.BitString `asn1:"optional,tag:1"`
}

// ParsePKCS8 parses an unencrypted PrivateKeyInfo: everything crypto/x509
// reads, plus DSA, RSASSA-PSS, ECDSA on Brainpool curves and secp256k1,
// Ed448, X448, ML-DSA (seed or seed and expanded key), ML-KEM, SLH-DSA
// and the composite algorithms.
func ParsePKCS8(der []byte) (crypto.Signer, error) {
	var p oneAsymmetricKey
	if _, err := asn1.Unmarshal(der, &p); err != nil {
		return nil, err
	}
	oid := p.Algo.Algorithm
	switch {
	case oid.Equal(oidDSA):
		var dp dsaParams
		if _, err := asn1.Unmarshal(p.Algo.Parameters.FullBytes, &dp); err != nil {
			return nil, err
		}
		x := new(big.Int)
		if _, err := asn1.Unmarshal(p.PrivateKey, &x); err != nil {
			return nil, err
		}
		y := new(big.Int).Exp(dp.G, x, dp.P)
		return dsaKey(dp.P, dp.Q, dp.G, y, x), nil
	case oid.Equal(oidRSAPSS):
		k, err := x509.ParsePKCS1PrivateKey(p.PrivateKey)
		if err != nil {
			return nil, err
		}
		params, err := parsePSSKeyParams(p.Algo.Parameters)
		if err != nil {
			return nil, err
		}
		return RSAPSSKey{k, params}, nil
	case oid.Equal(oidECPublic):
		var curve asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(p.Algo.Parameters.FullBytes, &curve); err == nil {
			if c := curveByOID(curve); c != nil && !c.NIST {
				return parseSEC1(p.PrivateKey, c)
			}
		}
	case oid.Equal(oidEd448):
		seed, err := curvePrivateKey(p.PrivateKey, ed448.SeedSize)
		if err != nil {
			return nil, err
		}
		return ed448.NewKeyFromSeed(seed), nil
	case oid.Equal(oidX448):
		secret, err := curvePrivateKey(p.PrivateKey, 56)
		if err != nil {
			return nil, err
		}
		return NewX448Key(secret)
	}
	if mp := mldsaByOID(oid); mp != nil {
		seed, err := pqSeed(p.PrivateKey, mldsa.PrivateKeySize, "ML-DSA")
		if err != nil {
			return nil, err
		}
		return mldsa.NewPrivateKey(mp.Params(), seed)
	}
	if mp := mlkemByOID(oid); mp != nil {
		seed, err := pqSeed(p.PrivateKey, MLKEMSeedSize, "ML-KEM")
		if err != nil {
			return nil, err
		}
		return NewMLKEMKey(mp, seed)
	}
	if sp := slhdsaByOID(oid); sp != nil {
		raw := p.PrivateKey
		var inner []byte // tolerate an OCTET STRING wrapped once more
		if rest, err := asn1.Unmarshal(raw, &inner); err == nil && len(rest) == 0 {
			raw = inner
		}
		k := slhdsa.PrivateKey{ID: sp.ID}
		if err := k.UnmarshalBinary(raw); err != nil {
			return nil, err
		}
		return k, nil
	}
	if a := compositeByOID(oid); a != nil {
		if len(p.PrivateKey) <= mldsa.PrivateKeySize {
			return nil, errors.New("composite: private key too short")
		}
		m, err := mldsa.NewPrivateKey(a.MLDSA.Params(), p.PrivateKey[:mldsa.PrivateKeySize])
		if err != nil {
			return nil, err
		}
		trad, err := parseTradPrivate(a.Trad, a.Curve, p.PrivateKey[mldsa.PrivateKeySize:])
		if err != nil {
			return nil, err
		}
		return CompositeKey{a, m, trad}, nil
	}
	if a := compositeKEMByOID(oid); a != nil {
		if len(p.PrivateKey) <= MLKEMSeedSize {
			return nil, errors.New("composite: private key too short")
		}
		m, err := NewMLKEMKey(a.MLKEM, p.PrivateKey[:MLKEMSeedSize])
		if err != nil {
			return nil, err
		}
		trad, err := parseTradPrivate(a.Trad, a.Curve, p.PrivateKey[MLKEMSeedSize:])
		if err != nil {
			return nil, err
		}
		return CompositeKEMKey{a, m, trad}, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	if x, ok := k.(*ecdh.PrivateKey); ok && x.Curve() == ecdh.X25519() {
		return X25519Key{x}, nil
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key %T", k)
	}
	return s, nil
}

// MarshalPKCS8 encodes a private key as an unencrypted PrivateKeyInfo,
// for every key type ParsePKCS8 returns.
func MarshalPKCS8(key crypto.Signer) ([]byte, error) {
	info := oneAsymmetricKey{}
	var err error
	switch k := key.(type) {
	case DSAKey:
		params, err := asn1.Marshal(dsaParams{P: k.P, Q: k.Q, G: k.G})
		if err != nil {
			return nil, err
		}
		x, err := asn1.Marshal(k.X)
		if err != nil {
			return nil, err
		}
		info.Algo, info.PrivateKey = pkix.AlgorithmIdentifier{Algorithm: oidDSA, Parameters: asn1.RawValue{FullBytes: params}}, x
	case X25519Key:
		return x509.MarshalPKCS8PrivateKey(k.PrivateKey)
	case RSAPSSKey:
		info.Algo = pkix.AlgorithmIdentifier{Algorithm: oidRSAPSS}
		if k.Params != nil {
			b, err := marshalPSSParams(*k.Params)
			if err != nil {
				return nil, err
			}
			info.Algo.Parameters = asn1.RawValue{FullBytes: b}
		}
		info.PrivateKey = x509.MarshalPKCS1PrivateKey(k.PrivateKey)
	case *ecdsa.PrivateKey:
		c := CurveOf(k.Curve)
		if c == nil || c.NIST {
			return x509.MarshalPKCS8PrivateKey(k)
		}
		params, _ := asn1.Marshal(c.OID)
		info.Algo = pkix.AlgorithmIdentifier{Algorithm: oidECPublic, Parameters: asn1.RawValue{FullBytes: params}}
		// the curve is in the algorithm identifier, as OpenSSL writes it
		if info.PrivateKey, err = marshalSEC1Params(k, true, false); err != nil {
			return nil, err
		}
	case ed448.PrivateKey:
		info.Algo = pkix.AlgorithmIdentifier{Algorithm: oidEd448}
		info.PrivateKey, _ = asn1.Marshal(k.Seed())
	case X448Key:
		info.Algo = pkix.AlgorithmIdentifier{Algorithm: oidX448}
		info.PrivateKey, _ = asn1.Marshal(k.Bytes())
	case MLKEMKey:
		info.Algo = pkix.AlgorithmIdentifier{Algorithm: k.pub.Params.OID}
		info.PrivateKey, _ = asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: k.seed})
	case slhdsa.PrivateKey:
		p := slhdsaByID(k.ID)
		if p == nil {
			return nil, errors.New("slh-dsa: unknown parameter set")
		}
		info.Algo = pkix.AlgorithmIdentifier{Algorithm: p.OID}
		if info.PrivateKey, err = k.MarshalBinary(); err != nil {
			return nil, err
		}
	case CompositeKey:
		t, err := tradPrivateBytes(k.Trad)
		if err != nil {
			return nil, err
		}
		info.Algo = pkix.AlgorithmIdentifier{Algorithm: k.Alg.OID}
		info.PrivateKey = append(k.MLDSA.Bytes(), t...)
	case CompositeKEMKey:
		t, err := tradPrivateBytes(k.Trad)
		if err != nil {
			return nil, err
		}
		info.Algo = pkix.AlgorithmIdentifier{Algorithm: k.Alg.OID}
		info.PrivateKey = append(k.MLKEM.Seed(), t...)
	default:
		return x509.MarshalPKCS8PrivateKey(key)
	}
	return asn1.Marshal(info)
}

// curvePrivateKey unwraps RFC 8410's CurvePrivateKey (an OCTET STRING in
// the privateKey OCTET STRING).
func curvePrivateKey(b []byte, size int) ([]byte, error) {
	var k []byte
	if rest, err := asn1.Unmarshal(b, &k); err != nil || len(rest) > 0 {
		return nil, errors.New("bad curve private key")
	}
	if len(k) != size {
		return nil, fmt.Errorf("bad private key length %d", len(k))
	}
	return k, nil
}

// pqSeed reads the seed of an ML-DSA or ML-KEM private key: the CHOICE of
// seed [0], expandedKey and both (RFC 9881, RFC 9935). A key without its
// seed cannot be used.
func pqSeed(b []byte, size int, name string) ([]byte, error) {
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(b, &raw); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("%s: bad private key", name)
	}
	switch {
	case raw.Class == asn1.ClassContextSpecific && raw.Tag == 0 && !raw.IsCompound:
		if len(raw.Bytes) != size {
			return nil, fmt.Errorf("%s: bad seed length", name)
		}
		return raw.Bytes, nil
	case raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagSequence:
		var both struct{ Seed, Expanded []byte }
		if _, err := asn1.Unmarshal(b, &both); err != nil || len(both.Seed) != size {
			return nil, fmt.Errorf("%s: bad private key", name)
		}
		return both.Seed, nil
	case raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagOctetString:
		return nil, fmt.Errorf("%s: private keys without their seed are not supported", name)
	}
	return nil, fmt.Errorf("%s: bad private key", name)
}

// ecPrivateKey is SEC 1's ECPrivateKey (RFC 5915).
type ecPrivateKey struct {
	Version    int
	PrivateKey []byte
	Params     asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey  asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// marshalSEC1 writes an ECPrivateKey with the named curve, and with the
// public key if withPublic is set; it works for every curve.
func marshalSEC1(k *ecdsa.PrivateKey, withPublic bool) ([]byte, error) {
	return marshalSEC1Params(k, withPublic, true)
}

func marshalSEC1Params(k *ecdsa.PrivateKey, withPublic, withCurve bool) ([]byte, error) {
	c := CurveOf(k.Curve)
	if c == nil {
		return nil, errors.New("ec: unsupported curve")
	}
	v := ecPrivateKey{Version: 1, PrivateKey: k.D.FillBytes(make([]byte, ecSize(k.Curve)))} //nolint:staticcheck // no accessor for generic curves
	if withCurve {
		v.Params = c.OID
	}
	if withPublic {
		p := ECPoint(&k.PublicKey)
		v.PublicKey = asn1.BitString{Bytes: p, BitLength: 8 * len(p)}
	}
	return asn1.Marshal(v)
}

// MarshalECPrivateKey is x509.MarshalECPrivateKey for every curve go-ca
// knows.
func MarshalECPrivateKey(k *ecdsa.PrivateKey) ([]byte, error) {
	if c := CurveOf(k.Curve); c != nil && c.NIST {
		return x509.MarshalECPrivateKey(k)
	}
	return marshalSEC1(k, true)
}

// parseSEC1 reads an ECPrivateKey on c, or on its own named curve if c is
// nil.
func parseSEC1(der []byte, c *ECCurve) (*ecdsa.PrivateKey, error) {
	var v ecPrivateKey
	if rest, err := asn1.Unmarshal(der, &v); err != nil || len(rest) > 0 {
		return nil, errors.New("ec: bad private key")
	}
	if c == nil {
		if c = curveByOID(v.Params); c == nil {
			return nil, errors.New("ec: unsupported curve")
		}
	} else if v.Params != nil && !v.Params.Equal(c.OID) {
		return nil, errors.New("ec: curve mismatch")
	}
	if len(v.PrivateKey) > ecSize(c.Curve()) {
		return nil, errors.New("ec: bad private key length")
	}
	k, err := ecPrivateFromScalar(c.Curve(), v.PrivateKey)
	if err != nil {
		return nil, err
	}
	if v.PublicKey.BitLength > 0 && !bytes.Equal(v.PublicKey.RightAlign(), ECPoint(&k.PublicKey)) {
		return nil, errors.New("ec: the public key does not match the private key")
	}
	return k, nil
}

// ParseECPrivateKey is x509.ParseECPrivateKey for every curve go-ca knows.
func ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return parseSEC1(der, nil)
}

func newX25519Key(b []byte) (X25519Key, error) {
	k, err := ecdh.X25519().NewPrivateKey(b)
	return X25519Key{k}, err
}

func parseX25519Public(b []byte) (*ecdh.PublicKey, error) { return ecdh.X25519().NewPublicKey(b) }

// pssParams is RSASSA-PSS-params (RFC 4055) with its defaults.
type pssParams struct {
	Hash         pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength   int                      `asn1:"optional,explicit,tag:2,default:20"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

var hashOIDs = []struct {
	oid  asn1.ObjectIdentifier
	hash crypto.Hash
}{{oidSHA256, crypto.SHA256}, {oidSHA384, crypto.SHA384}, {oidSHA512, crypto.SHA512}, {oidSHA1, crypto.SHA1}}

func hashOID(h crypto.Hash) asn1.ObjectIdentifier {
	for _, x := range hashOIDs {
		if x.hash == h {
			return x.oid
		}
	}
	return nil
}

func hashOfOID(oid asn1.ObjectIdentifier) crypto.Hash {
	for _, x := range hashOIDs {
		if x.oid.Equal(oid) {
			return x.hash
		}
	}
	return 0
}

// parsePSSParams reads RSASSA-PSS-params; MGF1 must use the same hash.
func parsePSSParams(der []byte) (PSSParams, error) {
	var p pssParams
	if rest, err := asn1.Unmarshal(der, &p); err != nil || len(rest) > 0 {
		return PSSParams{}, errors.New("rsa-pss: bad parameters")
	}
	h := crypto.SHA1
	if len(p.Hash.Algorithm) > 0 {
		if h = hashOfOID(p.Hash.Algorithm); h == 0 {
			return PSSParams{}, fmt.Errorf("rsa-pss: unsupported hash %v", p.Hash.Algorithm)
		}
	}
	mgfHash := crypto.SHA1
	if len(p.MGF.Algorithm) > 0 {
		if !p.MGF.Algorithm.Equal(oidMGF1) {
			return PSSParams{}, errors.New("rsa-pss: unsupported mask generation")
		}
		var ai pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(p.MGF.Parameters.FullBytes, &ai); err != nil {
			return PSSParams{}, errors.New("rsa-pss: bad MGF1 parameters")
		}
		mgfHash = hashOfOID(ai.Algorithm)
	}
	if mgfHash != h || p.TrailerField != 1 || p.SaltLength < 0 {
		return PSSParams{}, errors.New("rsa-pss: unsupported parameters")
	}
	return PSSParams{h, p.SaltLength}, nil
}

// parsePSSKeyParams reads the optional parameters of an RSASSA-PSS key.
func parsePSSKeyParams(v asn1.RawValue) (*PSSParams, error) {
	if len(v.FullBytes) == 0 || bytes.Equal(v.FullBytes, asn1.NullBytes) {
		return nil, nil
	}
	p, err := parsePSSParams(v.FullBytes)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func marshalPSSParams(p PSSParams) ([]byte, error) {
	oid := hashOID(p.Hash)
	if oid == nil {
		return nil, errors.New("rsa-pss: unsupported hash")
	}
	h := pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue}
	mgfParams, err := asn1.Marshal(h)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(pssParams{Hash: h, MGF: pkix.AlgorithmIdentifier{Algorithm: oidMGF1, Parameters: asn1.RawValue{FullBytes: mgfParams}},
		SaltLength: p.SaltLength, TrailerField: 1})
}

// rsaPublic returns the RSA key of an RSA or RSASSA-PSS public key.
func rsaPublic(pub crypto.PublicKey) *rsa.PublicKey {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return k
	case *RSAPSSPublicKey:
		return k.PublicKey
	}
	return nil
}

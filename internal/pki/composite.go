package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha3"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cloudflare/circl/sign/ed448"
)

// Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs) and Composite
// ML-KEM (draft-ietf-lamps-pq-composite-kem): an ML-DSA or ML-KEM key
// paired with a traditional key under one algorithm identifier. Keys,
// signatures and private keys are the concatenations of the components'
// encodings.

// Traditional components.
const (
	tradRSAPSS   = "RSA-PSS"
	tradRSAPKCS1 = "RSA"
	tradECDSA    = "ECDSA"
	tradEd25519  = "Ed25519"
	tradEd448    = "Ed448"
	tradRSAOAEP  = "RSA-OAEP"
	tradECDH     = "ECDH"
	tradX25519   = "X25519"
	tradX448     = "X448"
)

// compositePrefix starts every composite signature's message
// representative M'.
const compositePrefix = "CompositeAlgorithmSignatures2025"

// CompositeAlg is a Composite ML-DSA algorithm.
type CompositeAlg struct {
	Name     string // without the "id-" of the ASN.1 name
	OID      asn1.ObjectIdentifier
	Label    string
	MLDSA    *MLDSAParams
	PH       crypto.Hash // pre-hash; 0 is SHAKE256 with 64 bytes of output
	Trad     string
	TradHash crypto.Hash // hash of RSA and ECDSA signatures over M'
	RSABits  int
	Curve    string // ECDSA
}

func compSig(name string, arc int, mldsaName string, ph crypto.Hash, trad string, tradHash crypto.Hash, bits int, curve string) *CompositeAlg {
	// the labels abbreviate the Brainpool curves
	label := strings.NewReplacer("brainpoolP256r1", "BP256", "brainpoolP384r1", "BP384").Replace("COMPSIG-" + name)
	return &CompositeAlg{name, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, arc}, label, mldsaByName(mldsaName), ph, trad, tradHash, bits, curve}
}

// CompositeAlgs lists the Composite ML-DSA algorithms.
var CompositeAlgs = []*CompositeAlg{
	compSig("MLDSA44-RSA2048-PSS-SHA256", 37, "ML-DSA-44", crypto.SHA256, tradRSAPSS, crypto.SHA256, 2048, ""),
	compSig("MLDSA44-RSA2048-PKCS15-SHA256", 38, "ML-DSA-44", crypto.SHA256, tradRSAPKCS1, crypto.SHA256, 2048, ""),
	compSig("MLDSA44-Ed25519-SHA512", 39, "ML-DSA-44", crypto.SHA512, tradEd25519, 0, 0, ""),
	compSig("MLDSA44-ECDSA-P256-SHA256", 40, "ML-DSA-44", crypto.SHA256, tradECDSA, crypto.SHA256, 0, "P-256"),
	compSig("MLDSA65-RSA3072-PSS-SHA512", 41, "ML-DSA-65", crypto.SHA512, tradRSAPSS, crypto.SHA256, 3072, ""),
	compSig("MLDSA65-RSA3072-PKCS15-SHA512", 42, "ML-DSA-65", crypto.SHA512, tradRSAPKCS1, crypto.SHA256, 3072, ""),
	compSig("MLDSA65-RSA4096-PSS-SHA512", 43, "ML-DSA-65", crypto.SHA512, tradRSAPSS, crypto.SHA384, 4096, ""),
	compSig("MLDSA65-RSA4096-PKCS15-SHA512", 44, "ML-DSA-65", crypto.SHA512, tradRSAPKCS1, crypto.SHA384, 4096, ""),
	compSig("MLDSA65-ECDSA-P256-SHA512", 45, "ML-DSA-65", crypto.SHA512, tradECDSA, crypto.SHA256, 0, "P-256"),
	compSig("MLDSA65-ECDSA-P384-SHA512", 46, "ML-DSA-65", crypto.SHA512, tradECDSA, crypto.SHA384, 0, "P-384"),
	compSig("MLDSA65-ECDSA-brainpoolP256r1-SHA512", 47, "ML-DSA-65", crypto.SHA512, tradECDSA, crypto.SHA256, 0, "brainpoolP256r1"),
	compSig("MLDSA65-Ed25519-SHA512", 48, "ML-DSA-65", crypto.SHA512, tradEd25519, 0, 0, ""),
	compSig("MLDSA87-ECDSA-P384-SHA512", 49, "ML-DSA-87", crypto.SHA512, tradECDSA, crypto.SHA384, 0, "P-384"),
	compSig("MLDSA87-ECDSA-brainpoolP384r1-SHA512", 50, "ML-DSA-87", crypto.SHA512, tradECDSA, crypto.SHA384, 0, "brainpoolP384r1"),
	compSig("MLDSA87-Ed448-SHAKE256", 51, "ML-DSA-87", 0, tradEd448, 0, 0, ""),
	compSig("MLDSA87-RSA3072-PSS-SHA512", 52, "ML-DSA-87", crypto.SHA512, tradRSAPSS, crypto.SHA256, 3072, ""),
	compSig("MLDSA87-RSA4096-PSS-SHA512", 53, "ML-DSA-87", crypto.SHA512, tradRSAPSS, crypto.SHA384, 4096, ""),
	compSig("MLDSA87-ECDSA-P521-SHA512", 54, "ML-DSA-87", crypto.SHA512, tradECDSA, crypto.SHA512, 0, "P-521"),
}

func compositeByOID(oid asn1.ObjectIdentifier) *CompositeAlg {
	for _, a := range CompositeAlgs {
		if a.OID.Equal(oid) {
			return a
		}
	}
	return nil
}

func compositeByName(name string) *CompositeAlg {
	for _, a := range CompositeAlgs {
		if a.Name == name {
			return a
		}
	}
	return nil
}

// CompositeKEMAlg is a Composite ML-KEM algorithm.
type CompositeKEMAlg struct {
	Name    string
	OID     asn1.ObjectIdentifier
	MLKEM   *MLKEMParams
	Trad    string
	RSABits int
	Curve   string // ECDH
}

func compKEM(name string, arc int, mlkem, trad string, bits int, curve string) *CompositeKEMAlg {
	return &CompositeKEMAlg{name, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, arc}, mlkemByName(mlkem), trad, bits, curve}
}

// CompositeKEMAlgs lists the Composite ML-KEM algorithms.
var CompositeKEMAlgs = []*CompositeKEMAlg{
	compKEM("MLKEM768-RSA2048-SHA3-256", 55, "ML-KEM-768", tradRSAOAEP, 2048, ""),
	compKEM("MLKEM768-RSA3072-SHA3-256", 56, "ML-KEM-768", tradRSAOAEP, 3072, ""),
	compKEM("MLKEM768-RSA4096-SHA3-256", 57, "ML-KEM-768", tradRSAOAEP, 4096, ""),
	compKEM("MLKEM768-X25519-SHA3-256", 58, "ML-KEM-768", tradX25519, 0, ""),
	compKEM("MLKEM768-ECDH-P256-SHA3-256", 59, "ML-KEM-768", tradECDH, 0, "P-256"),
	compKEM("MLKEM768-ECDH-P384-SHA3-256", 60, "ML-KEM-768", tradECDH, 0, "P-384"),
	compKEM("MLKEM768-ECDH-brainpoolP256r1-SHA3-256", 61, "ML-KEM-768", tradECDH, 0, "brainpoolP256r1"),
	compKEM("MLKEM1024-RSA3072-SHA3-256", 62, "ML-KEM-1024", tradRSAOAEP, 3072, ""),
	compKEM("MLKEM1024-ECDH-P384-SHA3-256", 63, "ML-KEM-1024", tradECDH, 0, "P-384"),
	compKEM("MLKEM1024-ECDH-brainpoolP384r1-SHA3-256", 64, "ML-KEM-1024", tradECDH, 0, "brainpoolP384r1"),
	compKEM("MLKEM1024-X448-SHA3-256", 65, "ML-KEM-1024", tradX448, 0, ""),
	compKEM("MLKEM1024-ECDH-P521-SHA3-256", 66, "ML-KEM-1024", tradECDH, 0, "P-521"),
}

func compositeKEMByOID(oid asn1.ObjectIdentifier) *CompositeKEMAlg {
	for _, a := range CompositeKEMAlgs {
		if a.OID.Equal(oid) {
			return a
		}
	}
	return nil
}

func compositeKEMByName(name string) *CompositeKEMAlg {
	for _, a := range CompositeKEMAlgs {
		if a.Name == name {
			return a
		}
	}
	return nil
}

// CompositePublicKey is a Composite ML-DSA public key.
type CompositePublicKey struct {
	Alg   *CompositeAlg
	MLDSA *mldsa.PublicKey
	Trad  crypto.PublicKey // *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey or ed448.PublicKey
}

func (k *CompositePublicKey) Equal(x crypto.PublicKey) bool {
	o, ok := x.(*CompositePublicKey)
	return ok && o.Alg == k.Alg && k.MLDSA.Equal(o.MLDSA) && publicEqual(k.Trad, o.Trad)
}

// CompositeKey is a Composite ML-DSA private key. Sign takes the whole
// message (crypto.Hash(0)); *CompositeOptions sets an application
// context.
type CompositeKey struct {
	Alg   *CompositeAlg
	MLDSA *mldsa.PrivateKey
	Trad  crypto.Signer
}

// CompositeOptions carry the application context of a composite
// signature; certificates use none.
type CompositeOptions struct{ Context []byte }

func (*CompositeOptions) HashFunc() crypto.Hash { return 0 }

func (k CompositeKey) Public() crypto.PublicKey {
	return &CompositePublicKey{k.Alg, k.MLDSA.PublicKey(), k.Trad.Public()}
}

// messageRepresentative is M' = Prefix || Label || len(ctx) || ctx || PH(M).
func (a *CompositeAlg) messageRepresentative(msg, ctx []byte) ([]byte, error) {
	if len(ctx) > 255 {
		return nil, errors.New("composite: context too long")
	}
	var ph []byte
	if a.PH == 0 {
		ph = sha3.SumSHAKE256(msg, 64)
	} else {
		h := a.PH.New()
		h.Write(msg)
		ph = h.Sum(nil)
	}
	m := append([]byte(compositePrefix+a.Label), byte(len(ctx)))
	m = append(m, ctx...)
	return append(m, ph...), nil
}

func hashed(h crypto.Hash, msg []byte) []byte {
	d := h.New()
	d.Write(msg)
	return d.Sum(nil)
}

func (k CompositeKey) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != 0 {
		return nil, errors.New("composite: the message must not be hashed")
	}
	if r == nil {
		r = rand.Reader
	}
	var ctx []byte
	if o, ok := opts.(*CompositeOptions); ok && o != nil {
		ctx = o.Context
	}
	a := k.Alg
	m, err := a.messageRepresentative(msg, ctx)
	if err != nil {
		return nil, err
	}
	sig, err := k.MLDSA.Sign(r, m, &mldsa.Options{Context: a.Label})
	if err != nil {
		return nil, err
	}
	var trad []byte
	switch a.Trad {
	case tradRSAPSS:
		trad, err = k.Trad.Sign(r, hashed(a.TradHash, m), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: a.TradHash})
	case tradRSAPKCS1, tradECDSA:
		trad, err = k.Trad.Sign(r, hashed(a.TradHash, m), a.TradHash)
	case tradEd25519, tradEd448:
		trad, err = k.Trad.Sign(r, m, crypto.Hash(0))
	}
	if err != nil {
		return nil, err
	}
	return append(sig, trad...), nil
}

// verifyComposite checks a composite signature over msg with an empty
// context.
func verifyComposite(pub *CompositePublicKey, msg, sig []byte) error {
	a := pub.Alg
	n := mldsaSignatureSize(a.MLDSA)
	if len(sig) <= n {
		return errors.New("composite: signature too short")
	}
	m, err := a.messageRepresentative(msg, nil)
	if err != nil {
		return err
	}
	if err := mldsa.Verify(pub.MLDSA, m, sig[:n], &mldsa.Options{Context: a.Label}); err != nil {
		return err
	}
	trad := sig[n:]
	ok := false
	switch a.Trad {
	case tradRSAPSS:
		ok = rsa.VerifyPSS(pub.Trad.(*rsa.PublicKey), a.TradHash, hashed(a.TradHash, m), trad, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	case tradRSAPKCS1:
		ok = rsa.VerifyPKCS1v15(pub.Trad.(*rsa.PublicKey), a.TradHash, hashed(a.TradHash, m), trad) == nil
	case tradECDSA:
		ok = ecdsa.VerifyASN1(pub.Trad.(*ecdsa.PublicKey), hashed(a.TradHash, m), trad)
	case tradEd25519:
		ok = ed25519.Verify(pub.Trad.(ed25519.PublicKey), m, trad)
	case tradEd448:
		ok = ed448.Verify(pub.Trad.(ed448.PublicKey), m, trad, "")
	}
	if !ok {
		return errors.New("composite: the traditional signature does not verify")
	}
	return nil
}

func mldsaSignatureSize(p *MLDSAParams) int {
	switch p.Name {
	case "ML-DSA-44":
		return 2420
	case "ML-DSA-65":
		return 3309
	}
	return 4627
}

func mldsaPublicSize(p *MLDSAParams) int {
	switch p.Name {
	case "ML-DSA-44":
		return 1312
	case "ML-DSA-65":
		return 1952
	}
	return 2592
}

// CompositeKEMPublicKey is a Composite ML-KEM public key.
type CompositeKEMPublicKey struct {
	Alg   *CompositeKEMAlg
	MLKEM *MLKEMPublicKey
	Trad  crypto.PublicKey // *rsa.PublicKey, *ecdsa.PublicKey (for ECDH), *ecdh.PublicKey (X25519) or X448PublicKey
}

func (k *CompositeKEMPublicKey) Equal(x crypto.PublicKey) bool {
	o, ok := x.(*CompositeKEMPublicKey)
	return ok && o.Alg == k.Alg && k.MLKEM.Equal(o.MLKEM) && publicEqual(k.Trad, o.Trad)
}

// CompositeKEMKey is a Composite ML-KEM private key; it cannot sign.
type CompositeKEMKey struct {
	Alg   *CompositeKEMAlg
	MLKEM MLKEMKey
	Trad  crypto.Signer // *rsa.PrivateKey, *ecdsa.PrivateKey, X25519Key or X448Key
}

func (k CompositeKEMKey) Public() crypto.PublicKey {
	return &CompositeKEMPublicKey{k.Alg, k.MLKEM.pub, k.Trad.Public()}
}

func (k CompositeKEMKey) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("composite ML-KEM keys cannot sign")
}

func publicEqual(a, b crypto.PublicKey) bool {
	e, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && e.Equal(b)
}

// tradPublicBytes encodes the traditional public key of a composite.
func tradPublicBytes(pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return x509.MarshalPKCS1PublicKey(k), nil
	case *ecdsa.PublicKey:
		return ECPoint(k), nil
	case ed25519.PublicKey:
		return k, nil
	case ed448.PublicKey:
		return k, nil
	case X448PublicKey:
		return k, nil
	}
	if isX25519(pub) {
		return pub.(interface{ Bytes() []byte }).Bytes(), nil
	}
	return nil, fmt.Errorf("composite: unsupported traditional key %T", pub)
}

// parseTradPublic decodes the traditional public key of a composite.
func parseTradPublic(trad, curve string, b []byte) (crypto.PublicKey, error) {
	switch trad {
	case tradRSAPSS, tradRSAPKCS1, tradRSAOAEP:
		return x509.ParsePKCS1PublicKey(b)
	case tradECDSA, tradECDH:
		return parseECPoint(curveByName(curve).Curve(), b)
	case tradEd25519:
		if len(b) != ed25519.PublicKeySize {
			return nil, errors.New("composite: bad Ed25519 key")
		}
		return ed25519.PublicKey(append([]byte(nil), b...)), nil
	case tradEd448:
		if len(b) != ed448.PublicKeySize {
			return nil, errors.New("composite: bad Ed448 key")
		}
		return ed448.PublicKey(append([]byte(nil), b...)), nil
	case tradX25519:
		return parseX25519Public(b)
	case tradX448:
		if len(b) != 56 {
			return nil, errors.New("composite: bad X448 key")
		}
		return X448PublicKey(append([]byte(nil), b...)), nil
	}
	return nil, errors.New("composite: unknown traditional algorithm")
}

// tradPrivateBytes encodes the traditional private key of a composite:
// RSAPrivateKey, ECPrivateKey without the public key, or the raw key.
func tradPrivateBytes(k crypto.Signer) ([]byte, error) {
	switch v := k.(type) {
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(v), nil
	case *ecdsa.PrivateKey:
		return marshalSEC1(v, false)
	case ed25519.PrivateKey:
		return append([]byte(nil), v.Seed()...), nil
	case ed448.PrivateKey:
		return append([]byte(nil), v.Seed()...), nil
	case X25519Key:
		return v.Bytes(), nil
	case X448Key:
		return v.Bytes(), nil
	}
	return nil, fmt.Errorf("composite: unsupported traditional key %T", k)
}

// parseTradPrivate decodes the traditional private key of a composite.
func parseTradPrivate(trad, curve string, b []byte) (crypto.Signer, error) {
	switch trad {
	case tradRSAPSS, tradRSAPKCS1, tradRSAOAEP:
		return x509.ParsePKCS1PrivateKey(b)
	case tradECDSA, tradECDH:
		return parseSEC1(b, curveByName(curve))
	case tradEd25519:
		if len(b) != ed25519.SeedSize {
			return nil, errors.New("composite: bad Ed25519 key")
		}
		return ed25519.NewKeyFromSeed(b), nil
	case tradEd448:
		if len(b) != ed448.SeedSize {
			return nil, errors.New("composite: bad Ed448 key")
		}
		return ed448.NewKeyFromSeed(b), nil
	case tradX25519:
		return newX25519Key(b)
	case tradX448:
		return NewX448Key(b)
	}
	return nil, errors.New("composite: unknown traditional algorithm")
}

// generateTrad creates the traditional component of a composite key.
func generateTrad(trad string, bits int, curve string) (crypto.Signer, error) {
	switch trad {
	case tradRSAPSS, tradRSAPKCS1, tradRSAOAEP:
		return rsa.GenerateKey(rand.Reader, bits)
	case tradECDSA, tradECDH:
		return ecdsa.GenerateKey(curveByName(curve).Curve(), rand.Reader)
	case tradEd25519:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	case tradEd448:
		_, k, err := ed448.GenerateKey(rand.Reader)
		return k, err
	case tradX25519:
		return GenerateKey(KeySpec{Type: "X25519"})
	case tradX448:
		return GenerateKey(KeySpec{Type: "X448"})
	}
	return nil, errors.New("composite: unknown traditional algorithm")
}

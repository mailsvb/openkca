package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Certificates, requests and CRLs are built and signed here rather than by
// crypto/x509, which signs only with RSA (without PSS restrictions),
// NIST ECDSA, Ed25519 and ML-DSA keys and writes only the public keys it
// can parse. The encoding follows crypto/x509's: a version 3 certificate,
// UTCTime until 2049, the extensions exactly as given.

type validity struct{ NotBefore, NotAfter asn1.RawValue }

type tbsCertificate struct {
	Version    int `asn1:"optional,explicit,default:0,tag:0"`
	Serial     *big.Int
	Signature  pkix.AlgorithmIdentifier
	Issuer     asn1.RawValue
	Validity   validity
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Extensions []pkix.Extension `asn1:"omitempty,optional,explicit,tag:3"`
}

// signStructure signs tbs and returns SEQUENCE { tbs, algorithm,
// signature }, after checking the signature with the signer's public key.
func signStructure(tbs []byte, s sigScheme, key crypto.Signer) ([]byte, error) {
	sig, err := s.sign(key, tbs)
	if err != nil {
		return nil, err
	}
	if err := VerifySignature(key.Public(), s.id, tbs, sig); err != nil {
		return nil, fmt.Errorf("the signature does not verify: %w", err)
	}
	return asn1.Marshal(signedData{asn1.RawValue{FullBytes: tbs}, s.id, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
}

// CreateCertificate signs a certificate. All extensions come from
// req.Extensions; nothing is added implicitly.
func CreateCertificate(req CertRequest) ([]byte, error) {
	s, err := signatureScheme(req.SignerKey, req.Hash)
	if err != nil {
		return nil, err
	}
	if !req.NotAfter.After(req.NotBefore) {
		return nil, errors.New("not after must be later than not before")
	}
	if req.Serial == nil || req.Serial.Sign() < 0 {
		return nil, errors.New("the serial number must not be negative")
	}
	spki := req.SPKI
	if spki == nil {
		if spki, err = MarshalPublicKey(req.PublicKey); err != nil {
			return nil, err
		}
	}
	issuer, issuerSPKI := req.Subject, spki
	if req.Issuer != nil {
		issuer, issuerSPKI = req.Issuer.RawSubject, req.Issuer.RawSubjectPublicKeyInfo
	}
	if ok, err := MatchesPublic(req.SignerKey, issuerSPKI); err != nil || !ok {
		return nil, errors.New("the signing key does not belong to the issuer")
	}
	tbs, err := asn1.Marshal(tbsCertificate{
		Version:    2,
		Serial:     req.Serial,
		Signature:  s.id,
		Issuer:     asn1.RawValue{FullBytes: issuer},
		Validity:   validity{asn1Time(req.NotBefore), asn1Time(req.NotAfter)},
		Subject:    asn1.RawValue{FullBytes: req.Subject},
		PublicKey:  asn1.RawValue{FullBytes: spki},
		Extensions: req.Extensions,
	})
	if err != nil {
		return nil, err
	}
	der, err := signStructure(tbs, s, req.SignerKey)
	if err != nil {
		return nil, err
	}
	if _, err := ParseCertificate(der); err != nil {
		return nil, err
	}
	return der, nil
}

var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

type certificationRequestInfo struct {
	Version    int
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Attributes asn1.RawValue
}

// CreateRequest signs a PKCS#10 request; the extensions become an
// extensionRequest attribute.
func CreateRequest(subject []byte, exts []pkix.Extension, key crypto.Signer, hash string) ([]byte, error) {
	s, err := signatureScheme(key, hash)
	if err != nil {
		return nil, err
	}
	spki, err := MarshalPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	var attrs []byte
	if len(exts) > 0 {
		e, err := asn1.Marshal(exts)
		if err != nil {
			return nil, err
		}
		if attrs, err = asn1.Marshal(attribute{oidExtensionRequest,
			asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: e}}); err != nil {
			return nil, err
		}
	}
	tbs, err := asn1.Marshal(certificationRequestInfo{
		Subject:    asn1.RawValue{FullBytes: subject},
		PublicKey:  asn1.RawValue{FullBytes: spki},
		Attributes: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: attrs},
	})
	if err != nil {
		return nil, err
	}
	der, err := signStructure(tbs, s, key)
	if err != nil {
		return nil, err
	}
	if _, err := ParseCertificateRequest(der); err != nil {
		return nil, err
	}
	return der, nil
}

// placeholderOID stands in for a public key algorithm crypto/x509 rejects
// while the rest of a certificate or request is parsed.
var placeholderOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// elements splits the contents of a DER SEQUENCE.
func elements(der []byte) ([][]byte, error) {
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &seq); err != nil {
		return nil, err
	} else if len(rest) > 0 || seq.Tag != asn1.TagSequence {
		return nil, errors.New("not a sequence")
	}
	var out [][]byte
	for b := seq.Bytes; len(b) > 0; {
		var e asn1.RawValue
		rest, err := asn1.Unmarshal(b, &e)
		if err != nil {
			return nil, err
		}
		out = append(out, e.FullBytes)
		b = rest
	}
	return out, nil
}

func sequence(parts [][]byte) []byte {
	b, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(parts, nil)})
	return b
}

// withPlaceholderKey re-encodes a certificate or request (the public key
// is element index of its TBS part) with a placeholder algorithm and
// returns it with the original SubjectPublicKeyInfo.
func withPlaceholderKey(der []byte, index func(tbs [][]byte) int) ([]byte, []byte, error) {
	outer, err := elements(der)
	if err != nil || len(outer) != 3 {
		return nil, nil, errors.New("malformed signed structure")
	}
	tbs, err := elements(outer[0])
	if err != nil {
		return nil, nil, err
	}
	i := index(tbs)
	if i >= len(tbs) {
		return nil, nil, errors.New("malformed TBS structure")
	}
	var s spki
	if _, err := asn1.Unmarshal(tbs[i], &s); err != nil {
		return nil, nil, err
	}
	orig := tbs[i]
	if _, err := ParsePublicKey(orig); err != nil {
		return nil, nil, err
	}
	tbs[i], err = asn1.Marshal(spki{pkix.AlgorithmIdentifier{Algorithm: placeholderOID}, s.PublicKey})
	if err != nil {
		return nil, nil, err
	}
	outer[0] = sequence(tbs)
	return sequence(outer), orig, nil
}

// ParseCertificate is x509.ParseCertificate, also for certificates with
// keys crypto/x509 refuses (ECDSA on Brainpool curves and secp256k1).
// PublicKey holds any key ParsePublicKey returns.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		mod, orig, perr := withPlaceholderKey(der, func(tbs [][]byte) int {
			if len(tbs) > 0 && tbs[0][0] == 0xa0 { // [0] version
				return 6
			}
			return 5
		})
		if perr != nil {
			return nil, err
		}
		if c, perr = x509.ParseCertificate(mod); perr != nil {
			return nil, err
		}
		var parts signedData
		if _, perr := asn1.Unmarshal(der, &parts); perr != nil {
			return nil, err
		}
		c.Raw, c.RawTBSCertificate, c.RawSubjectPublicKeyInfo = der, parts.TBS.FullBytes, orig
		c.PublicKey = nil
	}
	fillPublicKey(&c.PublicKey, &c.PublicKeyAlgorithm, c.RawSubjectPublicKeyInfo)
	return c, nil
}

// ParseCertificateRequest is x509.ParseCertificateRequest, also for
// requests with keys crypto/x509 refuses.
func ParseCertificateRequest(der []byte) (*x509.CertificateRequest, error) {
	r, err := x509.ParseCertificateRequest(der)
	if err != nil {
		mod, orig, perr := withPlaceholderKey(der, func([][]byte) int { return 2 })
		if perr != nil {
			return nil, err
		}
		if r, perr = x509.ParseCertificateRequest(mod); perr != nil {
			return nil, err
		}
		var parts signedData
		if _, perr := asn1.Unmarshal(der, &parts); perr != nil {
			return nil, err
		}
		r.Raw, r.RawTBSCertificateRequest, r.RawSubjectPublicKeyInfo = der, parts.TBS.FullBytes, orig
		r.PublicKey = nil
	}
	fillPublicKey(&r.PublicKey, &r.PublicKeyAlgorithm, r.RawSubjectPublicKeyInfo)
	return r, nil
}

func fillPublicKey(pub *any, algo *x509.PublicKeyAlgorithm, spki []byte) {
	if *pub != nil {
		return
	}
	k, err := ParsePublicKey(spki)
	if err != nil {
		return
	}
	*pub = k
	if _, ok := k.(*ecdsa.PublicKey); ok {
		*algo = x509.ECDSA
	}
}

// asn1Time encodes like OpenSSL's ASN1_TIME_set: UTCTime until 2049,
// GeneralizedTime from 2050.
func asn1Time(t time.Time) asn1.RawValue {
	t = t.UTC().Truncate(time.Second)
	if t.Year() >= 1950 && t.Year() < 2050 {
		b, _ := asn1.MarshalWithParams(t, "utc")
		return asn1.RawValue{FullBytes: b}
	}
	b, _ := asn1.MarshalWithParams(t, "generalized")
	return asn1.RawValue{FullBytes: b}
}

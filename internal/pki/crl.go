package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"sort"
	"time"
)

// CRL reason codes as stored in revocations.reasonBit (XCA's crl_reasons
// "bitnum", which is the RFC 5280 CRLReason value).
const (
	ReasonUnspecified = 0
	ReasonSuperseded  = 4
)

// ReasonCodes lists the reasons offered when revoking, by code.
var ReasonCodes = []int{0, 1, 2, 3, 4, 5, 6, 8, 9, 10}

// Revoked is one revocation to put on a CRL.
type Revoked struct {
	Serial     *big.Int
	Date       time.Time
	InvalDate  time.Time // zero = none
	Reason     int
	WithReason bool
}

// CRLParams are the options of XCA's "Create CRL" dialog.
type CRLParams struct {
	Issuer     *x509.Certificate
	Key        crypto.Signer
	Hash       string
	ThisUpdate time.Time
	NextUpdate time.Time
	Number     *big.Int // nil = no CRL number extension
	AuthKeyID  bool     // authorityKeyIdentifier keyid,issuer
	IssuerAlt  bool     // issuerAltName issuer:copy (only if the CA has a SAN)
	Revoked    []Revoked
}

var (
	oidCRLNumber   = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidReasonCode  = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidInvalidDate = asn1.ObjectIdentifier{2, 5, 29, 24}
)

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

type sigAlg struct {
	oid  asn1.ObjectIdentifier
	null bool
	hash crypto.Hash
}

var sigAlgs = map[x509.SignatureAlgorithm]sigAlg{
	x509.SHA256WithRSA:   {asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, true, crypto.SHA256},
	x509.SHA384WithRSA:   {asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}, true, crypto.SHA384},
	x509.SHA512WithRSA:   {asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}, true, crypto.SHA512},
	x509.ECDSAWithSHA256: {asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, false, crypto.SHA256},
	x509.ECDSAWithSHA384: {asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, false, crypto.SHA384},
	x509.ECDSAWithSHA512: {asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}, false, crypto.SHA512},
	x509.PureEd25519:     {asn1.ObjectIdentifier{1, 3, 101, 112}, false, 0},
}

func (a sigAlg) identifier() pkix.AlgorithmIdentifier {
	id := pkix.AlgorithmIdentifier{Algorithm: a.oid}
	if a.null {
		id.Parameters = asn1.NullRawValue
	}
	return id
}

// signTBS signs DER data and returns the complete signed structure
// SEQUENCE { tbs, algorithm, signature }.
func signTBS(tbs []byte, alg sigAlg, key crypto.Signer) ([]byte, error) {
	digest := tbs
	var opts crypto.SignerOpts = crypto.Hash(0)
	if alg.hash != 0 {
		h := alg.hash.New()
		h.Write(tbs)
		digest, opts = h.Sum(nil), alg.hash
	}
	sig, err := key.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, alg.identifier(), asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
}

type revokedEntry struct {
	Serial     *big.Int
	Date       asn1.RawValue
	Extensions []pkix.Extension `asn1:"optional"`
}

// CreateCRL builds and signs a version 2 CRL the way XCA's db_crl::newCrl
// does: entries sorted by serial, each with its invalidity date (if set)
// and reason (if wanted and not unspecified); extensions in the order AKI,
// IAN, CRL number.
func CreateCRL(p CRLParams) ([]byte, error) {
	sa, err := SignatureAlgorithm(p.Key, p.Hash)
	if err != nil {
		return nil, err
	}
	alg, ok := sigAlgs[sa]
	if !ok {
		return nil, errors.New("unsupported signature algorithm")
	}
	if !p.NextUpdate.After(p.ThisUpdate) {
		return nil, errors.New("the next update must be later than the last update")
	}
	pub, _ := x509.MarshalPKIXPublicKey(p.Key.Public())
	if !bytes.Equal(pub, p.Issuer.RawSubjectPublicKeyInfo) {
		return nil, errors.New("the key does not belong to the CA certificate")
	}
	revoked := append([]Revoked(nil), p.Revoked...)
	sort.Slice(revoked, func(i, j int) bool { return revoked[i].Serial.Cmp(revoked[j].Serial) < 0 })
	var entries []revokedEntry
	for _, r := range revoked {
		e := revokedEntry{Serial: r.Serial, Date: asn1Time(r.Date)}
		if !r.InvalDate.IsZero() && r.InvalDate.Year() < 9999 {
			v, _ := asn1.MarshalWithParams(r.InvalDate.UTC().Truncate(time.Second), "generalized")
			e.Extensions = append(e.Extensions, pkix.Extension{Id: oidInvalidDate, Value: v})
		}
		if r.WithReason && r.Reason != ReasonUnspecified {
			v, _ := asn1.Marshal(asn1.Enumerated(r.Reason))
			e.Extensions = append(e.Extensions, pkix.Extension{Id: oidReasonCode, Value: v})
		}
		entries = append(entries, e)
	}
	var exts []pkix.Extension
	if p.AuthKeyID {
		var aki struct {
			KeyID  []byte        `asn1:"optional,tag:0"`
			Issuer asn1.RawValue `asn1:"optional,tag:1"`
			Serial *big.Int      `asn1:"optional,tag:2"`
		}
		aki.KeyID = p.Issuer.SubjectKeyId
		if len(aki.KeyID) == 0 { // "issuer" is only used without a keyid
			dir, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: p.Issuer.RawIssuer})
			aki.Issuer = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: dir}
			aki.Serial = p.Issuer.SerialNumber
		}
		v, err := asn1.Marshal(aki)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{Id: oidAKI, Value: v})
	}
	if p.IssuerAlt {
		for _, e := range p.Issuer.Extensions {
			if e.Id.Equal(oidSAN) {
				exts = append(exts, pkix.Extension{Id: oidIAN, Value: e.Value})
			}
		}
	}
	if p.Number != nil {
		v, err := asn1.Marshal(p.Number)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{Id: oidCRLNumber, Value: v})
	}
	tbs := struct {
		Version    int
		Signature  pkix.AlgorithmIdentifier
		Issuer     asn1.RawValue
		ThisUpdate asn1.RawValue
		NextUpdate asn1.RawValue
		Revoked    []revokedEntry   `asn1:"optional,omitempty"`
		Extensions []pkix.Extension `asn1:"optional,omitempty,explicit,tag:0"`
	}{1, alg.identifier(), asn1.RawValue{FullBytes: p.Issuer.RawSubject}, asn1Time(p.ThisUpdate), asn1Time(p.NextUpdate), entries, exts}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}
	return signTBS(tbsDER, alg, p.Key)
}

package pki

import (
	"crypto"
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
	alg, err := signatureScheme(p.Key, p.Hash)
	if err != nil {
		return nil, err
	}
	if !p.NextUpdate.After(p.ThisUpdate) {
		return nil, errors.New("the next update must be later than the last update")
	}
	if ok, err := MatchesPublic(p.Key, p.Issuer.RawSubjectPublicKeyInfo); err != nil || !ok {
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
	}{1, alg.id, asn1.RawValue{FullBytes: p.Issuer.RawSubject}, asn1Time(p.ThisUpdate), asn1Time(p.NextUpdate), entries, exts}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}
	return signStructure(tbsDER, alg, p.Key)
}

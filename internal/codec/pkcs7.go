package codec

import (
	"encoding/asn1"
	"errors"
)

var (
	oidPKCS7Data   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7Signed = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      contentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

var emptySet = asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: []byte{}}

// PKCS7 writes a degenerate PKCS#7 SignedData holding certificates (DER),
// in the given order, as XCA's pki_pkcs7::writeP7 does.
func PKCS7(certs [][]byte) ([]byte, error) {
	var body []byte
	for _, c := range certs {
		body = append(body, c...)
	}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: emptySet,
		ContentInfo:      contentInfo{ContentType: oidPKCS7Data},
		SignerInfos:      emptySet,
	}
	if len(certs) > 0 {
		sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: body}
	}
	inner, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(contentInfo{ContentType: oidPKCS7Signed,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
}

// ParsePKCS7 returns the certificates and CRLs (DER) of a PKCS#7
// SignedData; signatures are not checked.
func ParsePKCS7(der []byte) (certs, crls [][]byte, err error) {
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, nil, err
	} else if len(rest) > 0 {
		return nil, nil, errors.New("pkcs7: trailing data")
	}
	if !ci.ContentType.Equal(oidPKCS7Signed) {
		return nil, nil, errors.New("pkcs7: not SignedData")
	}
	var sd signedData
	if _, err := asn1.Unmarshal(inner(ci.Content), &sd); err != nil {
		return nil, nil, err
	}
	split := func(b []byte) ([][]byte, error) {
		var out [][]byte
		for len(b) > 0 {
			var v asn1.RawValue
			rest, err := asn1.Unmarshal(b, &v)
			if err != nil {
				return nil, err
			}
			out = append(out, v.FullBytes)
			b = rest
		}
		return out, nil
	}
	if certs, err = split(sd.Certificates.Bytes); err != nil {
		return nil, nil, err
	}
	if crls, err = split(sd.CRLs.Bytes); err != nil {
		return nil, nil, err
	}
	return certs, crls, nil
}

// inner returns the element inside an explicitly tagged RawValue field.
func inner(rv asn1.RawValue) []byte {
	if rv.Class == asn1.ClassContextSpecific {
		return rv.Bytes
	}
	return rv.FullBytes
}

// octets unwraps the OCTET STRING inside an explicitly tagged field.
func octets(rv asn1.RawValue) []byte {
	var b []byte
	if _, err := asn1.Unmarshal(inner(rv), &b); err != nil {
		return nil
	}
	return b
}

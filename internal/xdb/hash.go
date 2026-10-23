package xdb

import (
	"bytes"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Hash is XCA's 31 bit object hash (pki_base::hash): the first four bytes of
// SHA-1 over the DER, read little-endian, masked with 0x7fffffff. It is used
// for items' own hash columns (certs.hash, requests.hash, crls.hash and
// public_keys.hash over the SubjectPublicKeyInfo).
func Hash(der []byte) int64 {
	d := sha1.Sum(der)
	return int64(binary.LittleEndian.Uint32(d[:4]) & 0x7fffffff)
}

// NameHash is XCA's name hash (x509name::hashNum), which is OpenSSL's
// X509_NAME_hash masked to 31 bits: SHA-1 over the canonical encoding of the
// name. It fills subj_hash and iss_hash columns.
func NameHash(nameDER []byte) (int64, error) {
	canon, err := canonicalName(nameDER)
	if err != nil {
		return 0, err
	}
	return Hash(canon), nil
}

type atv struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

// canonicalName reproduces OpenSSL's x509_name_canon: every string value that
// is one of the text types becomes a trimmed, whitespace-collapsed, ASCII
// lower-cased UTF8String; the RDN SETs are concatenated without the outer
// SEQUENCE header.
func canonicalName(der []byte) ([]byte, error) {
	var rdns []asn1.RawValue
	rest, err := asn1.Unmarshal(der, &rdns)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("xdb: trailing data after name")
	}
	var out []byte
	for _, rdn := range rdns {
		var atvs []atv
		if _, err := asn1.UnmarshalWithParams(rdn.FullBytes, &atvs, "set"); err != nil {
			return nil, err
		}
		var elems [][]byte
		for _, a := range atvs {
			v := a.Value
			if s, ok := asn1Text(v); ok {
				enc, err := asn1.MarshalWithParams(canonText(s), "utf8")
				if err != nil {
					return nil, err
				}
				v = asn1.RawValue{FullBytes: enc}
			}
			seq, err := asn1.Marshal(struct {
				Type  asn1.ObjectIdentifier
				Value asn1.RawValue
			}{a.Type, v})
			if err != nil {
				return nil, err
			}
			elems = append(elems, seq)
		}
		// DER orders SET OF members by their encoding (multi-valued RDNs).
		slices.SortFunc(elems, bytes.Compare)
		setBody := bytes.Join(elems, nil)
		set, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: setBody})
		if err != nil {
			return nil, err
		}
		out = append(out, set...)
	}
	return out, nil
}

// asn1Text decodes the string types OpenSSL canonicalises (ASN1_MASK_CANON).
func asn1Text(v asn1.RawValue) (string, bool) {
	if v.Class != asn1.ClassUniversal {
		return "", false
	}
	switch v.Tag {
	case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String, asn1.TagT61String, 26 /* VisibleString */ :
		if v.Tag == asn1.TagUTF8String && utf8.Valid(v.Bytes) {
			return string(v.Bytes), true
		}
		// The single byte types are treated as Latin-1, as OpenSSL does.
		r := make([]rune, len(v.Bytes))
		for i, b := range v.Bytes {
			r[i] = rune(b)
		}
		return string(r), true
	case 30: // BMPString
		if len(v.Bytes)%2 != 0 {
			return "", false
		}
		u := make([]uint16, len(v.Bytes)/2)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(v.Bytes[2*i:])
		}
		return string(utf16.Decode(u)), true
	case 28: // UniversalString
		if len(v.Bytes)%4 != 0 {
			return "", false
		}
		r := make([]rune, len(v.Bytes)/4)
		for i := range r {
			r[i] = rune(binary.BigEndian.Uint32(v.Bytes[4*i:]))
		}
		return string(r), true
	}
	return "", false
}

func isSpace(b byte) bool { return b == ' ' || (b >= '\t' && b <= '\r') }

func canonText(s string) string {
	b := []byte(s)
	i, j := 0, len(b)
	for i < j && isSpace(b[i]) {
		i++
	}
	for j > i && isSpace(b[j-1]) {
		j--
	}
	var out strings.Builder
	prevSpace := false
	for _, c := range b[i:j] {
		if isSpace(c) {
			if !prevSpace {
				out.WriteByte(' ')
			}
			prevSpace = true
			continue
		}
		prevSpace = false
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out.WriteByte(c)
	}
	return out.String()
}

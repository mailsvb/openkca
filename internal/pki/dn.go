package pki

import (
	"encoding/asn1"
	"fmt"
	"strings"
	"unicode/utf8"
)

// DNAttr is one subject attribute as entered.
type DNAttr struct {
	Name  string // short or long name (C, CN, emailAddress, …) or a dotted OID
	Value string
}

var attrByName = func() map[string]asn1.ObjectIdentifier {
	m := map[string]asn1.ObjectIdentifier{}
	for oid, n := range attrNames {
		o, err := parseOID(oid)
		if err != nil {
			panic(err)
		}
		m[strings.ToLower(n[0])] = o
		m[strings.ToLower(n[1])] = o
	}
	m["email"] = m["emailaddress"]
	m["sn"] = m["surname"]
	return m
}()

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var o asn1.ObjectIdentifier
	for _, p := range strings.Split(s, ".") {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
			return nil, fmt.Errorf("invalid OID %q", s)
		}
		o = append(o, n)
	}
	if len(o) < 2 {
		return nil, fmt.Errorf("invalid OID %q", s)
	}
	return o, nil
}

// AttrOID resolves an attribute name or dotted OID.
func AttrOID(name string) (asn1.ObjectIdentifier, error) {
	if o, ok := attrByName[strings.ToLower(strings.TrimSpace(name))]; ok {
		return o, nil
	}
	return parseOID(strings.TrimSpace(name))
}

// AttrShortName returns the short name XCA uses for an OID.
func AttrShortName(oid asn1.ObjectIdentifier) string {
	if n, ok := attrNames[oid.String()]; ok {
		return n[0]
	}
	return oid.String()
}

func isPrintable(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune(" '()+,-./:=?", c):
		default:
			return false
		}
	}
	return true
}

// Fixed string types from OpenSSL's tbl_standard (a_strnid.c).
var fixedTypes = map[string]int{
	"2.5.4.6":                    asn1.TagPrintableString, // C
	"2.5.4.5":                    asn1.TagPrintableString, // serialNumber
	"2.5.4.46":                   asn1.TagPrintableString, // dnQualifier
	"1.2.840.113549.1.9.1":       asn1.TagIA5String,       // emailAddress
	"0.9.2342.19200300.100.1.25": asn1.TagIA5String,       // DC
}

// BuildName encodes a distinguished name in the given order. stringOpt is
// XCA's string_opt setting: "utf8only" forces UTF8String, anything else
// (default "MASK:0x2002") uses PrintableString when the value fits and
// UTF8String otherwise, as OpenSSL does with that mask.
func BuildName(attrs []DNAttr, stringOpt string) ([]byte, error) {
	var rdns []asn1.RawValue
	for _, a := range attrs {
		v := strings.TrimSpace(a.Value)
		if v == "" {
			continue
		}
		if !utf8.ValidString(v) {
			return nil, fmt.Errorf("%s: invalid UTF-8", a.Name)
		}
		oid, err := AttrOID(a.Name)
		if err != nil {
			return nil, err
		}
		tag := asn1.TagUTF8String
		if t, ok := fixedTypes[oid.String()]; ok {
			tag = t
			if (t == asn1.TagPrintableString && !isPrintable(v)) || (t == asn1.TagIA5String && !isASCII(v)) {
				return nil, fmt.Errorf("%s: characters not allowed in this field", AttrShortName(oid))
			}
			if oid.String() == "2.5.4.6" && len(v) != 2 {
				return nil, fmt.Errorf("C: the country must be a two-letter code")
			}
		} else if stringOpt != "utf8only" && isPrintable(v) {
			tag = asn1.TagPrintableString
		}
		val, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, Bytes: []byte(v)})
		if err != nil {
			return nil, err
		}
		atv, err := asn1.Marshal(struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}{oid, asn1.RawValue{FullBytes: val}})
		if err != nil {
			return nil, err
		}
		set, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: atv})
		if err != nil {
			return nil, err
		}
		rdns = append(rdns, asn1.RawValue{FullBytes: set})
	}
	if len(rdns) == 0 {
		return nil, fmt.Errorf("the subject is empty")
	}
	return asn1.Marshal(rdns)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// NameAttrs decodes a DER name into editable attributes.
func NameAttrs(der []byte) []DNAttr {
	entries, _ := ParseName(der)
	out := make([]DNAttr, len(entries))
	for i, e := range entries {
		out[i] = DNAttr{Name: e.Short, Value: e.Value}
	}
	return out
}

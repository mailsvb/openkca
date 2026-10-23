package pki

import (
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"unicode/utf16"
)

// Attribute names follow OpenSSL's short names, as XCA shows them.
var attrNames = map[string][2]string{
	"2.5.4.6":                    {"C", "countryName"},
	"2.5.4.8":                    {"ST", "stateOrProvinceName"},
	"2.5.4.7":                    {"L", "localityName"},
	"2.5.4.10":                   {"O", "organizationName"},
	"2.5.4.11":                   {"OU", "organizationalUnitName"},
	"2.5.4.3":                    {"CN", "commonName"},
	"1.2.840.113549.1.9.1":       {"emailAddress", "emailAddress"},
	"2.5.4.5":                    {"serialNumber", "serialNumber"},
	"2.5.4.12":                   {"title", "title"},
	"2.5.4.42":                   {"GN", "givenName"},
	"2.5.4.4":                    {"SN", "surname"},
	"2.5.4.43":                   {"initials", "initials"},
	"2.5.4.44":                   {"generationQualifier", "generationQualifier"},
	"2.5.4.46":                   {"dnQualifier", "dnQualifier"},
	"2.5.4.65":                   {"pseudonym", "pseudonym"},
	"2.5.4.9":                    {"street", "streetAddress"},
	"2.5.4.17":                   {"postalCode", "postalCode"},
	"2.5.4.13":                   {"description", "description"},
	"2.5.4.15":                   {"businessCategory", "businessCategory"},
	"0.9.2342.19200300.100.1.25": {"DC", "domainComponent"},
	"0.9.2342.19200300.100.1.1":  {"UID", "userId"},
	"1.3.6.1.4.1.311.60.2.1.3":   {"jurisdictionC", "jurisdictionCountryName"},
	"2.5.4.97":                   {"organizationIdentifier", "organizationIdentifier"},
}

// NameEntry is one attribute of a distinguished name, in encoded order.
type NameEntry struct {
	Short, Long, OID, Value, Type string
}

// ParseName decodes a DER Name keeping the encoded order and string types.
func ParseName(der []byte) ([]NameEntry, error) {
	var rdns []asn1.RawValue
	if _, err := asn1.Unmarshal(der, &rdns); err != nil {
		return nil, err
	}
	var out []NameEntry
	for _, rdn := range rdns {
		var atvs []struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		if _, err := asn1.UnmarshalWithParams(rdn.FullBytes, &atvs, "set"); err != nil {
			return nil, err
		}
		for _, a := range atvs {
			oid := a.Type.String()
			n, ok := attrNames[oid]
			if !ok {
				n = [2]string{oid, oid}
			}
			v, typ := stringValue(a.Value)
			out = append(out, NameEntry{Short: n[0], Long: n[1], OID: oid, Value: v, Type: typ})
		}
	}
	return out, nil
}

func stringValue(v asn1.RawValue) (string, string) {
	switch v.Tag {
	case asn1.TagUTF8String:
		return string(v.Bytes), "UTF8String"
	case asn1.TagPrintableString:
		return string(v.Bytes), "PrintableString"
	case asn1.TagIA5String:
		return string(v.Bytes), "IA5String"
	case asn1.TagT61String:
		return latin1(v.Bytes), "T61String"
	case 26:
		return string(v.Bytes), "VisibleString"
	case 30:
		u := make([]uint16, len(v.Bytes)/2)
		for i := range u {
			u[i] = uint16(v.Bytes[2*i])<<8 | uint16(v.Bytes[2*i+1])
		}
		return string(utf16.Decode(u)), "BMPString"
	}
	return "#" + hex.EncodeToString(v.FullBytes), "other"
}

func latin1(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// FormatName renders a DER Name as "C=DE, O=Example, CN=Name" in encoded
// order. It returns the hex form for undecodable input.
func FormatName(der []byte) string {
	entries, err := ParseName(der)
	if err != nil {
		return "#" + hex.EncodeToString(der)
	}
	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = e.Short + "=" + e.Value
	}
	return strings.Join(parts, ", ")
}

// CommonName returns the last CN of a DER Name, or "".
func CommonName(der []byte) string {
	entries, _ := ParseName(der)
	cn := ""
	for _, e := range entries {
		if e.OID == "2.5.4.3" {
			cn = e.Value
		}
	}
	return cn
}

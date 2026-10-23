package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
)

// Extension is a decoded X.509 extension for display.
type Extension struct {
	OID      string
	Name     string
	Critical bool
	Lines    []string
}

var extNames = map[string]string{
	"2.5.29.19":               "Basic Constraints",
	"2.5.29.15":               "Key Usage",
	"2.5.29.37":               "Extended Key Usage",
	"2.5.29.17":               "Subject Alternative Name",
	"2.5.29.18":               "Issuer Alternative Name",
	"2.5.29.14":               "Subject Key Identifier",
	"2.5.29.35":               "Authority Key Identifier",
	"2.5.29.31":               "CRL Distribution Points",
	"1.3.6.1.5.5.7.1.1":       "Authority Information Access",
	"2.5.29.32":               "Certificate Policies",
	"2.5.29.30":               "Name Constraints",
	"2.5.29.20":               "CRL Number",
	"2.5.29.21":               "Reason Code",
	"2.5.29.24":               "Invalidity Date",
	"2.5.29.28":               "Issuing Distribution Point",
	"2.16.840.1.113730.1.1":   "Netscape Cert Type",
	"2.16.840.1.113730.1.13":  "Netscape Comment",
	"1.3.6.1.4.1.11129.2.4.2": "CT Precertificate SCTs",
	"1.3.6.1.5.5.7.48.1.5":    "OCSP No Check",
	"1.3.6.1.5.5.7.1.24":      "TLS Feature",
}

var ekuNames = map[string]string{
	"1.3.6.1.5.5.7.3.1":      "TLS Web Server Authentication",
	"1.3.6.1.5.5.7.3.2":      "TLS Web Client Authentication",
	"1.3.6.1.5.5.7.3.3":      "Code Signing",
	"1.3.6.1.5.5.7.3.4":      "E-mail Protection",
	"1.3.6.1.5.5.7.3.8":      "Time Stamping",
	"1.3.6.1.5.5.7.3.9":      "OCSP Signing",
	"1.3.6.1.5.5.7.3.17":     "IPSec Internet Key Exchange",
	"1.3.6.1.4.1.311.20.2.2": "Microsoft Smartcard Login",
	"1.3.6.1.4.1.311.10.3.4": "Microsoft Encrypted File System",
	"2.5.29.37.0":            "Any Extended Key Usage",
}

var kuNames = []string{"Digital Signature", "Non Repudiation", "Key Encipherment", "Data Encipherment",
	"Key Agreement", "Certificate Sign", "CRL Sign", "Encipher Only", "Decipher Only"}

var nsTypeNames = []string{"SSL Client", "SSL Server", "S/MIME", "Object Signing", "Reserved",
	"SSL CA", "S/MIME CA", "Object Signing CA"}

// ReasonNames are the CRL reason codes (RFC 5280), indexed by code.
var ReasonNames = []string{"unspecified", "keyCompromise", "CACompromise", "affiliationChanged",
	"superseded", "cessationOfOperation", "certificateHold", "", "removeFromCRL",
	"privilegeWithdrawn", "AACompromise"}

// DecodeExtensions decodes a list of extensions in their encoded order.
func DecodeExtensions(exts []pkix.Extension) []Extension {
	out := make([]Extension, 0, len(exts))
	for _, e := range exts {
		oid := e.Id.String()
		name, ok := extNames[oid]
		if !ok {
			name = oid
		}
		lines, err := decodeExt(oid, e.Value)
		if err != nil || lines == nil {
			lines = []string{hexDump(e.Value)}
		}
		out = append(out, Extension{OID: oid, Name: name, Critical: e.Critical, Lines: lines})
	}
	return out
}

func hexDump(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var s strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			s.WriteByte(':')
		}
		s.WriteString(h[i : i+2])
	}
	return s.String()
}

func bits(b asn1.BitString, names []string) []string {
	var out []string
	for i, n := range names {
		if b.At(i) == 1 {
			out = append(out, n)
		}
	}
	return out
}

func decodeExt(oid string, v []byte) ([]string, error) {
	switch oid {
	case "2.5.29.19":
		var bc struct {
			CA      bool `asn1:"optional"`
			PathLen int  `asn1:"optional,default:-1"`
		}
		if _, err := asn1.Unmarshal(v, &bc); err != nil {
			return nil, err
		}
		l := []string{fmt.Sprintf("CA:%s", strings.ToUpper(fmt.Sprint(bc.CA)))}
		if bc.PathLen >= 0 {
			l = append(l, fmt.Sprintf("pathlen:%d", bc.PathLen))
		}
		return l, nil
	case "2.5.29.15":
		var b asn1.BitString
		if _, err := asn1.Unmarshal(v, &b); err != nil {
			return nil, err
		}
		return bits(b, kuNames), nil
	case "2.16.840.1.113730.1.1":
		var b asn1.BitString
		if _, err := asn1.Unmarshal(v, &b); err != nil {
			return nil, err
		}
		return bits(b, nsTypeNames), nil
	case "2.5.29.37":
		var oids []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(v, &oids); err != nil {
			return nil, err
		}
		var l []string
		for _, o := range oids {
			if n, ok := ekuNames[o.String()]; ok {
				l = append(l, n)
			} else {
				l = append(l, o.String())
			}
		}
		return l, nil
	case "2.5.29.17", "2.5.29.18":
		return generalNames(v)
	case "2.5.29.14":
		var kid []byte
		if _, err := asn1.Unmarshal(v, &kid); err != nil {
			return nil, err
		}
		return []string{hexDump(kid)}, nil
	case "2.5.29.35":
		var aki struct {
			KeyID  []byte        `asn1:"optional,tag:0"`
			Issuer asn1.RawValue `asn1:"optional,tag:1"`
			Serial *big.Int      `asn1:"optional,tag:2"`
		}
		if _, err := asn1.Unmarshal(v, &aki); err != nil {
			return nil, err
		}
		var l []string
		if len(aki.KeyID) > 0 {
			l = append(l, "keyid:"+hexDump(aki.KeyID))
		}
		if len(aki.Issuer.Bytes) > 0 {
			if n, err := generalNamesBody(aki.Issuer.Bytes); err == nil {
				for _, s := range n {
					l = append(l, "issuer:"+s)
				}
			}
		}
		if aki.Serial != nil {
			l = append(l, "serial:"+strings.ToUpper(aki.Serial.Text(16)))
		}
		return l, nil
	case "2.5.29.31":
		var dps []struct {
			Name asn1.RawValue `asn1:"optional,tag:0"`
		}
		if _, err := asn1.Unmarshal(v, &dps); err != nil {
			return nil, err
		}
		var l []string
		for _, dp := range dps {
			// DistributionPointName: fullName [0] GeneralNames
			var full asn1.RawValue
			if _, err := asn1.Unmarshal(dp.Name.Bytes, &full); err == nil && full.Tag == 0 {
				if n, err := generalNamesBody(full.Bytes); err == nil {
					l = append(l, n...)
				}
			}
		}
		return l, nil
	case "1.3.6.1.5.5.7.1.1":
		var ads []struct {
			Method   asn1.ObjectIdentifier
			Location asn1.RawValue
		}
		if _, err := asn1.Unmarshal(v, &ads); err != nil {
			return nil, err
		}
		var l []string
		for _, ad := range ads {
			m := ad.Method.String()
			switch m {
			case "1.3.6.1.5.5.7.48.1":
				m = "OCSP"
			case "1.3.6.1.5.5.7.48.2":
				m = "CA Issuers"
			}
			l = append(l, m+" - "+generalName(ad.Location))
		}
		return l, nil
	case "2.5.29.32":
		var pols []struct {
			ID         asn1.ObjectIdentifier
			Qualifiers asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(v, &pols); err != nil {
			return nil, err
		}
		var l []string
		for _, p := range pols {
			l = append(l, "Policy: "+p.ID.String())
		}
		return l, nil
	case "2.5.29.30":
		var nc struct {
			Permitted asn1.RawValue `asn1:"optional,tag:0"`
			Excluded  asn1.RawValue `asn1:"optional,tag:1"`
		}
		if _, err := asn1.Unmarshal(v, &nc); err != nil {
			return nil, err
		}
		var l []string
		for _, sub := range []struct {
			label string
			raw   asn1.RawValue
		}{{"Permitted", nc.Permitted}, {"Excluded", nc.Excluded}} {
			rest := sub.raw.Bytes
			for len(rest) > 0 {
				var gs struct{ Base asn1.RawValue }
				var err error
				if rest, err = asn1.Unmarshal(rest, &gs); err != nil {
					return nil, err
				}
				l = append(l, sub.label+": "+generalName(gs.Base))
			}
		}
		return l, nil
	case "2.5.29.20":
		var n *big.Int
		if _, err := asn1.Unmarshal(v, &n); err != nil {
			return nil, err
		}
		return []string{n.String()}, nil
	case "2.5.29.21":
		var e asn1.Enumerated
		if _, err := asn1.Unmarshal(v, &e); err != nil {
			return nil, err
		}
		if int(e) >= 0 && int(e) < len(ReasonNames) {
			return []string{ReasonNames[e]}, nil
		}
		return []string{fmt.Sprint(e)}, nil
	case "2.16.840.1.113730.1.13":
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(v, &raw); err != nil {
			return nil, err
		}
		return []string{string(raw.Bytes)}, nil
	}
	return nil, nil
}

func generalNames(v []byte) ([]string, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(v, &seq); err != nil {
		return nil, err
	}
	return generalNamesBody(seq.Bytes)
}

func generalNamesBody(b []byte) ([]string, error) {
	var out []string
	for len(b) > 0 {
		var gn asn1.RawValue
		var err error
		if b, err = asn1.Unmarshal(b, &gn); err != nil {
			return nil, err
		}
		out = append(out, generalName(gn))
	}
	return out, nil
}

// generalName formats a GeneralName the way OpenSSL's config syntax writes it.
func generalName(gn asn1.RawValue) string {
	if gn.Class != asn1.ClassContextSpecific {
		return hexDump(gn.FullBytes)
	}
	switch gn.Tag {
	case 1:
		return "email:" + string(gn.Bytes)
	case 2:
		return "DNS:" + string(gn.Bytes)
	case 4:
		return "dirName:" + FormatName(gn.Bytes)
	case 6:
		return "URI:" + string(gn.Bytes)
	case 7:
		switch len(gn.Bytes) {
		case 4, 16:
			return "IP:" + net.IP(gn.Bytes).String()
		case 8, 32:
			n := len(gn.Bytes) / 2
			mask := net.IPMask(gn.Bytes[n:])
			return "IP:" + (&net.IPNet{IP: net.IP(gn.Bytes[:n]), Mask: mask}).String()
		}
	case 8:
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(append([]byte{0x06, byte(len(gn.Bytes))}, gn.Bytes...), &oid); err == nil {
			return "RID:" + oid.String()
		}
	case 0:
		return "otherName:" + hexDump(gn.Bytes)
	}
	return hexDump(gn.FullBytes)
}

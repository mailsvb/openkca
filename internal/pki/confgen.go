package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
)

// ConfFromExtensions writes extensions in OpenSSL config syntax, in their
// order, for the "OpenSSL config" export (XCA's extList::genGenericConf).
// Extensions without a textual form are written as DER.
func ConfFromExtensions(exts []pkix.Extension) string {
	var b strings.Builder
	for _, e := range exts {
		s, rest := SpecFromExtensions([]pkix.Extension{e})
		line := ""
		if len(rest) == 0 {
			line = confLine(e, s)
		}
		if strings.HasSuffix(line, "=") {
			line = ""
		}
		if line == "" {
			b.WriteString(GenConf([]pkix.Extension{e}))
			continue
		}
		crit := ""
		if e.Critical {
			crit = "critical,"
		}
		name, value, _ := strings.Cut(line, "=")
		b.WriteString(name + "=" + crit + value + "\n")
	}
	return b.String()
}

func confLine(e pkix.Extension, s ExtSpec) string {
	switch {
	case e.Id.Equal(oidBC):
		if s.CA == 1 {
			v := "basicConstraints=CA:TRUE"
			if s.PathLen != "" {
				v += ",pathlen:" + s.PathLen
			}
			return v
		}
		return "basicConstraints=CA:FALSE"
	case e.Id.Equal(oidSKI):
		return "subjectKeyIdentifier=hash"
	case e.Id.Equal(oidAKI):
		var aki struct {
			KeyID  []byte        `asn1:"optional,tag:0"`
			Issuer asn1.RawValue `asn1:"optional,tag:1"`
			Serial asn1.RawValue `asn1:"optional,tag:2"`
		}
		if _, err := asn1.Unmarshal(e.Value, &aki); err != nil {
			return ""
		}
		var parts []string
		if aki.KeyID != nil {
			parts = append(parts, "keyid")
		}
		if len(aki.Issuer.FullBytes) > 0 {
			parts = append(parts, "issuer")
		}
		if len(parts) == 0 {
			return ""
		}
		return "authorityKeyIdentifier=" + strings.Join(parts, ",")
	case e.Id.Equal(oidKU):
		return "keyUsage=" + bitNames(s.KeyUse, KeyUsageNames)
	case e.Id.Equal(oidNSType):
		return "nsCertType=" + bitNames(s.NSCertType, NSCertTypeNames)
	case e.Id.Equal(oidEKU):
		return "extendedKeyUsage=" + strings.Join(s.EKU, ", ")
	case e.Id.Equal(oidSAN):
		return "subjectAltName=" + s.SubAltName
	case e.Id.Equal(oidIAN):
		return "issuerAltName=" + s.IssAltName
	case e.Id.Equal(oidCRLDP):
		return "crlDistributionPoints=" + s.CRLDist
	case e.Id.Equal(oidAIA):
		return "authorityInfoAccess=" + s.AuthInfAcc
	case e.Id.Equal(oidNC):
		return "nameConstraints=" + s.NameCons
	case e.Id.Equal(oidTLSFeat):
		return "tlsfeature=status_request"
	case e.Id.Equal(oidNSComment):
		return "nsComment=" + s.NSComment
	case e.Id.Equal(oidNSBase):
		return "nsBaseUrl=" + s.NSBaseURL
	case e.Id.Equal(oidNSRev):
		return "nsRevocationUrl=" + s.NSRevocationURL
	case e.Id.Equal(oidNSCARev):
		return "nsCaRevocationUrl=" + s.NSCARevocationURL
	case e.Id.Equal(oidNSRenew):
		return "nsRenewalUrl=" + s.NSRenewalURL
	case e.Id.Equal(oidNSPolicy):
		return "nsCaPolicyUrl=" + s.NSCAPolicyURL
	case e.Id.Equal(oidNSSSLName):
		return "nsSslServerName=" + s.NSSSLServerName
	}
	return ""
}

func bitNames(bits int, names []string) string {
	var out []string
	for i, n := range names {
		if bits&(1<<i) != 0 {
			out = append(out, n)
		}
	}
	return strings.Join(out, ", ")
}

package pki

import (
	"encoding/asn1"
	"sort"
	"strings"
)

// OIDInfo names an object identifier.
type OIDInfo struct {
	OID   string
	Short string
	Long  string
	Kind  string // attribute, extension, eku, signature, curve, policy, other
}

// The registry combines OpenSSL's names for what go-ca displays with XCA's
// own additions from misc/oids.txt.
var oidRegistry = func() []OIDInfo {
	var list []OIDInfo
	for oid, n := range attrNames {
		list = append(list, OIDInfo{oid, n[0], n[1], "attribute"})
	}
	extShort := map[string]string{
		"2.5.29.19": "basicConstraints", "2.5.29.15": "keyUsage", "2.5.29.37": "extendedKeyUsage",
		"2.5.29.17": "subjectAltName", "2.5.29.18": "issuerAltName", "2.5.29.14": "subjectKeyIdentifier",
		"2.5.29.35": "authorityKeyIdentifier", "2.5.29.31": "crlDistributionPoints", "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
		"2.5.29.32": "certificatePolicies", "2.5.29.30": "nameConstraints", "2.5.29.20": "crlNumber",
		"2.5.29.21": "CRLReason", "2.5.29.24": "invalidityDate", "2.5.29.28": "issuingDistributionPoint",
		"2.16.840.1.113730.1.1": "nsCertType", "2.16.840.1.113730.1.13": "nsComment",
		"1.3.6.1.4.1.11129.2.4.2": "ct_precert_scts", "1.3.6.1.5.5.7.48.1.5": "noCheck", "1.3.6.1.5.5.7.1.24": "tlsfeature",
	}
	for oid, long := range extNames {
		list = append(list, OIDInfo{oid, extShort[oid], long, "extension"})
	}
	for _, x := range []OIDInfo{
		{"2.5.29.36", "policyConstraints", "X509v3 Policy Constraints", "extension"},
		{"2.5.29.54", "inhibitAnyPolicy", "X509v3 Inhibit Any Policy", "extension"},
		{"2.5.29.33", "policyMappings", "X509v3 Policy Mappings", "extension"},
		{"2.16.840.1.113730.1.2", "nsBaseUrl", "Netscape Base Url", "extension"},
		{"2.16.840.1.113730.1.3", "nsRevocationUrl", "Netscape Revocation Url", "extension"},
		{"2.16.840.1.113730.1.4", "nsCaRevocationUrl", "Netscape CA Revocation Url", "extension"},
		{"2.16.840.1.113730.1.7", "nsRenewalUrl", "Netscape Renewal Url", "extension"},
		{"2.16.840.1.113730.1.8", "nsCaPolicyUrl", "Netscape CA Policy Url", "extension"},
		{"2.16.840.1.113730.1.12", "nsSslServerName", "Netscape SSL Server Name", "extension"},
		{"1.3.6.1.5.5.7.48.1", "OCSP", "OCSP", "other"},
		{"1.3.6.1.5.5.7.48.2", "caIssuers", "CA Issuers", "other"},
		{"1.3.6.1.5.5.7.2.1", "id-qt-cps", "Policy Qualifier CPS", "policy"},
		{"1.3.6.1.5.5.7.2.2", "id-qt-unotice", "Policy Qualifier User Notice", "policy"},
		{"2.5.29.32.0", "anyPolicy", "X509v3 Any Policy", "policy"},
		{"1.3.6.1.4.1.311.20.2.3", "msUPN", "Microsoft User Principal Name", "other"},
		{"1.2.840.113549.1.1.1", "rsaEncryption", "rsaEncryption", "other"},
		{"1.2.840.10045.2.1", "id-ecPublicKey", "id-ecPublicKey", "other"},
		{"1.2.840.10040.4.1", "DSA", "dsaEncryption", "other"},
		{"1.3.101.112", "ED25519", "ED25519", "other"},
		{"1.3.101.113", "ED448", "ED448", "other"},
		{"1.2.840.113549.1.1.11", "RSA-SHA256", "sha256WithRSAEncryption", "signature"},
		{"1.2.840.113549.1.1.12", "RSA-SHA384", "sha384WithRSAEncryption", "signature"},
		{"1.2.840.113549.1.1.13", "RSA-SHA512", "sha512WithRSAEncryption", "signature"},
		{"1.2.840.113549.1.1.5", "RSA-SHA1", "sha1WithRSAEncryption", "signature"},
		{"1.2.840.113549.1.1.10", "RSASSA-PSS", "rsassaPss", "signature"},
		{"1.2.840.10045.4.3.2", "ecdsa-with-SHA256", "ecdsa-with-SHA256", "signature"},
		{"1.2.840.10045.4.3.3", "ecdsa-with-SHA384", "ecdsa-with-SHA384", "signature"},
		{"1.2.840.10045.4.3.4", "ecdsa-with-SHA512", "ecdsa-with-SHA512", "signature"},
		// XCA misc/oids.txt
		{"1.3.6.1.4.1.311.20.2", "dom", "Domain Controller", "other"},
		{"1.3.6.1.4.1.311.21.1", "MsCaV", "Microsoft CA Version", "extension"},
		{"1.3.6.1.4.1.311.10.3.4.1", "msEFSFR", "Microsoft EFS File Recovery", "eku"},
		{"1.3.6.1.5.5.8.2.2", "iKEIntermediate", "IP security end entity", "eku"},
		{"0.2.262.1.10.7.20", "nameDistinguisher", "Name distinguisher", "attribute"},
		{"1.3.6.1.5.5.7.3.13", "id-kp-eapOverPPP", "EAP over PPP", "eku"},
		{"1.3.6.1.5.5.7.3.14", "id-kp-eapOverLAN", "EAP over Lan", "eku"},
		{"1.3.6.1.5.2.3.5", "pkInitKDC", "Signing KDC Response", "eku"},
		{"1.3.6.1.5.5.7.3.21", "secureShellClient", "SSH Client", "eku"},
		{"1.3.6.1.5.2.3.4", "pkInitClientAuth", "PKINIT Client Auth", "eku"},
		{"1.2.840.113583.1.1.5", "adobePDFSigning", "Adobe PDF Signing", "eku"},
		{"1.3.6.1.4.1.311.10.3.12", "msofficeSigning", "Microsoft Office Signing", "eku"},
		{"1.3.6.1.4.1.311.67.1.1", "driveEncryption", "Microsoft BitLocker Drive Encryption", "eku"},
		{"1.3.6.1.4.1.311.67.1.2", "dataRecoveryAgent", "Microsoft BitLocker Data Recovery Agent", "eku"},
		// further EKUs XCA lists (misc/eku.txt)
		{"1.3.6.1.4.1.311.2.1.21", "msCodeInd", "Microsoft Individual Code Signing", "eku"},
		{"1.3.6.1.4.1.311.2.1.22", "msCodeCom", "Microsoft Commercial Code Signing", "eku"},
		{"1.3.6.1.4.1.311.10.3.1", "msCTLSign", "Microsoft Trust List Signing", "eku"},
		{"1.3.6.1.4.1.311.10.3.3", "msSGC", "Microsoft Server Gated Crypto", "eku"},
		{"2.16.840.1.113730.4.1", "nsSGC", "Netscape Server Gated Crypto", "eku"},
		{"1.3.6.1.5.5.7.3.5", "ipsecEndSystem", "IPSec End System", "eku"},
		{"1.3.6.1.5.5.7.3.6", "ipsecTunnel", "IPSec Tunnel", "eku"},
		{"1.3.6.1.5.5.7.3.7", "ipsecUser", "IPSec User", "eku"},
	} {
		list = append(list, x)
	}
	// key and signature algorithms beyond OpenSSL 3.0's names (OpenSSL
	// 3.5 and the LAMPS drafts)
	list = append(list, OIDInfo{"1.3.101.110", "X25519", "X25519", "other"}, OIDInfo{"1.3.101.111", "X448", "X448", "other"},
		OIDInfo{"1.2.840.113549.1.1.8", "MGF1", "mgf1", "other"},
		OIDInfo{"2.16.840.1.101.3.4.2.1", "SHA256", "sha256", "other"},
		OIDInfo{"2.16.840.1.101.3.4.2.2", "SHA384", "sha384", "other"},
		OIDInfo{"2.16.840.1.101.3.4.2.3", "SHA512", "sha512", "other"})
	for _, p := range MLDSAParamSets {
		list = append(list, OIDInfo{p.OID.String(), "id-ml-dsa-" + strings.TrimPrefix(p.Name, "ML-DSA-"), p.Name, "signature"})
	}
	for _, p := range SLHDSAParamSets {
		list = append(list, OIDInfo{p.OID.String(), "id-slh-dsa-" + strings.ToLower(strings.TrimPrefix(p.Name, "SLH-DSA-")), p.Name, "signature"})
	}
	for _, p := range MLKEMParamSets {
		list = append(list, OIDInfo{p.OID.String(), "id-alg-ml-kem-" + strings.TrimPrefix(p.Name, "ML-KEM-"), p.Name, "other"})
	}
	for _, a := range CompositeAlgs {
		list = append(list, OIDInfo{a.OID.String(), "id-" + a.Name, a.Name, "signature"})
	}
	for _, a := range CompositeKEMAlgs {
		list = append(list, OIDInfo{a.OID.String(), "id-" + a.Name, a.Name, "other"})
	}
	for name, oid := range ekuOIDs {
		list = append(list, OIDInfo{oid.String(), name, ekuNames[oid.String()], "eku"})
	}
	for oid, name := range curveOIDs {
		short, _, _ := strings.Cut(name, " ")
		list = append(list, OIDInfo{oid, short, name, "curve"})
	}
	// de-duplicate by OID, keeping the first long name that is set
	seen := map[string]int{}
	var out []OIDInfo
	for _, x := range list {
		if i, ok := seen[x.OID]; ok {
			if out[i].Long == "" {
				out[i].Long = x.Long
			}
			if out[i].Short == "" {
				out[i].Short = x.Short
			}
			continue
		}
		seen[x.OID] = len(out)
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OID < out[j].OID })
	return out
}()

// OIDs returns the registry.
func OIDs() []OIDInfo { return oidRegistry }

// OIDByName resolves a short or long name.
func OIDByName(name string) (asn1.ObjectIdentifier, bool) {
	for _, x := range oidRegistry {
		if strings.EqualFold(x.Short, name) || strings.EqualFold(x.Long, name) {
			o, err := parseOID(x.OID)
			return o, err == nil
		}
	}
	return nil, false
}

// ResolveOID finds entries by OID, short or long name (case-insensitive,
// substring match on names).
func ResolveOID(q string) []OIDInfo {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil
	}
	var out []OIDInfo
	lq := strings.ToLower(q)
	for _, x := range oidRegistry {
		if x.OID == q || strings.Contains(strings.ToLower(x.Short), lq) || strings.Contains(strings.ToLower(x.Long), lq) {
			out = append(out, x)
		}
	}
	return out
}

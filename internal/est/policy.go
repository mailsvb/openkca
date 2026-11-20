package est

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/tmpl"
)

// Decision is what to issue for an accepted CSR.
type Decision struct {
	Subject []pki.DNAttr // in rule order
	Ext     pki.ExtSpec  // the profile's, with the SANs and the key usage for this key
	NotBefore,
	NotAfter time.Time
	Hash   string // signature hash choice for the CA key (pki.AutoHashName)
	KeyAlg string // the CSR key as a key choice: "RSA:2048", "EC:P-256", "Ed25519", "ML-DSA:ML-DSA-65", ...
}

// Violation is one reason a CSR is refused.
type Violation struct {
	Field  string // "csr", "signature", "key", "subject", "subject.<attr>", "san", "san.<type>", "validity"
	Reason string
}

func (v Violation) String() string { return v.Field + ": " + v.Reason }

var oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}

// Evaluate checks a DER CSR against the config and, when it passes,
// returns what to issue with the CA ca. The decision is only set when there
// are no violations.
func Evaluate(cfg Config, ca *x509.Certificate, csrDER []byte, now time.Time) (Decision, []Violation) {
	var vs []Violation
	bad := func(field, format string, a ...any) {
		vs = append(vs, Violation{field, fmt.Sprintf(format, a...)})
	}
	if ca == nil {
		bad("ca", "no issuing CA")
		return Decision{}, vs
	}

	// 1. Parse, check the signature hash and the self-signature.
	r, err := pki.ParseCertificateRequest(csrDER)
	if err != nil {
		bad("csr", "cannot parse the request: %v", err)
		return Decision{}, vs
	}
	if h, err := requestHash(csrDER); err != nil {
		bad("signature", "%v", err)
	} else if h != "" {
		switch min := minHash(cfg.Keys.MinCSRHash); {
		case hashRank[h] <= hashRank["SHA-1"]: // MD2, MD4, MD5, SHA-1
			bad("signature", "the request is signed with %s", h)
		case hashRank[h] < hashRank[min]:
			bad("signature", "the request is signed with %s, at least %s is required", h, min)
		}
	}
	if len(vs) == 0 {
		if err := pki.CheckRequestSignature(r); err != nil {
			bad("signature", "the request's signature is invalid: %v", err)
		}
	}

	// 2. The key.
	keyAlg, reason := checkKey(cfg.Keys, r.RawSubjectPublicKeyInfo)
	if reason != "" {
		bad("key", "%s", reason)
	}

	// 3. The subject.
	subject := evalSubject(cfg, pki.NameAttrs(r.RawSubject), bad)
	if len(subject) == 0 {
		bad("subject", "the subject is empty")
	}

	// 4. The SANs: the CSR's, filtered; the CN; the profile's fixed ones.
	// 5. Every other requested extension is ignored.
	spec, rest := pki.SpecFromExtensions(r.Extensions)
	for _, e := range rest {
		if e.Id.Equal(oidSAN) {
			bad("san", "the requested SANs contain names that are not supported")
		}
	}
	sans := evalSANs(cfg.SAN, splitSANs(spec.SubAltName), cnOf(subject), bad)
	for _, n := range splitSANs(cfg.Profile.Ext.SubAltName) {
		if !isCopyToken(n) && !containsSAN(sans, n) {
			sans = append(sans, n)
		}
	}

	// 6. Extensions from the profile, the key usage fitted to the key.
	ext := cfg.Profile.Ext
	ext.EKU = slices.Clone(ext.EKU)
	ext.CRLMirrors = slices.Clone(ext.CRLMirrors)
	ext.CAIssuers = slices.Clone(ext.CAIssuers)
	ext.SubAltName = strings.Join(sans, ", ")
	ext.KeyUse = fitKeyUsage(ext.KeyUse, keyAlg)

	// 7. Validity, capped at the CA's.
	nb, na := validity(cfg.Profile.Validity, now)
	if ca.NotAfter.Before(now) {
		bad("validity", "the CA expired on %s", ca.NotAfter.UTC().Format(time.DateOnly))
	} else if ca.NotBefore.After(now) {
		bad("validity", "the CA is not valid before %s", ca.NotBefore.UTC().Format(time.DateOnly))
	}
	if na.After(ca.NotAfter) {
		na = ca.NotAfter
	}

	if len(vs) > 0 {
		return Decision{}, vs
	}
	return Decision{
		Subject:   subject,
		Ext:       ext,
		NotBefore: nb,
		NotAfter:  na,
		Hash:      pki.AutoHashName(ca.RawSubjectPublicKeyInfo),
		KeyAlg:    keyAlg,
	}, nil
}

// Signature algorithm OIDs with the hash they use.
var sigHashes = map[string]string{
	"1.2.840.113549.1.1.2":   "MD2",
	"1.2.840.113549.1.1.3":   "MD4",
	"1.2.840.113549.1.1.4":   "MD5",
	"1.2.840.113549.1.1.5":   "SHA-1",
	"1.3.14.3.2.29":          "SHA-1",
	"1.2.840.113549.1.1.14":  "SHA-224",
	"1.2.840.113549.1.1.11":  "SHA-256",
	"1.2.840.113549.1.1.12":  "SHA-384",
	"1.2.840.113549.1.1.13":  "SHA-512",
	"1.2.840.10045.4.1":      "SHA-1",
	"1.2.840.10045.4.3.1":    "SHA-224",
	"1.2.840.10045.4.3.2":    "SHA-256",
	"1.2.840.10045.4.3.3":    "SHA-384",
	"1.2.840.10045.4.3.4":    "SHA-512",
	"1.2.840.10040.4.3":      "SHA-1",
	"2.16.840.1.101.3.4.3.1": "SHA-224",
	"2.16.840.1.101.3.4.3.2": "SHA-256",
}

// Digest OIDs, for RSASSA-PSS parameters.
var digestNames = map[string]string{
	"1.2.840.113549.2.5":     "MD5",
	"1.3.14.3.2.26":          "SHA-1",
	"2.16.840.1.101.3.4.2.4": "SHA-224",
	"2.16.840.1.101.3.4.2.1": "SHA-256",
	"2.16.840.1.101.3.4.2.2": "SHA-384",
	"2.16.840.1.101.3.4.2.3": "SHA-512",
}

// Algorithms that hash internally.
var intrinsicSigs = func() map[string]bool {
	m := map[string]bool{"1.3.101.112": true, "1.3.101.113": true} // Ed25519, Ed448
	for _, p := range pki.MLDSAParamSets {
		m[p.OID.String()] = true
	}
	for _, p := range pki.SLHDSAParamSets {
		m[p.OID.String()] = true
	}
	for _, a := range pki.CompositeAlgs {
		m[a.OID.String()] = true
	}
	return m
}()

const oidRSAPSS = "1.2.840.113549.1.1.10"

// requestHash names the hash a DER CSR is signed with, "" for algorithms
// that hash internally.
func requestHash(der []byte) (string, error) {
	var sd struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &sd); err != nil {
		return "", fmt.Errorf("cannot read the signature algorithm: %v", err)
	}
	oid := sd.Algorithm.Algorithm.String()
	switch {
	case intrinsicSigs[oid]:
		return "", nil
	case sigHashes[oid] != "":
		return sigHashes[oid], nil
	case oid == oidRSAPSS:
		var p struct {
			Hash pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
		}
		if len(sd.Algorithm.Parameters.FullBytes) > 0 {
			if _, err := asn1.Unmarshal(sd.Algorithm.Parameters.FullBytes, &p); err != nil {
				return "", fmt.Errorf("cannot read the RSASSA-PSS parameters: %v", err)
			}
		}
		if len(p.Hash.Algorithm) == 0 {
			return "SHA-1", nil // RFC 4055 default
		}
		if h := digestNames[p.Hash.Algorithm.String()]; h != "" {
			return h, nil
		}
		return "", fmt.Errorf("unsupported RSASSA-PSS hash %s", p.Hash.Algorithm)
	}
	return "", fmt.Errorf("unsupported signature algorithm %s", oid)
}

// checkKey checks a SubjectPublicKeyInfo against the rules and returns the
// key as a key choice, or why it is refused.
func checkKey(k KeyRules, spkiDER []byte) (alg, reason string) {
	info := pki.DescribePublicKey(spkiDER)
	switch a := info.Algorithm; {
	case a == "RSA" || a == "RSA-PSS":
		alg = fmt.Sprintf("%s:%d", a, info.Bits)
		switch {
		case k.RSAMinBits <= 0:
			return alg, "RSA keys are not allowed"
		case info.Bits < k.RSAMinBits:
			return alg, fmt.Sprintf("the RSA key has %d bits, at least %d are required", info.Bits, k.RSAMinBits)
		case k.RSAMaxBits > 0 && info.Bits > k.RSAMaxBits:
			return alg, fmt.Sprintf("the RSA key has %d bits, at most %d are allowed", info.Bits, k.RSAMaxBits)
		case info.Exponent%2 == 0 || info.Exponent < 65537:
			return alg, fmt.Sprintf("the RSA exponent %d is not allowed (odd, at least 65537)", info.Exponent)
		}
		return alg, ""
	case a == "EC":
		curve := curveOf(spkiDER)
		if curve == "" {
			return "EC", "the EC key's curve is not supported"
		}
		alg = "EC:" + curve
		if !slices.Contains(k.ECCurves, curve) {
			return alg, fmt.Sprintf("EC keys on %s are not allowed", curve)
		}
		return alg, ""
	case a == "Ed25519" || a == "Ed448":
		if !slices.Contains(k.EdDSA, a) {
			return a, a + " keys are not allowed"
		}
		return a, ""
	case slices.Contains(validMLDSA, a):
		alg = "ML-DSA:" + a
		if !slices.Contains(k.MLDSA, a) {
			return alg, a + " keys are not allowed"
		}
		return alg, ""
	case slices.Contains(validSLHDSA, a):
		alg = "SLH-DSA:" + a
		if !slices.Contains(k.SLHDSA, a) {
			return alg, a + " keys are not allowed"
		}
		return alg, ""
	case info.Composite == "ML-DSA" && slices.Contains(validComposite, a):
		alg = "Composite:" + a
		if !slices.Contains(k.Composite, a) {
			return alg, a + " keys are not allowed"
		}
		return alg, ""
	}
	return info.Algorithm, fmt.Sprintf("%s keys are not supported", info.Algorithm)
}

// curveOf names the curve of an EC SubjectPublicKeyInfo as pki.ECCurves
// does, "" for curves it does not list and explicit parameters.
func curveOf(spkiDER []byte) string {
	var s struct {
		Algo      pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &s); err != nil {
		return ""
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(s.Algo.Parameters.FullBytes, &oid); err != nil {
		return ""
	}
	for _, c := range pki.ECCurves {
		if c.OID.Equal(oid) {
			return c.Name
		}
	}
	return ""
}

// evalSubject applies the subject rules to the CSR's attributes. The
// result is in rule order; the profile's fixed attributes no rule names
// follow.
func evalSubject(cfg Config, csr []pki.DNAttr, bad func(field, format string, a ...any)) []pki.DNAttr {
	var out []pki.DNAttr
	ruled := map[string]bool{}
	values := func(attr string) []string {
		var vs []string
		for _, a := range csr {
			if a.Name == attr && strings.TrimSpace(a.Value) != "" {
				vs = append(vs, a.Value)
			}
		}
		return vs
	}
	for _, d := range cfg.Subject.Rules {
		attr := canonAttr(d.Attr)
		field := "subject." + d.Attr
		re, err := compilePattern(d.Pattern)
		if attr == "" || err != nil {
			bad(field, "the rule is invalid")
			continue
		}
		ruled[attr] = true
		got := values(attr)
		switch d.Mode {
		case ModeFixed:
			out = append(out, pki.DNAttr{Name: attr, Value: d.Value})
			continue
		case ModeForbidden:
			if len(got) > 0 {
				bad(field, "%s is not allowed", d.Attr)
			}
			continue
		case ModeRequired:
			if len(got) == 0 {
				bad(field, "%s is required", d.Attr)
				continue
			}
		case ModeOptional:
		default:
			bad(field, "unknown rule mode %q", d.Mode)
			continue
		}
		for _, v := range got {
			if re != nil && !re.MatchString(v) {
				bad(field, "%q does not match the allowed pattern", v)
				continue
			}
			out = append(out, pki.DNAttr{Name: attr, Value: v})
		}
	}
	for _, a := range cfg.Profile.Subject {
		if attr := canonAttr(a.Name); attr != "" && !ruled[attr] && strings.TrimSpace(a.Value) != "" {
			ruled[attr] = true
			out = append(out, pki.DNAttr{Name: attr, Value: a.Value})
		}
	}
	if cfg.Subject.Unlisted == UnlistedReject {
		reported := map[string]bool{}
		for _, a := range csr {
			if !ruled[a.Name] && !reported[a.Name] {
				reported[a.Name] = true
				bad("subject."+a.Name, "%s is not allowed", a.Name)
			}
		}
	}
	return out
}

func cnOf(subject []pki.DNAttr) string {
	for _, a := range subject {
		if a.Name == "CN" {
			return a.Value
		}
	}
	return ""
}

// evalSANs filters the CSR's SANs (one-line syntax) and adds the CN when
// configured.
func evalSANs(s SANRules, csr []string, cn string, bad func(field, format string, a ...any)) []string {
	var out []string
	if s.Max > 0 && len(csr) > s.Max {
		bad("san", "the request has %d SANs, at most %d are allowed", len(csr), s.Max)
	}
	for _, n := range csr {
		typ, v, _ := strings.Cut(n, ":")
		var norm, reason string
		switch typ {
		case "DNS":
			norm, reason = checkDNS(s, v)
		case "IP":
			norm, reason = checkIP(s.IP, v)
		case "email":
			norm, reason = checkEmail(s.Email, v)
		case "URI":
			norm, reason = checkURI(s.URI, v)
		default:
			bad("san", "%s names are not supported", typ)
			continue
		}
		if reason != "" {
			bad("san."+typ, "%s", reason)
			continue
		}
		if n = typ + ":" + norm; !containsSAN(out, n) {
			out = append(out, n)
		}
	}
	if s.CopyCN && cn != "" {
		if norm, reason := checkDNS(s, cn); reason == "" && !strings.HasPrefix(norm, "*.") {
			if n := "DNS:" + norm; !containsSAN(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

func containsSAN(l []string, n string) bool {
	return slices.ContainsFunc(l, func(x string) bool { return strings.EqualFold(x, n) })
}

func checkDNS(s SANRules, name string) (string, string) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if !s.DNS.Enabled {
		return "", "DNS names are not allowed"
	}
	host := n
	if strings.HasPrefix(n, "*.") {
		if !s.Wildcards {
			return "", fmt.Sprintf("the wildcard name %q is not allowed", name)
		}
		host = n[2:]
	}
	if !validHostname(host) {
		return "", fmt.Sprintf("%q is not a valid host name", name)
	}
	if !matchDomain(s.DNS.Patterns, n) {
		return "", fmt.Sprintf("%q is not an allowed DNS name", name)
	}
	return n, ""
}

func checkIP(r IPRule, v string) (string, string) {
	if !r.Enabled {
		return "", "IP addresses are not allowed"
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return "", fmt.Sprintf("%q is not an IP address", v)
	}
	a = a.Unmap()
	for _, c := range r.CIDRs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil && p.Contains(a) {
			return a.String(), ""
		}
	}
	return "", fmt.Sprintf("%s is not in an allowed network", a)
}

func checkEmail(r EmailRule, v string) (string, string) {
	if !r.Enabled {
		return "", "e-mail addresses are not allowed"
	}
	local, domain, ok := strings.Cut(v, "@")
	if !ok || local == "" || strings.ContainsAny(local, " \t<>") || !validHostname(strings.ToLower(domain)) {
		return "", fmt.Sprintf("%q is not a valid e-mail address", v)
	}
	domain = strings.ToLower(domain)
	if !matchDomain(r.Domains, domain) {
		return "", fmt.Sprintf("the domain of %q is not allowed", v)
	}
	return local + "@" + domain, ""
}

func checkURI(r URIRule, v string) (string, string) {
	if !r.Enabled {
		return "", "URIs are not allowed"
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme == "" || strings.ContainsAny(v, " \t,") {
		return "", fmt.Sprintf("%q is not a valid URI", v)
	}
	for _, p := range r.Prefixes {
		if strings.HasPrefix(v, p) {
			return v, ""
		}
	}
	return "", fmt.Sprintf("%q does not start with an allowed prefix", v)
}

// matchDomain matches a lower-case name (which may start with "*.") against
// patterns: "*", an exact name, or "*.suffix" for names below suffix.
func matchDomain(patterns []string, name string) bool {
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "."))
		switch {
		case p == "*":
			return true
		case strings.HasPrefix(p, "*."):
			if strings.HasSuffix(name, p[1:]) && len(name) > len(p)-1 {
				return true
			}
		case p == name:
			return true
		}
	}
	return false
}

// validHostname checks a host name of letters, digits and hyphens.
func validHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i] | 0x20
			if !(c >= 'a' && c <= 'z' || l[i] >= '0' && l[i] <= '9' || l[i] == '-') {
				return false
			}
		}
	}
	return true
}

// fitKeyUsage keeps the key usage bits the key can serve: encipherment for
// RSA keys, key agreement for EC keys. A usage left empty becomes
// digitalSignature.
func fitKeyUsage(ku int, keyAlg string) int {
	if ku == 0 {
		return 0
	}
	typ, _, _ := strings.Cut(keyAlg, ":")
	if typ != "RSA" {
		ku &^= kuKeyEncipherment | kuDataEncipherment
	}
	if typ != "EC" {
		ku &^= kuKeyAgreement
	}
	if ku == 0 {
		ku = kuDigitalSignature
	}
	return ku
}

// validity is the certificate's validity from now, as the certificate
// editor computes it.
// TODO: use tmpl.Validity.NotAfter
func validity(v tmpl.Validity, now time.Time) (nb, na time.Time) {
	nb = now.UTC().Truncate(time.Second)
	switch {
	case v.NoExpiry:
		na = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	case v.Unit == 2:
		na = nb.AddDate(v.N, 0, 0)
	case v.Unit == 1:
		na = nb.AddDate(0, v.N, 0)
	default:
		na = nb.AddDate(0, 0, v.N)
	}
	if v.Midnight && !v.NoExpiry { // XCA: 00:00:00 and 23:59:59
		nb = time.Date(nb.Year(), nb.Month(), nb.Day(), 0, 0, 0, 0, time.UTC)
		na = time.Date(na.Year(), na.Month(), na.Day(), 23, 59, 59, 0, time.UTC)
	}
	return nb, na
}

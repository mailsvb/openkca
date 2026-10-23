package pki

import (
	"bufio"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// Advanced extensions use OpenSSL's config syntax (XCA's adv_ext): lines
// "name = value" before any [section] form the extension list; sections
// are referenced as "@name". Supported are the extensions XCA itself
// writes into adv_ext plus generic DER and simple ASN1 values. Unknown
// lines are errors, never silently dropped.

// ConfError reports a problem on one line of the advanced extensions.
type ConfError struct {
	Line int
	Msg  string
}

func (e *ConfError) Error() string {
	return fmt.Sprintf("advanced extensions, line %d: %s", e.Line, e.Msg)
}

type confValue struct {
	key, value string
	line       int
}

type conf struct {
	sections map[string][]confValue
}

func parseConf(text string) (*conf, error) {
	c := &conf{sections: map[string][]confValue{}}
	sect := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, &ConfError{n, "unterminated section name"}
			}
			sect = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, &ConfError{n, "expected name = value"}
		}
		c.sections[sect] = append(c.sections[sect], confValue{strings.TrimSpace(k), strings.TrimSpace(v), n})
	}
	return c, sc.Err()
}

func (c *conf) section(ref string, line int) ([]confValue, error) {
	name := strings.TrimPrefix(strings.TrimSpace(ref), "@")
	s, ok := c.sections[name]
	if !ok {
		return nil, &ConfError{line, fmt.Sprintf("section [%s] not found", name)}
	}
	return s, nil
}

// extension names OpenSSL accepts, mapped to OIDs
var confExtOIDs = map[string]asn1.ObjectIdentifier{
	"basicConstraints": oidBC, "keyUsage": oidKU, "extendedKeyUsage": oidEKU,
	"subjectKeyIdentifier": oidSKI, "authorityKeyIdentifier": oidAKI, "subjectAltName": oidSAN,
	"issuerAltName": oidIAN, "crlDistributionPoints": oidCRLDP, "authorityInfoAccess": oidAIA,
	"nameConstraints": oidNC, "certificatePolicies": {2, 5, 29, 32}, "policyConstraints": {2, 5, 29, 36},
	"inhibitAnyPolicy": {2, 5, 29, 54}, "policyMappings": {2, 5, 29, 33}, "noCheck": {1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
	"tlsfeature": oidTLSFeat, "nsCertType": oidNSType, "nsComment": oidNSComment, "nsBaseUrl": oidNSBase,
	"nsRevocationUrl": oidNSRev, "nsCaRevocationUrl": oidNSCARev, "nsRenewalUrl": oidNSRenew,
	"nsCaPolicyUrl": oidNSPolicy, "nsSslServerName": oidNSSSLName,
}

// BuildAdvanced turns adv_ext text into extensions.
func BuildAdvanced(text string, ctx ExtContext) ([]pkix.Extension, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	c, err := parseConf(text)
	if err != nil {
		return nil, err
	}
	var out []pkix.Extension
	for _, kv := range c.sections[""] {
		ext, err := c.extension(kv, ctx)
		if err != nil {
			if _, ok := err.(*ConfError); ok {
				return nil, err
			}
			return nil, &ConfError{kv.line, err.Error()}
		}
		out = append(out, ext)
	}
	return out, nil
}

func cutCritical(v string) (string, bool) {
	t := strings.TrimSpace(v)
	if rest, ok := strings.CutPrefix(t, "critical,"); ok {
		return strings.TrimSpace(rest), true
	}
	if t == "critical" {
		return "", true
	}
	return t, false
}

func (c *conf) extension(kv confValue, ctx ExtContext) (pkix.Extension, error) {
	val, critical := cutCritical(kv.value)
	oid, known := confExtOIDs[kv.key]
	if !known {
		o, err := lookupOID(kv.key)
		if err != nil {
			return pkix.Extension{}, fmt.Errorf("unknown extension %q", kv.key)
		}
		oid = o
	}
	ext := pkix.Extension{Id: oid, Critical: critical}
	// Generic values work for every extension.
	if strings.HasPrefix(val, "DER:") || strings.HasPrefix(val, "ASN1:") {
		b, err := c.genericValue(val, kv.line)
		ext.Value = b
		return ext, err
	}
	if !known {
		return ext, fmt.Errorf("%s: use DER:… or ASN1:… for this extension", kv.key)
	}
	var err error
	spec := ExtSpec{}
	single := func(s ExtSpec) ([]byte, error) {
		exts, err := BuildExtensions(s, ExtContext{SubjectSPKI: ctx.SubjectSPKI, Subject: ctx.Subject,
			IssuerSPKI: ctx.IssuerSPKI, IssuerSKI: ctx.IssuerSKI, IssuerName: ctx.IssuerName, IssuerSerial: ctx.IssuerSerial,
			IssuerSAN: ctx.IssuerSAN})
		if err != nil {
			return nil, err
		}
		if len(exts) != 1 {
			return nil, fmt.Errorf("%s: empty value", kv.key)
		}
		return exts[0].Value, nil
	}
	switch kv.key {
	case "basicConstraints":
		spec.CA = 2
		for _, p := range splitList(val) {
			switch {
			case strings.EqualFold(p, "CA:TRUE"):
				spec.CA = 1
			case strings.EqualFold(p, "CA:FALSE"):
				spec.CA = 2
			case strings.HasPrefix(p, "pathlen:"):
				spec.PathLen = strings.TrimPrefix(p, "pathlen:")
			default:
				return ext, fmt.Errorf("basicConstraints: unknown value %q", p)
			}
		}
		ext.Value, err = single(spec)
	case "keyUsage":
		for _, p := range splitList(val) {
			i := indexOf(KeyUsageNames, p)
			if i < 0 {
				return ext, fmt.Errorf("keyUsage: unknown usage %q", p)
			}
			spec.KeyUse |= 1 << i
		}
		ext.Value, err = single(spec)
	case "nsCertType":
		for _, p := range splitList(val) {
			i := indexOf(NSCertTypeNames, p)
			if i < 0 {
				return ext, fmt.Errorf("nsCertType: unknown type %q", p)
			}
			spec.NSCertType |= 1 << i
		}
		ext.Value, err = single(spec)
	case "extendedKeyUsage":
		spec.EKU = splitList(val)
		ext.Value, err = single(spec)
	case "subjectKeyIdentifier":
		if val == "hash" {
			spec.SubKey = true
			ext.Value, err = single(spec)
		} else {
			var id []byte
			if id, err = hex.DecodeString(strings.ReplaceAll(val, ":", "")); err == nil {
				ext.Value, err = asn1.Marshal(id)
			}
		}
	case "authorityKeyIdentifier":
		spec.AuthKey = true
		ext.Value, err = single(spec)
	case "subjectAltName", "issuerAltName":
		var body []byte
		if body, err = c.generalNamesConf(val, kv.line, ctx); err == nil {
			ext.Value, err = seqOf(body)
		}
	case "crlDistributionPoints":
		items := splitList(val)
		if len(items) == 1 && strings.HasPrefix(items[0], "@") {
			s, e := c.section(items[0], kv.line)
			if e != nil {
				return ext, e
			}
			items = nil
			for _, x := range s {
				if x.key == "fullname" {
					items = append(items, splitList(x.value)...)
				}
			}
		}
		spec.CRLDist = strings.Join(items, ",")
		ext.Value, err = single(spec)
	case "authorityInfoAccess":
		spec.AuthInfAcc = val
		ext.Value, err = single(spec)
	case "nameConstraints":
		spec.NameCons = val
		var exts []pkix.Extension
		if exts, err = BuildExtensions(spec, ExtContext{}); err == nil {
			ext.Value = exts[0].Value
		}
	case "certificatePolicies":
		ext.Value, err = c.certPolicies(val, kv.line)
	case "policyConstraints":
		var pc struct {
			Require *big.Int `asn1:"optional,tag:0"`
			Inhibit *big.Int `asn1:"optional,tag:1"`
		}
		for _, p := range splitList(val) {
			k, v, _ := strings.Cut(p, ":")
			n, ok := new(big.Int).SetString(strings.TrimSpace(v), 10)
			if !ok {
				return ext, fmt.Errorf("policyConstraints: %q is not a number", v)
			}
			switch k {
			case "requireExplicitPolicy":
				pc.Require = n
			case "inhibitPolicyMapping":
				pc.Inhibit = n
			default:
				return ext, fmt.Errorf("policyConstraints: unknown %q", k)
			}
		}
		ext.Value, err = asn1.Marshal(pc)
	case "inhibitAnyPolicy":
		n, ok := new(big.Int).SetString(val, 10)
		if !ok {
			return ext, fmt.Errorf("inhibitAnyPolicy: %q is not a number", val)
		}
		ext.Value, err = asn1.Marshal(n)
	case "policyMappings":
		type mapping struct{ Issuer, Subject asn1.ObjectIdentifier }
		var maps []mapping
		for _, p := range splitList(val) {
			a, b, ok := strings.Cut(p, ":")
			oa, e1 := lookupOID(a)
			ob, e2 := lookupOID(b)
			if !ok || e1 != nil || e2 != nil {
				return ext, fmt.Errorf("policyMappings: expected issuerOID:subjectOID, got %q", p)
			}
			maps = append(maps, mapping{oa, ob})
		}
		ext.Value, err = asn1.Marshal(maps)
	case "noCheck":
		ext.Value = []byte{0x05, 0x00}
	case "tlsfeature":
		var feats []int
		for _, p := range splitList(val) {
			switch strings.ToLower(p) {
			case "status_request":
				feats = append(feats, 5)
			case "status_request_v2":
				feats = append(feats, 17)
			default:
				return ext, fmt.Errorf("tlsfeature: unknown feature %q", p)
			}
		}
		ext.Value, err = asn1.Marshal(feats)
	default: // Netscape IA5 strings
		ext.Value, err = asn1.MarshalWithParams(val, "ia5")
	}
	return ext, err
}

func indexOf(list []string, v string) int {
	for i, x := range list {
		if x == strings.TrimSpace(v) {
			return i
		}
	}
	return -1
}

// lookupOID accepts a dotted OID or a name known to go-ca.
func lookupOID(s string) (asn1.ObjectIdentifier, error) {
	s = strings.TrimSpace(s)
	if o, err := parseOID(s); err == nil {
		return o, nil
	}
	if o, ok := ekuOIDs[s]; ok {
		return o, nil
	}
	if e, ok := OIDByName(s); ok {
		return e, nil
	}
	return nil, fmt.Errorf("unknown object %q", s)
}

// generalNamesConf parses a GeneralNames value that may be a list or an
// @section with entries like "DNS.1 = name" or "dirName = sect".
func (c *conf) generalNamesConf(val string, line int, ctx ExtContext) ([]byte, error) {
	items := splitList(val)
	var body []byte
	for _, it := range items {
		if strings.HasPrefix(it, "@") {
			s, err := c.section(it, line)
			if err != nil {
				return nil, err
			}
			for _, x := range s {
				typ, _, _ := strings.Cut(x.key, ".")
				b, err := c.oneGeneralName(typ+":"+x.value, x.line, ctx)
				if err != nil {
					return nil, err
				}
				body = append(body, b...)
			}
			continue
		}
		b, err := c.oneGeneralName(it, line, ctx)
		if err != nil {
			return nil, err
		}
		body = append(body, b...)
	}
	return body, nil
}

func (c *conf) oneGeneralName(item string, line int, ctx ExtContext) ([]byte, error) {
	typ, val, _ := strings.Cut(item, ":")
	if strings.EqualFold(strings.TrimSpace(typ), "dirName") {
		s, err := c.section(val, line)
		if err != nil {
			return nil, err
		}
		var attrs []DNAttr
		for _, x := range s {
			name := x.key
			if i := strings.LastIndex(name, "."); i >= 0 && strings.Trim(name[i+1:], "0123456789") == "" {
				name = name[:i] // "OU.1 = …" style
			}
			attrs = append(attrs, DNAttr{Name: name, Value: x.value})
		}
		dn, err := BuildName(attrs, "")
		if err != nil {
			return nil, &ConfError{line, err.Error()}
		}
		return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: dn})
	}
	body, err := buildGeneralNames(item, ctx)
	if err != nil {
		return nil, &ConfError{line, err.Error()}
	}
	return body, nil
}

// certPolicies supports OID lists and @sections with policyIdentifier,
// CPS.n and userNotice.n = @sect (explicitText, organization, noticeNumbers).
func (c *conf) certPolicies(val string, line int) ([]byte, error) {
	var pols []byte
	for _, it := range splitList(val) {
		if it == "ia5org" {
			continue
		}
		if !strings.HasPrefix(it, "@") {
			o, err := lookupOID(it)
			if err != nil {
				return nil, &ConfError{line, err.Error()}
			}
			p, _ := asn1.Marshal(struct{ ID asn1.ObjectIdentifier }{o})
			pols = append(pols, p...)
			continue
		}
		s, err := c.section(it, line)
		if err != nil {
			return nil, err
		}
		var id asn1.ObjectIdentifier
		var quals []byte
		for _, x := range s {
			key, _, _ := strings.Cut(x.key, ".")
			switch key {
			case "policyIdentifier":
				if id, err = lookupOID(x.value); err != nil {
					return nil, &ConfError{x.line, err.Error()}
				}
			case "CPS":
				ia5, _ := asn1.MarshalWithParams(x.value, "ia5")
				q, _ := asn1.Marshal(struct {
					ID asn1.ObjectIdentifier
					V  asn1.RawValue
				}{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}, asn1.RawValue{FullBytes: ia5}})
				quals = append(quals, q...)
			case "userNotice":
				un, err := c.section(x.value, x.line)
				if err != nil {
					return nil, err
				}
				var org string
				var nums []int
				var text []byte
				for _, u := range un {
					switch u.key {
					case "explicitText":
						text, _ = asn1.MarshalWithParams(u.value, "utf8")
					case "organization":
						org = u.value
					case "noticeNumbers":
						for _, n := range splitList(u.value) {
							v, err := strconv.Atoi(n)
							if err != nil {
								return nil, &ConfError{u.line, "noticeNumbers must be numbers"}
							}
							nums = append(nums, v)
						}
					}
				}
				var body []byte
				if org != "" {
					o, _ := asn1.MarshalWithParams(org, "utf8")
					n, _ := asn1.Marshal(nums)
					ref, _ := seqOf(append(o, n...))
					body = append(body, ref...)
				}
				body = append(body, text...)
				unDER, _ := seqOf(body)
				q, _ := asn1.Marshal(struct {
					ID asn1.ObjectIdentifier
					V  asn1.RawValue
				}{asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}, asn1.RawValue{FullBytes: unDER}})
				quals = append(quals, q...)
			default:
				return nil, &ConfError{x.line, fmt.Sprintf("certificatePolicies: unknown %q", x.key)}
			}
		}
		if id == nil {
			return nil, &ConfError{line, "certificatePolicies: policyIdentifier missing"}
		}
		oidDER, _ := asn1.Marshal(id)
		body := oidDER
		if len(quals) > 0 {
			qs, _ := seqOf(quals)
			body = append(body, qs...)
		}
		p, _ := seqOf(body)
		pols = append(pols, p...)
	}
	return seqOf(pols)
}

// genericValue handles "DER:30:03:…" and "ASN1:TYPE:value".
func (c *conf) genericValue(v string, line int) ([]byte, error) {
	if rest, ok := strings.CutPrefix(v, "DER:"); ok {
		b, err := hex.DecodeString(strings.NewReplacer(":", "", " ", "").Replace(rest))
		if err != nil {
			return nil, &ConfError{line, "DER: invalid hex"}
		}
		return b, nil
	}
	return asn1Value(strings.TrimPrefix(v, "ASN1:"), line)
}

func asn1Value(spec string, line int) ([]byte, error) {
	typ, val, _ := strings.Cut(spec, ":")
	switch strings.ToUpper(strings.TrimSpace(typ)) {
	case "UTF8", "UTF8STRING":
		return asn1.MarshalWithParams(val, "utf8")
	case "IA5", "IA5STRING":
		return asn1.MarshalWithParams(val, "ia5")
	case "PRINTABLE", "PRINTABLESTRING":
		return asn1.MarshalWithParams(val, "printable")
	case "BOOL", "BOOLEAN":
		switch strings.ToUpper(val) {
		case "TRUE", "Y", "YES":
			return asn1.Marshal(true)
		case "FALSE", "N", "NO":
			return asn1.Marshal(false)
		}
	case "INT", "INTEGER":
		n, ok := new(big.Int).SetString(strings.TrimPrefix(val, "0x"), map[bool]int{true: 16, false: 10}[strings.HasPrefix(val, "0x")])
		if ok {
			return asn1.Marshal(n)
		}
	case "OID", "OBJECT":
		o, err := lookupOID(val)
		if err == nil {
			return asn1.Marshal(o)
		}
	case "NULL":
		return []byte{0x05, 0x00}, nil
	case "OCT", "OCTETSTRING":
		if h, ok := strings.CutPrefix(val, "FORMAT:HEX,"); ok {
			b, err := hex.DecodeString(strings.ReplaceAll(h, ":", ""))
			if err == nil {
				return asn1.Marshal(b)
			}
		} else {
			return asn1.Marshal([]byte(val))
		}
	default:
		return nil, &ConfError{line, fmt.Sprintf("ASN1 type %q is not supported; use DER:… instead", typ)}
	}
	return nil, &ConfError{line, fmt.Sprintf("invalid %s value %q", typ, val)}
}

// GenConf writes extensions the editor has no fields for in adv_ext form,
// as XCA's genGenericConf does for unknown extensions: "oid=[critical,]DER:…".
func GenConf(exts []pkix.Extension) string {
	var b strings.Builder
	for _, e := range exts {
		name := e.Id.String()
		for n, o := range confExtOIDs {
			if o.Equal(e.Id) {
				name = n
			}
		}
		crit := ""
		if e.Critical {
			crit = "critical,"
		}
		h := hex.EncodeToString(e.Value)
		var der strings.Builder
		for i := 0; i < len(h); i += 2 {
			der.WriteString(":" + h[i:i+2])
		}
		fmt.Fprintf(&b, "%s=%sDER%s\n", name, crit, der.String())
	}
	return b.String()
}

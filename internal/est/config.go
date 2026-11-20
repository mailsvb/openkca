// Package est is the EST (RFC 7030) connector: its configuration, the
// policy that turns a CSR into what to issue, and (later) the HTTP handler.
//
// The package may import store; store must never import est.
package est

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/store"
	"github.com/mailsvb/openkca/internal/tmpl"
)

// Version is the config format this package writes.
const Version = 1

// DN rule modes.
const (
	ModeRequired  = "required"  // the CSR must have the attribute; its value is taken
	ModeOptional  = "optional"  // taken from the CSR when present
	ModeFixed     = "fixed"     // the rule's Value replaces whatever the CSR has
	ModeForbidden = "forbidden" // the CSR must not have the attribute
)

// What happens to subject attributes no rule names.
const (
	UnlistedDrop   = "drop"
	UnlistedReject = "reject"
)

// Config is an EST connector's configuration, stored as versioned JSON in
// connectors.config.
type Config struct {
	Version int          `json:"version"`
	Auth    Auth         `json:"auth"`
	Keys    KeyRules     `json:"keys"`
	Subject SubjectRules `json:"subject"`
	SAN     SANRules     `json:"san"`
	// Profile gives the extensions (KU, EKU, CDP, AIA, ...) and the validity
	// of every issued certificate. Profile.Subject holds fixed subject
	// attributes for attributes no rule names; Profile.Ext.SubAltName holds
	// fixed SANs appended to the CSR's.
	Profile store.TemplateData `json:"profile"`
}

// Auth is how clients authenticate.
type Auth struct {
	User     string `json:"user"`
	PassHash string `json:"pass_hash"` // auth.HashPassword (Argon2id)
	Reenroll bool   `json:"reenroll"`  // accept the current certificate for simplereenroll
}

// KeyRules are the public keys a CSR may carry. Names are those of the pki
// lists the key picker offers (pki.ECCurves, pki.MLDSAParamSets, ...).
type KeyRules struct {
	RSAMinBits int      `json:"rsa_min_bits"` // 0: RSA (and RSA-PSS) not allowed
	RSAMaxBits int      `json:"rsa_max_bits"` // 0: no upper limit
	ECCurves   []string `json:"ec_curves"`    // "P-256", "brainpoolP384r1", ...
	EdDSA      []string `json:"eddsa"`        // "Ed25519", "Ed448"
	MLDSA      []string `json:"mldsa"`        // "ML-DSA-65", ...
	SLHDSA     []string `json:"slhdsa"`       // "SLH-DSA-SHA2-128s", ...
	Composite  []string `json:"composite"`    // "MLDSA65-ECDSA-P256-SHA512", ...
	// MinCSRHash is the weakest hash the CSR may be signed with: "SHA-256"
	// (also when empty), "SHA-384" or "SHA-512". MD5 and SHA-1 are always
	// refused. Algorithms that hash internally (EdDSA, ML-DSA, ...) pass.
	MinCSRHash string `json:"min_csr_hash"`
}

// SubjectRules decide the subject of the certificate.
type SubjectRules struct {
	Rules    []DNRule `json:"rules"`
	Unlisted string   `json:"unlisted"` // UnlistedDrop (also when empty) or UnlistedReject
}

// DNRule is the rule for one subject attribute.
type DNRule struct {
	Attr    string `json:"attr"`              // short name as pki.NameAttrs gives it ("CN", "O", "emailAddress") or a dotted OID
	Mode    string `json:"mode"`              // ModeRequired, ModeOptional, ModeFixed, ModeForbidden
	Value   string `json:"value,omitempty"`   // ModeFixed: the value
	Pattern string `json:"pattern,omitempty"` // optional regex each CSR value must match in full
}

// SANRules decide the subject alternative names taken from the CSR. A type
// that is not enabled allows no names of that type.
type SANRules struct {
	DNS   DNSRule   `json:"dns"`
	IP    IPRule    `json:"ip"`
	Email EmailRule `json:"email"`
	URI   URIRule   `json:"uri"`
	// Wildcards allows DNS names with a "*" leftmost label.
	Wildcards bool `json:"wildcards"`
	// Max limits the SANs taken from the CSR (0: no limit). Copied CNs and
	// the profile's fixed SANs do not count.
	Max int `json:"max"`
	// CopyCN adds the CN as a DNS name when it is a host name that passes
	// the DNS rules.
	CopyCN bool `json:"copy_cn"`
}

// DNSRule allows DNS names. A pattern is a host name (exact match),
// "*.suffix" (any name below suffix, not suffix itself) or "*" (any host
// name). Matching ignores case.
type DNSRule struct {
	Enabled  bool     `json:"enabled"`
	Patterns []string `json:"patterns"`
}

// IPRule allows IP addresses inside one of the CIDRs.
type IPRule struct {
	Enabled bool     `json:"enabled"`
	CIDRs   []string `json:"cidrs"`
}

// EmailRule allows e-mail addresses whose domain matches one of Domains,
// with the same syntax as DNS patterns.
type EmailRule struct {
	Enabled bool     `json:"enabled"`
	Domains []string `json:"domains"`
}

// URIRule allows URIs starting with one of the prefixes.
type URIRule struct {
	Enabled  bool     `json:"enabled"`
	Prefixes []string `json:"prefixes"`
}

// Key usage bits (pki.KeyUsageNames).
const (
	kuDigitalSignature = 1 << 0
	kuKeyEncipherment  = 1 << 2
	kuDataEncipherment = 1 << 3
	kuKeyAgreement     = 1 << 4
	kuKeyCertSign      = 1 << 5
	kuCRLSign          = 1 << 6
)

// Default is a new connector's configuration: CN required, every other
// attribute dropped, no SANs, EC P-256/P-384 and RSA from 2048 bits, CSRs
// signed with at least SHA-256, a one-year TLS client profile.
func Default() Config {
	return Config{
		Version: Version,
		Keys: KeyRules{
			RSAMinBits: 2048,
			ECCurves:   []string{"P-256", "P-384"},
			MinCSRHash: "SHA-256",
		},
		Subject: SubjectRules{
			Rules:    []DNRule{{Attr: "CN", Mode: ModeRequired}},
			Unlisted: UnlistedDrop,
		},
		SAN: SANRules{Max: 10},
		Profile: store.TemplateData{
			Ext: pki.ExtSpec{CA: 2, SubKey: true, AuthKey: true, KeyUse: kuDigitalSignature | kuKeyAgreement | kuKeyEncipherment,
				KUCritical: true, EKU: []string{"clientAuth"}},
			Validity: tmpl.Validity{N: 1, Unit: 2},
		},
	}
}

// Parse reads a stored config.
func Parse(b []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("est: config: %w", err)
	}
	if c.Version != Version {
		return Config{}, fmt.Errorf("est: config version %d is not supported", c.Version)
	}
	return c, nil
}

// Marshal encodes the config for storage, as the current version.
func (c Config) Marshal() ([]byte, error) {
	c.Version = Version
	return json.Marshal(c)
}

// Hash ranks for MinCSRHash.
var hashRank = map[string]int{"MD5": 1, "SHA-1": 2, "SHA-224": 3, "SHA-256": 4, "SHA-384": 5, "SHA-512": 6}

func minHash(s string) string {
	if s == "" {
		return "SHA-256"
	}
	return s
}

// Names allowed in KeyRules, from the lists keyGroups offers.
var (
	validCurves = func() []string {
		var out []string
		for _, c := range pki.ECCurves {
			out = append(out, c.Name)
		}
		return out
	}()
	validEdDSA = []string{"Ed25519", "Ed448"}
	validMLDSA = func() []string {
		var out []string
		for _, p := range pki.MLDSAParamSets {
			out = append(out, p.Name)
		}
		return out
	}()
	validSLHDSA = func() []string {
		var out []string
		for _, p := range pki.SLHDSAParamSets {
			out = append(out, p.Name)
		}
		return out
	}()
	validComposite = func() []string {
		var out []string
		for _, a := range pki.CompositeAlgs {
			out = append(out, a.Name)
		}
		return out
	}()
)

// Validate returns the reasons the config is unusable; none means it can
// serve requests.
func (c Config) Validate() []string {
	var r []string
	add := func(format string, a ...any) { r = append(r, fmt.Sprintf(format, a...)) }

	if c.Version != Version {
		add("config version %d is not supported", c.Version)
	}

	// Authentication.
	if strings.TrimSpace(c.Auth.User) == "" {
		add("no user name is set")
	}
	if c.Auth.PassHash == "" {
		add("no password is set")
	}

	// Keys.
	k := c.Keys
	if k.RSAMinBits <= 0 && len(k.ECCurves)+len(k.EdDSA)+len(k.MLDSA)+len(k.SLHDSA)+len(k.Composite) == 0 {
		add("no key type is allowed")
	}
	if k.RSAMinBits < 0 || k.RSAMaxBits < 0 {
		add("RSA key sizes must not be negative")
	}
	if k.RSAMinBits > 0 && k.RSAMinBits < 2048 {
		add("the RSA minimum of %d bits is below 2048", k.RSAMinBits)
	}
	if k.RSAMinBits > 0 && k.RSAMaxBits > 0 && k.RSAMinBits > k.RSAMaxBits {
		add("the RSA minimum of %d bits is above the maximum of %d", k.RSAMinBits, k.RSAMaxBits)
	}
	for _, l := range []struct {
		what       string
		got, valid []string
	}{
		{"EC curve", k.ECCurves, validCurves},
		{"EdDSA algorithm", k.EdDSA, validEdDSA},
		{"ML-DSA parameter set", k.MLDSA, validMLDSA},
		{"SLH-DSA parameter set", k.SLHDSA, validSLHDSA},
		{"composite algorithm", k.Composite, validComposite},
	} {
		for _, n := range l.got {
			if !slices.Contains(l.valid, n) {
				add("unknown %s %q", l.what, n)
			}
		}
	}
	if h := minHash(k.MinCSRHash); hashRank[h] < hashRank["SHA-256"] {
		add("unknown or too weak minimum CSR hash %q", k.MinCSRHash)
	}

	// Subject.
	switch c.Subject.Unlisted {
	case "", UnlistedDrop, UnlistedReject:
	default:
		add("unknown handling %q of unlisted subject attributes", c.Subject.Unlisted)
	}
	seen := map[string]bool{}
	for _, d := range c.Subject.Rules {
		if strings.TrimSpace(d.Attr) == "" {
			add("a subject rule has no attribute")
			continue
		}
		if !knownAttr(d.Attr) {
			add("unknown subject attribute %q", d.Attr)
		}
		if n := canonAttr(d.Attr); n != "" {
			if seen[n] {
				add("subject attribute %s has more than one rule", d.Attr)
			}
			seen[n] = true
		}
		re, err := compilePattern(d.Pattern)
		if err != nil {
			add("subject attribute %s: bad pattern: %v", d.Attr, err)
		}
		switch d.Mode {
		case ModeRequired, ModeOptional, ModeForbidden:
		case ModeFixed:
			if strings.TrimSpace(d.Value) == "" {
				add("subject attribute %s is fixed but has no value", d.Attr)
			} else if re != nil && !re.MatchString(d.Value) {
				add("the fixed value of subject attribute %s does not match its pattern", d.Attr)
			}
		default:
			add("subject attribute %s: unknown mode %q", d.Attr, d.Mode)
		}
	}
	for _, a := range c.Profile.Subject {
		if !knownAttr(a.Name) {
			add("unknown fixed subject attribute %q", a.Name)
		}
	}

	// SANs.
	s := c.SAN
	if s.Max < 0 {
		add("the SAN limit must not be negative")
	}
	if s.DNS.Enabled && len(s.DNS.Patterns) == 0 {
		add("DNS names are enabled without patterns")
	}
	for _, p := range s.DNS.Patterns {
		if !validDomainPattern(p) {
			add("bad DNS pattern %q", p)
		}
	}
	if s.IP.Enabled && len(s.IP.CIDRs) == 0 {
		add("IP addresses are enabled without CIDRs")
	}
	for _, p := range s.IP.CIDRs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(p)); err != nil {
			add("bad CIDR %q", p)
		}
	}
	if s.Email.Enabled && len(s.Email.Domains) == 0 {
		add("e-mail addresses are enabled without domains")
	}
	for _, p := range s.Email.Domains {
		if !validDomainPattern(p) {
			add("bad e-mail domain %q", p)
		}
	}
	if s.URI.Enabled && len(s.URI.Prefixes) == 0 {
		add("URIs are enabled without prefixes")
	}
	for _, p := range s.URI.Prefixes {
		if i := strings.Index(p, ":"); i <= 0 || strings.ContainsAny(p, " \t,") {
			add("bad URI prefix %q", p)
		}
	}

	// Profile.
	e := c.Profile.Ext
	if e.CA == 1 {
		add("the profile issues CA certificates")
	}
	if e.KeyUse&(kuKeyCertSign|kuCRLSign) != 0 {
		add("the profile's key usage allows signing certificates or CRLs")
	}
	for _, n := range splitSANs(e.SubAltName) {
		if isCopyToken(n) {
			add("the profile's SAN %q is not supported; use the CN copy option", n)
		}
	}
	v := c.Profile.Validity
	if v.Unit < 0 || v.Unit > 2 {
		add("unknown validity unit %d", v.Unit)
	}
	if v.N <= 0 && !v.NoExpiry {
		add("the profile has no validity")
	}
	return r
}

// knownAttr reports whether pki knows a subject attribute name.
func knownAttr(name string) bool { return canonAttr(name) != "" }

// canonAttr is the short name pki.NameAttrs gives an attribute name ("CN"
// for "commonName"), "" for names pki does not know.
func canonAttr(name string) string {
	der, err := pki.BuildName([]pki.DNAttr{{Name: strings.TrimSpace(name), Value: "XX"}}, "")
	if err != nil {
		return ""
	}
	if attrs := pki.NameAttrs(der); len(attrs) == 1 {
		return attrs[0].Name
	}
	return ""
}

// compilePattern compiles a DN rule pattern anchored at both ends; an empty
// pattern gives nil.
func compilePattern(p string) (*regexp.Regexp, error) {
	if p == "" {
		return nil, nil
	}
	return regexp.Compile(`^(?:` + p + `)$`)
}

// validDomainPattern accepts "*", "*.host" and "host".
func validDomainPattern(p string) bool {
	p = strings.TrimSpace(p)
	if p == "*" {
		return true
	}
	return validHostname(strings.TrimPrefix(p, "*."))
}

// splitSANs splits the one-line SAN syntax ("DNS:a, IP:192.0.2.1").
func splitSANs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// isCopyToken reports XCA's "DNS:copycn" and "email:copy", which copy from
// the subject without the connector's rules.
func isCopyToken(n string) bool {
	typ, v, _ := strings.Cut(n, ":")
	return strings.EqualFold(typ, "DNS") && strings.EqualFold(v, "copycn") ||
		strings.EqualFold(typ, "email") && strings.EqualFold(v, "copy")
}

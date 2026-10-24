package web

import (
	"fmt"
	"strings"

	"github.com/mailsvb/go-ca/internal/pki"
)

// Key usage bits (pki.KeyUsageNames order).
const (
	kuDigitalSignature = 1 << 0
	kuKeyEncipherment  = 1 << 2
	kuKeyAgreement     = 1 << 4
	kuKeyCertSign      = 1 << 5
	kuCRLSign          = 1 << 6
)

// validity is a lifetime choice of a profile.
type validity struct {
	N    int
	Unit string // "d", "m", "y"
}

func (v validity) String() string { return fmt.Sprintf("%d%s", v.N, v.Unit) }

func parseValidity(s string) (validity, bool) {
	var v validity
	if len(s) < 2 {
		return v, false
	}
	if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &v.N); err != nil || v.N < 1 {
		return v, false
	}
	v.Unit = s[len(s)-1:]
	return v, v.Unit == "d" || v.Unit == "m" || v.Unit == "y"
}

// days is the approximate length in days.
func (v validity) days() int {
	switch v.Unit {
	case "y":
		return v.N * 365
	case "m":
		return v.N * 30
	}
	return v.N
}

// profile is a built-in purpose: what a certificate (or key) is for and
// the settings that follow from it. Profiles are fixed; the database's
// own templates are offered next to them.
type profile struct {
	ID       string
	Group    string // "ca", "cert" or "keys"
	Key      string // key choice of keyGroups
	Validity []validity
	Default  int    // index into Validity
	Issuer   string // "self" (root only), "ca" (a CA required) or "any"
	Fields   []string
	Ext      pki.ExtSpec
	KURSA    int    // key usage for RSA keys, if different
	KUEC     int    // key usage for EC keys, if different
	Link     string // keys: the page that makes the key, below the database
}

// Fields of the short form.
const (
	fieldHosts = "hosts" // DNS names and IP addresses: SAN, the first one the CN
	fieldCN    = "cn"
	fieldEmail = "email"
	fieldOrg   = "org" // O and C
)

var profiles = []profile{
	{ID: "root-ca", Group: "ca", Key: "EC:P-384", Validity: []validity{{10, "y"}, {20, "y"}, {30, "y"}}, Default: 1,
		Issuer: "self", Fields: []string{fieldCN, fieldOrg},
		Ext: pki.ExtSpec{CA: 1, BCCritical: true, PathLen: "1", SubKey: true, KeyUse: kuKeyCertSign | kuCRLSign, KUCritical: true}},
	{ID: "intermediate-ca", Group: "ca", Key: "EC:P-256", Validity: []validity{{5, "y"}, {10, "y"}, {15, "y"}}, Default: 1,
		Issuer: "ca", Fields: []string{fieldCN, fieldOrg},
		Ext: pki.ExtSpec{CA: 1, BCCritical: true, PathLen: "0", SubKey: true, AuthKey: true, KeyUse: kuKeyCertSign | kuCRLSign, KUCritical: true}},
	{ID: "tls-server", Group: "cert", Key: "EC:P-256", Validity: []validity{{90, "d"}, {397, "d"}, {2, "y"}}, Default: 1,
		Issuer: "any", Fields: []string{fieldHosts},
		Ext:   pki.ExtSpec{CA: 2, SubKey: true, AuthKey: true, KeyUse: kuDigitalSignature, KUCritical: true, EKU: []string{"serverAuth"}},
		KURSA: kuDigitalSignature | kuKeyEncipherment},
	{ID: "tls-client", Group: "cert", Key: "EC:P-256", Validity: []validity{{90, "d"}, {1, "y"}, {2, "y"}}, Default: 1,
		Issuer: "any", Fields: []string{fieldCN, fieldEmail},
		Ext: pki.ExtSpec{CA: 2, SubKey: true, AuthKey: true, KeyUse: kuDigitalSignature, KUCritical: true, EKU: []string{"clientAuth"}}},
	{ID: "smime", Group: "cert", Key: "RSA:3072", Validity: []validity{{1, "y"}, {2, "y"}, {3, "y"}}, Default: 1,
		Issuer: "any", Fields: []string{fieldEmail, fieldCN},
		Ext:   pki.ExtSpec{CA: 2, SubKey: true, AuthKey: true, KeyUse: kuDigitalSignature, KUCritical: true, EKU: []string{"emailProtection"}},
		KURSA: kuDigitalSignature | kuKeyEncipherment, KUEC: kuDigitalSignature | kuKeyAgreement},
	{ID: "code-signing", Group: "cert", Key: "EC:P-256", Validity: []validity{{1, "y"}, {3, "y"}, {5, "y"}}, Default: 1,
		Issuer: "any", Fields: []string{fieldCN, fieldOrg},
		Ext: pki.ExtSpec{CA: 2, SubKey: true, AuthKey: true, KeyUse: kuDigitalSignature, KUCritical: true, EKU: []string{"codeSigning"}}},
	{ID: "ssh", Group: "keys", Key: "Ed25519", Link: "new/sshkey"},
	{ID: "openpgp", Group: "keys", Key: "Ed25519", Link: "new/pgpkey"},
}

func profileByID(id string) *profile {
	for i := range profiles {
		if profiles[i].ID == id {
			return &profiles[i]
		}
	}
	return nil
}

func (p *profile) has(field string) bool {
	for _, f := range p.Fields {
		if f == field {
			return true
		}
	}
	return false
}

// ext is the profile's extensions for a key choice: RSA keys encipher,
// EC keys agree on keys where the purpose needs it.
func (p *profile) ext(key string) pki.ExtSpec {
	e := p.Ext
	e.EKU = append([]string(nil), p.Ext.EKU...)
	switch typ, _, _ := strings.Cut(key, ":"); typ {
	case "RSA", "RSA-PSS":
		if p.KURSA != 0 {
			e.KeyUse = p.KURSA
		}
	case "EC":
		if p.KUEC != 0 {
			e.KeyUse = p.KUEC
		}
	}
	return e
}

func (p *profile) defaultValidity() validity { return p.Validity[p.Default] }

// keyLabel names a key choice as the picker does ("ECDSA P-256").
func keyLabel(v string) string {
	for _, g := range keyGroups {
		for _, c := range g.Choices {
			if c.Value == v {
				return c.Label
			}
		}
	}
	return v
}

// summary is the one line on the profile's card: key, lifetime, purpose.
func (p *profile) summary(pr func(string, ...any) string) string {
	parts := []string{keyLabel(p.Key)}
	if p.Group == "keys" {
		if p.ID == "openpgp" {
			parts = []string{"Ed25519 + X25519"}
		}
		return strings.Join(parts, " · ")
	}
	parts = append(parts, validityText(pr, p.defaultValidity()))
	if p.Ext.CA == 1 {
		parts = append(parts, "CA, pathlen "+p.Ext.PathLen)
	} else {
		parts = append(parts, strings.Join(p.Ext.EKU, ", "))
	}
	return strings.Join(parts, " · ")
}

func validityText(pr func(string, ...any) string, v validity) string {
	unit := map[string]string{"d": "profile.days", "m": "profile.months", "y": "profile.years"}[v.Unit]
	return pr(unit, v.N)
}

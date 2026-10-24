package tmpl

import (
	"encoding/binary"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/mailsvb/go-ca/internal/pki"
)

// Keys are pki_temp::tmpl_keys: every template carries all of them.
var Keys = []string{"nameCons", "subAltName", "issAltName", "crlDist", "authInfAcc", "nsCertType", "nsComment",
	"nsBaseUrl", "nsRevocationUrl", "nsCARevocationUrl", "nsRenewalUrl", "nsCaPolicyUrl", "nsSslServerName",
	"ca", "bcCritical", "ekuCritical", "kuCritical", "subKey", "authKey", "basicPath", "validN", "validM",
	"validMidn", "keyUse", "eKeyUse", "adv_ext", "noWellDefinedExpDate", "OCSPstaple"}

// go-ca's own keys, kept in its database but not in XCA's export form:
// whether a certificate made from the template gets the issuer's published
// CRL (CDP) and certificate (AIA caIssuers).
const (
	KeyPubCDP = "goca.pubCDP"
	KeyPubAIA = "goca.pubAIA"
)

// IsGoCAKey reports whether a settings key is go-ca's own (XCA knows no
// equivalent; Encode leaves such keys out).
func IsGoCAKey(k string) bool { return strings.HasPrefix(k, "goca.") }

func putQString(b []byte, s string) []byte {
	u := utf16.Encode([]rune(s))
	b = binary.BigEndian.AppendUint32(b, uint32(2*len(u)))
	for _, c := range u {
		b = binary.BigEndian.AppendUint16(b, c)
	}
	return b
}

// Encode writes a version 10 template: DER subject, then the settings
// (without go-ca's own keys) as a QDataStream QMap<QString,QString>. Entries are written in descending key
// order, as Qt 5's QDataStream (and thus XCA) writes a QMap.
func Encode(t *Template) []byte {
	subject := t.Subject
	if len(subject) == 0 {
		subject = []byte{0x30, 0x00}
	}
	keys := make([]string, 0, len(t.Settings))
	for k := range t.Settings {
		if !IsGoCAKey(k) {
			keys = append(keys, k)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	b := append([]byte(nil), subject...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(keys)))
	for _, k := range keys {
		b = putQString(b, k)
		b = putQString(b, t.Settings[k])
	}
	return b
}

// Validity is the template's validity: validN units of validM (0 days,
// 1 months, 2 years), midnight and "no well-defined expiration".
type Validity struct {
	N        int
	Unit     int
	Midnight bool
	NoExpiry bool
}

func on(s string) bool { return s == "1" || strings.EqualFold(s, "true") }

func bit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// Spec maps the template keys onto the editor's extension fields
// (NewX509::extensionsFromTemplate).
func (t *Template) Spec() pki.ExtSpec {
	s := t.Settings
	spec := pki.ExtSpec{
		CA: atoi(s["ca"]), BCCritical: on(s["bcCritical"]), PathLen: s["basicPath"],
		SubKey: on(s["subKey"]), AuthKey: on(s["authKey"]),
		KeyUse: atoi(s["keyUse"]), KUCritical: on(s["kuCritical"]), EKUCrit: on(s["ekuCritical"]),
		NameCons: s["nameCons"], SubAltName: s["subAltName"], IssAltName: s["issAltName"],
		CRLDist: s["crlDist"], AuthInfAcc: s["authInfAcc"], OCSPStaple: on(s["OCSPstaple"]),
		NSCertType: atoi(s["nsCertType"]), NSComment: s["nsComment"], NSBaseURL: s["nsBaseUrl"],
		NSRevocationURL: s["nsRevocationUrl"], NSCARevocationURL: s["nsCARevocationUrl"],
		NSRenewalURL: s["nsRenewalUrl"], NSCAPolicyURL: s["nsCaPolicyUrl"], NSSSLServerName: s["nsSslServerName"],
		AdvExt: s["adv_ext"], PubCDP: on(s[KeyPubCDP]), PubAIA: on(s[KeyPubAIA]),
	}
	for _, e := range strings.Split(s["eKeyUse"], ",") {
		if e = strings.TrimSpace(e); e != "" {
			spec.EKU = append(spec.EKU, e)
		}
	}
	return spec
}

// Validity returns the template's validity settings.
func (t *Template) Validity() Validity {
	s := t.Settings
	return Validity{N: atoi(s["validN"]), Unit: atoi(s["validM"]), Midnight: on(s["validMidn"]), NoExpiry: on(s["noWellDefinedExpDate"])}
}

// New builds a template from editor values (NewX509::toTemplate). All of
// XCA's keys are present, as in a template XCA writes.
func New(subject []byte, spec pki.ExtSpec, v Validity) *Template {
	s := map[string]string{}
	for _, k := range Keys {
		s[k] = ""
	}
	s["ca"] = strconv.Itoa(spec.CA)
	s["bcCritical"] = bit(spec.BCCritical)
	if p := strings.TrimSpace(spec.PathLen); p != "" {
		s["basicPath"] = strconv.Itoa(atoi(p))
	}
	s["subKey"], s["authKey"] = bit(spec.SubKey), bit(spec.AuthKey)
	s["keyUse"], s["kuCritical"] = strconv.Itoa(spec.KeyUse), bit(spec.KUCritical)
	s["eKeyUse"], s["ekuCritical"] = strings.Join(spec.EKU, ", "), bit(spec.EKUCrit)
	s["nameCons"], s["subAltName"], s["issAltName"] = spec.NameCons, spec.SubAltName, spec.IssAltName
	s["crlDist"], s["authInfAcc"], s["OCSPstaple"] = spec.CRLDist, spec.AuthInfAcc, bit(spec.OCSPStaple)
	s["nsCertType"], s["nsComment"] = strconv.Itoa(spec.NSCertType), spec.NSComment
	s["nsBaseUrl"], s["nsRevocationUrl"], s["nsCARevocationUrl"] = spec.NSBaseURL, spec.NSRevocationURL, spec.NSCARevocationURL
	s["nsRenewalUrl"], s["nsCaPolicyUrl"], s["nsSslServerName"] = spec.NSRenewalURL, spec.NSCAPolicyURL, spec.NSSSLServerName
	s["adv_ext"] = spec.AdvExt
	s[KeyPubCDP], s[KeyPubAIA] = bit(spec.PubCDP), bit(spec.PubAIA)
	s["validN"], s["validM"] = strconv.Itoa(v.N), strconv.Itoa(v.Unit)
	s["validMidn"], s["noWellDefinedExpDate"] = bit(v.Midnight), bit(v.NoExpiry)
	return &Template{Subject: subject, Settings: s}
}

// ValidityFromDates derives validN/validM as pki_temp::fromCert does:
// days up to 60, then months up to 24, then years.
func ValidityFromDates(days int) (n, unit int) {
	if days > 60 {
		days /= 30
		if days > 24 {
			return days / 12, 2
		}
		return days, 1
	}
	return days, 0
}

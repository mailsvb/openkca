package codec

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/tmpl"
)

// icsValue escapes a vCalendar text value and folds it: 60 bytes on the
// first line, then continuation lines of up to 74, never splitting an
// escape sequence (pki_base.cpp icsValue).
func icsValue(s string) string {
	s = strings.NewReplacer(`\`, `\\`, ",", `\,`, ";", `\;`, "\n", `\n`, "\r", `\r`).Replace(s)
	var lines []string
	limit := 60
	for s != "" {
		cut, size := 0, 0
		for i, r := range s {
			n := utf8.RuneLen(r)
			if size+n > limit {
				break
			}
			size += n
			cut = i + n
		}
		for cut > 1 && cut < len(s) && s[cut-1] == '\\' && !escapedAt(s, cut-1) {
			cut--
		}
		lines = append(lines, s[:cut])
		s = s[cut:]
		limit = 73
	}
	return strings.Join(lines, "\r\n ")
}

// escapedAt reports whether the backslash at i is itself escaped.
func escapedAt(s string, i int) bool {
	n := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		n++
	}
	return n%2 == 1
}

// VEvent is an expiry reminder (pki_base::icsVEVENT). der is the item's
// DER encoding for the UID, alarm the ical_expiry setting (e.g. "1W").
func VEvent(der []byte, expires time.Time, summary, description, comment, alarm string, now time.Time) []string {
	sum := sha1.Sum(der)
	desc := icsValue(description + "\n----------\n" + comment)
	sv := icsValue(summary)
	return []string{
		"BEGIN:VEVENT",
		"DTSTAMP:" + now.UTC().Format("20060102T150405Z"),
		"UID:EXP-" + strings.ToUpper(hex.EncodeToString(sum[:])) + "@xca.ovh",
		"STATUS:CONFIRMED",
		"DTSTART:" + expires.UTC().Format("20060102"),
		"DURATION:P1D",
		"SUMMARY:" + sv,
		"DESCRIPTION:" + desc,
		"BEGIN:VALARM",
		"ACTION:DISPLAY",
		"SUMMARY:" + sv,
		"DESCRIPTION:" + desc,
		"TRIGGER:-P" + alarm,
		"END:VALARM",
		"END:VEVENT",
	}
}

// VCalendar wraps events (db_base::writeVcalendar).
func VCalendar(events []string, product string) []byte {
	lines := append([]string{"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//" + product + "//"}, events...)
	lines = append(lines, "END:VCALENDAR")
	return []byte(strings.Join(lines, "\r\n"))
}

// OpenVPN writes the inline tags of an OpenVPN configuration in XCA's
// order; empty parts are left out. XCA's <tls-auth> part is not written.
func OpenVPN(ca, extra, cert, key []byte) []byte {
	var b bytes.Buffer
	for _, p := range []struct {
		tag  string
		data []byte
	}{{"ca", ca}, {"extra-certs", extra}, {"cert", cert}, {"key", key}} {
		if len(p.data) > 0 {
			fmt.Fprintf(&b, "<%s>\n%s</%s>\n", p.tag, p.data, p.tag)
		}
	}
	return b.Bytes()
}

// OpenSSLConf writes an "openssl req" configuration that recreates a
// subject and extensions (pki_x509super::opensslConf). stringOpt is the
// string_opt setting, which openssl accepts as string_mask unchanged.
func OpenSSLConf(subject []byte, exts []pkix.Extension, stringOpt string) []byte {
	if stringOpt == "" {
		stringOpt = "MASK:0x2002"
	}
	var dn strings.Builder
	entries, _ := pki.ParseName(subject)
	for i, e := range entries {
		fmt.Fprintf(&dn, "%d.%s=%s\n", i, e.Short, e.Value)
	}
	return []byte(fmt.Sprintf("[ req ]\n"+
		"default_bits = 1024\n"+
		"default_keyfile = privkey.pem\n"+
		"distinguished_name = xca_dn\n"+
		"x509_extensions = xca_extensions\n"+
		"req_extensions = xca_extensions\n"+
		"string_mask = %s\n"+
		"utf8 = yes\n"+
		"prompt = no\n\n"+
		"[ xca_dn ]\n"+
		"%s\n"+
		"[ xca_extensions ]\n"+
		"%s", stringOpt, dn.String(), pki.ConfFromExtensions(exts)))
}

// XCATemplate writes a template in XCA's export form: a PEM block "XCA
// TEMPLATE" holding the data size, the template version and the version 10
// data with the internal name and comment added (pki_temp::toExportData).
func XCATemplate(name, comment string, t *tmpl.Template) []byte {
	settings := make(map[string]string, len(t.Settings)+2)
	for k, v := range t.Settings {
		settings[k] = v
	}
	settings["internal_name"] = name
	settings["internal_comment"] = comment
	data := tmpl.Encode(&tmpl.Template{Subject: t.Subject, Settings: settings})
	b := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	b = binary.BigEndian.AppendUint32(b, tmpl.Version)
	return PEM(PEMTemplate, append(b, data...))
}

// ParseXCATemplate decodes the contents of an "XCA TEMPLATE" block or of
// a raw template export file.
func ParseXCATemplate(b []byte) (*tmpl.Template, error) {
	if len(b) < 8 {
		return nil, errors.New("template file content error (too small)")
	}
	return tmpl.Decode(b[8:], int(binary.BigEndian.Uint32(b[4:8])))
}

// JWKJSON writes one JWK, or a set {"keys": [...]} for several, with
// duplicate key IDs numbered as XCA does. The layout follows Qt's
// indented QJsonDocument: sorted keys, four spaces.
func JWKJSON(keys []map[string]any) ([]byte, error) {
	var v any
	if len(keys) == 1 {
		v = keys[0]
	} else {
		seen := map[string]bool{}
		arr := make([]any, len(keys))
		for i, k := range keys {
			kid, _ := k["kid"].(string)
			name := kid
			for n := 1; seen[name]; n++ {
				name = fmt.Sprintf("%s (%d)", kid, n)
			}
			seen[name] = true
			k["kid"] = name
			arr[i] = k
		}
		v = map[string]any{"keys": arr}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// decodePEMAll returns all PEM blocks of b, skipping text between them.
func decodePEMAll(b []byte) []*pem.Block {
	var out []*pem.Block
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out
		}
		out = append(out, blk)
	}
}

// Thumbprints returns the JWK "x5t" and "x5t#256" values of a certificate.
func Thumbprints(der []byte) (string, string) {
	s1 := sha1.Sum(der)
	s256 := sha256.Sum256(der)
	return b64u(s1[:]), b64u(s256[:])
}

// Base64 is standard base64, as used in JWK "x5c".
func Base64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Package tmpl decodes (and in phase 5 encodes) XCA templates as stored in
// templates.template.
//
// Version 10 (current): DER X509_NAME followed by a Qt QDataStream (Qt 4.2
// format) serialised QMap<QString,QString>: a 32-bit big-endian count, then
// key/value pairs, each QString a 32-bit byte length (0xffffffff = null)
// plus UTF-16BE. Versions below 10 use pki_temp::old_fromData's fixed field
// list with NUL-terminated UTF-8 strings, 32-bit big-endian integers and
// one-byte booleans, with the subject name in the middle.
package tmpl

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"
)

// Version is the template format XCA writes today (TMPL_VERSION).
const Version = 10

// Template is a decoded template.
type Template struct {
	Subject  []byte            // DER X509_NAME, may be an empty SEQUENCE
	Settings map[string]string // XCA's template keys, e.g. "subAltName", "keyUse"
	IntName  string            // only present in exported templates
	Comment  string
}

var errShort = errors.New("tmpl: out of data")

// Decode parses a stored template blob of the given version.
func Decode(blob []byte, version int) (*Template, error) {
	if version < 10 {
		return decodeOld(blob, version)
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(blob, &raw)
	if err != nil {
		return nil, fmt.Errorf("tmpl: subject: %w", err)
	}
	t := &Template{Subject: raw.FullBytes, Settings: map[string]string{}}
	r := &reader{b: rest}
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if n > 10000 {
		return nil, errors.New("tmpl: implausible entry count")
	}
	for i := uint32(0); i < n; i++ {
		k, err := r.qstring()
		if err != nil {
			return nil, err
		}
		v, err := r.qstring()
		if err != nil {
			return nil, err
		}
		t.Settings[k] = v
	}
	// Renamed keys, as in pki_temp::fromData.
	for old, cur := range map[string]string{"eKyUseCritical": "ekuCritical", "keyUseCritical": "kuCritical"} {
		if v, ok := t.Settings[old]; ok {
			t.Settings[cur] = v
			delete(t.Settings, old)
		}
	}
	if v, ok := t.Settings["internal_name"]; ok {
		t.IntName = v
		delete(t.Settings, "internal_name")
	}
	if v, ok := t.Settings["internal_comment"]; ok {
		t.Comment = v
		delete(t.Settings, "internal_comment")
	}
	return t, nil
}

type reader struct{ b []byte }

func (r *reader) u32() (uint32, error) {
	if len(r.b) < 4 {
		return 0, errShort
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v, nil
}

func (r *reader) qstring() (string, error) {
	n, err := r.u32()
	if err != nil {
		return "", err
	}
	if n == 0xffffffff {
		return "", nil
	}
	if n%2 != 0 || int(n) > len(r.b) {
		return "", errShort
	}
	u := make([]uint16, n/2)
	for i := range u {
		u[i] = binary.BigEndian.Uint16(r.b[2*i:])
	}
	r.b = r.b[n:]
	return string(utf16.Decode(u)), nil
}

func (r *reader) cstring() (string, error) {
	for i, c := range r.b {
		if c == 0 {
			s := string(r.b[:i])
			r.b = r.b[i+1:]
			return s, nil
		}
	}
	return "", errors.New("tmpl: unterminated string")
}

func (r *reader) boolean() (string, error) {
	if len(r.b) < 1 {
		return "", errShort
	}
	v := "0"
	if r.b[0] != 0 {
		v = "1"
	}
	r.b = r.b[1:]
	return v, nil
}

func (r *reader) number() (string, error) {
	v, err := r.u32()
	return strconv.FormatUint(uint64(v), 10), err
}

// decodeOld follows pki_temp::old_fromData field by field.
func decodeOld(blob []byte, version int) (*Template, error) {
	r := &reader{b: blob}
	s := map[string]string{}
	t := &Template{Settings: s}
	type step struct {
		key string
		fn  func() (string, error)
		ok  bool
	}
	str, bln, num := r.cstring, r.boolean, r.number
	steps := []step{
		{"", str, true}, // destination, unused
		{"bcCritical", bln, true}, {"kuCritical", bln, true}, {"ekuCritical", bln, true},
		{"subKey", bln, true}, {"authKey", bln, true}, {"ca", num, true},
		{"basicPath", str, version > 5}, {"basicPath", num, version <= 5},
		{"validN", num, true}, {"validM", num, true}, {"keyUse", num, true},
		{"eKeyUse", str, version > 4}, {"eKeyUseLegacyBits", num, version <= 4},
		{"nsCertType", num, true}, {"subAltName", str, true}, {"issAltName", str, true},
		{"crlDist", str, true}, {"nsComment", str, true}, {"nsBaseUrl", str, true},
		{"nsRevocationUrl", str, true}, {"nsCARevocationUrl", str, true}, {"nsRenewalUrl", str, true},
		{"nsCaPolicyUrl", str, true}, {"nsSslServerName", str, true},
	}
	run := func(st []step) error {
		for _, x := range st {
			if !x.ok {
				continue
			}
			v, err := x.fn()
			if err != nil {
				return err
			}
			if x.key != "" {
				s[x.key] = v
			}
		}
		return nil
	}
	if err := run(steps); err != nil {
		return nil, err
	}
	if version <= 5 && s["basicPath"] == "0" {
		s["basicPath"] = ""
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(r.b, &raw)
	if err != nil {
		return nil, fmt.Errorf("tmpl: subject: %w", err)
	}
	t.Subject, r.b = raw.FullBytes, rest
	steps = []step{
		{"authInfAcc", str, true}, {"", str, true}, // certPol, unused
		{"validMidn", bln, true}, {"adv_ext", str, version > 2}, {"noWellDefinedExpDate", bln, version > 3},
	}
	if err := run(steps); err != nil {
		return nil, err
	}
	if len(r.b) > 0 {
		return t, fmt.Errorf("tmpl: %d bytes left over", len(r.b))
	}
	return t, nil
}

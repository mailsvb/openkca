// Package xdbpass verifies the database password hash that XCA stores in
// settings.pwhash. OpenKCA checks it once, before converting an XCA database,
// whose conversion drops the hash.
//
// Three forms exist (lib/pki_evp.cpp, lib/database_model.cpp):
//
//	T form: "T" + 16 lowercase hex digits (17 character salt), followed by the
//	        upper case hex SHA-512 digest applied 8000 times. The first round
//	        hashes salt+password, each further round the previous digest.
//	S form: a 5 character salt starting with "S", one SHA-512 round.
//	MD5:    upper case MD5 hex digest of the password, bytes separated by ':'.
package xdbpass

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// Form identifies which hash form a stored value uses.
type Form int

const (
	FormUnknown Form = iota
	FormT
	FormS
	FormMD5
)

// FormOf reports the hash form of a stored settings.pwhash value.
func FormOf(stored string) Form {
	switch {
	case strings.HasPrefix(stored, "T") && len(stored) == 17+128:
		return FormT
	case strings.HasPrefix(stored, "S") && len(stored) == 5+128:
		return FormS
	case len(stored) == 47 && strings.Count(stored, ":") == 15:
		return FormMD5
	}
	return FormUnknown
}

func sha512Rounds(salt string, password []byte, rounds int) string {
	buf := make([]byte, 0, len(salt)+len(password))
	buf = append(buf, salt...)
	buf = append(buf, password...)
	for i := 0; i < rounds; i++ {
		d := sha512.Sum512(buf)
		clear(buf)
		buf = d[:]
	}
	return salt + strings.ToUpper(hex.EncodeToString(buf))
}

func md5Form(password []byte) string {
	d := md5.Sum(password)
	h := strings.ToUpper(hex.EncodeToString(d[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// Verify checks password against stored. It returns ok when the password
// matches and upgrade when the stored value uses an old form that should be
// replaced by NewHash after a successful login, as XCA does.
func Verify(stored string, password []byte) (ok, upgrade bool) {
	var computed string
	switch FormOf(stored) {
	case FormT:
		computed = sha512Rounds(stored[:17], password, 8000)
	case FormS:
		computed = sha512Rounds(stored[:5], password, 1)
		upgrade = true
	case FormMD5:
		computed = md5Form(password)
		upgrade = true
	default:
		return false, false
	}
	ok = subtle.ConstantTimeCompare([]byte(computed), []byte(stored)) == 1
	return ok, ok && upgrade
}

// NewHash returns a T form hash of password with a fresh random salt.
func NewHash(password []byte) string {
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		panic(err)
	}
	return sha512Rounds("T"+hex.EncodeToString(r[:]), password, 8000)
}

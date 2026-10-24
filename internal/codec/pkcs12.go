package codec

import (
	"encoding/asn1"

	"github.com/mailsvb/go-ca/internal/pkcs12"
)

// PKCS12Algorithms are the values of the pkcs12_enc_algo setting
// (OpenSSL short names, as XCA stores them). The first is go-ca's default,
// as in OpenSSL 3; XCA defaults to PBE-SHA1-3DES, which is kept, like
// RC2-40, only for software that cannot read anything else (Windows before
// Server 2019 / Windows 10 1709, old Java and macOS versions).
var PKCS12Algorithms = []string{"AES-256-CBC", "PBE-SHA1-3DES", "PBE-SHA1-RC2-40"}

// PKCS12 writes a key, its certificate and further certificates as a
// password protected PKCS#12 file. key is an unencrypted PKCS#8
// PrivateKeyInfo of any type go-ca stores; certs[0] is its certificate, and
// the key gets that certificate's friendlyName. algo is a PKCS12Algorithms
// value: AES-256-CBC with PBKDF2 and a SHA-256 MAC; 3DES for keys and
// certificates with a SHA-1 MAC; RC2-40 for the certificates with a 3DES
// key, as XCA combines it. An unknown value gets the default.
func PKCS12(key []byte, certs []pkcs12.Bag, password, algo string) ([]byte, error) {
	prof := pkcs12.AES256
	switch algo {
	case "PBE-SHA1-3DES":
		prof = pkcs12.DES3
	case "PBE-SHA1-RC2-40":
		prof = pkcs12.RC2
	}
	k := pkcs12.Bag{DER: key}
	if len(certs) > 0 {
		k.FriendlyName = certs[0].FriendlyName
	}
	return pkcs12.Encode(k, certs, password, prof)
}

// ErrPassword is returned when a PKCS#12 password is wrong.
var ErrPassword = pkcs12.ErrPassword

// pfx is just enough of a PFX to recognize one.
type pfx struct {
	Version  int
	AuthSafe contentInfo
	MacData  asn1.RawValue `asn1:"optional"`
}

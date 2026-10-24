package codec

import (
	"encoding/asn1"
	"strconv"

	"github.com/mailsvb/openkca/internal/pkcs12"
)

// PKCS12Algorithms are the values of the pkcs12_enc_algo setting
// (OpenSSL short names, as XCA stores them). The first is OpenKCA's default,
// as in OpenSSL 3; XCA defaults to PBE-SHA1-3DES, which is kept, like
// RC2-40, only for software that cannot read anything else (Windows before
// Server 2019 / Windows 10 1709, old Java and macOS versions).
var PKCS12Algorithms = []string{"AES-256-CBC", "PBE-SHA1-3DES", "PBE-SHA1-RC2-40"}

// PKCS12 writes a key, its certificate and further certificates as a
// password protected PKCS#12 file. key is an unencrypted PKCS#8
// PrivateKeyInfo of any type OpenKCA stores; certs[0] is its certificate, and
// the key gets that certificate's friendlyName. algo is a PKCS12Algorithms
// value: AES-256-CBC with PBKDF2 and a SHA-256 MAC; 3DES for keys and
// certificates with a SHA-1 MAC; RC2-40 for the certificates with a 3DES
// key, as XCA combines it. An unknown value gets the default.
//
// iterations, for AES-256-CBC only, is the count of the MAC and of both
// encryptions; 0 means PKCS12Iterations. The legacy algorithms keep 2048
// (and a MAC iteration of 1), as the software that needs them expects.
func PKCS12(key []byte, certs []pkcs12.Bag, password, algo string, iterations int) ([]byte, error) {
	if iterations == 0 {
		iterations = PKCS12Iterations
	}
	prof := pkcs12.AES256.WithIterations(iterations)
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

// PKCS12Iterations is the default of the pkcs12_iterations setting. Windows
// and .NET refuse files whose MAC and encryption iterations add up to more
// than 600 000 (KB5025823), so 200 000 each is the most they import; it is
// still about 100 times OpenSSL's 2048. Tests lower it.
var PKCS12Iterations = 200_000

// The range of the pkcs12_iterations setting.
const (
	PKCS12MinIterations = 2048
	PKCS12MaxIterations = 10_000_000
)

// ParsePKCS12Iterations reads a pkcs12_iterations value: "" is the default.
func ParsePKCS12Iterations(s string) (int, bool) {
	if s == "" {
		return PKCS12Iterations, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < PKCS12MinIterations || n > PKCS12MaxIterations {
		return 0, false
	}
	return n, true
}

// ErrPassword is returned when a PKCS#12 password is wrong.
var ErrPassword = pkcs12.ErrPassword

// pfx is just enough of a PFX to recognize one.
type pfx struct {
	Version  int
	AuthSafe contentInfo
	MacData  asn1.RawValue `asn1:"optional"`
}

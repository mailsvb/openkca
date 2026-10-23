package codec

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"unicode/utf16"

	"software.sslmate.com/src/go-pkcs12"
)

// PKCS12Algorithms are the values of the pkcs12_enc_algo setting
// (OpenSSL short names, as XCA stores them). The first is go-ca's default,
// as in OpenSSL 3; XCA defaults to PBE-SHA1-3DES, which is kept, like
// RC2-40, only for software that cannot read anything else (Windows before
// Server 2019 / Windows 10 1709, old Java and macOS versions).
var PKCS12Algorithms = []string{"AES-256-CBC", "PBE-SHA1-3DES", "PBE-SHA1-RC2-40"}

// PKCS12 writes a key, its certificate and further certificates as a
// password protected PKCS#12 file. algo is a PKCS12Algorithms value:
// AES-256-CBC with PBKDF2 and a SHA-256 MAC; 3DES for keys and certificates
// with a SHA-1 MAC; RC2-40 for the certificates with a 3DES key, as XCA
// combines it. An unknown value gets the default.
func PKCS12(key crypto.Signer, cert *x509.Certificate, chain []*x509.Certificate, password, algo string) ([]byte, error) {
	enc := pkcs12.Modern2023
	switch algo {
	case "PBE-SHA1-3DES":
		enc = pkcs12.LegacyDES
	case "PBE-SHA1-RC2-40":
		enc = pkcs12.LegacyRC2
	}
	return enc.Encode(key, cert, chain, password)
}

// ErrPassword is returned when a PKCS#12 password is wrong.
var ErrPassword = pkcs12.ErrIncorrectPassword

// PKCS12Contents is what a PKCS#12 file holds.
type PKCS12Contents struct {
	Key   any // nil when the file has no key
	Cert  *x509.Certificate
	Chain []*x509.Certificate
	Alias string // friendlyName, when readable without the password
}

// ParsePKCS12 decrypts a PKCS#12 file.
func ParsePKCS12(der []byte, password string) (*PKCS12Contents, error) {
	key, cert, chain, err := pkcs12.DecodeChain(der, password)
	if err != nil {
		if errors.Is(err, pkcs12.ErrIncorrectPassword) {
			return nil, ErrPassword
		}
		// a file with certificates only
		certs, err2 := pkcs12.DecodeTrustStore(der, password)
		if err2 != nil || len(certs) == 0 {
			return nil, err
		}
		return &PKCS12Contents{Cert: certs[0], Chain: certs[1:], Alias: PKCS12Alias(der)}, nil
	}
	return &PKCS12Contents{Key: key, Cert: cert, Chain: chain, Alias: PKCS12Alias(der)}, nil
}

var oidFriendlyName = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}

type pfx struct {
	Version  int
	AuthSafe contentInfo
	MacData  asn1.RawValue `asn1:"optional"`
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue `asn1:"tag:0,explicit"`
	Attributes []struct {
		ID     asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	} `asn1:"set,optional"`
}

// PKCS12Alias reads the friendlyName from the unencrypted parts of a
// PKCS#12 file. OpenSSL (and XCA) put the shrouded key bag, which carries
// the name, into a plain data content.
func PKCS12Alias(der []byte) string {
	var p pfx
	if _, err := asn1.Unmarshal(der, &p); err != nil || !p.AuthSafe.ContentType.Equal(oidPKCS7Data) {
		return ""
	}
	var cis []contentInfo
	if _, err := asn1.Unmarshal(octets(p.AuthSafe.Content), &cis); err != nil {
		return ""
	}
	for _, ci := range cis {
		if !ci.ContentType.Equal(oidPKCS7Data) {
			continue
		}
		var bags []safeBag
		if _, err := asn1.Unmarshal(octets(ci.Content), &bags); err != nil {
			continue
		}
		for _, b := range bags {
			for _, a := range b.Attributes {
				if !a.ID.Equal(oidFriendlyName) {
					continue
				}
				var bmp asn1.RawValue
				if _, err := asn1.Unmarshal(a.Values.Bytes, &bmp); err != nil || bmp.Tag != asn1.TagBMPString || len(bmp.Bytes)%2 != 0 {
					continue
				}
				u := make([]uint16, len(bmp.Bytes)/2)
				for i := range u {
					u[i] = uint16(bmp.Bytes[2*i])<<8 | uint16(bmp.Bytes[2*i+1])
				}
				return string(utf16.Decode(u))
			}
		}
	}
	return ""
}

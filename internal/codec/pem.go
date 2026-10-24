package codec

import (
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/mailsvb/openkca/internal/pki"
)

// PEM block types.
const (
	PEMCert        = "CERTIFICATE"
	PEMRequest     = "CERTIFICATE REQUEST"
	PEMCRL         = "X509 CRL"
	PEMPublicKey   = "PUBLIC KEY"
	PEMPrivateKey  = "PRIVATE KEY"
	PEMEncrypted   = "ENCRYPTED PRIVATE KEY"
	PEMPKCS7       = "PKCS7"
	PEMTemplate    = "XCA TEMPLATE"
	PEMOpenSSHKey  = "OPENSSH PRIVATE KEY"
	pemRSAPrivate  = "RSA PRIVATE KEY"
	pemECPrivate   = "EC PRIVATE KEY"
	pemDSAPrivate  = "DSA PRIVATE KEY"
	pemNewRequest  = "NEW CERTIFICATE REQUEST"
	pemTrustedCert = "TRUSTED CERTIFICATE"
	pemX509Cert    = "X509 CERTIFICATE"
)

// PEM encodes one block.
func PEM(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// Comment is the optional text XCA writes before a PEM block
// (pki_base::PEM_comment and its overrides): the internal name, the
// comment, and per type a subject line or the key size and type.
func Comment(name, comment string, extra ...string) []byte {
	s := fmt.Sprintf("XCA internal name: %s\n%s\n", name, comment)
	for _, e := range extra {
		s += e + "\n"
	}
	return []byte(s)
}

// RFC2253 renders a DER name as X509_NAME_print_ex with XN_FLAG_RFC2253:
// last attribute first, comma separated, special characters escaped and
// bytes outside printable ASCII written as \XX.
func RFC2253(der []byte) string {
	entries, err := pki.ParseName(der)
	if err != nil {
		return ""
	}
	parts := make([]string, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		var b strings.Builder
		b.WriteString(e.Short + "=")
		v := []byte(e.Value)
		for j, c := range v {
			switch {
			case c < 0x20 || c >= 0x7f:
				fmt.Fprintf(&b, "\\%02X", c)
			case strings.IndexByte(",+\"\\<>;", c) >= 0,
				c == '#' && j == 0, c == ' ' && (j == 0 || j == len(v)-1):
				b.WriteByte('\\')
				b.WriteByte(c)
			default:
				b.WriteByte(c)
			}
		}
		parts = append(parts, b.String())
	}
	return strings.Join(parts, ",")
}

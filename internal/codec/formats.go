// Package codec converts between the objects of an XCA database and the
// file formats XCA exports and imports: PEM, DER, PKCS#7, PKCS#8, PKCS#12,
// OpenSSH, PuTTY, PVK, JWK, vCalendar, OpenVPN, OpenSSL config and XCA
// templates.
// It works on DER and Go keys only; it does not touch databases.
package codec

import "github.com/mailsvb/go-ca/internal/xdb"

// Flags describe an export format, as pki_export's F_* flags do in XCA.
type Flags uint32

const (
	FPEM       Flags = 1 << iota
	FDER             // binary
	FPKCS7           // degenerate PKCS#7 SignedData
	FPKCS12          // PKCS#12 with the private key
	FPKCS8           // PKCS#8 private key
	FSSH2            // OpenSSH formats
	FPVK             // Microsoft PVK
	FJWK             // JSON Web Key
	FX5C             // JWK with the certificate chain
	FCal             // vCalendar
	FConfig          // OpenSSL config
	FOVPN            // OpenVPN inline tags
	FIndex           // OpenSSL index file
	FChain           // the item and its issuers
	FPrivate         // includes the private key
	FCrypt           // asks for an export password
	FTradition       // OpenSSL "traditional" key format
	FUnusable        // all expired or revoked certificates
	FCA              // needs a CA certificate
	FSingle          // exactly one item
	FMulti           // several items
	FClipboard       // text that fits the clipboard
	FUsual           // listed first
	FOpenSSH         // OpenSSH's own private key format
	FPuTTY           // PuTTY formats: PPK private key, RFC 4716 public key
	FPPK2            // PPK format version 2
)

// Format is one export format. IDs below 100 are XCA's, so its names and
// the "CertFormat"/"KeyFormat" settings map onto them; formats XCA lacks
// start at 100.
type Format struct {
	ID    int
	Type  int    // xdb.Type*
	Ext   string // file name extension
	Label string // message key
	Help  string // message key
	Flags Flags
}

// Text reports whether the format's output is printable text.
func (f Format) Text() bool {
	return f.Flags&(FDER|FPKCS7|FPKCS12|FPVK) == 0
}

// Formats follows XCA's pki_export::init_elements without the OpenVPN
// tls-auth key, with go-ca's SSH formats next to XCA's.
var Formats = []Format{
	{1, xdb.TypeCert, "crt", "fmt.pem", "fmt.help.cert_pem", FPEM | FUsual | FSingle | FClipboard},
	{3, xdb.TypeCert, "pem", "fmt.pem_selected", "fmt.help.cert_pem_selected", FPEM | FMulti},
	{2, xdb.TypeCert, "pem", "fmt.pem_chain", "fmt.help.cert_pem_chain", FPEM | FUsual | FChain | FSingle | FClipboard},
	{4, xdb.TypeCert, "ovpn", "fmt.openvpn", "fmt.help.cert_ovpn", FOVPN | FChain | FPrivate | FSingle},
	{6, xdb.TypeCert, "pem", "fmt.pem_key", "fmt.help.cert_pem_key", FPEM | FPrivate | FSingle | FClipboard},
	{7, xdb.TypeCert, "pem", "fmt.pem_pkcs8", "fmt.help.cert_pem_pkcs8", FPEM | FPKCS8 | FPrivate | FCrypt | FSingle | FClipboard},
	{40, xdb.TypeCert, "pem", "fmt.all_unusable", "fmt.help.cert_unusable", FPEM | FUnusable},
	{8, xdb.TypeCert, "p7b", "fmt.pkcs7", "fmt.help.cert_p7_single", FPKCS7 | FUsual | FSingle},
	{10, xdb.TypeCert, "p7b", "fmt.pkcs7", "fmt.help.cert_p7_selected", FPKCS7 | FUsual | FMulti},
	{12, xdb.TypeCert, "p7b", "fmt.pkcs7_chain", "fmt.help.cert_p7_chain", FPKCS7 | FUsual | FChain | FSingle},
	{41, xdb.TypeCert, "p7b", "fmt.pkcs7_unusable", "fmt.help.cert_p7_unusable", FPKCS7 | FUnusable},
	{13, xdb.TypeCert, "cer", "fmt.der", "fmt.help.cert_der", FDER | FSingle},
	{14, xdb.TypeCert, "pfx", "fmt.pkcs12_chain", "fmt.help.cert_p12_chain", FPKCS12 | FUsual | FChain | FCrypt | FPrivate | FSingle},
	{15, xdb.TypeCert, "pfx", "fmt.pkcs12", "fmt.help.cert_p12", FPKCS12 | FUsual | FCrypt | FPrivate | FSingle},
	{16, xdb.TypeCert, "txt", "fmt.index", "fmt.help.cert_index", FIndex | FCA},
	{17, xdb.TypeCert, "ics", "fmt.vcal", "fmt.help.cert_vcal", FCal},
	{18, xdb.TypeCert, "ics", "fmt.ca_vcal", "fmt.help.cert_ca_vcal", FCal | FCA},
	{38, xdb.TypeCert, "conf", "fmt.conf", "fmt.help.conf", FSingle | FConfig},
	{42, xdb.TypeCert, "jwk", "fmt.jwk", "fmt.help.cert_jwk", FJWK},
	{43, xdb.TypeCert, "jwk", "fmt.jwk_chain", "fmt.help.cert_jwk_chain", FJWK | FX5C},

	{19, xdb.TypeKey, "pem", "fmt.pem_public", "fmt.help.key_pem_public", FPEM | FClipboard},
	{20, xdb.TypeKey, "pem", "fmt.pem_private", "fmt.help.key_pem_private", FPEM | FPrivate | FUsual | FClipboard},
	{21, xdb.TypeKey, "pem", "fmt.pem_encrypted", "fmt.help.key_pem_encrypted", FPEM | FPrivate | FCrypt | FSingle | FTradition},
	{22, xdb.TypeKey, "priv", "fmt.ssh2_private", "fmt.help.key_ssh2_private", FPrivate | FSSH2 | FSingle},
	{23, xdb.TypeKey, "pub", "fmt.ssh2_public", "fmt.help.key_ssh2_public", FSSH2},
	{100, xdb.TypeKey, "priv", "fmt.openssh_private", "fmt.help.key_openssh_private", FSSH2 | FOpenSSH | FPrivate | FSingle | FClipboard},
	{101, xdb.TypeKey, "priv", "fmt.openssh_encrypted", "fmt.help.key_openssh_encrypted", FSSH2 | FOpenSSH | FPrivate | FCrypt | FSingle},
	{102, xdb.TypeKey, "ppk", "fmt.ppk", "fmt.help.key_ppk", FSSH2 | FPuTTY | FPrivate | FSingle | FClipboard},
	{103, xdb.TypeKey, "ppk", "fmt.ppk_encrypted", "fmt.help.key_ppk_encrypted", FSSH2 | FPuTTY | FPrivate | FCrypt | FSingle},
	{104, xdb.TypeKey, "ppk", "fmt.ppk2", "fmt.help.key_ppk2", FSSH2 | FPuTTY | FPPK2 | FPrivate | FSingle},
	{105, xdb.TypeKey, "ppk", "fmt.ppk2_encrypted", "fmt.help.key_ppk2_encrypted", FSSH2 | FPuTTY | FPPK2 | FPrivate | FCrypt | FSingle},
	{106, xdb.TypeKey, "pub", "fmt.rfc4716_public", "fmt.help.key_rfc4716_public", FSSH2 | FPuTTY | FClipboard},
	{24, xdb.TypeKey, "der", "fmt.der_public", "fmt.help.key_der_public", FDER | FSingle},
	{25, xdb.TypeKey, "der", "fmt.der_private", "fmt.help.key_der_private", FDER | FPrivate | FSingle},
	{26, xdb.TypeKey, "pvk", "fmt.pvk_private", "fmt.help.key_pvk", FPVK | FPrivate | FSingle},
	{28, xdb.TypeKey, "pk8", "fmt.pkcs8_encrypted", "fmt.help.key_pkcs8_encrypted", FPKCS8 | FPrivate | FCrypt | FUsual | FSingle},
	{29, xdb.TypeKey, "pk8", "fmt.pkcs8", "fmt.help.key_pkcs8", FPKCS8 | FPrivate | FClipboard | FSingle},
	{50, xdb.TypeKey, "jwk", "fmt.jwk_private", "fmt.help.key_jwk_private", FJWK | FPrivate},
	{51, xdb.TypeKey, "jwk", "fmt.jwk_public", "fmt.help.key_jwk_public", FJWK},

	{30, xdb.TypeRequest, "csr", "fmt.pem", "fmt.help.req_pem", FPEM},
	{31, xdb.TypeRequest, "der", "fmt.der", "fmt.help.req_der", FDER | FSingle},
	{37, xdb.TypeRequest, "conf", "fmt.conf", "fmt.help.conf", FSingle | FConfig},

	{32, xdb.TypeCRL, "crl", "fmt.pem", "fmt.help.crl_pem", FPEM},
	{33, xdb.TypeCRL, "der", "fmt.der", "fmt.help.crl_der", FDER | FSingle},
	{34, xdb.TypeCRL, "ics", "fmt.vcal", "fmt.help.crl_vcal", FCal},

	{35, xdb.TypeTemplate, "xca", "fmt.pem", "fmt.help.tmpl_single", FPEM | FSingle},
	{36, xdb.TypeTemplate, "pem", "fmt.pem", "fmt.help.tmpl_multi", FPEM | FMulti},
}

// FormatByID returns the format with an XCA export ID.
func FormatByID(id int) (Format, bool) {
	for _, f := range Formats {
		if f.ID == id {
			return f, true
		}
	}
	return Format{}, false
}

// Select lists the formats for an item type whose flags do not intersect
// disabled, in XCA's order with the usual ones first.
func Select(typ int, disabled Flags) []Format {
	var usual, rest []Format
	for _, f := range Formats {
		if f.Type != typ || f.Flags&disabled != 0 {
			continue
		}
		if f.Flags&FUsual != 0 {
			usual = append(usual, f)
		} else {
			rest = append(rest, f)
		}
	}
	return append(usual, rest...)
}

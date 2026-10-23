package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Fingerprints of a DER object.
type Fingerprints struct{ MD5, SHA1, SHA256 string }

func fingerprints(der []byte) Fingerprints {
	m, s1, s2 := md5.Sum(der), sha1.Sum(der), sha256.Sum256(der)
	return Fingerprints{hexDump(m[:]), hexDump(s1[:]), hexDump(s2[:])}
}

// PublicKeyInfo describes a SubjectPublicKeyInfo.
type PublicKeyInfo struct {
	Algorithm string // RSA, EC, DSA, Ed25519, or the OID
	Bits      int
	Curve     string
	Exponent  int
	SHA256    string // fingerprint of the SPKI DER
}

var curveOIDs = map[string]string{
	"1.2.840.10045.3.1.7":   "prime256v1 (P-256)",
	"1.3.132.0.34":          "secp384r1 (P-384)",
	"1.3.132.0.35":          "secp521r1 (P-521)",
	"1.3.132.0.10":          "secp256k1",
	"1.3.36.3.3.2.8.1.1.7":  "brainpoolP256r1",
	"1.3.36.3.3.2.8.1.1.11": "brainpoolP384r1",
	"1.3.36.3.3.2.8.1.1.13": "brainpoolP512r1",
}

// DescribePublicKey decodes a DER SubjectPublicKeyInfo. Keys Go cannot parse
// (non-NIST curves, DSA) are described from their ASN.1 structure.
func DescribePublicKey(der []byte) PublicKeyInfo {
	sum := sha256.Sum256(der)
	info := PublicKeyInfo{SHA256: hexDump(sum[:])}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		switch k := pub.(type) {
		case *rsa.PublicKey:
			info.Algorithm, info.Bits, info.Exponent = "RSA", k.N.BitLen(), k.E
			return info
		case *ecdsa.PublicKey:
			info.Algorithm, info.Bits = "EC", k.Curve.Params().BitSize
		case ed25519.PublicKey:
			info.Algorithm, info.Bits = "Ed25519", 256
			return info
		}
	}
	var s spki
	if _, err := asn1.Unmarshal(der, &s); err != nil {
		info.Algorithm = "unknown"
		return info
	}
	switch s.Algo.Algorithm.String() {
	case "1.2.840.10045.2.1":
		info.Algorithm = "EC"
		var curve asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(s.Algo.Parameters.FullBytes, &curve); err == nil {
			info.Curve = curveOIDs[curve.String()]
			if info.Curve == "" {
				info.Curve = curve.String()
			}
		}
		if info.Bits == 0 {
			info.Bits = (s.PublicKey.BitLength/8 - 1) / 2 * 8
		}
	case "1.2.840.10040.4.1":
		info.Algorithm = "DSA"
		var p dsaParams
		if _, err := asn1.Unmarshal(s.Algo.Parameters.FullBytes, &p); err == nil {
			info.Bits = p.P.BitLen()
		}
	case "1.3.101.112":
		info.Algorithm, info.Bits = "Ed25519", 256
	case "1.3.101.113":
		info.Algorithm, info.Bits = "Ed448", 456
	default:
		info.Algorithm = s.Algo.Algorithm.String()
	}
	return info
}

// CertInfo describes a certificate for display.
type CertInfo struct {
	Version      int
	Serial       string // upper case hex, as XCA stores it
	Subject      []NameEntry
	SubjectText  string
	IssuerText   string
	CommonName   string
	NotBefore    time.Time
	NotAfter     time.Time
	NoExpiry     bool // notAfter 99991231235959Z
	SigAlg       string
	PublicKey    PublicKeyInfo
	Extensions   []Extension
	Fingerprints Fingerprints
	IsCA         bool
	ParseError   string // set when Go's parser rejected it; fields come from the fallback
}

// tbsFallback is a lenient TBSCertificate used when crypto/x509 refuses a
// certificate OpenSSL accepted (negative serials, odd encodings).
type tbsFallback struct {
	Raw        asn1.RawContent
	Version    int `asn1:"optional,explicit,default:0,tag:0"`
	Serial     asn1.RawValue
	SigAlg     pkix.AlgorithmIdentifier
	Issuer     asn1.RawValue
	Validity   struct{ NotBefore, NotAfter time.Time }
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	UniqueID   asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUID asn1.BitString   `asn1:"optional,tag:2"`
	Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

var noExpiry = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// SerialHex formats a serial number the way XCA stores it (OpenSSL's
// BN_bn2hex): upper case, whole bytes, "-" for negative values, "0" for zero.
func SerialHex(n *big.Int) string {
	if n == nil {
		return ""
	}
	if n.Sign() == 0 {
		return "0"
	}
	h := strings.ToUpper(hex.EncodeToString(new(big.Int).Abs(n).Bytes()))
	if n.Sign() < 0 {
		return "-" + h
	}
	return h
}

// DescribeCert decodes a DER certificate.
func DescribeCert(der []byte) *CertInfo {
	info := &CertInfo{Fingerprints: fingerprints(der)}
	c, err := x509.ParseCertificate(der)
	if err == nil {
		info.Version = c.Version
		info.Serial = SerialHex(c.SerialNumber)
		info.Subject, _ = ParseName(c.RawSubject)
		info.SubjectText = FormatName(c.RawSubject)
		info.IssuerText = FormatName(c.RawIssuer)
		info.CommonName = CommonName(c.RawSubject)
		info.NotBefore, info.NotAfter = c.NotBefore, c.NotAfter
		info.SigAlg = c.SignatureAlgorithm.String()
		info.PublicKey = DescribePublicKey(c.RawSubjectPublicKeyInfo)
		info.Extensions = DecodeExtensions(c.Extensions)
		info.IsCA = c.BasicConstraintsValid && c.IsCA
	} else {
		info.ParseError = err.Error()
		var cert struct {
			TBS    tbsFallback
			SigAlg pkix.AlgorithmIdentifier
			Sig    asn1.BitString
		}
		if _, err := asn1.Unmarshal(der, &cert); err != nil {
			info.ParseError += "; " + err.Error()
			return info
		}
		t := cert.TBS
		info.Version = t.Version + 1
		var serial *big.Int
		if _, err := asn1.Unmarshal(t.Serial.FullBytes, &serial); err == nil {
			info.Serial = SerialHex(serial)
		}
		info.Subject, _ = ParseName(t.Subject.FullBytes)
		info.SubjectText = FormatName(t.Subject.FullBytes)
		info.IssuerText = FormatName(t.Issuer.FullBytes)
		info.CommonName = CommonName(t.Subject.FullBytes)
		info.NotBefore, info.NotAfter = t.Validity.NotBefore, t.Validity.NotAfter
		info.SigAlg = cert.SigAlg.Algorithm.String()
		info.PublicKey = DescribePublicKey(t.PublicKey.FullBytes)
		info.Extensions = DecodeExtensions(t.Extensions)
		for _, e := range info.Extensions {
			if e.OID == "2.5.29.19" && len(e.Lines) > 0 && e.Lines[0] == "CA:TRUE" {
				info.IsCA = true
			}
		}
	}
	info.NoExpiry = info.NotAfter.Equal(noExpiry)
	return info
}

// RequestInfo describes a PKCS#10 request.
type RequestInfo struct {
	Subject      []NameEntry
	SubjectText  string
	CommonName   string
	SigAlg       string
	SignatureOK  bool
	PublicKey    PublicKeyInfo
	Extensions   []Extension
	Fingerprints Fingerprints
	ParseError   string
}

// SubjectAttrs returns the subject as editable attributes.
func (r *RequestInfo) SubjectAttrs() []DNAttr {
	out := make([]DNAttr, len(r.Subject))
	for i, e := range r.Subject {
		out[i] = DNAttr{Name: e.Short, Value: e.Value}
	}
	return out
}

// DescribeRequest decodes a DER certificate request.
func DescribeRequest(der []byte) *RequestInfo {
	info := &RequestInfo{Fingerprints: fingerprints(der)}
	r, err := x509.ParseCertificateRequest(der)
	if err != nil {
		info.ParseError = err.Error()
		return info
	}
	info.Subject, _ = ParseName(r.RawSubject)
	info.SubjectText = FormatName(r.RawSubject)
	info.CommonName = CommonName(r.RawSubject)
	info.SigAlg = r.SignatureAlgorithm.String()
	info.SignatureOK = r.CheckSignature() == nil
	info.PublicKey = DescribePublicKey(r.RawSubjectPublicKeyInfo)
	info.Extensions = DecodeExtensions(r.Extensions)
	return info
}

// RevokedEntry is one entry of a CRL.
type RevokedEntry struct {
	Serial string
	Date   time.Time
	Reason string
}

// CRLInfo describes a revocation list.
type CRLInfo struct {
	IssuerText   string
	Number       string
	ThisUpdate   time.Time
	NextUpdate   time.Time
	SigAlg       string
	Entries      []RevokedEntry
	Extensions   []Extension
	Fingerprints Fingerprints
	ParseError   string
}

// DescribeCRL decodes a DER CRL.
func DescribeCRL(der []byte) *CRLInfo {
	info := &CRLInfo{Fingerprints: fingerprints(der)}
	l, err := x509.ParseRevocationList(der)
	if err != nil {
		info.ParseError = err.Error()
		return info
	}
	info.IssuerText = FormatName(l.RawIssuer)
	if l.Number != nil {
		info.Number = l.Number.String()
	}
	info.ThisUpdate, info.NextUpdate = l.ThisUpdate, l.NextUpdate
	info.SigAlg = l.SignatureAlgorithm.String()
	info.Extensions = DecodeExtensions(l.Extensions)
	for _, e := range l.RevokedCertificateEntries {
		re := RevokedEntry{Serial: SerialHex(e.SerialNumber), Date: e.RevocationTime}
		if e.ReasonCode > 0 && e.ReasonCode < len(ReasonNames) {
			re.Reason = ReasonNames[e.ReasonCode]
		}
		info.Entries = append(info.Entries, re)
	}
	return info
}

// FormatBits renders a key size for lists, e.g. "2048 bit".
func FormatBits(n int) string { return fmt.Sprintf("%d bit", n) }

package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// RandomSerial returns a serial number like XCA's randomSerial: serialLen
// bits taken from SHA-512 over random bytes, retried until the first byte is
// between 0x01 and 0x7f (positive, full length).
func RandomSerial(serialLen int) (*big.Int, error) {
	if serialLen < 8 || serialLen > 512 || serialLen%8 != 0 {
		serialLen = 64
	}
	for {
		buf := make([]byte, sha512.Size)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		md := sha512.Sum512(buf)
		if md[0] != 0 && md[0] < 0x80 {
			return new(big.Int).SetBytes(md[:serialLen/8]), nil
		}
	}
}

// NoExpiry is notAfter for "no well-defined expiration" (RFC 5280 4.1.2.5).
var NoExpiry = noExpiry

// CertRequest holds everything needed to issue a certificate.
type CertRequest struct {
	Subject    []byte // DER name
	PublicKey  crypto.PublicKey
	SPKI       []byte // DER SubjectPublicKeyInfo, used instead of PublicKey when set
	Serial     *big.Int
	NotBefore  time.Time
	NotAfter   time.Time
	Extensions []pkix.Extension // complete and in order
	Hash       string
	Issuer     *x509.Certificate // nil = self-signed
	SignerKey  crypto.Signer
}

// HashName names the hash choice of a signature algorithm, for "Similar".
func HashName(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		return "sha384"
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		return "sha512"
	case x509.SHA256WithRSAPSS:
		return "sha256-pss"
	case x509.SHA384WithRSAPSS:
		return "sha384-pss"
	case x509.SHA512WithRSAPSS:
		return "sha512-pss"
	}
	return "sha256"
}

// SpecFromExtensions reads editor choices back from existing extensions
// (for "Similar certificate" and "Similar request"). Extensions it cannot
// express are returned separately; SpecWithAdvanced puts them into AdvExt.
func SpecFromExtensions(exts []pkix.Extension) (ExtSpec, []pkix.Extension) {
	var s ExtSpec
	var rest []pkix.Extension
	for _, e := range exts {
		ok := true
		switch {
		case e.Id.Equal(oidBC):
			var bc struct {
				CA      bool `asn1:"optional"`
				PathLen int  `asn1:"optional,default:-1"`
			}
			if _, err := asn1.Unmarshal(e.Value, &bc); err == nil {
				s.CA, s.BCCritical = 2, e.Critical
				if bc.CA {
					s.CA = 1
					if bc.PathLen >= 0 {
						s.PathLen = fmt.Sprint(bc.PathLen)
					}
				}
			}
		case e.Id.Equal(oidSKI):
			s.SubKey = true
		case e.Id.Equal(oidAKI):
			s.AuthKey = true
		case e.Id.Equal(oidKU):
			var b asn1.BitString
			if _, err := asn1.Unmarshal(e.Value, &b); err == nil {
				for i := range KeyUsageNames {
					if b.At(i) == 1 {
						s.KeyUse |= 1 << i
					}
				}
				s.KUCritical = e.Critical
			}
		case e.Id.Equal(oidNSType):
			var b asn1.BitString
			if _, err := asn1.Unmarshal(e.Value, &b); err == nil {
				for i, bit := range nsCertTypeBits {
					if b.At(bit) == 1 {
						s.NSCertType |= 1 << i
					}
				}
			}
		case e.Id.Equal(oidEKU):
			var oids []asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(e.Value, &oids); err == nil {
				for _, o := range oids {
					name := o.String()
					for n, known := range ekuOIDs {
						if known.Equal(o) {
							name = n
						}
					}
					if name == o.String() {
						for _, x := range oidRegistry {
							if x.OID == name && x.Kind == "eku" && x.Short != "" {
								name = x.Short
							}
						}
					}
					s.EKU = append(s.EKU, name)
				}
				s.EKUCrit = e.Critical
			}
		case e.Id.Equal(oidSAN), e.Id.Equal(oidIAN):
			l, err := generalNames(e.Value)
			joined := strings.Join(l, ", ")
			// names the one-line field cannot express go to adv_ext
			if err != nil || e.Critical || strings.Contains(joined, "dirName:") || strings.Contains(joined, "otherName:") && !strings.Contains(joined, ";") {
				ok = false
				break
			}
			if e.Id.Equal(oidSAN) {
				s.SubAltName = joined
			} else {
				s.IssAltName = joined
			}
		case e.Id.Equal(oidCRLDP):
			l, _ := decodeExt("2.5.29.31", e.Value)
			s.CRLDist = strings.Join(l, ", ")
		case e.Id.Equal(oidAIA):
			l, _ := decodeExt("1.3.6.1.5.5.7.1.1", e.Value)
			for i := range l {
				l[i] = strings.Replace(strings.Replace(l[i], "CA Issuers - ", "caIssuers;", 1), "OCSP - ", "OCSP;", 1)
			}
			s.AuthInfAcc = strings.Join(l, ", ")
		case e.Id.Equal(oidNC):
			l, _ := decodeExt("2.5.29.30", e.Value)
			for i := range l {
				l[i] = strings.Replace(strings.Replace(l[i], "Permitted: ", "permitted;", 1), "Excluded: ", "excluded;", 1)
			}
			s.NameCons = strings.Join(l, ", ")
		case e.Id.Equal(oidTLSFeat):
			s.OCSPStaple = true
		case e.Id.Equal(oidNSComment), e.Id.Equal(oidNSBase), e.Id.Equal(oidNSRev), e.Id.Equal(oidNSCARev),
			e.Id.Equal(oidNSRenew), e.Id.Equal(oidNSPolicy), e.Id.Equal(oidNSSSLName):
			var v asn1.RawValue
			if _, err := asn1.Unmarshal(e.Value, &v); err == nil {
				str := string(v.Bytes)
				switch {
				case e.Id.Equal(oidNSComment):
					s.NSComment = str
				case e.Id.Equal(oidNSBase):
					s.NSBaseURL = str
				case e.Id.Equal(oidNSRev):
					s.NSRevocationURL = str
				case e.Id.Equal(oidNSCARev):
					s.NSCARevocationURL = str
				case e.Id.Equal(oidNSRenew):
					s.NSRenewalURL = str
				case e.Id.Equal(oidNSPolicy):
					s.NSCAPolicyURL = str
				case e.Id.Equal(oidNSSSLName):
					s.NSSSLServerName = str
				}
			}
		default:
			ok = false
		}
		if !ok {
			rest = append(rest, e)
		}
	}
	return s, rest
}

// SpecWithAdvanced is SpecFromExtensions with the remaining extensions
// written to AdvExt, as XCA does when it turns a certificate into a
// template.
func SpecWithAdvanced(exts []pkix.Extension) ExtSpec {
	s, rest := SpecFromExtensions(exts)
	s.AdvExt = GenConf(rest)
	return s
}

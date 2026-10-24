package pki

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys exist in old databases; display only
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// Hashes offered for signatures; "sha256" is XCA's default_hash. The
// "-pss" variants sign with RSASSA-PSS instead of PKCS#1 v1.5 when the
// key is an RSA key, and like the plain hash otherwise.
var Hashes = []string{"sha256", "sha384", "sha512", "sha256-pss", "sha384-pss", "sha512-pss"}

// HashAuto is the hash choice that follows the signing key's strength:
// see AutoHash. It is OpenKCA's default.
const HashAuto = "auto"

// HashChoices are the choices offered in forms and options: HashAuto,
// then Hashes.
var HashChoices = append([]string{HashAuto}, Hashes...)

// AutoHash is the digest HashAuto picks for a key of the given algorithm
// (as DescribePublicKey names it) and size, after NIST SP 800-57: SHA-256
// up to 128 bit security (RSA below 7680 bit, curves up to 256 bit),
// SHA-384 up to 192 bit (RSA below 15360, curves up to 384 bit), SHA-512
// above. Algorithms that sign without a separate hash give 0.
func AutoHash(algorithm string, bits int) crypto.Hash {
	switch algorithm {
	case "RSA", "RSA-PSS", "DSA":
		switch {
		case bits >= 15360:
			return crypto.SHA512
		case bits >= 7680:
			return crypto.SHA384
		}
		return crypto.SHA256
	case "EC":
		switch {
		case bits > 384:
			return crypto.SHA512
		case bits > 256:
			return crypto.SHA384
		}
		return crypto.SHA256
	}
	return 0
}

// AutoHashName names the choice of Hashes HashAuto makes for a public
// key (DER SubjectPublicKeyInfo): "sha256", "sha384", "sha512", or "" when
// the algorithm signs without a separate hash (EdDSA, ML-DSA, ...).
func AutoHashName(spki []byte) string {
	info := DescribePublicKey(spki)
	return hashChoiceName(AutoHash(info.Algorithm, info.Bits))
}

// AutoHashNameForSpec is AutoHashName for a key yet to be generated.
func AutoHashNameForSpec(spec KeySpec) string {
	switch spec.Type {
	case "RSA", "RSA-PSS":
		return hashChoiceName(AutoHash(spec.Type, spec.Bits))
	case "EC":
		if c := curveByName(spec.Curve); c != nil {
			return hashChoiceName(AutoHash("EC", c.Curve().Params().BitSize))
		}
	}
	return ""
}

func hashChoiceName(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	}
	return ""
}

func autoHashOf(pub crypto.PublicKey) crypto.Hash {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return AutoHash("RSA", k.N.BitLen())
	case *RSAPSSPublicKey:
		return AutoHash("RSA", k.N.BitLen())
	case *ecdsa.PublicKey:
		return AutoHash("EC", k.Curve.Params().BitSize)
	}
	return crypto.SHA256
}

var (
	oidSigRSASHA1    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSigRSASHA256  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSigRSASHA384  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSigRSASHA512  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSigECDSASHA1  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidSigECDSA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSigECDSA384   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSigECDSA512   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSigDSASHA1    = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSigDSASHA256  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSigRSAPKCS1   = map[crypto.Hash]asn1.ObjectIdentifier{crypto.SHA256: oidSigRSASHA256, crypto.SHA384: oidSigRSASHA384, crypto.SHA512: oidSigRSASHA512}
	oidSigECDSA      = map[crypto.Hash]asn1.ObjectIdentifier{crypto.SHA256: oidSigECDSA256, crypto.SHA384: oidSigECDSA384, crypto.SHA512: oidSigECDSA512}
	hashOfSigRSA     = map[string]crypto.Hash{oidSigRSASHA1.String(): crypto.SHA1, oidSigRSASHA256.String(): crypto.SHA256, oidSigRSASHA384.String(): crypto.SHA384, oidSigRSASHA512.String(): crypto.SHA512}
	hashOfSigECDSA   = map[string]crypto.Hash{oidSigECDSASHA1.String(): crypto.SHA1, oidSigECDSA256.String(): crypto.SHA256, oidSigECDSA384.String(): crypto.SHA384, oidSigECDSA512.String(): crypto.SHA512}
	hashOfSigDSA     = map[string]crypto.Hash{oidSigDSASHA1.String(): crypto.SHA1, oidSigDSASHA256.String(): crypto.SHA256}
	errUnsupportedSA = errors.New("unsupported signature algorithm")
)

// sigScheme is how a key signs a certificate, request or CRL.
type sigScheme struct {
	id   pkix.AlgorithmIdentifier
	hash crypto.Hash // digest handed to the signer; 0 signs the message itself
	pss  *PSSParams
}

// parseHash reads a hash choice ("sha256", "SHA-384", "sha512-pss", ""
// for sha256).
func parseHash(name string) (crypto.Hash, bool, error) {
	name = strings.ToLower(strings.ReplaceAll(name, "-", ""))
	name, pss := strings.CutSuffix(name, "pss")
	switch name {
	case "sha256", "":
		return crypto.SHA256, pss, nil
	case "sha384":
		return crypto.SHA384, pss, nil
	case "sha512":
		return crypto.SHA512, pss, nil
	}
	return 0, false, fmt.Errorf("unsupported hash %q", name)
}

func pssScheme(p PSSParams) (sigScheme, error) {
	b, err := marshalPSSParams(p)
	if err != nil {
		return sigScheme{}, err
	}
	return sigScheme{pkix.AlgorithmIdentifier{Algorithm: oidRSAPSS, Parameters: asn1.RawValue{FullBytes: b}}, p.Hash, &p}, nil
}

// signatureScheme picks the algorithm for a signer key and hash choice.
// Ed25519, Ed448, ML-DSA, SLH-DSA and composite keys ignore the hash; an
// RSASSA-PSS key always signs with PSS, with its own parameters if it has
// them.
func signatureScheme(key crypto.Signer, hash string) (sigScheme, error) {
	var h crypto.Hash
	var pss bool
	if strings.EqualFold(hash, HashAuto) {
		h = autoHashOf(key.Public())
	} else {
		var err error
		if h, pss, err = parseHash(hash); err != nil {
			return sigScheme{}, err
		}
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if pss {
			return pssScheme(PSSParams{h, h.Size()})
		}
		return sigScheme{id: pkix.AlgorithmIdentifier{Algorithm: oidSigRSAPKCS1[h], Parameters: asn1.NullRawValue}, hash: h}, nil
	case RSAPSSKey:
		if k.Params != nil {
			return pssScheme(*k.Params)
		}
		return pssScheme(PSSParams{h, h.Size()})
	case *ecdsa.PrivateKey:
		if CurveOf(k.Curve) == nil {
			return sigScheme{}, errors.New("unsupported elliptic curve")
		}
		return sigScheme{id: pkix.AlgorithmIdentifier{Algorithm: oidSigECDSA[h]}, hash: h}, nil
	case ed25519.PrivateKey:
		return sigScheme{id: pkix.AlgorithmIdentifier{Algorithm: oidEd25519}}, nil
	case ed448.PrivateKey:
		return sigScheme{id: pkix.AlgorithmIdentifier{Algorithm: oidEd448}}, nil
	case *mldsa.PrivateKey:
		return sigScheme{id: pkix.AlgorithmIdentifier{Algorithm: mldsaOf(k.PublicKey().Parameters()).OID}}, nil
	case slhdsa.PrivateKey:
		return sigScheme{id: pkix.AlgorithmIdentifier{Algorithm: slhdsaByID(k.ID).OID}}, nil
	case CompositeKey:
		return sigScheme{id: pkix.AlgorithmIdentifier{Algorithm: k.Alg.OID}}, nil
	case DSAKey:
		return sigScheme{}, errors.New("DSA keys cannot sign in OpenKCA")
	}
	if !CanSign(key) {
		return sigScheme{}, fmt.Errorf("%s keys cannot sign", KeyAlgorithm(key))
	}
	return sigScheme{}, fmt.Errorf("unsupported signing key %T", key)
}

// sign signs msg (a DER TBS structure) with the scheme.
func (s sigScheme) sign(key crypto.Signer, msg []byte) ([]byte, error) {
	if s.hash == 0 {
		return key.Sign(rand.Reader, msg, crypto.Hash(0))
	}
	digest := hashed(s.hash, msg)
	if s.pss != nil {
		return key.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: s.pss.SaltLength, Hash: s.hash})
	}
	return key.Sign(rand.Reader, digest, s.hash)
}

// VerifySignature checks a signature made with the algorithm algo over
// msg by pub, for every algorithm OpenKCA reads: RSA (PKCS#1 v1.5 and PSS
// with any parameters), DSA, ECDSA on every curve OpenKCA knows, Ed25519,
// Ed448, ML-DSA, SLH-DSA and Composite ML-DSA.
func VerifySignature(pub crypto.PublicKey, algo pkix.AlgorithmIdentifier, msg, sig []byte) error {
	oid := algo.Algorithm
	switch {
	case hashOfSigRSA[oid.String()] != 0:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("the signature needs an RSA key")
		}
		h := hashOfSigRSA[oid.String()]
		return rsa.VerifyPKCS1v15(k, h, hashed(h, msg), sig)
	case oid.Equal(oidRSAPSS):
		k := rsaPublic(pub)
		if k == nil {
			return errors.New("the signature needs an RSA key")
		}
		p, err := parsePSSParams(algo.Parameters.FullBytes)
		if err != nil {
			return err
		}
		if pk, ok := pub.(*RSAPSSPublicKey); ok && pk.Params != nil && (pk.Params.Hash != p.Hash || p.SaltLength < pk.Params.SaltLength) {
			return errors.New("rsa-pss: the signature does not meet the key's restriction")
		}
		return rsa.VerifyPSS(k, p.Hash, hashed(p.Hash, msg), sig, &rsa.PSSOptions{SaltLength: p.SaltLength})
	case hashOfSigECDSA[oid.String()] != 0:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("the signature needs an EC key")
		}
		if !ecdsa.VerifyASN1(k, hashed(hashOfSigECDSA[oid.String()], msg), sig) {
			return errors.New("ecdsa: verification error")
		}
		return nil
	case hashOfSigDSA[oid.String()] != 0:
		k, ok := pub.(*dsa.PublicKey)
		if !ok {
			return errors.New("the signature needs a DSA key")
		}
		var rs struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(sig, &rs); err != nil {
			return err
		}
		d := hashed(hashOfSigDSA[oid.String()], msg)
		if n := (k.Q.BitLen() + 7) / 8; len(d) > n {
			d = d[:n]
		}
		if !dsa.Verify(k, d, rs.R, rs.S) { //nolint:staticcheck // verifying signatures of old DSA CAs
			return errors.New("dsa: verification error")
		}
		return nil
	case oid.Equal(oidEd25519):
		k, ok := pub.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(k, msg, sig) {
			return errors.New("ed25519: verification error")
		}
		return nil
	case oid.Equal(oidEd448):
		k, ok := pub.(ed448.PublicKey)
		if !ok || !ed448.Verify(k, msg, sig, "") {
			return errors.New("ed448: verification error")
		}
		return nil
	}
	if p := mldsaByOID(oid); p != nil {
		k, ok := pub.(*mldsa.PublicKey)
		if !ok || k.Parameters() != p.Params() {
			return errors.New("the signature needs an " + p.Name + " key")
		}
		return mldsa.Verify(k, msg, sig, nil)
	}
	if p := slhdsaByOID(oid); p != nil {
		k, ok := pub.(slhdsa.PublicKey)
		if !ok || k.ID != p.ID {
			return errors.New("the signature needs an " + p.Name + " key")
		}
		if !slhdsa.Verify(&k, slhdsa.NewMessage(msg), sig, nil) {
			return errors.New("slh-dsa: verification error")
		}
		return nil
	}
	if a := compositeByOID(oid); a != nil {
		k, ok := pub.(*CompositePublicKey)
		if !ok || k.Alg != a {
			return errors.New("the signature needs an " + a.Name + " key")
		}
		return verifyComposite(k, msg, sig)
	}
	return errUnsupportedSA
}

// signedData is a signed X.509 structure: certificate, request or CRL.
type signedData struct {
	TBS       asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

// CheckSignatureOf verifies the signature of a DER certificate, request
// or CRL with the public key in spki.
func CheckSignatureOf(der, spki []byte) error {
	var sd signedData
	if rest, err := asn1.Unmarshal(der, &sd); err != nil {
		return err
	} else if len(rest) > 0 {
		return errors.New("trailing data")
	}
	pub, err := ParsePublicKey(spki)
	if err != nil {
		return err
	}
	return VerifySignature(pub, sd.Algorithm, sd.TBS.FullBytes, sd.Signature.RightAlign())
}

// CheckCertSignature reports whether parent signed child, also for
// algorithms crypto/x509 does not verify. Unlike
// x509.Certificate.CheckSignatureFrom it checks only the signature.
func CheckCertSignature(parent, child *x509.Certificate) error {
	return CheckSignatureOf(child.Raw, parent.RawSubjectPublicKeyInfo)
}

// CheckCRLSignature reports whether the CA signed the CRL.
func CheckCRLSignature(ca *x509.Certificate, crl *x509.RevocationList) error {
	return CheckSignatureOf(crl.Raw, ca.RawSubjectPublicKeyInfo)
}

// CheckRequestSignature verifies the self-signature of a request.
func CheckRequestSignature(r *x509.CertificateRequest) error {
	return CheckSignatureOf(r.Raw, r.RawSubjectPublicKeyInfo)
}

// SignatureAlgorithmName names the signature algorithm of a DER
// certificate, request or CRL, also those crypto/x509 does not know.
func SignatureAlgorithmName(der []byte) string {
	var sd signedData
	if _, err := asn1.Unmarshal(der, &sd); err != nil {
		return ""
	}
	return sigAlgName(sd.Algorithm)
}

// HashChoice reads the hash choice of Hashes back from a DER certificate,
// request or CRL (for "Similar", renewal and "to request"), also for PSS
// parameters crypto/x509 does not name. Algorithms without a hash choice
// give "sha256".
func HashChoice(der []byte) string {
	var sd signedData
	if _, err := asn1.Unmarshal(der, &sd); err != nil {
		return "sha256"
	}
	oid := sd.Algorithm.Algorithm
	h := hashOfSigRSA[oid.String()]
	if h == 0 {
		h = hashOfSigECDSA[oid.String()]
	}
	suffix := ""
	if oid.Equal(oidRSAPSS) {
		if p, err := parsePSSParams(sd.Algorithm.Parameters.FullBytes); err == nil {
			h, suffix = p.Hash, "-pss"
		}
	}
	switch h {
	case crypto.SHA384:
		return "sha384" + suffix
	case crypto.SHA512:
		return "sha512" + suffix
	}
	return "sha256" + suffix
}

func sigAlgName(ai pkix.AlgorithmIdentifier) string {
	oid := ai.Algorithm
	switch {
	case oid.Equal(oidRSAPSS):
		if p, err := parsePSSParams(ai.Parameters.FullBytes); err == nil {
			return fmt.Sprintf("RSASSA-PSS (%s)", pssText(p))
		}
		return "RSASSA-PSS"
	case oid.Equal(oidEd448):
		return "Ed448"
	}
	if p := mldsaByOID(oid); p != nil {
		return p.Name
	}
	if p := slhdsaByOID(oid); p != nil {
		return p.Name
	}
	if a := compositeByOID(oid); a != nil {
		return a.Name
	}
	for _, x := range oidRegistry {
		if x.OID == oid.String() && x.Kind == "signature" {
			return x.Long
		}
	}
	return oid.String()
}

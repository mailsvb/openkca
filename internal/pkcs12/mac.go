package pkcs12

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"

	"github.com/mailsvb/openkca/internal/pki"
)

var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidPBMAC1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
)

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

// pbmac1Params are RFC 8018's PBMAC1-params.
type pbmac1Params struct {
	KDF pkix.AlgorithmIdentifier
	MAC pkix.AlgorithmIdentifier
}

// errMAC is a MAC that does not match: the wrong password.
var errMAC = errors.New("pkcs12: MAC mismatch")

func macHash(alg asn1.ObjectIdentifier) func() hash.Hash {
	switch {
	case alg.Equal(oidSHA1):
		return sha1.New
	case alg.Equal(oidSHA224):
		return sha256.New224
	case alg.Equal(oidSHA256):
		return sha256.New
	case alg.Equal(oidSHA384):
		return sha512.New384
	case alg.Equal(oidSHA512):
		return sha512.New
	}
	return nil
}

// mac computes the MAC of msg as md describes it: the PKCS#12 HMAC with a
// key from the PKCS#12 derivation, or PBMAC1 (RFC 9579).
func (md *macData) mac(msg []byte, pw password) ([]byte, error) {
	alg := md.Mac.Algorithm
	if alg.Algorithm.Equal(oidPBMAC1) {
		var p pbmac1Params
		if rest, err := asn1.Unmarshal(alg.Parameters.FullBytes, &p); err != nil || len(rest) > 0 {
			return nil, fmt.Errorf("pkcs12: PBMAC1 parameters: %v", err)
		}
		if !p.KDF.Algorithm.Equal(oidPBKDF2) {
			return nil, fmt.Errorf("pkcs12: unsupported PBMAC1 key derivation %v", p.KDF.Algorithm)
		}
		kdf, err := pki.ParsePBKDF2(p.KDF.Parameters.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("pkcs12: PBMAC1: %w", err)
		}
		h := pki.HMACHash(p.MAC.Algorithm)
		if h == nil {
			return nil, fmt.Errorf("pkcs12: unsupported PBMAC1 MAC %v", p.MAC.Algorithm)
		}
		// RFC 9579 requires the key length; short keys allow forgeries
		// (CVE-2026-34181), and more than any HMAC output is pointless.
		if kdf.KeyLength < 20 || kdf.KeyLength > 64 {
			return nil, fmt.Errorf("pkcs12: PBMAC1 key length %d", kdf.KeyLength)
		}
		key := kdf.Key(pw.utf8, kdf.KeyLength)
		defer clear(key)
		m := hmac.New(h, key)
		m.Write(msg)
		return m.Sum(nil), nil
	}
	h := macHash(alg.Algorithm)
	if h == nil {
		return nil, fmt.Errorf("pkcs12: unsupported MAC %v", alg.Algorithm)
	}
	if md.Iterations < 1 || md.Iterations > maxIterations {
		return nil, errors.New("pkcs12: implausible MAC iteration count")
	}
	key := deriveKey(h, idMAC, pw.bmp, md.MacSalt, md.Iterations, h().Size())
	defer clear(key)
	m := hmac.New(h, key)
	m.Write(msg)
	return m.Sum(nil), nil
}

func (md *macData) verify(msg []byte, pw password) error {
	sum, err := md.mac(msg, pw)
	if err != nil {
		return err
	}
	if !hmac.Equal(sum, md.Mac.Digest) {
		return errMAC
	}
	return nil
}

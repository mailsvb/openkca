package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// ErrWrongPassword is returned when a private key does not decrypt.
var ErrWrongPassword = errors.New("wrong password")

var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3   = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidDESCBC    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	oidScrypt    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
)

// encryptedPrivateKeyInfo is PKCS#8's EncryptedPrivateKeyInfo (RFC 5208).
type encryptedPrivateKeyInfo struct {
	Algo          pkix.AlgorithmIdentifier
	EncryptedData []byte
}

type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

// IsEncryptedPKCS8 reports whether blob parses as an EncryptedPrivateKeyInfo.
// XCA's legacy 3DES blobs do not.
func IsEncryptedPKCS8(blob []byte) bool {
	var epki encryptedPrivateKeyInfo
	rest, err := asn1.Unmarshal(blob, &epki)
	return err == nil && len(rest) == 0 && len(epki.Algo.Algorithm) > 0
}

// PKCS8Iterations returns the PBKDF2 iteration count of an
// EncryptedPrivateKeyInfo; ok is false unless it uses PBES2 with PBKDF2.
func PKCS8Iterations(blob []byte) (n int, ok bool) {
	var epki encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(blob, &epki); err != nil || len(rest) > 0 || !epki.Algo.Algorithm.Equal(oidPBES2) {
		return 0, false
	}
	var p pbes2Params
	if _, err := asn1.Unmarshal(epki.Algo.Parameters.FullBytes, &p); err != nil || !p.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return 0, false
	}
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(p.KeyDerivationFunc.Parameters.FullBytes, &kdf); err != nil {
		return 0, false
	}
	return kdf.IterationCount, true
}

// DecryptPKCS8 decrypts an EncryptedPrivateKeyInfo as written by OpenSSL's
// i2d_PKCS8PrivateKey_bio (PBES2 with PBKDF2) and returns the DER
// PrivateKeyInfo.
func DecryptPKCS8(blob, password []byte) ([]byte, error) {
	var epki encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(blob, &epki); err != nil {
		return nil, fmt.Errorf("pkcs8: %w", err)
	}
	if !epki.Algo.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("pkcs8: unsupported encryption %v", epki.Algo.Algorithm)
	}
	plain, err := PBES2Decrypt(epki.Algo.Parameters.FullBytes, epki.EncryptedData, password)
	if err != nil {
		return nil, err
	}
	// A wrong password usually fails the padding check; make sure the
	// result is DER as well.
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(plain, &raw); err != nil || len(rest) > 0 {
		clear(plain)
		return nil, ErrWrongPassword
	}
	return plain, nil
}

// OIDPBES2 identifies PBES2 (RFC 8018) in an AlgorithmIdentifier.
var OIDPBES2 = oidPBES2

// PBKDF2Params are parsed PBKDF2-params (RFC 8018 A.2).
type PBKDF2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int // 0 when the parameters do not state it
	PRF        func() hash.Hash
}

// Key derives keyLen bytes from password.
func (p *PBKDF2Params) Key(password []byte, keyLen int) []byte {
	return pbkdf2.Key(password, p.Salt, p.Iterations, keyLen, p.PRF)
}

// ParsePBKDF2 reads DER PBKDF2-params with an HMAC-SHA-1 or SHA-2 PRF and a
// plausible iteration count.
func ParsePBKDF2(params []byte) (*PBKDF2Params, error) {
	var kdf pbkdf2Params
	if rest, err := asn1.Unmarshal(params, &kdf); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("PBKDF2 parameters: %v", err)
	}
	prf := sha1.New // the default
	if alg := kdf.PRF.Algorithm; len(alg) > 0 {
		if prf = HMACHash(alg); prf == nil {
			return nil, fmt.Errorf("unsupported PBKDF2 PRF %v", alg)
		}
	}
	if kdf.IterationCount < 1 || kdf.IterationCount > 10_000_000 {
		return nil, errors.New("implausible PBKDF2 iteration count")
	}
	return &PBKDF2Params{Salt: kdf.Salt, Iterations: kdf.IterationCount, KeyLength: kdf.KeyLength, PRF: prf}, nil
}

// HMACHash returns the hash of an hmacWithSHA* AlgorithmIdentifier OID.
func HMACHash(alg asn1.ObjectIdentifier) func() hash.Hash {
	switch {
	case alg.Equal(oidHMACSHA1):
		return sha1.New
	case alg.Equal(oidHMACSHA224):
		return sha256.New224
	case alg.Equal(oidHMACSHA256):
		return sha256.New
	case alg.Equal(oidHMACSHA384):
		return sha512.New384
	case alg.Equal(oidHMACSHA512):
		return sha512.New
	}
	return nil
}

// PBES2Decrypt decrypts data with DER PBES2-params (PBKDF2 or scrypt with
// AES-CBC, 3DES-CBC or DES-CBC) and removes the padding. A padding error is
// ErrWrongPassword.
func PBES2Decrypt(params, data, password []byte) ([]byte, error) {
	var p pbes2Params
	if _, err := asn1.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("pkcs8: PBES2 parameters: %w", err)
	}
	var keyLen int
	var newCipher func([]byte) (cipher.Block, error)
	switch alg := p.EncryptionScheme.Algorithm; {
	case alg.Equal(oidAES128CBC):
		keyLen, newCipher = 16, aes.NewCipher
	case alg.Equal(oidAES192CBC):
		keyLen, newCipher = 24, aes.NewCipher
	case alg.Equal(oidAES256CBC):
		keyLen, newCipher = 32, aes.NewCipher
	case alg.Equal(oidDESEDE3):
		keyLen, newCipher = 24, des.NewTripleDESCipher
	case alg.Equal(oidDESCBC):
		keyLen, newCipher = 8, des.NewCipher
	default:
		return nil, fmt.Errorf("pkcs8: unsupported cipher %s", CipherName(alg))
	}
	var key []byte
	switch kdfParams := p.KeyDerivationFunc.Parameters.FullBytes; {
	case p.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2):
		kdf, err := ParsePBKDF2(kdfParams)
		if err != nil {
			return nil, fmt.Errorf("pkcs8: %w", err)
		}
		key = kdf.Key(password, keyLen)
	case p.KeyDerivationFunc.Algorithm.Equal(oidScrypt):
		var err error
		if key, err = scryptKey(kdfParams, password, keyLen); err != nil {
			return nil, fmt.Errorf("pkcs8: %w", err)
		}
	default:
		return nil, fmt.Errorf("pkcs8: unsupported key derivation %v", p.KeyDerivationFunc.Algorithm)
	}
	defer clear(key)
	var iv []byte
	if _, err := asn1.Unmarshal(p.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("pkcs8: IV: %w", err)
	}
	plain, err := cbcDecrypt(newCipher, key, iv, data)
	if err != nil {
		return nil, ErrWrongPassword
	}
	return plain, nil
}

// scryptParams are RFC 7914's scrypt-params.
type scryptParams struct {
	Salt                     []byte
	CostParameter            int
	BlockSize                int
	ParallelizationParameter int
	KeyLength                int `asn1:"optional"`
}

// scryptMaxMem bounds the memory scrypt parameters from a file may ask for.
// OpenSSL writes N=16384, r=8, p=1 (16 MiB) by default.
const scryptMaxMem = 256 << 20

func scryptKey(params, password []byte, keyLen int) ([]byte, error) {
	var sp scryptParams
	if rest, err := asn1.Unmarshal(params, &sp); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("scrypt parameters: %v", err)
	}
	n, r, p := sp.CostParameter, sp.BlockSize, sp.ParallelizationParameter
	if n < 2 || n&(n-1) != 0 || r < 1 || p < 1 || p > 16 || int64(128)*int64(n)*int64(r) > scryptMaxMem {
		return nil, fmt.Errorf("implausible scrypt parameters N=%d r=%d p=%d", n, r, p)
	}
	if sp.KeyLength != 0 && sp.KeyLength != keyLen {
		return nil, fmt.Errorf("scrypt key length %d for a %d byte key", sp.KeyLength, keyLen)
	}
	return scrypt.Key(password, sp.Salt, n, r, p, keyLen)
}

// CipherName names a cipher OID in an error message.
func CipherName(alg asn1.ObjectIdentifier) string {
	names := map[string]string{
		"1.2.392.200011.61.1.1.1.2": "Camellia-128-CBC", "1.2.392.200011.61.1.1.1.3": "Camellia-192-CBC",
		"1.2.392.200011.61.1.1.1.4": "Camellia-256-CBC", "1.2.410.200046.1.1.2": "ARIA-128-CBC",
		"1.2.410.200046.1.1.7": "ARIA-192-CBC", "1.2.410.200046.1.1.12": "ARIA-256-CBC",
		"1.2.156.10197.1.104.2": "SM4-CBC", "1.2.840.113549.3.2": "RC2-CBC",
		"1.2.840.113549.3.4": "RC4", "1.3.6.1.4.1.3029.1.2": "Blowfish-CBC",
	}
	if n, ok := names[alg.String()]; ok {
		return n
	}
	return alg.String()
}

func cbcDecrypt(newCipher func([]byte) (cipher.Block, error), key, iv, data []byte) ([]byte, error) {
	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(iv) != bs || len(data) == 0 || len(data)%bs != 0 {
		return nil, errors.New("bad ciphertext length")
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	pad := int(out[len(out)-1])
	if pad == 0 || pad > bs {
		return nil, errors.New("bad padding")
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, errors.New("bad padding")
		}
	}
	return out[:len(out)-pad], nil
}

// evpBytesToKey is OpenSSL's EVP_BytesToKey with count iterations, returning
// only the key.
func evpBytesToKey(newHash func() hash.Hash, password, salt []byte, keyLen, count int) []byte {
	var out, prev []byte
	for len(out) < keyLen {
		h := newHash()
		h.Write(prev)
		h.Write(password)
		h.Write(salt)
		d := h.Sum(nil)
		for i := 1; i < count; i++ {
			h = newHash()
			h.Write(d)
			d = h.Sum(nil)
		}
		out = append(out, d...)
		prev = d
	}
	return out[:keyLen]
}

// DecryptLegacy decrypts XCA's pre-PKCS#8 private key blob: an 8 byte IV,
// then 3DES-CBC data keyed with EVP_BytesToKey(SHA-1, salt = IV, 1 round).
// The result is the type-specific DER key (PKCS#1, SEC1 or DSA).
func DecryptLegacy(blob, password []byte) ([]byte, error) {
	if len(blob) < 16 {
		return nil, errors.New("legacy key: too short")
	}
	iv := blob[:8]
	key := evpBytesToKey(sha1.New, password, iv, 24, 1)
	defer clear(key)
	plain, err := cbcDecrypt(des.NewTripleDESCipher, key, iv, blob[8:])
	if err != nil {
		return nil, ErrWrongPassword
	}
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(plain, &raw); err != nil || len(rest) > 0 {
		clear(plain)
		return nil, ErrWrongPassword
	}
	return plain, nil
}

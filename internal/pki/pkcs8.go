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
	var p pbes2Params
	if _, err := asn1.Unmarshal(epki.Algo.Parameters.FullBytes, &p); err != nil {
		return nil, fmt.Errorf("pkcs8: PBES2 parameters: %w", err)
	}
	if !p.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("pkcs8: unsupported key derivation %v", p.KeyDerivationFunc.Algorithm)
	}
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(p.KeyDerivationFunc.Parameters.FullBytes, &kdf); err != nil {
		return nil, fmt.Errorf("pkcs8: PBKDF2 parameters: %w", err)
	}
	prf := sha1.New
	switch alg := kdf.PRF.Algorithm; {
	case len(alg) == 0 || alg.Equal(oidHMACSHA1):
	case alg.Equal(oidHMACSHA224):
		prf = sha256.New224
	case alg.Equal(oidHMACSHA256):
		prf = sha256.New
	case alg.Equal(oidHMACSHA384):
		prf = sha512.New384
	case alg.Equal(oidHMACSHA512):
		prf = sha512.New
	default:
		return nil, fmt.Errorf("pkcs8: unsupported PRF %v", alg)
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
	default:
		return nil, fmt.Errorf("pkcs8: unsupported cipher %v", alg)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(p.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("pkcs8: IV: %w", err)
	}
	if kdf.IterationCount < 1 || kdf.IterationCount > 10_000_000 {
		return nil, errors.New("pkcs8: implausible iteration count")
	}
	key := pbkdf2.Key(password, kdf.Salt, kdf.IterationCount, keyLen, prf)
	defer clear(key)
	plain, err := cbcDecrypt(newCipher, key, iv, epki.EncryptedData)
	if err != nil {
		return nil, ErrWrongPassword
	}
	// A wrong password usually fails the padding check above; make sure the
	// result is DER as well.
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(plain, &raw); err != nil || len(rest) > 0 {
		clear(plain)
		return nil, ErrWrongPassword
	}
	return plain, nil
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

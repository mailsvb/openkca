package pkcs12

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"

	"github.com/mailsvb/go-ca/internal/pki"
)

var (
	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHAAnd2KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 4}
	oidPBEWithSHAAnd128BitRC2CBC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}
	oidPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}
)

// pbeParams are the parameters of the PKCS#12 PBE schemes (RFC 7292 C).
type pbeParams struct {
	Salt       []byte
	Iterations int
}

const maxIterations = 10_000_000

// errDecrypt is a padding or DER error after decryption: almost always a
// wrong password.
var errDecrypt = errors.New("pkcs12: decryption failed")

// pkcs12Cipher returns the block cipher and key length of a PKCS#12 PBE
// scheme, nil if algo is none.
func pkcs12Cipher(algo asn1.ObjectIdentifier) (func([]byte) (cipher.Block, error), int) {
	switch {
	case algo.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC):
		return des.NewTripleDESCipher, 24
	case algo.Equal(oidPBEWithSHAAnd2KeyTripleDESCBC):
		// K1 K2 K1
		return func(k []byte) (cipher.Block, error) { return des.NewTripleDESCipher(append(k[:16:16], k[:8]...)) }, 16
	case algo.Equal(oidPBEWithSHAAnd128BitRC2CBC):
		return func(k []byte) (cipher.Block, error) { return newRC2(k, 128) }, 16
	case algo.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		return func(k []byte) (cipher.Block, error) { return newRC2(k, 40) }, 5
	}
	return nil, 0
}

// decrypt decrypts data encrypted with a PKCS#12 PBE scheme, PBES2 or
// PBES1.
func decrypt(algo pkix.AlgorithmIdentifier, data []byte, pw password) ([]byte, error) {
	if algo.Algorithm.Equal(pki.OIDPBES2) {
		plain, err := pki.PBES2Decrypt(algo.Parameters.FullBytes, data, pw.utf8)
		if errors.Is(err, pki.ErrWrongPassword) {
			return nil, errDecrypt
		}
		return plain, err
	}
	if h, newCipher := pbes1Scheme(algo.Algorithm); h != nil {
		return pbes1Decrypt(algo, data, pw, h, newCipher)
	}
	newCipher, keyLen := pkcs12Cipher(algo.Algorithm)
	if newCipher == nil {
		return nil, fmt.Errorf("pkcs12: unsupported encryption %s", schemeName(algo.Algorithm))
	}
	var p pbeParams
	if rest, err := asn1.Unmarshal(algo.Parameters.FullBytes, &p); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("pkcs12: PBE parameters: %v", err)
	}
	if p.Iterations < 1 || p.Iterations > maxIterations {
		return nil, errors.New("pkcs12: implausible iteration count")
	}
	key := deriveKey(sha1.New, idKey, pw.bmp, p.Salt, p.Iterations, keyLen)
	defer clear(key)
	iv := deriveKey(sha1.New, idIV, pw.bmp, p.Salt, p.Iterations, 8)
	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	return cbcDecrypt(block, iv, data)
}

// encrypt encrypts plain with algo, a PKCS#12 PBE scheme or PBES2 with
// AES-256-CBC and PBKDF2-HMAC-SHA256.
func encrypt(algo asn1.ObjectIdentifier, plain []byte, pw password, iterations, saltLen int) (pkix.AlgorithmIdentifier, []byte, error) {
	if algo.Equal(pki.OIDPBES2) {
		return pki.PBES2Encrypt(plain, pw.utf8, iterations)
	}
	var none pkix.AlgorithmIdentifier
	newCipher, keyLen := pkcs12Cipher(algo)
	if newCipher == nil {
		return none, nil, fmt.Errorf("pkcs12: unsupported encryption %v", algo)
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return none, nil, err
	}
	params, err := asn1.Marshal(pbeParams{Salt: salt, Iterations: iterations})
	if err != nil {
		return none, nil, err
	}
	key := deriveKey(sha1.New, idKey, pw.bmp, salt, iterations, keyLen)
	defer clear(key)
	iv := deriveKey(sha1.New, idIV, pw.bmp, salt, iterations, 8)
	block, err := newCipher(key)
	if err != nil {
		return none, nil, err
	}
	bs := block.BlockSize()
	pad := bs - len(plain)%bs
	out := make([]byte, len(plain)+pad)
	copy(out, plain)
	for i := len(plain); i < len(out); i++ {
		out[i] = byte(pad)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, out)
	return pkix.AlgorithmIdentifier{Algorithm: algo, Parameters: asn1.RawValue{FullBytes: params}}, out, nil
}

func cbcDecrypt(block cipher.Block, iv, data []byte) ([]byte, error) {
	bs := block.BlockSize()
	if len(iv) != bs || len(data) == 0 || len(data)%bs != 0 {
		return nil, errors.New("pkcs12: bad ciphertext length")
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	pad := int(out[len(out)-1])
	if pad == 0 || pad > bs {
		clear(out)
		return nil, errDecrypt
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			clear(out)
			return nil, errDecrypt
		}
	}
	return out[:len(out)-pad], nil
}

// PBES1 (PKCS#5 v1.5, RFC 8018 6.1): PBKDF1 with MD5 or SHA-1, single DES
// or RC2 with 64 effective key bits. Only read, for old files.
var (
	oidPBEWithMD2AndDESCBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 1}
	oidPBEWithMD5AndDESCBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}
	oidPBEWithMD2AndRC2CBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 4}
	oidPBEWithMD5AndRC2CBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 6}
	oidPBEWithSHA1AndDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 10}
	oidPBEWithSHA1AndRC2CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 11}
)

func pbes1Scheme(algo asn1.ObjectIdentifier) (func() hash.Hash, func([]byte) (cipher.Block, error)) {
	rc2 := func(k []byte) (cipher.Block, error) { return newRC2(k, 64) }
	switch {
	case algo.Equal(oidPBEWithMD5AndDESCBC):
		return md5.New, des.NewCipher
	case algo.Equal(oidPBEWithMD5AndRC2CBC):
		return md5.New, rc2
	case algo.Equal(oidPBEWithSHA1AndDESCBC):
		return sha1.New, des.NewCipher
	case algo.Equal(oidPBEWithSHA1AndRC2CBC):
		return sha1.New, rc2
	}
	return nil, nil
}

func pbes1Decrypt(algo pkix.AlgorithmIdentifier, data []byte, pw password, h func() hash.Hash, newCipher func([]byte) (cipher.Block, error)) ([]byte, error) {
	var p pbeParams
	if rest, err := asn1.Unmarshal(algo.Parameters.FullBytes, &p); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("pkcs12: PBES1 parameters: %v", err)
	}
	if p.Iterations < 1 || p.Iterations > maxIterations || len(p.Salt) != 8 {
		return nil, errors.New("pkcs12: implausible PBES1 parameters")
	}
	// PBKDF1: T_1 = H(P || S), T_i = H(T_i-1); key and IV are T_c[0:16]
	d := h()
	d.Write(pw.utf8)
	d.Write(p.Salt)
	t := d.Sum(nil)
	for i := 1; i < p.Iterations; i++ {
		d.Reset()
		d.Write(t)
		t = d.Sum(t[:0])
	}
	defer clear(t)
	block, err := newCipher(t[:8])
	if err != nil {
		return nil, err
	}
	return cbcDecrypt(block, t[8:16], data)
}

// schemeName names an encryption scheme in an error message.
func schemeName(algo asn1.ObjectIdentifier) string {
	switch {
	case algo.Equal(oidPBEWithMD2AndDESCBC):
		return "PBE-MD2-DES"
	case algo.Equal(oidPBEWithMD2AndRC2CBC):
		return "PBE-MD2-RC2-64"
	case algo.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 1}):
		return "PBE-SHA1-RC4-128"
	case algo.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 2}):
		return "PBE-SHA1-RC4-40"
	}
	return algo.String()
}

// DecryptPKCS8 decrypts an EncryptedPrivateKeyInfo (RFC 5208) and returns
// the PrivateKeyInfo. It reads what OpenSSL's pkcs8 command writes: PBES2
// with PBKDF2 or scrypt, the PKCS#12 schemes (-v1 PBE-SHA1-3DES and the
// like) and PBES1 with MD5 or SHA-1. A wrong password is
// pki.ErrWrongPassword; anything else is a format or unsupported scheme.
func DecryptPKCS8(blob []byte, pass []byte) ([]byte, error) {
	var epki encryptedPrivateKeyInfo
	if rest, err := asn1.Unmarshal(blob, &epki); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("pkcs8: %v", err)
	}
	pw := password{utf8: pass}
	if !epki.Algorithm.Algorithm.Equal(pki.OIDPBES2) {
		if h, _ := pbes1Scheme(epki.Algorithm.Algorithm); h == nil {
			pw = newPassword(string(pass)) // the PKCS#12 schemes need the BMPString
			defer pw.clear()
		}
	}
	plain, err := decrypt(epki.Algorithm, epki.Data, pw)
	if errors.Is(err, errDecrypt) {
		return nil, pki.ErrWrongPassword
	}
	if err != nil {
		return nil, err
	}
	if !isDER(plain) {
		clear(plain)
		return nil, pki.ErrWrongPassword
	}
	return plain, nil
}

package pkcs12

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/mailsvb/go-ca/internal/pki"
)

var (
	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
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
	case algo.Equal(oidPBEWithSHAAnd128BitRC2CBC):
		return func(k []byte) (cipher.Block, error) { return newRC2(k, 128) }, 16
	case algo.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		return func(k []byte) (cipher.Block, error) { return newRC2(k, 40) }, 5
	}
	return nil, 0
}

// decrypt decrypts data encrypted with a PKCS#12 PBE scheme or PBES2.
func decrypt(algo pkix.AlgorithmIdentifier, data []byte, pw password) ([]byte, error) {
	if algo.Algorithm.Equal(pki.OIDPBES2) {
		plain, err := pki.PBES2Decrypt(algo.Parameters.FullBytes, data, pw.utf8)
		if errors.Is(err, pki.ErrWrongPassword) {
			return nil, errDecrypt
		}
		return plain, err
	}
	newCipher, keyLen := pkcs12Cipher(algo.Algorithm)
	if newCipher == nil {
		return nil, fmt.Errorf("pkcs12: unsupported encryption %v", algo.Algorithm)
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

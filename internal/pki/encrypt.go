package pki

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2Iterations is the iteration count for encrypted PKCS#8 exports
// (keys in the database are sealed by package vault). The scheme is OpenSSL's
// (PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC), but OpenSSL and XCA write only
// 2048 iterations, which is far too cheap to guess passwords against today.
// 600 000 follows OWASP's recommendation for PBKDF2-HMAC-SHA256; OpenSSL,
// Java and Windows read any count. Tests lower it.
var PBKDF2Iterations = 600_000

const pbkdf2SaltLen = 16

// EncryptPKCS8 encrypts a DER PrivateKeyInfo as EncryptedPrivateKeyInfo
// (PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC), readable by OpenSSL and XCA.
func EncryptPKCS8(der, password []byte) ([]byte, error) {
	algo, enc, err := PBES2Encrypt(der, password, PBKDF2Iterations)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{Algo: algo, EncryptedData: enc})
}

// PBES2Encrypt pads and encrypts plain with PBES2 (PBKDF2-HMAC-SHA256 with
// a random salt, AES-256-CBC with a random IV), as OpenSSL 3 does, and
// returns the AlgorithmIdentifier and the ciphertext.
func PBES2Encrypt(plain, password []byte, iterations int) (pkix.AlgorithmIdentifier, []byte, error) {
	var none pkix.AlgorithmIdentifier
	salt := make([]byte, pbkdf2SaltLen)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return none, nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return none, nil, err
	}
	key := pbkdf2.Key(password, salt, iterations, 32, sha256.New)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return none, nil, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := make([]byte, len(plain)+pad)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	defer clear(padded)
	enc := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(enc, padded)

	kdfParams, err := asn1.Marshal(pbkdf2Params{Salt: salt, IterationCount: iterations,
		PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue}})
	if err != nil {
		return none, nil, err
	}
	ivDER, err := asn1.Marshal(iv)
	if err != nil {
		return none, nil, err
	}
	pbes2, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfParams}},
		EncryptionScheme:  pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		return none, nil, err
	}
	return pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: pbes2}}, enc, nil
}

// EncryptPrivateKey encodes and encrypts key for storage in private_keys.
func EncryptPrivateKey(key crypto.Signer, password []byte) ([]byte, error) {
	der, err := MarshalPKCS8(key)
	if err != nil {
		return nil, fmt.Errorf("pkcs8: %w", err)
	}
	defer clear(der)
	return EncryptPKCS8(der, password)
}

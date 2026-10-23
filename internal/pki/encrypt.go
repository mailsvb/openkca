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

// PBKDF2Iterations is the iteration count for new encrypted keys, both in
// the database and in encrypted PKCS#8 exports. The scheme is OpenSSL's
// (PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC), but OpenSSL and XCA write only
// 2048 iterations, which is far too cheap to guess passwords against today.
// 600 000 follows OWASP's recommendation for PBKDF2-HMAC-SHA256; OpenSSL,
// Java and Windows read any count. Tests lower it.
var PBKDF2Iterations = 600_000

const pbkdf2SaltLen = 16

// EncryptPKCS8 encrypts a DER PrivateKeyInfo as EncryptedPrivateKeyInfo
// (PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC), readable by OpenSSL and XCA.
func EncryptPKCS8(der, password []byte) ([]byte, error) {
	salt := make([]byte, pbkdf2SaltLen)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	key := pbkdf2.Key(password, salt, PBKDF2Iterations, 32, sha256.New)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pad := aes.BlockSize - len(der)%aes.BlockSize
	plain := make([]byte, len(der)+pad)
	copy(plain, der)
	for i := len(der); i < len(plain); i++ {
		plain[i] = byte(pad)
	}
	defer clear(plain)
	enc := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(enc, plain)

	kdfParams, err := asn1.Marshal(pbkdf2Params{Salt: salt, IterationCount: PBKDF2Iterations,
		PRF: pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue}})
	if err != nil {
		return nil, err
	}
	ivDER, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}
	pbes2, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: pkix.AlgorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfParams}},
		EncryptionScheme:  pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: ivDER}},
	})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algo:          pkix.AlgorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: pbes2}},
		EncryptedData: enc,
	})
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

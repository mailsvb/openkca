package codec

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blowfish"
)

// bcryptMagic is the text bcrypt_hash encrypts ("OxychromaticBlowfishSwatDynamite").
var bcryptMagic = []byte("OxychromaticBlowfishSwatDynamite")

// bcryptHash is OpenBSD's bcrypt_hash: a Blowfish key schedule expanded
// 64 times with both inputs, then the magic text encrypted 64 times.
func bcryptHash(out, sha2pass, sha2salt []byte) {
	c, err := blowfish.NewSaltedCipher(sha2pass, sha2salt)
	if err != nil {
		panic(err) // the inputs are SHA-512 sums, a valid key size
	}
	for range 64 {
		blowfish.ExpandKey(sha2salt, c)
		blowfish.ExpandKey(sha2pass, c)
	}
	copy(out, bcryptMagic)
	for i := 0; i < 32; i += 8 {
		for range 64 {
			c.Encrypt(out[i:i+8], out[i:i+8])
		}
	}
	for i := 0; i < 32; i += 4 { // the words are written little endian
		binary.LittleEndian.PutUint32(out[i:], binary.BigEndian.Uint32(out[i:]))
	}
}

// bcryptPBKDF is OpenBSD's bcrypt_pbkdf, the KDF of passphrase protected
// OpenSSH keys.
func bcryptPBKDF(password, salt []byte, rounds, keyLen int) ([]byte, error) {
	if rounds < 1 || len(salt) == 0 || keyLen < 1 || keyLen > 1024 {
		return nil, errors.New("bcrypt_pbkdf: invalid parameters")
	}
	const hashLen = 32
	stride := (keyLen + hashLen - 1) / hashLen
	amt := (keyLen + stride - 1) / stride
	key := make([]byte, keyLen)
	sha2pass := sha512.Sum512(password)
	countSalt := append(append([]byte(nil), salt...), 0, 0, 0, 0)
	out, tmp := make([]byte, hashLen), make([]byte, hashLen)
	for count, left := 1, keyLen; left > 0; count++ {
		binary.BigEndian.PutUint32(countSalt[len(salt):], uint32(count))
		sha2salt := sha512.Sum512(countSalt)
		bcryptHash(tmp, sha2pass[:], sha2salt[:])
		copy(out, tmp)
		for i := 1; i < rounds; i++ {
			sha2salt = sha512.Sum512(tmp)
			bcryptHash(tmp, sha2pass[:], sha2salt[:])
			for j := range out {
				out[j] ^= tmp[j]
			}
		}
		n := min(amt, left)
		i := 0
		for ; i < n; i++ {
			dest := i*stride + count - 1
			if dest >= keyLen {
				break
			}
			key[dest] = out[i]
		}
		left -= i
	}
	return key, nil
}

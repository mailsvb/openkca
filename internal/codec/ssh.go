package codec

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/mailsvb/go-ca/internal/pki"
)

// SSHCompatible reports whether a public key has an OpenSSH encoding.
func SSHCompatible(pub crypto.PublicKey) bool {
	_, _, err := sshPublicBlob(pub)
	return err == nil
}

// SSHPublic writes an authorized_keys line: type, base64 key and the first
// line of the comment (pki_key::SSH2publicQByteArray).
func SSHPublic(pub crypto.PublicKey, comment string) ([]byte, error) {
	algo, blob, err := sshPublicBlob(pub)
	if err != nil {
		return nil, err
	}
	line := algo + " " + base64.StdEncoding.EncodeToString(blob)
	if c := SSHComment(comment); c != "" {
		line += " " + c
	}
	return []byte(line + "\n"), nil
}

// SSHPrivate writes a private key for OpenSSH: openssh-key-v1 for Ed25519,
// traditional PEM for the others, as XCA does.
func SSHPrivate(key crypto.Signer) ([]byte, error) {
	if k, ok := key.(ed25519.PrivateKey); ok {
		b, err := ssh.MarshalPrivateKey(k, "")
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(b), nil
	}
	if !SSHCompatible(key.Public()) {
		return nil, ErrUnsupportedKey
	}
	return PrivatePEM(key, nil)
}

// OpenSSH's private key format, openssh-key-v1 (PROTOCOL.key).
const (
	opensshMagic     = "openssh-key-v1\x00"
	opensshMaxRounds = 1 << 11 // refuse files that would take minutes to open
)

// opensshRounds are the bcrypt rounds ssh-keygen uses; tests lower them.
var opensshRounds uint32 = 24

type opensshCipher struct {
	keyLen, ivLen int
	mode          string // "ctr", "cbc" or "gcm"
}

// opensshCiphers are the ciphers ssh-keygen can protect a key with, except
// 3des-cbc and chacha20-poly1305@openssh.com.
var opensshCiphers = map[string]opensshCipher{
	"aes128-ctr":             {16, 16, "ctr"},
	"aes192-ctr":             {24, 16, "ctr"},
	"aes256-ctr":             {32, 16, "ctr"},
	"aes128-cbc":             {16, 16, "cbc"},
	"aes192-cbc":             {24, 16, "cbc"},
	"aes256-cbc":             {32, 16, "cbc"},
	"aes128-gcm@openssh.com": {16, 12, "gcm"},
	"aes256-gcm@openssh.com": {32, 12, "gcm"},
}

// OpenSSHPrivate writes a private key in OpenSSH's own format with its
// comment, as ssh-keygen does: unencrypted, or with a password encrypted
// with aes256-ctr under a bcrypt_pbkdf key.
func OpenSSHPrivate(key crypto.Signer, comment string, password []byte) ([]byte, error) {
	key, err := sshSigner(key)
	if err != nil {
		return nil, err
	}
	algo, pubBlob, err := sshPublicBlob(key.Public())
	if err != nil {
		return nil, err
	}
	var check [4]byte
	if _, err := rand.Read(check[:]); err != nil {
		return nil, err
	}
	plain := append(check[:], check[:]...)
	plain = appendSSHString(plain, []byte(algo))
	plain = opensshPrivateFields(plain, key)
	plain = appendSSHString(plain, []byte(SSHComment(comment)))
	cipherName, kdfName, block := "none", "none", 8
	var kdfOpts, k []byte
	if len(password) > 0 {
		cipherName, kdfName, block = "aes256-ctr", "bcrypt", aes.BlockSize
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		kdfOpts = appendSSHUint32(appendSSHString(nil, salt), opensshRounds)
		if k, err = bcryptPBKDF(password, salt, int(opensshRounds), 32+16); err != nil {
			return nil, err
		}
		defer clear(k)
	}
	for i := byte(1); len(plain)%block != 0; i++ {
		plain = append(plain, i)
	}
	defer clear(plain)
	section := plain
	if k != nil {
		c, err := aes.NewCipher(k[:32])
		if err != nil {
			return nil, err
		}
		section = make([]byte, len(plain))
		cipher.NewCTR(c, k[32:]).XORKeyStream(section, plain)
	}
	return opensshEnvelope(cipherName, kdfName, kdfOpts, pubBlob, section), nil
}

func opensshEnvelope(cipherName, kdfName string, kdfOpts, pubBlob, section []byte) []byte {
	b := []byte(opensshMagic)
	b = appendSSHString(b, []byte(cipherName))
	b = appendSSHString(b, []byte(kdfName))
	b = appendSSHString(b, kdfOpts)
	b = appendSSHUint32(b, 1)
	b = appendSSHString(b, pubBlob)
	b = appendSSHString(b, section)
	return pem.EncodeToMemory(&pem.Block{Type: PEMOpenSSHKey, Bytes: b})
}

// opensshPrivateFields appends the private key fields of openssh-key-v1
// (sshkey_private_serialize).
func opensshPrivateFields(b []byte, key crypto.Signer) []byte {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		for _, n := range []*big.Int{k.N, big.NewInt(int64(k.E)), k.D, k.Precomputed.Qinv, k.Primes[0], k.Primes[1]} {
			b = appendSSHMPInt(b, n)
		}
	case pki.DSAKey:
		for _, n := range []*big.Int{k.P, k.Q, k.G, k.Y, k.X} {
			b = appendSSHMPInt(b, n)
		}
	case *ecdsa.PrivateKey:
		_, curve := sshCurve(ecdsaAlgo(k))
		point, _ := k.PublicKey.Bytes()
		b = appendSSHString(b, []byte(curve))
		b = appendSSHString(b, point)
		b = appendSSHMPInt(b, k.D)
	case ed25519.PrivateKey:
		b = appendSSHString(b, k[32:])
		b = appendSSHString(b, k)
	}
	return b
}

func ecdsaAlgo(k *ecdsa.PrivateKey) string {
	algo, _, _ := sshPublicBlob(&k.PublicKey)
	return algo
}

// parseOpenSSHPrivate reads an openssh-key-v1 private key (the bytes inside
// the PEM armour) with its comment.
func parseOpenSSHPrivate(data []byte, password func() ([]byte, bool)) (crypto.Signer, string, error) {
	if !bytes.HasPrefix(data, []byte(opensshMagic)) {
		return nil, "", errors.New("ssh: not an openssh-key-v1 key")
	}
	r := &sshReader{b: data[len(opensshMagic):]}
	cipherName, kdfName, kdfOpts := r.string(), r.string(), r.bytes()
	n := r.uint32()
	pubBlob := r.bytes()
	section := r.bytes()
	if r.err != nil {
		return nil, "", r.err
	}
	if n != 1 {
		return nil, "", fmt.Errorf("ssh: %d keys in one file are not supported", n)
	}
	encrypted := cipherName != "none"
	plain := section
	if encrypted {
		var err error
		if plain, err = opensshDecrypt(cipherName, kdfName, kdfOpts, section, r.b, password); err != nil {
			return nil, "", err
		}
		defer clear(plain)
	} else if kdfName != "none" {
		return nil, "", fmt.Errorf("ssh: KDF %q without a cipher", kdfName)
	}
	pr := &sshReader{b: plain}
	if c1, c2 := pr.uint32(), pr.uint32(); pr.err != nil || c1 != c2 {
		if encrypted {
			return nil, "", errSSHPassword
		}
		return nil, "", errors.New("ssh: corrupt private key")
	}
	key, err := opensshReadPrivate(pr.string(), pr)
	comment := pr.string()
	switch {
	case err != nil:
		return nil, "", err
	case pr.err != nil:
		return nil, "", pr.err
	case !sameSSHPublic(key, pubBlob):
		return nil, "", errors.New("ssh: the private key does not match its public key")
	}
	return key, comment, nil
}

func opensshDecrypt(cipherName, kdfName string, kdfOpts, section, rest []byte, password func() ([]byte, bool)) ([]byte, error) {
	ci, ok := opensshCiphers[cipherName]
	if !ok {
		return nil, fmt.Errorf("ssh: cipher %q is not supported", cipherName)
	}
	if kdfName != "bcrypt" {
		return nil, fmt.Errorf("ssh: KDF %q is not supported", kdfName)
	}
	o := &sshReader{b: kdfOpts}
	salt, rounds := o.bytes(), o.uint32()
	if o.err != nil {
		return nil, o.err
	}
	if rounds > opensshMaxRounds {
		return nil, fmt.Errorf("ssh: %d bcrypt rounds exceed the maximum of %d", rounds, opensshMaxRounds)
	}
	pw, ok := password()
	if !ok {
		return nil, errSSHPassword
	}
	k, err := bcryptPBKDF(pw, salt, int(rounds), ci.keyLen+ci.ivLen)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	c, err := aes.NewCipher(k[:ci.keyLen])
	if err != nil {
		return nil, err
	}
	iv := k[ci.keyLen:]
	plain := make([]byte, len(section))
	switch ci.mode {
	case "ctr":
		cipher.NewCTR(c, iv).XORKeyStream(plain, section)
	case "cbc":
		if len(section)%aes.BlockSize != 0 {
			return nil, errors.New("ssh: encrypted key is not a multiple of the block size")
		}
		cipher.NewCBCDecrypter(c, iv).CryptBlocks(plain, section)
	case "gcm":
		g, err := cipher.NewGCM(c)
		if err != nil {
			return nil, err
		}
		if len(rest) < g.Overhead() {
			return nil, errSSHTruncated
		}
		if plain, err = g.Open(plain[:0], iv, append(append([]byte(nil), section...), rest[:g.Overhead()]...), nil); err != nil {
			return nil, errSSHPassword
		}
	}
	return plain, nil
}

// opensshReadPrivate reads the private key fields of openssh-key-v1.
func opensshReadPrivate(algo string, r *sshReader) (crypto.Signer, error) {
	switch algo {
	case ssh.KeyAlgoRSA:
		n, e, d, _, p, q := r.mpint(), r.mpint(), r.mpint(), r.mpint(), r.mpint(), r.mpint()
		if r.err != nil {
			return nil, r.err
		}
		return rsaPrivate(n, e, d, p, q)
	case ssh.KeyAlgoDSA:
		p, q, g, y, x := r.mpint(), r.mpint(), r.mpint(), r.mpint(), r.mpint()
		if r.err != nil {
			return nil, r.err
		}
		return dsaPrivateKey(p, q, g, y, x)
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		curve, name := sshCurve(algo)
		gotName, point, d := r.string(), r.bytes(), r.mpint()
		if r.err != nil {
			return nil, r.err
		}
		if gotName != name {
			return nil, fmt.Errorf("ssh: curve %q in a %s key", gotName, algo)
		}
		return ecdsaPrivate(curve, d, point)
	case ssh.KeyAlgoED25519:
		pub, priv := r.bytes(), r.bytes()
		if r.err != nil {
			return nil, r.err
		}
		if len(priv) != ed25519.PrivateKeySize || subtle.ConstantTimeCompare(priv[32:], pub) != 1 {
			return nil, errors.New("ssh: invalid Ed25519 private key")
		}
		return ed25519Private(priv[:ed25519.SeedSize], pub)
	}
	return nil, fmt.Errorf("ssh: key type %q is not supported", algo)
}

// ed25519Private builds an Ed25519 key from its seed and checks it against
// the public key.
func ed25519Private(seed, pub []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("ssh: invalid Ed25519 private key")
	}
	k := ed25519.NewKeyFromSeed(seed)
	if subtle.ConstantTimeCompare(k[32:], pub) != 1 {
		return nil, errors.New("ssh: Ed25519 private key does not match its public key")
	}
	return k, nil
}

// RFC 4716 public keys, the format PuTTYgen saves public keys in.
const (
	rfc4716Begin = "---- BEGIN SSH2 PUBLIC KEY ----"
	rfc4716End   = "---- END SSH2 PUBLIC KEY ----"
	rfc4716Line  = 72 // longest line, in bytes
)

// RFC4716Public writes a public key as an RFC 4716 block with the first
// line of the comment, as PuTTYgen does.
func RFC4716Public(pub crypto.PublicKey, comment string) ([]byte, error) {
	_, blob, err := sshPublicBlob(pub)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(rfc4716Begin + "\n")
	if c := SSHComment(comment); c != "" {
		writeRFC4716Header(&b, "Comment: \""+c+"\"")
	}
	writeBase64Lines(&b, blob)
	b.WriteString(rfc4716End + "\n")
	return []byte(b.String()), nil
}

// writeRFC4716Header folds a header line with backslashes so that no line
// is longer than 72 bytes, splitting between characters.
func writeRFC4716Header(b *strings.Builder, h string) {
	for len(h) > rfc4716Line {
		cut := rfc4716Line - 1
		for cut > 0 && !utf8.RuneStart(h[cut]) {
			cut--
		}
		b.WriteString(h[:cut] + "\\\n")
		h = h[cut:]
	}
	b.WriteString(h + "\n")
}

// writeBase64Lines writes base64 in lines of 64 characters, as PuTTY does.
func writeBase64Lines(b *strings.Builder, data []byte) int {
	s := base64.StdEncoding.EncodeToString(data)
	n := 0
	for len(s) > 0 {
		l := min(len(s), 64)
		b.WriteString(s[:l] + "\n")
		s = s[l:]
		n++
	}
	return n
}

type sshPublicKey struct {
	pub     crypto.PublicKey
	comment string
}

// parseRFC4716 reads all RFC 4716 public key blocks of a text.
func parseRFC4716(text []byte) (keys []sshPublicKey, errs []error) {
	lines := strings.Split(strings.ReplaceAll(string(text), "\r", ""), "\n")
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != rfc4716Begin {
			continue
		}
		var comment string
		var body strings.Builder
		done := false
		for i++; i < len(lines); i++ {
			l := strings.TrimSpace(lines[i])
			if l == rfc4716End {
				done = true
				break
			}
			if tag, value, ok := strings.Cut(l, ":"); ok && !strings.ContainsAny(tag, " ") {
				for strings.HasSuffix(value, "\\") && i+1 < len(lines) {
					i++
					value = strings.TrimSuffix(value, "\\") + strings.TrimSpace(lines[i])
				}
				if strings.EqualFold(tag, "Comment") {
					comment = strings.TrimSpace(value)
					if len(comment) >= 2 && comment[0] == '"' && comment[len(comment)-1] == '"' {
						comment = comment[1 : len(comment)-1]
					}
				}
				continue
			}
			body.WriteString(l)
		}
		if !done {
			errs = append(errs, errors.New("SSH2 public key: missing end line"))
			break
		}
		blob, err := base64.StdEncoding.DecodeString(body.String())
		if err != nil {
			errs = append(errs, fmt.Errorf("SSH2 public key: %v", err))
			continue
		}
		pub, err := parseSSHPublicBlob(blob)
		if err != nil {
			errs = append(errs, fmt.Errorf("SSH2 public key: %v", err))
			continue
		}
		keys = append(keys, sshPublicKey{pub, comment})
	}
	return keys, errs
}

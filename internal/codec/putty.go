package codec

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"

	"github.com/mailsvb/openkca/internal/pki"
)

// PuTTY's private key files (PPK), as described in the PuTTY manual,
// appendix C.
const (
	ppkPrefix = "PuTTY-User-Key-File-"
	// Argon2id parameters for new files: PuTTYgen's memory and parallelism,
	// and the passes it calibrates to 100 ms on a current machine.
	ppkArgon2Memory      = 8192 // KiB
	ppkArgon2Passes      = 13
	ppkArgon2Parallelism = 1
	// limits for files being read: memory, and memory times passes, about
	// 150 times PuTTYgen's default work
	ppkMaxArgon2Memory = 1 << 18 // KiB (256 MiB)
	ppkMaxArgon2Work   = 1 << 24 // KiB times passes
	ppkMaxLines        = 1 << 10
)

// PuTTYPrivate writes a PuTTY private key file in format version 2 or 3,
// with the first line of the comment and, when password is set, encrypted
// with aes256-cbc (format 3 derives the key with Argon2id).
func PuTTYPrivate(key crypto.Signer, comment string, version int, password []byte) ([]byte, error) {
	if version != 2 && version != 3 {
		return nil, fmt.Errorf("ppk: unsupported version %d", version)
	}
	key, err := sshSigner(key)
	if err != nil {
		return nil, err
	}
	algo, pubBlob, err := sshPublicBlob(key.Public())
	if err != nil {
		return nil, err
	}
	comment = SSHComment(comment)
	priv := ppkPrivateFields(key)
	enc := "none"
	if len(password) > 0 {
		enc = "aes256-cbc"
		if pad := aes.BlockSize - len(priv)%aes.BlockSize; pad < aes.BlockSize {
			p := make([]byte, pad)
			if _, err := rand.Read(p); err != nil {
				return nil, err
			}
			priv = append(priv, p...)
		}
	}
	defer clear(priv)
	var b strings.Builder
	fmt.Fprintf(&b, "%s%d: %s\nEncryption: %s\nComment: %s\n", ppkPrefix, version, algo, enc, comment)
	fmt.Fprintf(&b, "Public-Lines: %d\n", base64Lines(pubBlob))
	writeBase64Lines(&b, pubBlob)
	var k ppkKeys
	if version == 3 && len(password) > 0 {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		k = ppk3Keys(password, "Argon2id", salt, ppkArgon2Passes, ppkArgon2Memory, ppkArgon2Parallelism)
		fmt.Fprintf(&b, "Key-Derivation: Argon2id\nArgon2-Memory: %d\nArgon2-Passes: %d\nArgon2-Parallelism: %d\nArgon2-Salt: %x\n",
			ppkArgon2Memory, ppkArgon2Passes, ppkArgon2Parallelism, salt)
	} else {
		k = ppkKeysFor(version, password)
	}
	defer k.clear()
	mac := ppkMAC(version, k.mac, algo, enc, comment, pubBlob, priv)
	out := priv
	if len(password) > 0 {
		c, err := aes.NewCipher(k.cipher)
		if err != nil {
			return nil, err
		}
		out = make([]byte, len(priv))
		cipher.NewCBCEncrypter(c, k.iv).CryptBlocks(out, priv)
	}
	fmt.Fprintf(&b, "Private-Lines: %d\n", base64Lines(out))
	writeBase64Lines(&b, out)
	fmt.Fprintf(&b, "Private-MAC: %x\n", mac)
	return []byte(b.String()), nil
}

func base64Lines(data []byte) int { return (base64.StdEncoding.EncodedLen(len(data)) + 63) / 64 }

// ppkPrivateFields is the private blob of a PPK file.
func ppkPrivateFields(key crypto.Signer) []byte {
	var b []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		for _, n := range []*big.Int{k.D, k.Primes[0], k.Primes[1], k.Precomputed.Qinv} {
			b = appendSSHMPInt(b, n)
		}
	case pki.DSAKey:
		b = appendSSHMPInt(b, k.X)
	case *ecdsa.PrivateKey:
		b = appendSSHMPInt(b, k.D)
	case ed25519.PrivateKey:
		b = appendSSHString(b, k.Seed())
	}
	return b
}

type ppkKeys struct{ cipher, iv, mac []byte }

func (k ppkKeys) clear() {
	clear(k.cipher)
	clear(k.mac)
}

// ppkKeysFor derives the keys of a format 2 file, and of an unencrypted
// format 3 file (whose MAC key is empty).
func ppkKeysFor(version int, password []byte) ppkKeys {
	if version == 3 {
		return ppkKeys{}
	}
	var k ppkKeys
	if len(password) > 0 {
		for i := range 2 {
			h := sha1.New()
			h.Write([]byte{0, 0, 0, byte(i)})
			h.Write(password)
			k.cipher = h.Sum(k.cipher)
		}
		k.cipher, k.iv = k.cipher[:32], make([]byte, aes.BlockSize)
	}
	h := sha1.New()
	h.Write([]byte("putty-private-key-file-mac-key"))
	h.Write(password)
	k.mac = h.Sum(nil)
	return k
}

// ppk3Keys derives cipher key, IV and MAC key of an encrypted format 3
// file. Argon2d, which x/crypto lacks, yields no keys; callers refuse it.
func ppk3Keys(password []byte, kdf string, salt []byte, passes, memory uint32, parallelism uint8) ppkKeys {
	var out []byte
	switch kdf {
	case "Argon2id":
		out = argon2.IDKey(password, salt, passes, memory, parallelism, 80)
	case "Argon2i":
		out = argon2.Key(password, salt, passes, memory, parallelism, 80)
	default:
		return ppkKeys{}
	}
	return ppkKeys{cipher: out[:32], iv: out[32:48], mac: out[48:]}
}

func ppkMAC(version int, key []byte, algo, enc, comment string, pub, priv []byte) []byte {
	newHash := sha256.New
	if version == 2 {
		newHash = sha1.New
	}
	var data []byte
	for _, s := range [][]byte{[]byte(algo), []byte(enc), []byte(comment), pub, priv} {
		data = appendSSHString(data, s)
	}
	defer clear(data)
	m := hmac.New(newHash, key)
	m.Write(data)
	return m.Sum(nil)
}

// isPPK reports whether a text is a PuTTY private key file.
func isPPK(text []byte) bool { return bytes.HasPrefix(text, []byte(ppkPrefix)) }

// ppkFile reads the lines of a PPK file in order.
type ppkFile struct {
	lines []string
	err   error
}

func (f *ppkFile) field(name string) string {
	if f.err != nil {
		return ""
	}
	if len(f.lines) == 0 {
		f.err = fmt.Errorf("ppk: missing %s", name)
		return ""
	}
	key, value, ok := strings.Cut(f.lines[0], ":")
	if !ok || key != name {
		f.err = fmt.Errorf("ppk: %s expected", name)
		return ""
	}
	f.lines = f.lines[1:]
	return strings.TrimPrefix(value, " ")
}

func (f *ppkFile) number(name string, limit uint64) uint64 {
	v := f.field(name)
	if f.err != nil {
		return 0
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil || n > limit {
		f.err = fmt.Errorf("ppk: invalid %s", name)
	}
	return n
}

func (f *ppkFile) blob(name string) []byte {
	n := f.number(name, ppkMaxLines)
	if f.err != nil {
		return nil
	}
	if uint64(len(f.lines)) < n {
		f.err = fmt.Errorf("ppk: truncated %s", name)
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(strings.Join(f.lines[:n], ""))
	if err != nil {
		f.err = fmt.Errorf("ppk: %s: %v", name, err)
	}
	f.lines = f.lines[n:]
	return b
}

// parsePPK reads a PuTTY private key file of format version 2 or 3 with
// its comment.
func parsePPK(data []byte, password func() ([]byte, bool)) (crypto.Signer, string, error) {
	text := strings.ReplaceAll(string(data), "\r", "")
	f := &ppkFile{lines: strings.Split(strings.TrimSpace(text), "\n")}
	head, algo, _ := strings.Cut(f.lines[0], ": ")
	version, err := strconv.Atoi(strings.TrimPrefix(head, ppkPrefix))
	if err != nil || (version != 2 && version != 3) {
		return nil, "", fmt.Errorf("ppk: unsupported file version %q", strings.TrimPrefix(head, ppkPrefix))
	}
	f.lines = f.lines[1:]
	enc := f.field("Encryption")
	comment := f.field("Comment")
	pubBlob := f.blob("Public-Lines")
	if f.err != nil {
		return nil, "", f.err
	}
	if enc != "none" && enc != "aes256-cbc" {
		return nil, "", fmt.Errorf("ppk: encryption %q is not supported", enc)
	}
	var k ppkKeys
	encrypted := enc != "none"
	switch {
	case encrypted && version == 3:
		kdf := f.field("Key-Derivation")
		memory := f.number("Argon2-Memory", ppkMaxArgon2Memory)
		passes := f.number("Argon2-Passes", ppkMaxArgon2Work)
		par := f.number("Argon2-Parallelism", 255)
		salt, err := hex.DecodeString(f.field("Argon2-Salt"))
		if f.err != nil {
			return nil, "", f.err
		}
		if err != nil || passes == 0 || par == 0 || memory < 8*par {
			return nil, "", errors.New("ppk: invalid Argon2 parameters")
		}
		if memory*passes > ppkMaxArgon2Work {
			return nil, "", errors.New("ppk: the Argon2 parameters exceed OpenKCA's limit")
		}
		if kdf != "Argon2id" && kdf != "Argon2i" {
			return nil, "", fmt.Errorf("ppk: key derivation %q is not supported", kdf)
		}
		pw, ok := password()
		if !ok {
			return nil, "", errSSHPassword
		}
		k = ppk3Keys(pw, kdf, salt, uint32(passes), uint32(memory), uint8(par))
	case encrypted:
		pw, ok := password()
		if !ok {
			return nil, "", errSSHPassword
		}
		k = ppkKeysFor(version, pw)
	default:
		k = ppkKeysFor(version, nil)
	}
	defer k.clear()
	priv := f.blob("Private-Lines")
	wantMAC, err := hex.DecodeString(f.field("Private-MAC"))
	if f.err != nil {
		return nil, "", f.err
	}
	if err != nil {
		return nil, "", errors.New("ppk: invalid Private-MAC")
	}
	if encrypted {
		if len(priv)%aes.BlockSize != 0 {
			return nil, "", errors.New("ppk: encrypted key is not a multiple of the block size")
		}
		c, err := aes.NewCipher(k.cipher)
		if err != nil {
			return nil, "", err
		}
		cipher.NewCBCDecrypter(c, k.iv).CryptBlocks(priv, priv)
	}
	defer clear(priv)
	if !hmac.Equal(ppkMAC(version, k.mac, algo, enc, comment, pubBlob, priv), wantMAC) {
		if encrypted {
			return nil, "", errSSHPassword
		}
		return nil, "", errors.New("ppk: the MAC does not match, the file is damaged")
	}
	key, err := ppkReadPrivate(algo, pubBlob, priv)
	if err != nil {
		return nil, "", err
	}
	if !sameSSHPublic(key, pubBlob) {
		return nil, "", errors.New("ppk: the private key does not match its public key")
	}
	return key, comment, nil
}

// ppkReadPrivate combines the public blob and the private blob of a PPK
// file into a key.
func ppkReadPrivate(algo string, pubBlob, priv []byte) (crypto.Signer, error) {
	pub, r := &sshReader{b: pubBlob}, &sshReader{b: priv}
	if pub.string() != algo {
		return nil, errors.New("ppk: the public key does not match the key type")
	}
	var key crypto.Signer
	var err error
	switch algo {
	case ssh.KeyAlgoRSA:
		e, n := pub.mpint(), pub.mpint()
		d, p, q, _ := r.mpint(), r.mpint(), r.mpint(), r.mpint()
		if pub.err == nil && r.err == nil {
			key, err = rsaPrivate(n, e, d, p, q)
		}
	case ssh.KeyAlgoDSA:
		p, q, g, y := pub.mpint(), pub.mpint(), pub.mpint(), pub.mpint()
		x := r.mpint()
		if pub.err == nil && r.err == nil {
			key, err = dsaPrivateKey(p, q, g, y, x)
		}
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		curve, _ := sshCurve(algo)
		pub.string()
		point, d := pub.bytes(), r.mpint()
		if pub.err == nil && r.err == nil {
			key, err = ecdsaPrivate(curve, d, point)
		}
	case ssh.KeyAlgoED25519:
		pk, seed := pub.bytes(), r.bytes()
		if pub.err == nil && r.err == nil {
			key, err = ed25519Private(seed, pk)
		}
	default:
		return nil, fmt.Errorf("ppk: key type %q is not supported", algo)
	}
	switch {
	case pub.err != nil:
		return nil, pub.err
	case r.err != nil:
		return nil, r.err
	}
	return key, err
}

// Package vault protects private keys at rest with envelope encryption.
//
// The database password is stretched with Argon2id into a key encryption
// key (KEK). The KEK wraps a random 256-bit data encryption key (DEK) with
// AES-256-GCM; unwrapping the DEK is the password check, so no separate
// password hash is stored. Every private key is an unencrypted PKCS#8
// PrivateKeyInfo sealed with the DEK (AES-256-GCM), bound to its public key
// through the associated data. A key with its own password is sealed with a
// key derived from that password instead.
//
// Stored settings of a database:
//
//	kdf  argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt, base64>
//	dek  base64(nonce || AES-256-GCM(KEK, DEK))
//
// A key blob (private_keys.private, before base64):
//
//	"GCK" 0x01 mode                   header; mode 1 = DEK, 2 = own password
//	[mode 2: salt(16) m(4) t(4) p(1)] Argon2id parameters, big endian
//	nonce(12) ciphertext||tag         AES-256-GCM, AAD = header || SHA-256(SPKI)
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"

	"github.com/mailsvb/openkca/internal/pki"
)

// ErrWrongPassword is returned when a password does not open the DEK or a
// key; it is pki.ErrWrongPassword so callers need to check only one error.
var ErrWrongPassword = pki.ErrWrongPassword

// ErrLocked is returned when a wiped Keyring is used.
var ErrLocked = errors.New("vault: the keyring has been closed")

// Params are Argon2id cost parameters.
type Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// Default is the cost for new databases (256 MiB, 3 passes, 4 lanes).
// Tests lower it.
var Default = Params{MemoryKiB: 256 * 1024, Time: 3, Threads: 4}

// Limits for parameters read from a database file, which may have been
// uploaded by anyone with the server password: the memory a login may cost.
const (
	MaxMemoryKiB = 1024 * 1024 // 1 GiB
	MaxTime      = 10
	MaxThreads   = 16
)

// MemoryChoicesMiB and TimeChoices are the costs offered in the UI.
var (
	MemoryChoicesMiB = []int{64, 128, 256, 512, 1024}
	TimeChoices      = []int{1, 2, 3, 4, 6, 8, 10}
)

// Valid reports whether p is within the limits.
func (p Params) Valid() error {
	switch {
	case p.Threads < 1 || p.Threads > MaxThreads:
		return fmt.Errorf("vault: argon2id lanes %d out of range", p.Threads)
	case p.Time < 1 || p.Time > MaxTime:
		return fmt.Errorf("vault: argon2id passes %d out of range", p.Time)
	case p.MemoryKiB < 8*uint32(p.Threads) || p.MemoryKiB > MaxMemoryKiB:
		return fmt.Errorf("vault: argon2id memory %d KiB out of range", p.MemoryKiB)
	}
	return nil
}

// MemoryMiB returns the memory cost in MiB.
func (p Params) MemoryMiB() int { return int(p.MemoryKiB / 1024) }

const (
	saltLen  = 16
	keyLen   = 32
	nonceLen = 12
)

// argonSlots bounds concurrent Argon2id runs: each takes Params.MemoryKiB
// of memory, and logins may arrive in parallel.
var argonSlots = make(chan struct{}, 2)

func derive(password, salt []byte, p Params) ([]byte, error) {
	if err := p.Valid(); err != nil {
		return nil, err
	}
	argonSlots <- struct{}{}
	defer func() { <-argonSlots }()
	return argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, keyLen), nil
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return b
}

func gcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // key length is fixed
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return a
}

// FormatKDF encodes Argon2id parameters and salt as the "kdf" setting.
func FormatKDF(p Params, salt []byte) string {
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt))
}

// ParseKDF decodes the "kdf" setting and checks the parameters against the
// limits.
func ParseKDF(s string) (Params, []byte, error) {
	var p Params
	parts := strings.Split(strings.TrimSpace(s), "$")
	if len(parts) != 4 || parts[0] != "argon2id" || parts[1] != fmt.Sprintf("v=%d", argon2.Version) {
		return p, nil, errors.New("vault: unsupported kdf setting")
	}
	var m, t, th uint32
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &m, &t, &th); err != nil || th > 255 {
		return p, nil, errors.New("vault: invalid kdf parameters")
	}
	p = Params{MemoryKiB: m, Time: t, Threads: uint8(th)}
	if err := p.Valid(); err != nil {
		return p, nil, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) < 8 {
		return p, nil, errors.New("vault: invalid kdf salt")
	}
	return p, salt, nil
}

// Keyring holds an unwrapped DEK. It is safe for concurrent use; Wipe
// makes every later use fail with ErrLocked.
type Keyring struct {
	mu     sync.RWMutex
	dek    []byte
	params Params // the database's KDF cost, used for keys with their own password
}

// NewKeyring returns a keyring with a fresh random DEK.
func NewKeyring(p Params) *Keyring {
	return &Keyring{dek: random(keyLen), params: p}
}

// Params returns the KDF cost of the database the keyring belongs to.
func (k *Keyring) Params() Params {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.params
}

// Clone returns an independent copy, so that two sessions can wipe their
// own copy without affecting the other.
func (k *Keyring) Clone() *Keyring {
	k.mu.RLock()
	defer k.mu.RUnlock()
	c := &Keyring{params: k.params}
	if k.dek != nil {
		c.dek = append([]byte(nil), k.dek...)
	}
	return c
}

// Wipe zeroes the DEK.
func (k *Keyring) Wipe() {
	k.mu.Lock()
	clear(k.dek)
	k.dek = nil
	k.mu.Unlock()
}

func dekAAD(kdf string) []byte { return append([]byte("openkca dek v1\x00"), kdf...) }

// Wrap derives a KEK from password with fresh salt and parameters p and
// wraps the DEK. It returns the "kdf" and "dek" settings. The keyring
// takes p as its parameters.
func (k *Keyring) Wrap(password []byte, p Params) (kdf, wrapped string, err error) {
	salt := random(saltLen)
	kek, err := derive(password, salt, p)
	if err != nil {
		return "", "", err
	}
	defer clear(kek)
	kdf = FormatKDF(p, salt)
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.dek == nil {
		return "", "", ErrLocked
	}
	nonce := random(nonceLen)
	ct := gcm(kek).Seal(nil, nonce, k.dek, dekAAD(kdf))
	k.params = p
	return kdf, base64.StdEncoding.EncodeToString(append(nonce, ct...)), nil
}

// Unwrap opens the DEK stored in the kdf and dek settings with password.
func Unwrap(kdf, wrapped string, password []byte) (*Keyring, error) {
	p, salt, err := ParseKDF(kdf)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(wrapped))
	if err != nil || len(raw) != nonceLen+keyLen+16 {
		return nil, errors.New("vault: invalid dek setting")
	}
	kek, err := derive(password, salt, p)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	dek, err := gcm(kek).Open(nil, raw[:nonceLen], raw[nonceLen:], dekAAD(kdf))
	if err != nil {
		return nil, ErrWrongPassword
	}
	return &Keyring{dek: dek, params: p}, nil
}

// Blob modes.
const (
	ModeDEK      byte = 1
	ModePassword byte = 2
)

var magic = []byte{'G', 'C', 'K', 1}

const pwParamsLen = saltLen + 4 + 4 + 1

// IsSealed reports whether blob is in this package's format.
func IsSealed(blob []byte) bool {
	return len(blob) > len(magic) && bytes.Equal(blob[:len(magic)], magic) &&
		(blob[len(magic)] == ModeDEK || blob[len(magic)] == ModePassword)
}

// Mode returns the mode of a sealed blob, 0 if blob is not sealed.
func Mode(blob []byte) byte {
	if !IsSealed(blob) {
		return 0
	}
	return blob[len(magic)]
}

func aad(header, spki []byte) []byte {
	h := sha256.Sum256(spki)
	return append(append([]byte(nil), header...), h[:]...)
}

// Seal encrypts an unencrypted PKCS#8 PrivateKeyInfo with the DEK, bound to
// the key's DER SubjectPublicKeyInfo.
func (k *Keyring) Seal(pkcs8, spki []byte) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.dek == nil {
		return nil, ErrLocked
	}
	header := append(append([]byte(nil), magic...), ModeDEK)
	nonce := random(nonceLen)
	out := append(header, nonce...)
	return gcm(k.dek).Seal(out, nonce, pkcs8, aad(header, spki)), nil
}

// Open decrypts a blob sealed with Seal.
func (k *Keyring) Open(blob, spki []byte) ([]byte, error) {
	if Mode(blob) != ModeDEK {
		return nil, errors.New("vault: not a DEK-sealed key")
	}
	hl := len(magic) + 1
	if len(blob) < hl+nonceLen+16 {
		return nil, errors.New("vault: sealed key too short")
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.dek == nil {
		return nil, ErrLocked
	}
	plain, err := gcm(k.dek).Open(nil, blob[hl:hl+nonceLen], blob[hl+nonceLen:], aad(blob[:hl], spki))
	if err != nil {
		// The DEK is right (it was unwrapped), so the blob does not belong
		// to this public key or was altered.
		return nil, errors.New("vault: the stored key does not open (corrupt, or moved from another key)")
	}
	return plain, nil
}

// SealWithPassword encrypts a PKCS#8 PrivateKeyInfo under a key's own
// password, stretched with Argon2id at cost p.
func SealWithPassword(pkcs8, spki, password []byte, p Params) ([]byte, error) {
	salt := random(saltLen)
	key, err := derive(password, salt, p)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	header := append(append([]byte(nil), magic...), ModePassword)
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint32(header, p.MemoryKiB)
	header = binary.BigEndian.AppendUint32(header, p.Time)
	header = append(header, p.Threads)
	nonce := random(nonceLen)
	out := append(header, nonce...)
	return gcm(key).Seal(out, nonce, pkcs8, aad(header, spki)), nil
}

// OpenWithPassword decrypts a blob sealed with SealWithPassword.
func OpenWithPassword(blob, spki, password []byte) ([]byte, error) {
	if Mode(blob) != ModePassword {
		return nil, errors.New("vault: not a password-sealed key")
	}
	hl := len(magic) + 1 + pwParamsLen
	if len(blob) < hl+nonceLen+16 {
		return nil, errors.New("vault: sealed key too short")
	}
	ps := blob[len(magic)+1 : hl]
	salt := ps[:saltLen]
	p := Params{
		MemoryKiB: binary.BigEndian.Uint32(ps[saltLen:]),
		Time:      binary.BigEndian.Uint32(ps[saltLen+4:]),
		Threads:   ps[saltLen+8],
	}
	key, err := derive(password, salt, p)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	plain, err := gcm(key).Open(nil, blob[hl:hl+nonceLen], blob[hl+nonceLen:], aad(blob[:hl], spki))
	if err != nil {
		return nil, ErrWrongPassword
	}
	return plain, nil
}

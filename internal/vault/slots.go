package vault

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Unlock method types. Every type except SlotPassword holds a random
// secret of at least MinSecretLen bytes and derives its KEK with HKDF; a
// password is stretched with Argon2id.
const (
	SlotPassword    = "password"
	SlotSecurityKey = "security_key"
	SlotPasskey     = "passkey"
	SlotBackupCode  = "backup_code"
)

// SlotTypes lists the unlock method types in display order.
var SlotTypes = []string{SlotPassword, SlotSecurityKey, SlotPasskey, SlotBackupCode}

// ValidSlotType reports whether t is an unlock method type.
func ValidSlotType(t string) bool {
	for _, s := range SlotTypes {
		if s == t {
			return true
		}
	}
	return false
}

// MinSecretLen is the shortest random secret an HKDF slot accepts.
const MinSecretLen = 16

const hkdfPrefix = "hkdf-sha256$"

// FormatHKDF encodes the HKDF salt of a slot as its kdf recipe.
func FormatHKDF(salt []byte) string {
	return hkdfPrefix + base64.RawStdEncoding.EncodeToString(salt)
}

// ParseHKDF decodes an HKDF kdf recipe.
func ParseHKDF(s string) ([]byte, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), hkdfPrefix)
	if !ok {
		return nil, errors.New("vault: unsupported kdf setting")
	}
	salt, err := base64.RawStdEncoding.DecodeString(rest)
	if err != nil || len(salt) < 8 {
		return nil, errors.New("vault: invalid kdf salt")
	}
	return salt, nil
}

// slotAAD binds a wrapped DEK to its slot: the slot's UUID, its type and
// its kdf recipe. A wrap copied to another slot, or a slot whose type or
// recipe was changed, no longer opens.
func slotAAD(id, typ, kdf string) []byte {
	b := []byte("openkca slot v1\x00")
	b = append(b, id...)
	b = append(b, 0)
	b = append(b, typ...)
	b = append(b, 0)
	return append(b, kdf...)
}

func hkdfInfo(id string) string { return "openkca kek v1\x00" + id }

// slotKEK derives the KEK of a slot from its secret and kdf recipe.
func slotKEK(id, typ, kdf string, secret []byte) ([]byte, error) {
	if !ValidSlotType(typ) {
		return nil, fmt.Errorf("vault: unknown unlock method type %q", typ)
	}
	if typ == SlotPassword {
		p, salt, err := ParseKDF(kdf)
		if err != nil {
			return nil, err
		}
		return derive(secret, salt, p)
	}
	salt, err := ParseHKDF(kdf)
	if err != nil {
		return nil, err
	}
	if len(secret) < MinSecretLen {
		return nil, ErrWrongPassword
	}
	return hkdf.Key(sha256.New, secret, salt, hkdfInfo(id), keyLen)
}

// WrapSlot wraps the DEK for the unlock method with UUID id and type typ.
// A password is stretched with Argon2id at cost p and a fresh salt; any
// other type's secret goes through HKDF with a fresh salt (p is unused).
// It returns the slot's kdf recipe and wrapped DEK (nonce || ciphertext).
func (k *Keyring) WrapSlot(id, typ string, secret []byte, p Params) (kdf string, wrapped []byte, err error) {
	salt := random(saltLen)
	if typ == SlotPassword {
		if err := p.Valid(); err != nil {
			return "", nil, err
		}
		kdf = FormatKDF(p, salt)
	} else {
		kdf = FormatHKDF(salt)
	}
	kek, err := slotKEK(id, typ, kdf, secret)
	if err != nil {
		if errors.Is(err, ErrWrongPassword) {
			return "", nil, errors.New("vault: secret too short")
		}
		return "", nil, err
	}
	defer clear(kek)
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.dek == nil {
		return "", nil, ErrLocked
	}
	nonce := random(nonceLen)
	return kdf, gcm(kek).Seal(nonce, nonce, k.dek, slotAAD(id, typ, kdf)), nil
}

// UnwrapSlot opens the DEK wrapped in a slot with the method's secret. A
// wrong secret returns ErrWrongPassword. The keyring takes p, the
// database's Argon2id cost, as its parameters.
func UnwrapSlot(id, typ, kdf string, wrapped, secret []byte, p Params) (*Keyring, error) {
	if len(wrapped) != nonceLen+keyLen+16 {
		return nil, errors.New("vault: invalid wrapped data key")
	}
	kek, err := slotKEK(id, typ, kdf, secret)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	dek, err := gcm(kek).Open(nil, wrapped[:nonceLen], wrapped[nonceLen:], slotAAD(id, typ, kdf))
	if err != nil {
		return nil, ErrWrongPassword
	}
	return &Keyring{dek: dek, params: p}, nil
}

// SetParams sets the Argon2id cost the keyring passes on (for keys given
// their own password).
func (k *Keyring) SetParams(p Params) {
	k.mu.Lock()
	k.params = p
	k.mu.Unlock()
}

// Backup codes are 16 random bytes written as 26 characters of Crockford's
// Base32 in groups of five (the last group six).
const backupCodeLen = 16

var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// NewBackupCode returns a fresh backup code: its secret and its display
// form.
func NewBackupCode() (secret []byte, display string) {
	secret = random(backupCodeLen)
	s := crockford.EncodeToString(secret) // 26 characters
	return secret, s[0:5] + "-" + s[5:10] + "-" + s[10:15] + "-" + s[15:20] + "-" + s[20:]
}

// ParseBackupCode reads a backup code as a person types it: case, spaces
// and dashes are ignored, and I, L and O are read as 1, 1 and 0.
func ParseBackupCode(s string) ([]byte, error) {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == ' ' || r == '-' || r == '\t':
		case r == 'I' || r == 'L':
			b.WriteByte('1')
		case r == 'O':
			b.WriteByte('0')
		default:
			b.WriteRune(r)
		}
	}
	secret, err := crockford.DecodeString(b.String())
	if err != nil || len(secret) != backupCodeLen {
		return nil, ErrWrongPassword
	}
	return secret, nil
}

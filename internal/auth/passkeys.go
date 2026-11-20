package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PasskeysFile is the file in the state folder that holds the passkeys of
// the server login.
const PasskeysFile = "server-passkeys.json"

// MaxPasskeys is the most passkeys the server login can have.
const MaxPasskeys = 32

// MaxPasskeyLabel is the longest passkey name, in characters.
const MaxPasskeyLabel = 64

// Errors of PasskeyStore.Add.
var (
	ErrPasskeyLabel     = errors.New("passkey name missing or too long")
	ErrPasskeyDuplicate = errors.New("a passkey with this name already exists")
	ErrPasskeyKnown     = errors.New("this passkey is already registered")
	ErrPasskeyTooMany   = errors.New("too many passkeys")
)

// Passkey is a WebAuthn credential that logs in to the server. It holds
// only public data: the credential's ID and public key.
type Passkey struct {
	ID           string    `json:"id"` // random, names it in URLs
	Label        string    `json:"label"`
	CredentialID []byte    `json:"credential_id"`
	PublicKey    []byte    `json:"public_key"`
	AAGUID       []byte    `json:"aaguid,omitempty"`
	SignCount    uint32    `json:"sign_count"`
	Transports   []string  `json:"transports,omitempty"`
	Flags        byte      `json:"flags"`
	Created      time.Time `json:"created"`
	LastUsed     time.Time `json:"last_used,omitzero"`
}

type passkeyFile struct {
	// UserID is the WebAuthn user handle of the server login; every
	// passkey is registered for it.
	UserID   []byte    `json:"user_id"`
	Passkeys []Passkey `json:"passkeys"`
}

// PasskeyStore keeps the server login's passkeys in a JSON file.
type PasskeyStore struct {
	path string
	mu   sync.Mutex
	f    passkeyFile
}

// ValidPasskeyLabel trims a passkey name and reports whether it can be used.
func ValidPasskeyLabel(label string) (string, bool) {
	label = strings.TrimSpace(label)
	n := len([]rune(label))
	return label, n > 0 && n <= MaxPasskeyLabel
}

// OpenPasskeys loads the passkeys from data/.openkca/server-passkeys.json.
// A missing file means none; a file that cannot be read is an error.
func OpenPasskeys(dataDir string) (*PasskeyStore, error) {
	p := &PasskeyStore{path: filepath.Join(dataDir, StateDir, PasskeysFile)}
	b, err := os.ReadFile(p.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &p.f); err != nil {
			return nil, fmt.Errorf("%s: %w", p.path, err)
		}
		if len(p.f.UserID) != 16 {
			return nil, fmt.Errorf("%s: invalid user_id", p.path)
		}
		for i := range p.f.Passkeys {
			k := &p.f.Passkeys[i]
			if k.ID == "" || len(k.CredentialID) == 0 || len(k.PublicKey) == 0 {
				return nil, fmt.Errorf("%s: passkey %d is incomplete", p.path, i+1)
			}
		}
	}
	if p.f.UserID == nil {
		// Saved with the first passkey.
		p.f.UserID = make([]byte, 16)
		if _, err := rand.Read(p.f.UserID); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// UserID returns the WebAuthn user handle of the server login.
func (p *PasskeyStore) UserID() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Clone(p.f.UserID)
}

// List returns a copy of all passkeys, oldest first.
func (p *PasskeyStore) List() []Passkey {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Passkey, len(p.f.Passkeys))
	copy(out, p.f.Passkeys)
	return out
}

// Count returns the number of passkeys.
func (p *PasskeyStore) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.f.Passkeys)
}

// HasLabel reports whether a passkey has this name (case-insensitive).
func (p *PasskeyStore) HasLabel(label string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hasLabel(label)
}

func (p *PasskeyStore) hasLabel(label string) bool {
	for i := range p.f.Passkeys {
		if strings.EqualFold(p.f.Passkeys[i].Label, label) {
			return true
		}
	}
	return false
}

// Add stores a new passkey and returns it with its ID.
func (p *PasskeyStore) Add(k Passkey) (Passkey, error) {
	label, ok := ValidPasskeyLabel(k.Label)
	if !ok {
		return k, ErrPasskeyLabel
	}
	k.Label = label
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.f.Passkeys) >= MaxPasskeys {
		return k, ErrPasskeyTooMany
	}
	if p.hasLabel(label) {
		return k, ErrPasskeyDuplicate
	}
	for i := range p.f.Passkeys {
		if bytes.Equal(p.f.Passkeys[i].CredentialID, k.CredentialID) {
			return k, ErrPasskeyKnown
		}
	}
	k.ID = NewID()[:22]
	if k.Created.IsZero() {
		k.Created = time.Now().UTC()
	}
	old := p.f.Passkeys
	p.f.Passkeys = append(append([]Passkey(nil), old...), k)
	if err := p.save(); err != nil {
		p.f.Passkeys = old
		return k, err
	}
	return k, nil
}

// Remove deletes the passkey with this ID and returns it.
func (p *PasskeyStore) Remove(id string) (Passkey, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.f.Passkeys {
		if p.f.Passkeys[i].ID != id {
			continue
		}
		k, old := p.f.Passkeys[i], p.f.Passkeys
		p.f.Passkeys = append(append([]Passkey(nil), old[:i]...), old[i+1:]...)
		if err := p.save(); err != nil {
			p.f.Passkeys = old
			return k, false, err
		}
		return k, true, nil
	}
	return Passkey{}, false, nil
}

// ByCredential returns the passkey with this credential ID.
func (p *PasskeyStore) ByCredential(credID []byte) (Passkey, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.f.Passkeys {
		if bytes.Equal(p.f.Passkeys[i].CredentialID, credID) {
			return p.f.Passkeys[i], true
		}
	}
	return Passkey{}, false
}

// Used records a login with a passkey: its new signature counter and the
// time.
func (p *PasskeyStore) Used(credID []byte, signCount uint32) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.f.Passkeys {
		k := &p.f.Passkeys[i]
		if bytes.Equal(k.CredentialID, credID) {
			k.SignCount, k.LastUsed = signCount, time.Now().UTC()
			return p.save()
		}
	}
	return nil
}

func (p *PasskeyStore) save() error {
	b, err := json.MarshalIndent(&p.f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(p.path, append(b, '\n'), 0o600)
}

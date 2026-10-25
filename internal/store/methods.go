package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/vault"
	"github.com/mailsvb/openkca/internal/xcaimport"
)

// Limits on the unlock methods of one database. Every password slot costs
// one Argon2id run on a password login, so passwords are capped lower.
const (
	MaxPasswords   = 5
	MaxWebAuthn    = 16
	MaxLabelLength = 64
)

// Errors of the unlock method management. The web layer maps each to a
// message.
var (
	ErrLastPassword     = errors.New("the last password of a database cannot be removed")
	ErrConfiguredMethod = errors.New("the configuration file opens the database with this password")
	ErrTooManyMethods   = errors.New("this database has the most unlock methods of this type it can have")
	ErrBadLabel         = fmt.Errorf("a name needs 1 to %d characters", MaxLabelLength)
	ErrNotPassword      = errors.New("only a password can be changed")
	ErrBackground       = errors.New("the database is kept open in the background")
	ErrBadMethodType    = errors.New("unknown unlock method type")
)

// DefaultPasswordLabel names the password a database is created with.
const DefaultPasswordLabel = xcaimport.DefaultPasswordLabel

// cost returns the database's Argon2id cost; vault.Default when unset or
// invalid.
func cost(ctx context.Context, d *db.DB) vault.Params {
	s, err := d.Setting(ctx, db.SettingArgon2id)
	if err != nil || s == "" {
		return vault.Default
	}
	p, err := vault.ParseCost(s)
	if err != nil {
		return vault.Default
	}
	return p
}

// KDFParams returns the Argon2id cost of a current database.
func (h *Handle) KDFParams(ctx context.Context) (vault.Params, error) {
	return cost(ctx, h.DB), nil
}

// SetKDFParams sets the Argon2id cost for passwords set from now on and
// for keys given their own password; existing passwords keep theirs.
func (h *Handle) SetKDFParams(ctx context.Context, p vault.Params) error {
	if err := p.Valid(); err != nil {
		return err
	}
	old := cost(ctx, h.DB)
	err := h.DB.Write(ctx, func(tx *db.Tx) error {
		if err := tx.SetSetting(ctx, db.SettingArgon2id, vault.FormatCost(p)); err != nil {
			return err
		}
		return tx.Audit(ctx, "database.kdf", 0, fmt.Sprintf("argon2id %d→%d MiB, %d→%d passes",
			old.MemoryMiB(), p.MemoryMiB(), old.Time, p.Time))
	})
	return err
}

// unlockPassword tries password against every password slot of d, the
// most recently used first. A password that opens none returns
// pki.ErrWrongPassword.
func unlockPassword(ctx context.Context, d *db.DB, password []byte) (*vault.Keyring, *db.UnlockMethod, error) {
	ms, err := d.UnlockMethodsOfType(ctx, vault.SlotPassword)
	if err != nil {
		return nil, nil, err
	}
	p := cost(ctx, d)
	for i := range ms {
		m := &ms[i]
		kr, err := vault.UnwrapSlot(m.UUID, m.Type, m.KDF, m.Wrapped, password, p)
		if err == nil {
			return kr, m, nil
		}
		if !errors.Is(err, vault.ErrWrongPassword) {
			slog.Warn("password slot unusable", "uuid", m.UUID, "err", err)
		}
	}
	return nil, nil, pki.ErrWrongPassword
}

// Unlock opens the DEK with a password. A wrong password returns
// pki.ErrWrongPassword.
func (h *Handle) Unlock(ctx context.Context, password []byte) (*vault.Keyring, error) {
	kr, _, err := h.UnlockPassword(ctx, password)
	return kr, err
}

// UnlockPassword opens the DEK with a password and returns the method that
// opened it, recording its use.
func (h *Handle) UnlockPassword(ctx context.Context, password []byte) (*vault.Keyring, *db.UnlockMethod, error) {
	kr, m, err := unlockPassword(ctx, h.DB, password)
	if err != nil {
		return nil, nil, err
	}
	h.touch(ctx, m, m.SignCount)
	return kr, m, nil
}

// UnlockSecret opens the DEK with a security key's or passkey's PRF
// output; the caller has verified the WebAuthn assertion of m's
// credential. signCount is the authenticator's new signature counter.
func (h *Handle) UnlockSecret(ctx context.Context, m *db.UnlockMethod, prf []byte, signCount uint32) (*vault.Keyring, error) {
	if !m.WebAuthn() {
		return nil, ErrBadMethodType
	}
	kr, err := vault.UnwrapSlot(m.UUID, m.Type, m.KDF, m.Wrapped, prf, cost(ctx, h.DB))
	if err != nil {
		if errors.Is(err, vault.ErrWrongPassword) {
			return nil, pki.ErrWrongPassword
		}
		return nil, err
	}
	h.touch(ctx, m, signCount)
	return kr, nil
}

// UnlockBackupCode opens the DEK with the backup code and deletes the
// code: it is used once. A wrong code returns pki.ErrWrongPassword.
func (h *Handle) UnlockBackupCode(ctx context.Context, code string) (*vault.Keyring, error) {
	ms, err := h.DB.UnlockMethodsOfType(ctx, vault.SlotBackupCode)
	if err != nil {
		return nil, err
	}
	secret, err := vault.ParseBackupCode(code)
	if err != nil || len(ms) == 0 {
		return nil, pki.ErrWrongPassword
	}
	defer clear(secret)
	m := ms[0]
	kr, err := vault.UnwrapSlot(m.UUID, m.Type, m.KDF, m.Wrapped, secret, cost(ctx, h.DB))
	if err != nil {
		if errors.Is(err, vault.ErrWrongPassword) {
			return nil, pki.ErrWrongPassword
		}
		return nil, err
	}
	err = h.DB.Write(ctx, func(tx *db.Tx) error {
		if err := tx.DeleteUnlockMethod(ctx, m.UUID); err != nil {
			return err
		}
		return tx.Audit(ctx, "backupcode.used", 0, "used to log in and deleted")
	})
	if err != nil {
		kr.Wipe()
		return nil, err
	}
	h.methodsChanged(ctx)
	return kr, nil
}

// touch records a method's use; failure only costs the record.
func (h *Handle) touch(ctx context.Context, m *db.UnlockMethod, signCount uint32) {
	if err := h.DB.Write(ctx, func(tx *db.Tx) error { return tx.TouchUnlockMethod(ctx, m.UUID, signCount) }); err != nil {
		slog.Warn("recording an unlock method's use failed", "db", h.Name, "err", err)
	}
}

// HasBackupCode reports whether the database has a backup code.
func (h *Handle) HasBackupCode(ctx context.Context) bool {
	ms, err := h.DB.UnlockMethodsOfType(ctx, vault.SlotBackupCode)
	return err == nil && len(ms) > 0
}

// Methods returns the database's unlock methods, the most recently used
// first.
func (h *Handle) Methods(ctx context.Context) ([]db.UnlockMethod, error) {
	return h.DB.UnlockMethods(ctx)
}

// Method returns one unlock method by UUID.
func (h *Handle) Method(ctx context.Context, id string) (*db.UnlockMethod, error) {
	return h.DB.UnlockMethod(ctx, id)
}

// MethodByCredential returns the security key or passkey with this
// WebAuthn credential ID.
func (h *Handle) MethodByCredential(ctx context.Context, credID []byte) (*db.UnlockMethod, error) {
	return h.DB.UnlockMethodByCredential(ctx, credID)
}

// SetConfiguredMethod records the password slot the configuration file's
// password opens; it cannot be changed or removed while OpenKCA runs.
func (h *Handle) SetConfiguredMethod(id string) {
	h.mu.Lock()
	h.configured = id
	h.mu.Unlock()
}

// ConfiguredMethod returns the UUID recorded by SetConfiguredMethod, "" if
// none.
func (h *Handle) ConfiguredMethod() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.configured
}

func cleanLabel(label string) (string, error) {
	label = strings.Join(strings.Fields(label), " ")
	if label == "" || utf8.RuneCountInString(label) > MaxLabelLength {
		return "", ErrBadLabel
	}
	return label, nil
}

func countType(ms []db.UnlockMethod, types ...string) int {
	n := 0
	for _, m := range ms {
		for _, t := range types {
			if m.Type == t {
				n++
			}
		}
	}
	return n
}

// AddPassword adds a password unlock method.
func (h *Handle) AddPassword(ctx context.Context, kr *vault.Keyring, label string, password []byte) (*db.UnlockMethod, error) {
	label, err := cleanLabel(label)
	if err != nil {
		return nil, err
	}
	if len(password) < MinPasswordLen {
		return nil, ErrShortPassword
	}
	ms, err := h.Methods(ctx)
	if err != nil {
		return nil, err
	}
	if countType(ms, vault.SlotPassword) >= MaxPasswords {
		return nil, ErrTooManyMethods
	}
	m := db.UnlockMethod{Type: vault.SlotPassword, Label: label}
	if m.UUID, err = db.NewUUID(); err != nil {
		return nil, err
	}
	if m.KDF, m.Wrapped, err = kr.WrapSlot(m.UUID, m.Type, password, cost(ctx, h.DB)); err != nil {
		return nil, err
	}
	err = h.DB.Write(ctx, func(tx *db.Tx) error {
		if err := tx.InsertUnlockMethod(ctx, &m); err != nil {
			return err
		}
		return tx.Audit(ctx, "method.add", 0, methodText(&m))
	})
	if err != nil {
		return nil, err
	}
	h.methodsChanged(ctx)
	return &m, nil
}

// AddWebAuthn adds a security key or passkey: m carries the type, label
// and the verified credential (ID, public key, counter, transports,
// AAGUID, PRF salt); prf is the authenticator's PRF output for that salt.
func (h *Handle) AddWebAuthn(ctx context.Context, kr *vault.Keyring, m db.UnlockMethod, prf []byte) (*db.UnlockMethod, error) {
	if m.Type != vault.SlotSecurityKey && m.Type != vault.SlotPasskey {
		return nil, ErrBadMethodType
	}
	if len(m.CredentialID) == 0 || len(m.PublicKey) == 0 || len(m.PRFSalt) == 0 {
		return nil, errors.New("incomplete credential")
	}
	label, err := cleanLabel(m.Label)
	if err != nil {
		return nil, err
	}
	m.Label = label
	ms, err := h.Methods(ctx)
	if err != nil {
		return nil, err
	}
	if countType(ms, vault.SlotSecurityKey, vault.SlotPasskey) >= MaxWebAuthn {
		return nil, ErrTooManyMethods
	}
	m.ID, m.Created = 0, m.Created.UTC()
	if m.UUID, err = db.NewUUID(); err != nil {
		return nil, err
	}
	if m.KDF, m.Wrapped, err = kr.WrapSlot(m.UUID, m.Type, prf, vault.Params{}); err != nil {
		return nil, err
	}
	err = h.DB.Write(ctx, func(tx *db.Tx) error {
		if err := tx.InsertUnlockMethod(ctx, &m); err != nil {
			return err
		}
		return tx.Audit(ctx, "method.add", 0, methodText(&m))
	})
	if err != nil {
		return nil, err
	}
	h.methodsChanged(ctx)
	return &m, nil
}

// GenerateBackupCode creates the database's backup code, replacing the
// existing one. It returns the code for display; only its wrap is stored.
// Replacing a code deletes the backups, which still open with the old one.
func (h *Handle) GenerateBackupCode(ctx context.Context, kr *vault.Keyring) (string, error) {
	secret, display := vault.NewBackupCode()
	defer clear(secret)
	ms, err := h.DB.UnlockMethodsOfType(ctx, vault.SlotBackupCode)
	if err != nil {
		return "", err
	}
	m := db.UnlockMethod{Type: vault.SlotBackupCode, Label: "Backup code"}
	if m.UUID, err = db.NewUUID(); err != nil {
		return "", err
	}
	if m.KDF, m.Wrapped, err = kr.WrapSlot(m.UUID, m.Type, secret, vault.Params{}); err != nil {
		return "", err
	}
	replaced := len(ms) > 0
	err = h.DB.Write(ctx, func(tx *db.Tx) error {
		for _, old := range ms {
			if err := tx.DeleteUnlockMethod(ctx, old.UUID); err != nil {
				return err
			}
		}
		if err := tx.InsertUnlockMethod(ctx, &m); err != nil {
			return err
		}
		detail := "created"
		if replaced {
			detail = "replaced"
		}
		return tx.Audit(ctx, "backupcode.generate", 0, detail)
	})
	if err != nil {
		return "", err
	}
	h.methodsChanged(ctx)
	if replaced {
		h.renewBackups(ctx, "backup code replaced")
	}
	return display, nil
}

// RenameMethod sets a method's label.
func (h *Handle) RenameMethod(ctx context.Context, id, label string) error {
	label, err := cleanLabel(label)
	if err != nil {
		return err
	}
	m, err := h.Method(ctx, id)
	if err != nil {
		return err
	}
	err = h.DB.Write(ctx, func(tx *db.Tx) error {
		if err := tx.RenameUnlockMethod(ctx, id, label); err != nil {
			return err
		}
		return tx.Audit(ctx, "method.rename", 0, fmt.Sprintf("%s → %q", methodText(m), label))
	})
	if err == nil {
		h.methodsChanged(ctx)
	}
	return err
}

// ChangePassword gives a password method a new password at the database's
// current Argon2id cost. The data key stays; backups are deleted because
// they still open with the old password.
func (h *Handle) ChangePassword(ctx context.Context, kr *vault.Keyring, id string, password []byte) error {
	if len(password) < MinPasswordLen {
		return ErrShortPassword
	}
	m, err := h.Method(ctx, id)
	if err != nil {
		return err
	}
	if m.Type != vault.SlotPassword {
		return ErrNotPassword
	}
	if id == h.ConfiguredMethod() {
		return ErrConfiguredMethod
	}
	kdf, wrapped, err := kr.WrapSlot(m.UUID, m.Type, password, cost(ctx, h.DB))
	if err != nil {
		return err
	}
	err = h.DB.Write(ctx, func(tx *db.Tx) error {
		if err := tx.RewrapUnlockMethod(ctx, m.UUID, kdf, wrapped); err != nil {
			return err
		}
		return tx.Audit(ctx, "method.password", 0, methodText(m))
	})
	if err != nil {
		return err
	}
	h.methodsChanged(ctx)
	h.renewBackups(ctx, "password changed")
	return nil
}

// RemoveMethod deletes an unlock method. The last password and the one
// the configuration file uses stay. Backups are deleted because they still
// open with the removed method.
func (h *Handle) RemoveMethod(ctx context.Context, id string) error {
	m, err := h.Method(ctx, id)
	if err != nil {
		return err
	}
	if id == h.ConfiguredMethod() {
		return ErrConfiguredMethod
	}
	err = h.DB.Write(ctx, func(tx *db.Tx) error {
		if m.Type == vault.SlotPassword {
			ms, err := tx.UnlockMethods(ctx)
			if err != nil {
				return err
			}
			if countType(ms, vault.SlotPassword) <= 1 {
				return ErrLastPassword
			}
		}
		if err := tx.DeleteUnlockMethod(ctx, id); err != nil {
			return err
		}
		return tx.Audit(ctx, "method.remove", 0, methodText(m))
	})
	if err != nil {
		return err
	}
	h.methodsChanged(ctx)
	h.renewBackups(ctx, "unlock method removed")
	return nil
}

// ReplaceDataKey makes a new data key, re-seals every key protected by the
// old one with it and keeps only the password method that password opens:
// every other method is deleted, as are the backups. It returns the new
// keyring; other sessions' keyrings no longer open the keys. A database
// kept open in the background is refused (its keyring would go stale).
func (h *Handle) ReplaceDataKey(ctx context.Context, password []byte) (*vault.Keyring, error) {
	if h.ConfiguredMethod() != "" {
		return nil, ErrBackground
	}
	old, keep, err := unlockPassword(ctx, h.DB, password)
	if err != nil {
		return nil, err
	}
	defer old.Wipe()
	p := cost(ctx, h.DB)
	rows, err := h.DB.PrivateKeyRows(ctx)
	if err != nil {
		return nil, err
	}
	nk := vault.NewKeyring(p)
	fail := func(err error) (*vault.Keyring, error) {
		nk.Wipe()
		return nil, err
	}
	type re struct {
		id   int64
		blob []byte
	}
	var updates []re
	for _, r := range rows {
		if r.Protection != db.ProtDEK {
			continue
		}
		der, err := old.Open(r.Blob, r.Public)
		if err != nil {
			return fail(fmt.Errorf("key %d: %w", r.ID, err))
		}
		blob, err := nk.Seal(der, r.Public)
		clear(der)
		if err != nil {
			return fail(err)
		}
		updates = append(updates, re{r.ID, blob})
	}
	// The kept password is wrapped afresh at the current cost.
	kdf, wrapped, err := nk.WrapSlot(keep.UUID, keep.Type, password, p)
	if err != nil {
		return fail(err)
	}
	ms, err := h.Methods(ctx)
	if err != nil {
		return fail(err)
	}
	if _, err := h.Backup(ctx); err != nil {
		return fail(err)
	}
	removed := 0
	err = h.DB.Write(ctx, func(tx *db.Tx) error {
		for _, u := range updates {
			if err := tx.UpdatePrivateKey(ctx, u.id, u.blob, db.ProtDEK); err != nil {
				return err
			}
		}
		if err := tx.RewrapUnlockMethod(ctx, keep.UUID, kdf, wrapped); err != nil {
			return err
		}
		for _, m := range ms {
			if m.UUID == keep.UUID {
				continue
			}
			if err := tx.DeleteUnlockMethod(ctx, m.UUID); err != nil {
				return err
			}
			removed++
		}
		return tx.Audit(ctx, "database.rekey", 0, fmt.Sprintf("data key replaced, %d keys re-sealed, %d other unlock methods removed, kept %s",
			len(updates), removed, methodText(keep)))
	})
	if err != nil {
		return fail(err)
	}
	h.vacuum(ctx)
	h.changed(ctx)
	h.methodsChanged(ctx)
	h.renewBackups(ctx, "data key replaced")
	return nk, nil
}

// renewBackups deletes every backup (they open with a method or data key
// that no longer applies) and takes a new one. Failures are logged.
func (h *Handle) renewBackups(ctx context.Context, why string) {
	n, err := h.PurgeBackups()
	if err != nil {
		slog.Error("deleting backups failed", "db", h.Name, "why", why, "err", err)
		return
	}
	if _, err := h.Backup(ctx); err != nil {
		slog.Error("backup failed", "db", h.Name, "why", why, "err", err)
		return
	}
	h.DB.Audit(ctx, "backup.purge", 0, fmt.Sprintf("%d backups deleted (%s)", n, why))
}

// WebAuthnUser returns the database's WebAuthn user handle, creating it on
// first use.
func (h *Handle) WebAuthnUser(ctx context.Context) ([]byte, error) {
	h.methodMu.Lock()
	defer h.methodMu.Unlock()
	s, err := h.DB.Setting(ctx, db.SettingWebAuthnUser)
	if err != nil {
		return nil, err
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == 16 {
		return b, nil
	}
	b := make([]byte, 16)
	rand.Read(b)
	if err := h.DB.SetSetting(ctx, db.SettingWebAuthnUser, base64.RawURLEncoding.EncodeToString(b)); err != nil {
		return nil, err
	}
	return b, nil
}

// methodsChanged tells watchers (open pages, the database list) that the
// unlock methods changed.
func (h *Handle) methodsChanged(ctx context.Context) {
	h.changed(ctx)
}

func methodText(m *db.UnlockMethod) string {
	return fmt.Sprintf("%s %q", m.Type, m.Label)
}

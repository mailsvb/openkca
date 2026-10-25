package store

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/vault"
)

func newMethodsDB(t *testing.T) (*Store, *Handle) {
	t.Helper()
	s := copyFixtures(t)
	if err := s.Create(context.Background(), "methods", testPassword, testKDF); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "methods")
	return s, h
}

func webauthnMethod(typ, label string, cred byte) db.UnlockMethod {
	return db.UnlockMethod{Type: typ, Label: label, CredentialID: []byte{cred, 1, 2, 3}, PublicKey: []byte("cose"),
		PRFSalt: bytes.Repeat([]byte{cred}, 32), Transports: "usb"}
}

func prfOf(cred byte) []byte { return bytes.Repeat([]byte{cred, 0xaa}, 16) }

func TestUnlockMethods(t *testing.T) {
	ctx := context.Background()
	s, h := newMethodsDB(t)
	kr := krOf(t, h)

	ms, err := h.Methods(ctx)
	if err != nil || len(ms) != 1 || ms[0].Type != vault.SlotPassword || ms[0].Label != DefaultPasswordLabel {
		t.Fatalf("a new database has one password: %+v %v", ms, err)
	}
	first := ms[0].UUID

	// A second password, a security key and a passkey all open the same DEK.
	if _, err := h.AddPassword(ctx, kr, "Office", []byte("short")); !errors.Is(err, ErrShortPassword) {
		t.Fatalf("short password: %v", err)
	}
	if _, err := h.AddPassword(ctx, kr, "  ", []byte("long enough")); !errors.Is(err, ErrBadLabel) {
		t.Fatalf("empty label: %v", err)
	}
	office, err := h.AddPassword(ctx, kr, "  Office   laptop ", []byte("second password"))
	if err != nil || office.Label != "Office laptop" {
		t.Fatalf("%+v %v", office, err)
	}
	yk, err := h.AddWebAuthn(ctx, kr, webauthnMethod(vault.SlotSecurityKey, "YubiKey A", 1), prfOf(1))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := h.AddWebAuthn(ctx, kr, webauthnMethod(vault.SlotPasskey, "iCloud", 2), prfOf(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.AddWebAuthn(ctx, kr, webauthnMethod(vault.SlotPassword, "x", 3), prfOf(3)); !errors.Is(err, ErrBadMethodType) {
		t.Fatalf("password through AddWebAuthn: %v", err)
	}
	if _, err := h.AddWebAuthn(ctx, kr, webauthnMethod(vault.SlotSecurityKey, "dup", 1), prfOf(1)); err == nil {
		t.Fatal("same credential added twice")
	}

	same := func(k *vault.Keyring, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		defer k.Wipe()
		blob, err := kr.Seal([]byte("probe"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := k.Open(blob, nil); err != nil || string(got) != "probe" {
			t.Fatalf("another data key: %v", err)
		}
	}
	same(h.Unlock(ctx, []byte("second password")))
	same(h.Unlock(ctx, testPassword))
	m, err := h.MethodByCredential(ctx, yk.CredentialID)
	if err != nil {
		t.Fatal(err)
	}
	same(h.UnlockSecret(ctx, m, prfOf(1), 5))
	if _, err := h.UnlockSecret(ctx, m, prfOf(2), 6); !errors.Is(err, pki.ErrWrongPassword) {
		t.Fatalf("other key's PRF output: %v", err)
	}
	m, _ = h.Method(ctx, yk.UUID)
	if m.SignCount != 5 || m.LastUsed.IsZero() {
		t.Fatalf("use not recorded: %+v", m)
	}
	pm, _ := h.Method(ctx, pk.UUID)
	same(h.UnlockSecret(ctx, pm, prfOf(2), 0))

	// The backup code opens the database once; generating again replaces it.
	code, err := h.GenerateBackupCode(ctx, kr)
	if err != nil {
		t.Fatal(err)
	}
	code2, err := h.GenerateBackupCode(ctx, kr)
	if err != nil || code2 == code {
		t.Fatal("backup code not replaced", err)
	}
	if bc, _ := h.DB.UnlockMethodsOfType(ctx, vault.SlotBackupCode); len(bc) != 1 {
		t.Fatalf("%d backup codes", len(bc))
	}
	if _, err := h.UnlockBackupCode(ctx, code); !errors.Is(err, pki.ErrWrongPassword) {
		t.Fatalf("replaced code: %v", err)
	}
	same(h.UnlockBackupCode(ctx, strings.ToLower(code2)))
	if _, err := h.UnlockBackupCode(ctx, code2); !errors.Is(err, pki.ErrWrongPassword) {
		t.Fatalf("code used twice: %v", err)
	}

	// Rename, change, remove.
	if err := h.RenameMethod(ctx, yk.UUID, "YubiKey (desk)"); err != nil {
		t.Fatal(err)
	}
	if err := h.ChangePassword(ctx, kr, yk.UUID, []byte("long enough")); !errors.Is(err, ErrNotPassword) {
		t.Fatalf("change a key's password: %v", err)
	}
	if err := h.ChangePassword(ctx, kr, office.UUID, []byte("third password")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Unlock(ctx, []byte("second password")); !errors.Is(err, pki.ErrWrongPassword) {
		t.Fatal("old password still opens")
	}
	same(h.Unlock(ctx, []byte("third password")))
	if _, err := h.Backup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveMethod(ctx, office.UUID); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.Backups("methods"); len(all) != 1 {
		t.Fatalf("backups after removal: %v", all)
	}
	if err := h.RemoveMethod(ctx, first); !errors.Is(err, ErrLastPassword) {
		t.Fatalf("last password: %v", err)
	}
	if err := h.RemoveMethod(ctx, yk.UUID); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveMethod(ctx, yk.UUID); !errors.Is(err, db.ErrNoMethod) {
		t.Fatalf("removed twice: %v", err)
	}

	// The configured password slot stays as it is.
	h.SetConfiguredMethod(first)
	if err := h.RemoveMethod(ctx, first); !errors.Is(err, ErrConfiguredMethod) {
		t.Fatalf("configured slot removed: %v", err)
	}
	if err := h.ChangePassword(ctx, kr, first, []byte("long enough")); !errors.Is(err, ErrConfiguredMethod) {
		t.Fatalf("configured slot changed: %v", err)
	}
	if _, err := h.ReplaceDataKey(ctx, testPassword); !errors.Is(err, ErrBackground) {
		t.Fatalf("data key replaced under the background keyring: %v", err)
	}
	h.SetConfiguredMethod("")

	log, _ := h.AuditLog(ctx, 0, 0, 50)
	actions := map[string]bool{}
	for _, e := range log {
		actions[e.Action] = true
	}
	for _, a := range []string{"method.add", "method.rename", "method.password", "method.remove", "backupcode.generate", "backupcode.used", "backup.purge"} {
		if !actions[a] {
			t.Errorf("no %s in the audit log", a)
		}
	}
}

func TestReplaceDataKeyKeepsOnePassword(t *testing.T) {
	ctx := context.Background()
	_, h := newMethodsDB(t)
	kr := krOf(t, h)
	keyID, err := h.GenerateKey(ctx, "k", "", pki.KeySpec{Type: "EC", Curve: "P-256"}, kr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.AddPassword(ctx, kr, "Second", []byte("second password")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.AddWebAuthn(ctx, kr, webauthnMethod(vault.SlotSecurityKey, "Key", 9), prfOf(9)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.GenerateBackupCode(ctx, kr); err != nil {
		t.Fatal(err)
	}
	nk, err := h.ReplaceDataKey(ctx, []byte("second password"))
	if err != nil {
		t.Fatal(err)
	}
	defer nk.Wipe()
	ms, _ := h.Methods(ctx)
	if len(ms) != 1 || ms[0].Label != "Second" {
		t.Fatalf("kept %+v", ms)
	}
	if _, err := h.Unlock(ctx, testPassword); !errors.Is(err, pki.ErrWrongPassword) {
		t.Fatal("a removed password still opens")
	}
	got, err := h.Unlock(ctx, []byte("second password"))
	if err != nil {
		t.Fatal(err)
	}
	defer got.Wipe()
	sk, err := h.DB.StoredPrivateKey(ctx, keyID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := got.Open(sk.Blob, sk.Public); err != nil {
		t.Fatalf("key not re-sealed with the new data key: %v", err)
	}
	if _, err := kr.Open(sk.Blob, sk.Public); err == nil {
		t.Fatal("the old data key still opens the key")
	}
}

func TestMethodLimits(t *testing.T) {
	ctx := context.Background()
	_, h := newMethodsDB(t)
	kr := krOf(t, h)
	for i := 1; i < MaxPasswords; i++ {
		if _, err := h.AddPassword(ctx, kr, "p", []byte("password number")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.AddPassword(ctx, kr, "p", []byte("password number")); !errors.Is(err, ErrTooManyMethods) {
		t.Fatalf("password %d: %v", MaxPasswords+1, err)
	}
	for i := range MaxWebAuthn {
		if _, err := h.AddWebAuthn(ctx, kr, webauthnMethod(vault.SlotPasskey, "k", byte(i+10)), prfOf(byte(i+10))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.AddWebAuthn(ctx, kr, webauthnMethod(vault.SlotSecurityKey, "k", 99), prfOf(99)); !errors.Is(err, ErrTooManyMethods) {
		t.Fatalf("key %d: %v", MaxWebAuthn+1, err)
	}
	if _, err := h.AddPassword(ctx, kr, strings.Repeat("x", MaxLabelLength+1), []byte("long enough")); !errors.Is(err, ErrBadLabel) {
		t.Fatalf("long label: %v", err)
	}
}

func TestWebAuthnUserAndCost(t *testing.T) {
	ctx := context.Background()
	_, h := newMethodsDB(t)
	u1, err := h.WebAuthnUser(ctx)
	if err != nil || len(u1) != 16 {
		t.Fatal(u1, err)
	}
	if u2, _ := h.WebAuthnUser(ctx); !bytes.Equal(u1, u2) {
		t.Fatal("user handle changed")
	}
	p := vault.Params{MemoryKiB: 128, Time: 2, Threads: 1}
	if err := h.SetKDFParams(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.KDFParams(ctx); got != p {
		t.Fatalf("cost %+v", got)
	}
	// New passwords use it; the first keeps its own.
	kr := krOf(t, h)
	m, err := h.AddPassword(ctx, kr, "New", []byte("new password"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.KDF, "m=128,t=2,p=1$") {
		t.Fatalf("kdf %q", m.KDF)
	}
	if _, err := h.Unlock(ctx, testPassword); err != nil {
		t.Fatal(err)
	}
	if err := h.SetKDFParams(ctx, vault.Params{}); err == nil {
		t.Fatal("invalid cost accepted")
	}
}

package db

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestUnlockMethods(t *testing.T) {
	ctx := context.Background()
	sqldb := newDB(t)
	d, err := Open(ctx, sqldb)
	if err != nil {
		t.Fatal(err)
	}
	pw := UnlockMethod{Type: "password", Label: "Password", KDF: "argon2id$x", Wrapped: []byte("w1")}
	key := UnlockMethod{Type: "security_key", Label: "YubiKey", KDF: "hkdf-sha256$x", Wrapped: []byte("w2"),
		CredentialID: []byte("cred"), PublicKey: []byte("cose"), PRFSalt: []byte("salt"), Transports: "usb,nfc"}
	err = d.Write(ctx, func(tx *Tx) error {
		if err := tx.InsertUnlockMethod(ctx, &pw); err != nil {
			return err
		}
		return tx.InsertUnlockMethod(ctx, &key)
	})
	if err != nil || pw.UUID == "" || key.ID == 0 {
		t.Fatalf("insert: %v %+v", err, pw)
	}
	got, err := d.UnlockMethodByCredential(ctx, []byte("cred"))
	if err != nil || got.UUID != key.UUID || !got.WebAuthn() || got.Transports != "usb,nfc" || !bytes.Equal(got.PRFSalt, []byte("salt")) {
		t.Fatalf("by credential: %+v %v", got, err)
	}
	if err := d.Write(ctx, func(tx *Tx) error { return tx.TouchUnlockMethod(ctx, key.UUID, 7) }); err != nil {
		t.Fatal(err)
	}
	ms, err := d.UnlockMethods(ctx)
	if err != nil || len(ms) != 2 || ms[0].UUID != key.UUID || ms[0].SignCount != 7 || ms[0].LastUsed.IsZero() {
		t.Fatalf("list, most recently used first: %+v %v", ms, err)
	}
	if types, err := MethodTypes(ctx, sqldb); err != nil || types["password"] != 1 || types["security_key"] != 1 {
		t.Fatalf("types %v %v", types, err)
	}

	// The schema enforces one backup code, WebAuthn fields on keys only,
	// known types and a fixed UUID.
	bad := []UnlockMethod{
		{Type: "security_key", Label: "x", KDF: "k", Wrapped: []byte("w")},
		{Type: "password", Label: "x", KDF: "k", Wrapped: []byte("w"), CredentialID: []byte("c2"), PublicKey: []byte("p"), PRFSalt: []byte("s")},
		{Type: "token", Label: "x", KDF: "k", Wrapped: []byte("w")},
	}
	for _, m := range bad {
		if err := d.Write(ctx, func(tx *Tx) error { return tx.InsertUnlockMethod(ctx, &m) }); err == nil {
			t.Errorf("%s accepted", m.Type)
		}
	}
	code := func() error {
		return d.Write(ctx, func(tx *Tx) error {
			return tx.InsertUnlockMethod(ctx, &UnlockMethod{Type: "backup_code", Label: "Backup code", KDF: "k", Wrapped: []byte("w")})
		})
	}
	if err := code(); err != nil {
		t.Fatal(err)
	}
	if err := code(); err == nil {
		t.Fatal("second backup code accepted")
	}
	if _, err := sqldb.Exec("UPDATE unlock_methods SET uuid='00000000-0000-0000-0000-000000000000' WHERE id=?", pw.ID); err == nil {
		t.Fatal("uuid changed")
	}

	err = d.Write(ctx, func(tx *Tx) error {
		if err := tx.RewrapUnlockMethod(ctx, pw.UUID, "argon2id$y", []byte("w3")); err != nil {
			return err
		}
		if err := tx.RenameUnlockMethod(ctx, pw.UUID, "Office"); err != nil {
			return err
		}
		return tx.DeleteUnlockMethod(ctx, key.UUID)
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := d.UnlockMethod(ctx, pw.UUID)
	if err != nil || m.Label != "Office" || m.KDF != "argon2id$y" || string(m.Wrapped) != "w3" {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := d.UnlockMethod(ctx, key.UUID); !errors.Is(err, ErrNoMethod) {
		t.Fatalf("deleted: %v", err)
	}
	if err := d.Write(ctx, func(tx *Tx) error { return tx.DeleteUnlockMethod(ctx, key.UUID) }); !errors.Is(err, ErrNoMethod) {
		t.Fatalf("delete twice: %v", err)
	}
}

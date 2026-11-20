package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPasskeyStore(t *testing.T) {
	dir := t.TempDir()
	p, err := OpenPasskeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Count() != 0 || len(p.UserID()) != 16 {
		t.Fatalf("new store: %d passkeys, user id %x", p.Count(), p.UserID())
	}
	uid := p.UserID()
	a, err := p.Add(Passkey{Label: " Mac ", CredentialID: []byte{1}, PublicKey: []byte{2}})
	if err != nil || a.ID == "" || a.Label != "Mac" {
		t.Fatalf("add: %+v %v", a, err)
	}
	if _, err := p.Add(Passkey{Label: "mac", CredentialID: []byte{3}, PublicKey: []byte{4}}); !errors.Is(err, ErrPasskeyDuplicate) {
		t.Fatalf("duplicate label: %v", err)
	}
	if _, err := p.Add(Passkey{Label: "Other", CredentialID: []byte{1}, PublicKey: []byte{4}}); !errors.Is(err, ErrPasskeyKnown) {
		t.Fatalf("known credential: %v", err)
	}
	if _, err := p.Add(Passkey{Label: "", CredentialID: []byte{5}, PublicKey: []byte{4}}); !errors.Is(err, ErrPasskeyLabel) {
		t.Fatalf("empty label: %v", err)
	}
	b, err := p.Add(Passkey{Label: "Phone", CredentialID: []byte{3}, PublicKey: []byte{4}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Used([]byte{3}, 7); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, StateDir, PasskeysFile)
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: %v %v", fi, err)
	}
	q, err := OpenPasskeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(q.UserID()) != string(uid) || q.Count() != 2 {
		t.Fatalf("reloaded: user id changed or %d passkeys", q.Count())
	}
	if k, ok := q.ByCredential([]byte{3}); !ok || k.SignCount != 7 || k.LastUsed.IsZero() || k.ID != b.ID {
		t.Fatalf("reloaded phone: %+v", k)
	}
	if _, ok, err := q.Remove(a.ID); !ok || err != nil {
		t.Fatalf("remove: %v %v", ok, err)
	}
	if _, ok, _ := q.Remove(a.ID); ok {
		t.Fatal("removed twice")
	}
	if q.Count() != 1 || q.List()[0].Label != "Phone" {
		t.Fatalf("after remove: %+v", q.List())
	}

	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPasskeys(dir); err == nil {
		t.Fatal("a corrupt file was accepted")
	}
}

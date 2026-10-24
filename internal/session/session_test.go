package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/store"
	"github.com/mailsvb/openkca/internal/vault"
)

var cheap = vault.Params{MemoryKiB: 64, Time: 1, Threads: 1}

func handle(t *testing.T) (*store.Store, *store.Handle) {
	t.Helper()
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Create(ctx, "db", []byte("password"), cheap); err != nil {
		t.Fatal(err)
	}
	h, err := s.Acquire(ctx, "db")
	if err != nil {
		t.Fatal(err)
	}
	return s, h
}

func locked(kr *vault.Keyring) bool {
	_, err := kr.Seal([]byte("x"), nil)
	return errors.Is(err, vault.ErrLocked)
}

// Ending a session wipes its keyring and releases the database.
func TestKeyringWiped(t *testing.T) {
	s, h := handle(t)
	m := NewManager(time.Hour)
	kr, err := h.Unlock(context.Background(), []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	sess := m.Create("srv", "db", h, kr, nil)
	if !sess.Ready() || m.Get(sess.ID, "srv", "db") != sess {
		t.Fatal("session not ready")
	}
	if m.Get(sess.ID, "other", "db") != nil || m.Get(sess.ID, "srv", "other") != nil {
		t.Fatal("session reachable from another browser or database")
	}
	// A new keyring (password change) wipes the old one.
	kr2 := kr.Clone()
	sess.SetKeyring(kr2)
	if !locked(kr) || locked(kr2) {
		t.Fatal("old keyring not wiped on replacement")
	}
	m.EndServer("srv")
	if !locked(kr2) || sess.Keyring() != nil {
		t.Fatal("keyring not wiped when the server session ended")
	}
	// The database was released: it can be opened again by another Store
	// (the lock file is free).
	s2, err := store.New(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := s2.Acquire(context.Background(), "db")
	if err != nil {
		t.Fatalf("database still locked: %v", err)
	}
	h2.Release()
}

// Idle sessions end with the sweep.
func TestIdle(t *testing.T) {
	_, h := handle(t)
	m := NewManager(time.Millisecond)
	kr, _ := h.Unlock(context.Background(), []byte("password"))
	sess := m.Create("srv", "db", h, kr, nil)
	time.Sleep(5 * time.Millisecond)
	m.Sweep()
	if m.Get(sess.ID, "srv", "db") != nil || !locked(kr) {
		t.Fatal("idle session survived")
	}
}

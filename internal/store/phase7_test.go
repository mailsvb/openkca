package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mailsvb/openkca/internal/db"
)

// The trash: links read as unknown while an item is there, come back on
// restore and are cleared when it is purged, which also removes it from
// the file.
func TestTrash(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	p := buildSet(t, s, "trash", testPassword)
	h := p.h
	snap, _ := h.Snapshot(ctx)
	leaf := findCert(snap, p.leaf)
	keyID := leaf.KeyID
	if keyID == 0 || leaf.IssuerID != p.sub {
		t.Fatalf("leaf %+v", leaf)
	}
	keyBlob, _, _ := h.DB.PrivateKey(ctx, keyID)

	// trash the key and the issuing CA
	if err := h.Delete(ctx, keyID); err != nil {
		t.Fatal(err)
	}
	if err := h.Delete(ctx, p.sub); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	leaf = findCert(snap, p.leaf)
	if findKey(snap, keyID) != nil || findCert(snap, p.sub) != nil || leaf.KeyID != 0 || leaf.IssuerID != 0 || snap.Trashed != 2 {
		t.Fatalf("after trashing: leaf %+v, trashed %d", leaf, snap.Trashed)
	}
	for _, r := range snap.Revocations {
		if r.CAID == p.sub {
			t.Fatal("revocations of a trashed CA listed")
		}
	}
	trash, _ := h.Trash(ctx)
	if len(trash) != 2 {
		t.Fatalf("trash %+v", trash)
	}
	if err := h.Delete(ctx, keyID); err == nil {
		t.Fatal("trashed twice")
	}

	// restore both: links come back
	for _, id := range []int64{keyID, p.sub} {
		if err := h.Restore(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	snap, _ = h.Snapshot(ctx)
	leaf = findCert(snap, p.leaf)
	if leaf.KeyID != keyID || leaf.IssuerID != p.sub || snap.Trashed != 0 {
		t.Fatalf("after restoring: leaf %+v", leaf)
	}
	if _, err := h.unlock(ctx, keyID, findKey(snap, keyID).KeyType, krOf(t, h), nil); err != nil {
		t.Fatalf("restored key: %v", err)
	}

	// purge the key: gone from the file, the certificate keeps no link
	if _, err := h.Purge(ctx, []int64{keyID}); err == nil {
		t.Fatal("purged an item that is not in the trash")
	}
	if err := h.Delete(ctx, keyID); err != nil {
		t.Fatal(err)
	}
	if n, err := h.Purge(ctx, nil); err != nil || n != 1 {
		t.Fatalf("empty trash: %d %v", n, err)
	}
	var link any
	h.DB.SQL.QueryRow("SELECT key FROM certs WHERE item=?", p.leaf).Scan(&link)
	if link != nil {
		t.Fatalf("certificate still links the purged key: %v", link)
	}
	file, _ := os.ReadFile(filepath.Join(s.Dir, "trash.okca"))
	if bytes.Contains(file, keyBlob[20:60]) {
		t.Fatal("the purged key's ciphertext is still in the file")
	}

	// the log has it all, also for the purged item
	log, _ := h.AuditLog(ctx, keyID, 0, 50)
	var actions []string
	for _, e := range log {
		actions = append(actions, e.Action)
	}
	want := []string{"item.purge", "item.trash", "item.restore", "item.trash"}
	if len(actions) < len(want) {
		t.Fatalf("history %v", actions)
	}
	for i, a := range want {
		if actions[i] != a {
			t.Fatalf("history %v, want it to start with %v", actions, want)
		}
	}
	if log[0].ItemName == "" {
		t.Error("purged item's name not kept in the log")
	}
}

// A password change deletes every backup that opens with the old password
// and writes a new one.
func TestPasswordChangePurgesBackups(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "pw", testPassword, testKDF); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "pw")
	var old []string
	for range 3 {
		p, err := h.Backup(ctx)
		if err != nil {
			t.Fatal(err)
		}
		old = append(old, p)
	}
	kr, m, err := h.UnlockPassword(ctx, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Wipe()
	if err := h.ChangePassword(ctx, kr, m.UUID, []byte("another password")); err != nil {
		t.Fatal(err)
	}
	all, _ := s.Backups("pw")
	if len(all) != 1 {
		t.Fatalf("backups after the change: %v", all)
	}
	// the remaining backup is the new state: it opens with the new password
	_ = old
	sqldb, err := openRO(all[0])
	if err != nil {
		t.Fatal(err)
	}
	defer sqldb.Close()
	g, _ := db.Open(ctx, sqldb)
	if _, _, err := unlockPassword(ctx, g, []byte("another password")); err != nil {
		t.Fatalf("the backup does not open with the new password: %v", err)
	}
	actions := map[string]bool{}
	log, _ := h.AuditLog(ctx, 0, 0, 20)
	for _, e := range log {
		actions[e.Action] = true
	}
	if !actions["method.password"] || !actions["backup.purge"] {
		t.Fatalf("audit %+v", log)
	}
}

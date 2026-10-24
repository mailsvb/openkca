package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/go-ca/internal/cadir"
	"github.com/mailsvb/go-ca/internal/gcadb"
)

// allUUIDs maps every item, trash included, to its UUID.
func allUUIDs(t *testing.T, h *Handle) map[int64]string {
	t.Helper()
	rows, err := h.DB.SQL.Query("SELECT id, uuid FROM items")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var u string
		if err := rows.Scan(&id, &u); err != nil {
			t.Fatal(err)
		}
		out[id] = u
	}
	return out
}

func TestItemUUIDs(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	p := buildSet(t, s, "uuids", testPassword)
	h := p.h
	snap, _ := h.Snapshot(ctx)

	// Every item has a canonical UUID of its own, also as loaded.
	ids := allUUIDs(t, h)
	seen := map[string]bool{}
	for id, u := range ids {
		if !cadir.IsUUID(u) || seen[u] {
			t.Fatalf("item %d: uuid %q", id, u)
		}
		seen[u] = true
	}
	for _, c := range snap.Certs {
		if c.UUID != ids[c.ID] {
			t.Fatalf("cert %d loaded with uuid %q, stored %q", c.ID, c.UUID, ids[c.ID])
		}
	}
	for _, k := range snap.Keys {
		if k.UUID != ids[k.ID] {
			t.Fatalf("key %d loaded with uuid %q", k.ID, k.UUID)
		}
	}

	// Lookup by UUID, in any spelling uuid.Parse accepts.
	sub := findCert(snap, p.sub)
	for _, q := range []string{sub.UUID, strings.ToUpper(sub.UUID), "urn:uuid:" + sub.UUID} {
		if id, err := h.DB.ItemIDByUUID(ctx, q); err != nil || id != p.sub {
			t.Fatalf("lookup %q: %d %v", q, id, err)
		}
	}
	if _, err := h.DB.ItemIDByUUID(ctx, "00000000-0000-7000-8000-000000000000"); err != sql.ErrNoRows {
		t.Fatalf("lookup of an unknown uuid: %v", err)
	}
	if _, err := h.DB.ItemIDByUUID(ctx, "../etc"); err == nil {
		t.Fatal("lookup of an invalid uuid")
	}

	// The UUID cannot be changed.
	if _, err := h.DB.SQL.Exec("UPDATE items SET uuid=? WHERE id=?", "00000000-0000-7000-8000-000000000001", p.sub); err == nil {
		t.Fatal("uuid changed")
	}

	// The CA folder is named after the CA's authority ID (for a new CA its
	// UUID) and stays across a rename and a round trip through the trash;
	// other files in it are kept.
	if sub.Authority == nil || sub.Authority.UUID != sub.UUID {
		t.Fatalf("authority of a new CA: %+v", sub.Authority)
	}
	dir, err := h.CADir(sub.Authority.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(s.Dir, "ca", "uuids", sub.UUID); dir != want {
		t.Fatalf("CA folder %s, want %s", dir, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.txt")); err != nil {
		t.Fatal(err)
	}
	if err := h.Rename(ctx, p.sub, "Renamed Sub CA / with ../ odd chars", ""); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if c := findCert(snap, p.sub); c.UUID != sub.UUID {
		t.Fatal("rename changed the uuid")
	}
	if _, err := os.Stat(filepath.Join(dir, "index.txt")); err != nil {
		t.Fatal("index moved on rename")
	}
	extra := filepath.Join(dir, "serial")
	if err := os.WriteFile(extra, []byte("01\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.Delete(ctx, p.sub); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(extra); err != nil {
		t.Fatal("a file of a trashed CA was removed")
	}
	if err := h.Restore(ctx, p.sub); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if c := findCert(snap, p.sub); c == nil || c.UUID != sub.UUID {
		t.Fatal("restore changed the uuid")
	}
	if _, err := os.Stat(filepath.Join(dir, "index.txt")); err != nil {
		t.Fatal("index of the restored CA missing")
	}

	// A trashed CA's folder holding only index files is removed.
	root := findCert(snap, p.root)
	rootDir, _ := h.CADir(root.Authority.UUID)
	if _, err := os.Stat(rootDir); err != nil {
		t.Fatal(err)
	}
	if err := h.Delete(ctx, p.root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rootDir); !os.IsNotExist(err) {
		t.Fatal("index-only folder of a trashed CA kept")
	}

	// Folders that are not CA folders are not touched.
	other := filepath.Join(cadir.Base(s.Dir, "uuids"), "notes")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "index.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h.changed(ctx)
	if _, err := os.Stat(other); err != nil {
		t.Fatal("foreign folder removed")
	}

	// The audit log keeps the UUID of an item.
	log, _ := h.AuditLog(ctx, p.sub, 0, 50)
	if len(log) == 0 {
		t.Fatal("no audit entries")
	}
	for _, e := range log {
		if e.ItemUUID != sub.UUID {
			t.Fatalf("audit entry %+v", e)
		}
	}
}

// TestAuthorityRenewal: renewals with the same key take over the authority
// ID and with it the CA folder; at most one live CA holds an authority ID.
func TestAuthorityRenewal(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	p := buildSet(t, s, "renew", testPassword)
	h := p.h
	snap, _ := h.Snapshot(ctx)
	auth := findCert(snap, p.sub).Authority.UUID
	dir, _ := h.CADir(auth)
	extra := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(extra, []byte("kept\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	authOf := func(id int64) string {
		t.Helper()
		var u string
		if err := h.DB.SQL.QueryRow("SELECT uuid FROM authorities WHERE cert=?", id).Scan(&u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	renew := func(id int64, replace bool) int64 {
		t.Helper()
		n, err := h.Renew(ctx, id, RenewOptions{NotBefore: time.Now(), NotAfter: time.Now().AddDate(6, 0, 0),
			KeepSerial: true, Replace: replace}, krOf(t, h), nil)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Renewed, the old certificate staying live: the renewal takes the
	// authority ID, the old one gets a new ID and folder of its own.
	r1 := renew(p.sub, false)
	if authOf(r1) != auth {
		t.Fatal("renewal did not take over the authority ID")
	}
	old := authOf(p.sub)
	if old == auth || !cadir.IsUUID(old) {
		t.Fatalf("old CA kept authority ID %s", old)
	}
	oldDir, _ := h.CADir(old)
	if _, err := os.Stat(filepath.Join(oldDir, "index.txt")); err != nil {
		t.Fatal("folder of the old CA not written")
	}
	snap, _ = h.Snapshot(ctx)
	b, err := os.ReadFile(filepath.Join(dir, "index.txt"))
	if err != nil || !strings.Contains(string(b), "\t"+findCert(snap, p.leaf).Serial+"\t") {
		t.Fatalf("index in the taken-over folder: %q %v", b, err)
	}
	if _, err := os.Stat(extra); err != nil {
		t.Fatal("file in the CA folder lost")
	}

	// Renewed again, replacing the old certificate: it keeps the ID in the
	// trash and cannot be restored while the renewal is live.
	r2 := renew(r1, true)
	if authOf(r2) != auth || authOf(r1) != auth {
		t.Fatalf("authority IDs %s %s, want %s", authOf(r2), authOf(r1), auth)
	}
	if err := h.Restore(ctx, r1); !errors.Is(err, gcadb.ErrAuthorityInUse) {
		t.Fatalf("restore of a CA whose authority ID is in use: %v", err)
	}
	if err := h.Restore(ctx, p.leaf); err == nil {
		t.Fatal("restored a live item")
	}
	// With the renewal in the trash, the old one comes back with its folder.
	if err := h.Delete(ctx, r2); err != nil {
		t.Fatal(err)
	}
	if err := h.Restore(ctx, r1); err != nil {
		t.Fatal(err)
	}
	if authOf(r1) != auth {
		t.Fatal("restored CA lost its authority ID")
	}
	if err := h.Restore(ctx, r2); !errors.Is(err, gcadb.ErrAuthorityInUse) {
		t.Fatalf("restore of the renewal: %v", err)
	}
	if _, err := os.Stat(extra); err != nil {
		t.Fatal("file in the CA folder lost")
	}
}

// TestImportedUUIDs: items imported from XCA get UUIDs as well.
func TestImportedUUIDs(t *testing.T) {
	s := copyFixtures(t)
	h, _ := load(t, s, "sample")
	ids := allUUIDs(t, h)
	seen := map[string]bool{}
	for id, u := range ids {
		if !cadir.IsUUID(u) || seen[u] {
			t.Fatalf("item %d: uuid %q", id, u)
		}
		seen[u] = true
	}
	if len(ids) == 0 {
		t.Fatal("no items imported")
	}
}

// TestSchema3Refused: go-ca databases from before item UUIDs are not
// migrated; they are listed as invalid and not opened.
func TestSchema3Refused(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "old", testPassword, testKDF); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Dir, "old.gca")
	db, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("UPDATE settings SET value='3' WHERE key='schema'")
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if st, _, _, detail := Classify(ctx, path, true); st != Invalid || !strings.Contains(detail, "schema 3") {
		t.Fatalf("schema 3: %s %q", st, detail)
	}
	if _, err := s.Acquire(ctx, "old"); err == nil {
		t.Fatal("opened a schema 3 database")
	}
	if gcadb.MinMigratable != 4 {
		t.Fatalf("oldest migratable schema %d", gcadb.MinMigratable)
	}
}

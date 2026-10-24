package store

import (
	"bytes"
	"context"
	"database/sql"
	b64 "encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/vault"
)

func TestCreate(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "new-ca", testPassword, vault.Default); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, "new-ca", testPassword, vault.Default); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	// an XCA file waiting for import holds its name
	if err := s.Create(ctx, "sample", testPassword, vault.Default); !errors.Is(err, ErrExists) {
		t.Fatalf("name of an .xdb file: %v", err)
	}
	for _, bad := range []string{"", ".hidden", "a/b", "ä", "x.xdb", "y.GCA", string(bytes.Repeat([]byte("x"), 65))} {
		if err := s.Create(ctx, bad, testPassword, vault.Default); !errors.Is(err, ErrBadName) {
			t.Errorf("name %q: %v", bad, err)
		}
	}
	if err := s.Create(ctx, "short", []byte("1234567"), vault.Default); !errors.Is(err, ErrShortPassword) {
		t.Fatalf("short password: %v", err)
	}
	info, err := s.Lookup(ctx, "new-ca")
	if err != nil || info.Status != Supported || info.XCA || info.Schema != db.Schema ||
		filepath.Base(info.Path) != "new-ca.gca" {
		t.Fatalf("lookup: %+v %v", info, err)
	}
	h, snap := load(t, s, "new-ca")
	if _, ok := snap.Settings["pwhash"]; ok || snap.Settings["kdf"] == "" || snap.Settings["dek"] == "" {
		t.Fatalf("key settings %v", snap.Settings)
	}
	if _, err := h.Unlock(ctx, testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Unlock(ctx, []byte("wrong password")); !errors.Is(err, pki.ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	var fk int
	h.DB.SQL.QueryRow("PRAGMA foreign_keys").Scan(&fk)
	if fk != 1 {
		t.Fatal("foreign keys are not enforced")
	}
	if log, _ := h.AuditLog(ctx, 0, 0, 10); len(log) != 1 || log[0].Action != "database.create" {
		t.Fatalf("audit %+v", log)
	}
	if ents, _ := os.ReadDir(s.Dir); len(ents) == 0 {
		t.Fatal("empty dir")
	} else {
		for _, e := range ents {
			if len(e.Name()) > 5 && e.Name()[:5] == ".tmp-" {
				t.Errorf("temp file left: %s", e.Name())
			}
		}
	}
}

func TestUpload(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	data, _ := os.ReadFile(filepath.Join(fixtures, "sample.xdb"))
	name, err := s.Upload(ctx, `C:\Users\me\My CA.xdb`, bytes.NewReader(data), 1<<20)
	if err != nil || name != "My_CA.xdb" {
		t.Fatalf("upload: %q %v", name, err)
	}
	name, err = s.Upload(ctx, "My CA.xdb", bytes.NewReader(data), 1<<20)
	if err != nil || name != "My_CA-1.xdb" {
		t.Fatalf("collision: %q %v", name, err)
	}
	if _, err := s.Upload(ctx, "big.xdb", bytes.NewReader(data), 1000); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size cap: %v", err)
	}
	for _, f := range []string{"legacy.xdb", "garbage.xdb", "newer.xdb"} {
		b, _ := os.ReadFile(filepath.Join(fixtures, f))
		var rej *RejectedError
		if _, err := s.Upload(ctx, f, bytes.NewReader(b), 1<<20); !errors.As(err, &rej) {
			t.Errorf("%s accepted: %v", f, err)
		}
	}
	// a go-ca database keeps its kind, whatever the file is called
	if err := s.Create(ctx, "native", testPassword, testKDF); err != nil {
		t.Fatal(err)
	}
	gca, _ := os.ReadFile(filepath.Join(s.Dir, "native.gca"))
	if name, err := s.Upload(ctx, "copy.xdb", bytes.NewReader(gca), 1<<20); err != nil || name != "copy" {
		t.Fatalf("go-ca upload: %q %v", name, err)
	}
	if got := SanitizeName("../../etc/passwd"); got != "passwd" {
		t.Errorf("sanitize: %q", got)
	}
	if got := SanitizeName("...."); got != "imported" {
		t.Errorf("sanitize dots: %q", got)
	}
	if got := SanitizeName("a.xdb.gca"); got != "a" {
		t.Errorf("sanitize extensions: %q", got)
	}
}

func TestBackupRetention(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "bk", testPassword, testKDF); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "bk")
	var last string
	for i := 0; i < DefaultBackupKeep+3; i++ {
		p, err := h.Backup(ctx)
		if err != nil {
			t.Fatal(err)
		}
		last = p
	}
	all, _ := s.Backups("bk")
	if len(all) != DefaultBackupKeep || all[0] != last {
		t.Fatalf("backups %d, newest %s, want %s", len(all), all[0], last)
	}
	if st, xca, _, d := Classify(ctx, last, true); st != Supported || xca {
		t.Fatalf("backup status %s %s", st, d)
	}
	if err := h.SetSettings(ctx, map[string]string{"backup_keep": "3"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Backup(ctx); err != nil {
		t.Fatal(err)
	}
	if all, _ = s.Backups("bk"); len(all) != 3 {
		t.Fatalf("backup_keep 3: %d backups", len(all))
	}
	// age: backups older than backup_days go, the newest always stays
	old := time.Now().AddDate(0, 0, -40).UTC().Format("20060102150405")
	for i, p := range all {
		os.Rename(p, filepath.Join(s.BackupDir(), "bk."+old+"-"+strconv.Itoa(i)+".gca"))
	}
	if err := h.SetSettings(ctx, map[string]string{"backup_days": "30"}); err != nil {
		t.Fatal(err)
	}
	if err := s.rotateBackups("bk", 3, 30, time.Now()); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.Backups("bk"); len(all) != 1 {
		t.Fatalf("after the age limit: %v", all)
	}
	if _, err := h.Backup(ctx); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.Backups("bk"); len(all) != 1 {
		t.Fatalf("a new backup keeps only itself among old ones: %v", all)
	}
}

// TestImport imports an XCA database: keys under the database password
// (and XCA's "Bogus" one, and those of deleted items) are sealed with a
// new DEK, keys with their own password stay until it opens them, a key
// the database password does not open keeps its blob and needs its own,
// deleted items go to the trash, and the .xdb file and its old backups are
// deleted.
func TestImport(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	src := filepath.Join(s.Dir, "variants.xdb")
	// Variants the fixture lacks: a "Bogus" key, a deleted item and a key
	// encrypted with another password.
	{
		sqldb, err := sql.Open("sqlite", dsn(src, false))
		if err != nil {
			t.Fatal(err)
		}
		reencrypt := func(item int, typ, from, to string) string {
			var blob string
			sqldb.QueryRow("SELECT private FROM private_keys WHERE item=?", item).Scan(&blob)
			raw, _ := b64.StdEncoding.DecodeString(blob)
			der, err := legacyDER(raw, typ, []byte(from))
			if err != nil {
				t.Fatal(err)
			}
			enc, err := pki.EncryptPKCS8(der, []byte(to))
			if err != nil {
				t.Fatal(err)
			}
			return b64.StdEncoding.EncodeToString(enc)
		}
		for _, st := range []struct {
			q    string
			args []any
		}{
			{"UPDATE private_keys SET ownPass=2, private=? WHERE item=14", []any{reencrypt(14, "RSA", "secret", "Bogus")}},
			{"UPDATE private_keys SET private=? WHERE item=18", []any{reencrypt(18, "EC", "secret", "other")}},
			{"UPDATE items SET del=1 WHERE id=12", nil},
		} {
			if _, err := sqldb.Exec(st.q, st.args...); err != nil {
				t.Fatal(err)
			}
		}
		sqldb.Close()
	}
	// a file in the backup folder named like the source is not touched
	os.MkdirAll(s.BackupDir(), 0o700)
	other := filepath.Join(s.BackupDir(), "variants.20260101000000.xdb")
	os.WriteFile(other, []byte("other"), 0o600)

	if _, err := s.StartImport(ctx, "variants.xdb", []byte("wrong"), testKDF); !errors.Is(err, pki.ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	c, err := s.StartImport(ctx, "variants.xdb", fixturePassword, testKDF)
	if err != nil {
		t.Fatal(err)
	}
	<-c.Finished()
	kr, rep, err := c.Result()
	if err != nil {
		t.Fatal(err)
	}
	if done, total := c.Progress(); done != 8 || total != 8 {
		t.Errorf("progress %d/%d", done, total)
	}
	if rep.Target != "variants" || rep.Converted != 7 || rep.Unopened != 1 || rep.OwnPassLegacy != 1 ||
		rep.Trashed != 1 || len(rep.Skipped) != 0 || len(rep.Removed) != 1 {
		t.Fatalf("report %+v", rep)
	}
	if b, _ := s.Backups("variants"); len(b) != 1 {
		t.Errorf("backups of the new database: %v", b)
	}
	for _, p := range []string{src, src + ".lock"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists", filepath.Base(p))
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("a file in the backup folder was removed")
	}
	h, snap := load(t, s, "variants")
	setKR(h, kr)
	if _, err := h.Unlock(ctx, fixturePassword); err != nil {
		t.Fatal(err)
	}
	trash, _ := h.Trash(ctx)
	if len(trash) != 1 || trash[0].ID != 12 || findKey(snap, 12) != nil {
		t.Fatalf("trash %+v", trash)
	}

	rows, _ := h.DB.PrivateKeyRows(ctx)
	for _, r := range rows {
		switch r.ID {
		case 10, 18: // own password: mail (XCA), pending (did not open)
			if r.Protection != db.ProtPassword || vault.IsSealed(r.Blob) {
				t.Errorf("key %d: protection %d, sealed %v", r.ID, r.Protection, vault.IsSealed(r.Blob))
			}
			continue
		}
		if r.Protection != db.ProtDEK || vault.Mode(r.Blob) != vault.ModeDEK {
			t.Errorf("key %d: protection %d, mode %d", r.ID, r.Protection, vault.Mode(r.Blob))
			continue
		}
		der, err := kr.Open(r.Blob, r.Public)
		if err != nil {
			t.Errorf("key %d: %v", r.ID, err)
			continue
		}
		priv, err := pki.ParsePKCS8(der)
		if err != nil {
			t.Errorf("key %d: %v", r.ID, err)
			continue
		}
		if ok, _ := pki.MatchesPublic(priv, r.Public); !ok {
			t.Errorf("key %d: mismatch after import", r.ID)
		}
		if r.ID == 12 && !r.Trashed {
			t.Error("the deleted item is not in the trash")
		}
	}

	// Keys with their own password move to go-ca's form once it opens them.
	for id, pw := range map[int64]string{10: "mailpass", 18: "other"} {
		k := findKey(snap, id)
		if !k.Legacy {
			t.Errorf("key %d not marked legacy", id)
		}
		if _, err := h.unlock(ctx, id, k.KeyType, kr, KeyPasswords{id: []byte("wrong")}); !errors.Is(err, ErrNeedKeyPassword) {
			t.Errorf("key %d with a wrong password: %v", id, err)
		}
		if algo, ok, err := h.CheckKey(ctx, k, kr, []byte(pw)); err != nil || !ok || algo == "" {
			t.Errorf("key %d check: %s %v %v", id, algo, ok, err)
		}
		sk, _ := h.DB.StoredPrivateKey(ctx, id)
		if sk.Protection != db.ProtPassword || vault.Mode(sk.Blob) != vault.ModePassword {
			t.Errorf("key %d not upgraded: protection %d, mode %d", id, sk.Protection, vault.Mode(sk.Blob))
		}
	}
	snap, _ = h.Snapshot(ctx)
	for _, k := range snap.Keys {
		if k.Legacy {
			t.Errorf("key %s still legacy", k.Name)
		}
	}
}

// Every fixture imports, also those with XCA's older password hashes.
func TestImportFixtures(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	for _, name := range []string{"sample", "schema8", "md5"} {
		kr, rep, err := s.Import(ctx, name+".xdb", fixturePassword, testKDF)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.Converted != 10 || rep.Unopened != 0 || rep.Target != name {
			t.Errorf("%s: report %+v", name, rep)
		}
		h, snap := load(t, s, name)
		for _, k := range snap.Keys {
			if k.HasPrivate {
				if _, err := h.unlock(ctx, k.ID, k.KeyType, kr, nil); err != nil {
					t.Errorf("%s/%s: %v", name, k.Name, err)
				}
			}
		}
	}
}

// A database from go-ca's former XCA based format is not imported.
func TestFormerGoCARefused(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	path := filepath.Join(s.Dir, "sample.xdb")
	sqldb, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"UPDATE settings SET value='1000' WHERE key_='schema'",
		"INSERT INTO settings (key_, value) VALUES ('gca_schema', '2')",
	} {
		if _, err := sqldb.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	sqldb.Close()
	info, _ := s.Lookup(ctx, "sample.xdb")
	if info.Status != Invalid || !strings.Contains(info.Detail, "former") {
		t.Fatalf("lookup %+v", info)
	}
	if _, _, err := s.Import(ctx, "sample.xdb", fixturePassword, testKDF); err == nil {
		t.Fatal("imported go-ca's former format")
	}
}

// A database from a newer go-ca is refused.
func TestNewerGoCA(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "next", testPassword, testKDF); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Dir, "next.gca")
	sqldb, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	_, err = sqldb.Exec("UPDATE settings SET value=? WHERE key='schema'", strconv.Itoa(db.Schema+1))
	sqldb.Close()
	if err != nil {
		t.Fatal(err)
	}
	if st, _, v, _ := Classify(ctx, path, true); st != Newer || v.Schema != db.Schema+1 {
		t.Fatalf("newer go-ca: %s %+v", st, v)
	}
	if _, err := s.Acquire(ctx, "next"); err == nil {
		t.Fatal("opened a newer go-ca database")
	}
}

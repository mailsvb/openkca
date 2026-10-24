package store

import (
	"bytes"
	"context"
	"database/sql"
	b64 "encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/vault"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// schemaSQL returns the sorted DDL of a database file.
func schemaSQL(t *testing.T, path string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// gocaDDL is the DDL of a file XCA created and upgraded to schema 8, plus
// go-ca's tables.
func gocaDDL(t *testing.T) []string {
	out := append(schemaSQL(t, filepath.Join(fixtures, "schema8.xdb")),
		"CREATE TABLE gca_pgp (item INTEGER UNIQUE, fingerprint VARCHAR(64), cert TEXT, FOREIGN KEY (item) REFERENCES items (id))",
		"CREATE INDEX i_gca_pgp_item ON gca_pgp (item)")
	sort.Strings(out)
	return out
}

func TestCreate(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "new-ca", testPassword, vault.Default); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, "new-ca", testPassword, vault.Default); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	for _, bad := range []string{"", ".hidden", "a/b", "ä", strings.Repeat("x", 65)} {
		if err := s.Create(ctx, bad, nil, vault.Default); !errors.Is(err, ErrBadName) {
			t.Errorf("name %q: %v", bad, err)
		}
	}
	info, err := s.Lookup(ctx, "new-ca")
	if err != nil || info.Status != Supported || info.Schema != xdb.LockoutSchema || info.GoCA != xdb.CurrentSchema {
		t.Fatalf("lookup: %+v %v", info, err)
	}
	// XCA's schema 8 DDL plus go-ca's tables.
	got := schemaSQL(t, info.Path)
	want := gocaDDL(t)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("DDL differs:\n got %q\nwant %q", got, want)
	}
	if err := s.Create(ctx, "short", []byte("1234567"), vault.Default); !errors.Is(err, ErrShortPassword) {
		t.Fatalf("short password: %v", err)
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
	if snap.Settings["legacy-keys-updated"] != "yes" || len(snap.Keys)+len(snap.Certs) != 0 {
		t.Fatalf("settings %v", snap.Settings)
	}
	_ = h
	if ents, _ := os.ReadDir(s.Dir); len(ents) == 0 {
		t.Fatal("empty dir")
	} else {
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".tmp-") {
				t.Errorf("temp file left: %s", e.Name())
			}
		}
	}
}

func TestImport(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	data, _ := os.ReadFile(filepath.Join(fixtures, "sample.xdb"))
	name, err := s.Import(ctx, `C:\Users\me\My CA.xdb`, bytes.NewReader(data), 1<<20)
	if err != nil || name != "My_CA" {
		t.Fatalf("import: %q %v", name, err)
	}
	name, err = s.Import(ctx, "My CA.xdb", bytes.NewReader(data), 1<<20)
	if err != nil || name != "My_CA-1" {
		t.Fatalf("collision: %q %v", name, err)
	}
	if _, err := s.Import(ctx, "big.xdb", bytes.NewReader(data), 1000); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size cap: %v", err)
	}
	for _, f := range []string{"legacy.xdb", "garbage.xdb", "newer.xdb"} {
		b, _ := os.ReadFile(filepath.Join(fixtures, f))
		var rej *RejectedError
		if _, err := s.Import(ctx, f, bytes.NewReader(b), 1<<20); !errors.As(err, &rej) {
			t.Errorf("%s accepted: %v", f, err)
		}
	}
	if got := SanitizeName("../../etc/passwd"); got != "passwd" {
		t.Errorf("sanitize: %q", got)
	}
	if got := SanitizeName("...."); got != "imported" {
		t.Errorf("sanitize dots: %q", got)
	}
}

func TestBackupRotation(t *testing.T) {
	s := copyFixtures(t)
	h, _ := load(t, s, "sample")
	var last string
	for i := 0; i < KeepBackups+3; i++ {
		p, err := h.Backup(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		last = p
	}
	all, _ := s.Backups("sample")
	if len(all) != KeepBackups || all[0] != last {
		t.Fatalf("backups %d, newest %s, want %s", len(all), all[0], last)
	}
	if st, _, d := Classify(context.Background(), last, true); st != Upgradable {
		t.Fatalf("backup status %s %s", st, d)
	}
}

// TestConvert converts an XCA database: keys under the database password
// (and XCA's "Bogus" one, and those of deleted items) are sealed with a new
// DEK, keys with their own password stay until it opens them, and a key
// the database password does not open keeps its blob and needs its own.
func TestConvert(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	path := filepath.Join(s.Dir, "variants.xdb")
	// Variants the fixture lacks: a "Bogus" key, a deleted item and a key
	// encrypted with another password.
	{
		h, snap := load(t, s, "variants")
		reencrypt := func(name, from, to string) []byte {
			for _, k := range snap.Keys {
				if k.Name == name {
					blob, _, _ := h.DB.PrivateKey(ctx, k.ID)
					der, err := legacyDER(blob, k.KeyType, []byte(from))
					if err != nil {
						t.Fatal(err)
					}
					enc, err := pki.EncryptPKCS8(der, []byte(to))
					if err != nil {
						t.Fatal(err)
					}
					return enc
				}
			}
			t.Fatalf("no key %s", name)
			return nil
		}
		for _, st := range []struct {
			q    string
			args []any
		}{
			{"UPDATE private_keys SET ownPass=2, private=? WHERE item=14", []any{b64.StdEncoding.EncodeToString(reencrypt("old", "secret", "Bogus"))}},
			{"UPDATE private_keys SET private=? WHERE item=18", []any{b64.StdEncoding.EncodeToString(reencrypt("pending", "secret", "other"))}},
			{"UPDATE items SET del=1 WHERE id=12", nil},
		} {
			if _, err := h.DB.SQL.Exec(st.q, st.args...); err != nil {
				t.Fatal(err)
			}
		}
		h.Release()
	}

	h, err := s.Acquire(ctx, "variants")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Release)
	c := h.StartConversion(fixturePassword, testKDF)
	<-c.Finished()
	kr, rep, err := c.Result()
	if err != nil {
		t.Fatal(err)
	}
	if done, total := c.Progress(); done != 8 || total != 8 {
		t.Errorf("progress %d/%d", done, total)
	}
	if rep.UpgradedFrom != 7 || rep.Converted != 7 || rep.Unopened != 1 || rep.OwnPassLegacy != 1 || rep.Backup == "" {
		t.Fatalf("report %+v", rep)
	}
	if !h.DB.Current() {
		t.Fatal(h.DB.Version())
	}
	if got := schemaSQL(t, path); strings.Join(got, "\n") != strings.Join(gocaDDL(t), "\n") {
		t.Fatal("converted DDL differs from a new go-ca database")
	}
	if st, v, _ := Classify(ctx, path, true); st != Supported || v.GoCA != xdb.CurrentSchema {
		t.Fatalf("after conversion: %s %+v", st, v)
	}
	if st, _, _ := Classify(ctx, rep.Backup, true); st != Upgradable {
		t.Fatalf("backup: %s", st)
	}
	snap, _ := h.Snapshot(ctx)
	if _, ok := snap.Settings["pwhash"]; ok {
		t.Fatal("XCA's password hash is still stored")
	}
	if _, err := h.Unlock(ctx, fixturePassword); err != nil {
		t.Fatal(err)
	}

	rows, _ := h.DB.PrivateKeyRows(ctx, true)
	for _, r := range rows {
		switch r.ID {
		case 10, 18: // own password: mail (XCA), pending (did not open)
			if r.OwnPass != xdb.PassPrivate || vault.IsSealed(r.Blob) {
				t.Errorf("key %d: ownPass %d, sealed %v", r.ID, r.OwnPass, vault.IsSealed(r.Blob))
			}
			continue
		}
		if r.OwnPass != xdb.PassCommon || vault.Mode(r.Blob) != vault.ModeDEK {
			t.Errorf("key %d: ownPass %d, mode %d", r.ID, r.OwnPass, vault.Mode(r.Blob))
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
			t.Errorf("key %d: mismatch after conversion", r.ID)
		}
		if r.ID == 12 && !r.Deleted {
			t.Error("the deleted item is listed as live")
		}
	}
	for _, k := range snap.Keys {
		if k.Name == "www" && k.Stamp != snap.Stamp {
			t.Errorf("converted key stamp %d, max %d", k.Stamp, snap.Stamp)
		}
	}

	// Keys with their own password move to go-ca's form once it opens them.
	for id, pw := range map[int64]string{10: "mailpass", 18: "other"} {
		k := findKey(snap, id)
		if _, err := h.unlock(ctx, id, k.KeyType, kr, nil); !errors.Is(err, ErrNeedKeyPassword) {
			t.Errorf("key %d without password: %v", id, err)
		}
		if _, err := h.unlock(ctx, id, k.KeyType, kr, KeyPasswords{id: []byte("wrong")}); !errors.Is(err, ErrNeedKeyPassword) {
			t.Errorf("key %d with a wrong password: %v", id, err)
		}
		if _, err := h.unlock(ctx, id, k.KeyType, kr, KeyPasswords{id: []byte(pw)}); err != nil {
			t.Errorf("key %d: %v", id, err)
		}
		blob, own, _ := h.DB.PrivateKey(ctx, id)
		if own != xdb.PassPrivate || vault.Mode(blob) != vault.ModePassword {
			t.Errorf("key %d not upgraded: ownPass %d, mode %d", id, own, vault.Mode(blob))
		}
		if algo, ok, err := h.CheckKey(ctx, k, kr, []byte(pw)); err != nil || !ok || algo == "" {
			t.Errorf("key %d check: %s %v %v", id, algo, ok, err)
		}
	}

	// A second conversion is the finished one: no new backup.
	before, _ := s.Backups("variants")
	if _, _, err := h.Convert(ctx, fixturePassword, testKDF); err != nil {
		t.Fatal(err)
	}
	if after, _ := s.Backups("variants"); len(after) != len(before) {
		t.Fatal("second conversion took a backup")
	}
}

// Every fixture converts, also those with XCA's older password hashes.
func TestConvertFixtures(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	for _, name := range []string{"sample", "schema8", "md5"} {
		h, _ := load(t, s, name)
		ok, err := h.VerifyLegacyPassword(ctx, fixturePassword)
		if err != nil || !ok {
			t.Fatalf("%s: password %v %v", name, ok, err)
		}
		if ok, _ := h.VerifyLegacyPassword(ctx, []byte("wrong")); ok {
			t.Fatalf("%s: wrong password accepted", name)
		}
		kr, rep, err := h.Convert(ctx, fixturePassword, testKDF)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.Converted != 10 || rep.Unopened != 0 {
			t.Errorf("%s: report %+v", name, rep)
		}
		snap, _ := h.Snapshot(ctx)
		for _, k := range snap.Keys {
			if k.HasPrivate {
				if _, err := h.unlock(ctx, k.ID, k.KeyType, kr, nil); err != nil {
					t.Errorf("%s/%s: %v", name, k.Name, err)
				}
			}
		}
	}
}

// A database from a newer go-ca is refused.
func TestNewerGoCA(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "next", testPassword, vault.Default); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Dir, "next.xdb")
	db, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("UPDATE settings SET value=? WHERE key_='gca_schema'", strconv.Itoa(xdb.CurrentSchema+1))
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if st, v, _ := Classify(ctx, path, true); st != Newer || v.Schema != xdb.LockoutSchema {
		t.Fatalf("newer go-ca: %s %+v", st, v)
	}
	if _, err := s.Acquire(ctx, "next"); err == nil {
		t.Fatal("opened a newer go-ca database")
	}
}

package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/xdb"
	"github.com/mailsvb/go-ca/internal/xdbpass"
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
	if err := s.Create(ctx, "new-ca", []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, "new-ca", []byte("pw")); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	for _, bad := range []string{"", ".hidden", "a/b", "ä", strings.Repeat("x", 65)} {
		if err := s.Create(ctx, bad, nil); !errors.Is(err, ErrBadName) {
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
	h, snap := load(t, s, "new-ca")
	if ok, up := xdbpass.Verify(snap.Settings["pwhash"], []byte("pw")); !ok || up {
		t.Fatal("password hash")
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

func TestPrepareAfterLogin(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()

	h, _ := load(t, s, "variants")
	rep, err := h.PrepareAfterLogin(ctx, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.UpgradedFrom != 7 || rep.ConvertedKeys != 1 || rep.Backup == "" {
		t.Fatalf("report %+v", rep)
	}
	if !h.DB.Current() {
		t.Fatalf("schema %d, go-ca %d", h.DB.Schema, h.DB.GoCA)
	}
	got := schemaSQL(t, filepath.Join(s.Dir, "variants.xdb"))
	if strings.Join(got, "\n") != strings.Join(gocaDDL(t), "\n") {
		t.Fatal("upgraded DDL differs from XCA's schema 8 plus go-ca's tables")
	}
	if st, v, _ := Classify(ctx, filepath.Join(s.Dir, "variants.xdb"), true); st != Supported || v.GoCA != xdb.CurrentSchema {
		t.Fatalf("after upgrade: %s %+v", st, v)
	}
	snap, _ := h.Snapshot(ctx)
	for _, k := range snap.Keys {
		if !k.HasPrivate {
			continue
		}
		blob, own, _ := h.DB.PrivateKey(ctx, k.ID)
		if !pki.IsEncryptedPKCS8(blob) {
			t.Errorf("%s still legacy", k.Name)
		}
		pw := "secret"
		if own == xdb.PassPrivate {
			pw = "mailpass"
		}
		priv, legacy, err := pki.DecryptPrivateKey(blob, k.KeyType, []byte(pw))
		if err != nil || legacy {
			t.Errorf("%s: %v legacy=%v", k.Name, err, legacy)
			continue
		}
		if ok, _ := pki.MatchesPublic(priv, k.Public); !ok {
			t.Errorf("%s: mismatch after conversion", k.Name)
		}
		if k.Name == "www" && k.Stamp != snap.Stamp {
			t.Errorf("converted key stamp %d, max %d", k.Stamp, snap.Stamp)
		}
	}
	// A second run changes nothing.
	if rep, err := h.PrepareAfterLogin(ctx, []byte("secret")); err != nil || rep.Backup != "" {
		t.Fatalf("second run %+v %v", rep, err)
	}
}

// A database from a newer go-ca is refused.
func TestNewerGoCA(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "next", []byte("pw")); err != nil {
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

package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sort"
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
	if err != nil || info.Status != Supported || info.Schema != 8 {
		t.Fatalf("lookup: %+v %v", info, err)
	}
	// Same DDL as a file XCA created and upgraded to schema 8.
	got := schemaSQL(t, info.Path)
	want := schemaSQL(t, filepath.Join(fixtures, "schema8.xdb"))
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
	if h.DB.Schema != 8 {
		t.Fatalf("schema %d", h.DB.Schema)
	}
	got := schemaSQL(t, filepath.Join(s.Dir, "variants.xdb"))
	want := schemaSQL(t, filepath.Join(fixtures, "schema8.xdb"))
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatal("upgraded DDL differs from XCA's schema 8")
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

package db

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "t.okca"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if err := Create(context.Background(), db, map[string]string{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestMigrateCurrent(t *testing.T) {
	db := newDB(t)
	changed, err := Migrate(context.Background(), db, func() error { t.Fatal("backup without migration"); return nil })
	if err != nil || changed {
		t.Fatalf("current schema: %v %v", changed, err)
	}
	if MinMigratable+len(steps) != Schema {
		t.Fatal("migration steps do not match Schema")
	}
}

// TestMigrateSteps runs test-only steps 1 -> 2 -> 3: after a backup, in
// order, in one transaction; a failing step leaves the file as it was.
func TestMigrateSteps(t *testing.T) {
	ctx := context.Background()
	add := func(name string) step {
		return func(ctx context.Context, tx *Tx) error {
			_, err := tx.ExecContext(ctx, "INSERT INTO settings (key, value) VALUES (?, 'x')", name)
			return err
		}
	}
	fail := func(ctx context.Context, tx *Tx) error { return errors.New("boom") }

	db := newDB(t)
	if _, err := migrate(ctx, db, func() error { return nil }, []step{add("a"), fail}, 3); err == nil {
		t.Fatal("failing step accepted")
	}
	if s, _, _ := ReadSchema(ctx, db); s != 1 {
		t.Fatalf("schema after a failed migration %d", s)
	}
	var n int
	db.QueryRow("SELECT COUNT(*) FROM settings WHERE key='a'").Scan(&n)
	if n != 0 {
		t.Fatal("failed migration not rolled back")
	}

	if _, err := migrate(ctx, db, func() error { return errors.New("disk full") }, []step{add("a"), add("b")}, 3); err == nil {
		t.Fatal("migrated without a backup")
	}

	backups := 0
	changed, err := migrate(ctx, db, func() error { backups++; return nil }, []step{add("a"), add("b")}, 3)
	if err != nil || !changed || backups != 1 {
		t.Fatalf("migrate: %v %v backups %d", changed, err, backups)
	}
	db.QueryRow("SELECT COUNT(*) FROM settings WHERE key IN ('a', 'b')").Scan(&n)
	if s, _, _ := ReadSchema(ctx, db); s != 3 || n != 2 {
		t.Fatalf("schema %d, %d steps applied", s, n)
	}
	// Newer than the target, and a step list that does not fit: refused.
	if _, err := migrate(ctx, db, func() error { return nil }, []step{add("c")}, 2); err == nil {
		t.Fatal("newer schema migrated")
	}
	if _, err := migrate(ctx, db, func() error { return nil }, nil, 3); err == nil {
		t.Fatal("step list not matching the target accepted")
	}
}

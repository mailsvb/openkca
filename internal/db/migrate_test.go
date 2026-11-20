package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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
	if _, err := db.Exec("UPDATE settings SET value='1' WHERE key='schema'"); err != nil {
		t.Fatal(err)
	}
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

// schema1DB creates a database as schema 1 wrote it: without the
// connectors table and the certificates' connector column.
func schema1DB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "v1.okca"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	for _, stmt := range ddl {
		if stmt == connectorsDDL {
			continue
		}
		stmt = strings.Replace(stmt, ",\n\t\tconnector       INTEGER REFERENCES connectors (id) ON DELETE SET NULL", "", 1)
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA application_id = %d", ApplicationID)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO settings (key, value) VALUES ('schema', '1')"); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestMigrateConnectors(t *testing.T) {
	ctx := context.Background()
	sdb := schema1DB(t)
	var n int
	sdb.QueryRow("SELECT COUNT(*) FROM pragma_table_info('certs') WHERE name='connector'").Scan(&n)
	if n != 0 {
		t.Fatal("schema 1 fixture has the connector column")
	}
	changed, err := Migrate(ctx, sdb, func() error { return nil })
	if err != nil || !changed {
		t.Fatalf("migrate: %v %v", changed, err)
	}
	d, err := Open(ctx, sdb)
	if err != nil {
		t.Fatal(err)
	}
	c := &Connector{Type: ConnectorEST, Name: "Devices", Label: "devices", Enabled: true, Config: "{}"}
	if err := d.Write(ctx, func(tx *Tx) error { return tx.InsertConnector(ctx, c) }); err != nil {
		t.Fatal(err)
	}
	dup := &Connector{Type: ConnectorEST, Name: "Other", Label: "devices", Config: "{}"}
	if err := d.Write(ctx, func(tx *Tx) error { return tx.InsertConnector(ctx, dup) }); !errors.Is(err, ErrLabelTaken) {
		t.Fatalf("duplicate label: %v", err)
	}
	snap, err := d.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.ConnectorByLabel("devices"); got == nil || got.ID != c.ID || got.UUID == "" || !got.Enabled {
		t.Fatalf("connector after migration: %+v", got)
	}
}

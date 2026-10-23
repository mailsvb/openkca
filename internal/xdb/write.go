package xdb

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strconv"
)

// XCASchema is the newest XCA schema; XCA databases are upgraded to it
// before they become go-ca databases.
const XCASchema = 8

// LockoutSchema is the "schema" setting of a go-ca database. It is above
// every XCA schema, so desktop XCA refuses the file instead of losing the
// data only go-ca knows about.
const LockoutSchema = 1000

// CurrentSchema is go-ca's own schema version (the "gca_schema" setting),
// the one this package creates and upgrades to.
const CurrentSchema = 1

// upgradeSteps are XCA's schema steps (lib/database_schema.cpp, schemas[5]
// to schemas[7]) keyed by the version they start from; B64_BLOB is TEXT for
// SQLite.
var upgradeSteps = map[int][]string{
	5: {
		"ALTER TABLE settings RENAME TO __settings",
		"CREATE TABLE settings (key_ CHAR(20) UNIQUE, value TEXT)",
		"INSERT INTO settings(key_, value) SELECT key_, value FROM __settings",
		"DROP TABLE __settings",
		"UPDATE settings SET value='6' WHERE key_='schema'",
	},
	6: {
		"ALTER TABLE items ADD del SMALLINT NOT NULL DEFAULT 0",
		"CREATE INDEX i_items_del ON items (del)",
		"UPDATE settings SET value='7' WHERE key_='schema'",
	},
	7: {
		"CREATE TABLE takeys (item INTEGER UNIQUE, value TEXT, FOREIGN KEY (item) REFERENCES items (id))",
		"UPDATE settings SET value='8' WHERE key_='schema'",
	},
}

// gocaSteps turn a schema 8 XCA database into a go-ca database
// (gocaSteps[0]) and then step go-ca's own schema, keyed by the version
// they start from.
var gocaSteps = map[int][]string{
	0: {
		"CREATE TABLE gca_pgp (item INTEGER UNIQUE, fingerprint VARCHAR(64), cert TEXT, FOREIGN KEY (item) REFERENCES items (id))",
		"CREATE INDEX i_gca_pgp_item ON gca_pgp (item)",
		"UPDATE settings SET value='1000' WHERE key_='schema'",
		"INSERT INTO settings (key_, value) VALUES ('gca_schema', '1')",
	},
}

// applySteps upgrades an XCA database from schema from to XCASchema.
func applySteps(ctx context.Context, tx *sql.Tx, from int) (int, error) {
	v := from
	for v < XCASchema {
		steps, ok := upgradeSteps[v]
		if !ok {
			return v, fmt.Errorf("xdb: no upgrade path from schema %d", v)
		}
		for _, stmt := range steps {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return v, fmt.Errorf("xdb: schema %d step %q: %w", v, stmt, err)
			}
		}
		v++
	}
	return v, nil
}

// applyGoCASteps brings a schema 8 XCA database (from 0) or a go-ca
// database to CurrentSchema.
func applyGoCASteps(ctx context.Context, tx *sql.Tx, from int) error {
	for v := from; v < CurrentSchema; v++ {
		steps, ok := gocaSteps[v]
		if !ok {
			return fmt.Errorf("xdb: no upgrade path from go-ca schema %d", v)
		}
		for _, stmt := range steps {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("xdb: go-ca schema %d step %q: %w", v, stmt, err)
			}
		}
	}
	return nil
}

// Create writes a new, empty database: XCA's schema 7 DDL and initial
// settings, XCA's step to schema 8 and go-ca's steps, all in one
// transaction.
func Create(ctx context.Context, db *sql.DB, pwhash string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range schema7 {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("xdb: create: %w", err)
		}
	}
	for _, kv := range [][2]string{{"schema", "7"}, {"pwhash", pwhash}, {"legacy-keys-updated", "yes"}} {
		if _, err := tx.ExecContext(ctx, "INSERT INTO settings (key_, value) VALUES (?, ?)", kv[0], kv[1]); err != nil {
			return err
		}
	}
	if _, err := applySteps(ctx, tx, 7); err != nil {
		return err
	}
	if err := applyGoCASteps(ctx, tx, 0); err != nil {
		return err
	}
	return tx.Commit()
}

// Current reports whether the database is a go-ca database of
// CurrentSchema.
func (d *DB) Current() bool {
	return d.Schema == LockoutSchema && d.GoCA == CurrentSchema
}

// Upgrade brings an XCA database (schema 5 to 8) or an older go-ca
// database to CurrentSchema in one transaction. It returns the schema it
// started from: the XCA schema, or LockoutSchema for a go-ca database.
func (d *DB) Upgrade(ctx context.Context) (int, error) {
	from := d.Schema
	if d.Current() {
		return from, nil
	}
	tx, err := d.SQL.BeginTx(ctx, nil)
	if err != nil {
		return from, err
	}
	defer tx.Rollback()
	var s string
	if err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key_='schema'").Scan(&s); err != nil {
		return from, err
	}
	if v, err := strconv.Atoi(s); err != nil || v != from {
		return from, fmt.Errorf("xdb: schema changed underneath (%q)", s)
	}
	goca := d.GoCA
	if from != LockoutSchema {
		if _, err := applySteps(ctx, tx, from); err != nil {
			return from, err
		}
		goca = 0
	}
	if err := applyGoCASteps(ctx, tx, goca); err != nil {
		return from, err
	}
	if err := tx.Commit(); err != nil {
		return from, err
	}
	d.Schema, d.GoCA = LockoutSchema, CurrentSchema
	return from, nil
}

// Tx is a write transaction that bumps items.stamp on commit, as XCA's
// DbTransaction does; the snapshot cache reloads when MAX(stamp) changes.
type Tx struct {
	*sql.Tx
	touched []int64
}

// Touch marks an item as changed in this transaction.
func (t *Tx) Touch(id int64) { t.touched = append(t.touched, id) }

// Write runs fn in a transaction. On success it sets stamp = MAX(stamp)+1 on
// every new item (stamp 0) and every touched item, then commits.
func (d *DB) Write(ctx context.Context, fn func(*Tx) error) error {
	sqlTx, err := d.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	tx := &Tx{Tx: sqlTx}
	defer sqlTx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	var stamp int64
	if err := sqlTx.QueryRowContext(ctx, "SELECT COALESCE(MAX(stamp), 0) + 1 FROM items").Scan(&stamp); err != nil {
		return err
	}
	if _, err := sqlTx.ExecContext(ctx, "UPDATE items SET stamp=? WHERE stamp=0", stamp); err != nil {
		return err
	}
	for _, id := range tx.touched {
		if _, err := sqlTx.ExecContext(ctx, "UPDATE items SET stamp=? WHERE id=?", stamp, id); err != nil {
			return err
		}
	}
	return sqlTx.Commit()
}

// UpdatePrivateKey replaces a stored private key blob.
func (t *Tx) UpdatePrivateKey(ctx context.Context, id int64, blob []byte, ownPass int) error {
	res, err := t.ExecContext(ctx, "UPDATE private_keys SET private=?, ownPass=? WHERE item=?",
		base64.StdEncoding.EncodeToString(blob), ownPass, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("xdb: private key %d not found", id)
	}
	t.Touch(id)
	return nil
}

// SetSetting writes a settings value inside the transaction.
func (t *Tx) SetSetting(ctx context.Context, key, value string) error {
	res, err := t.ExecContext(ctx, "UPDATE settings SET value=? WHERE key_=?", value, key)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_, err = t.ExecContext(ctx, "INSERT INTO settings (key_, value) VALUES (?, ?)", key, value)
	}
	return err
}

// PrivateKeyRow is one stored private key (id, key type, ownPass, blob).
type PrivateKeyRow struct {
	ID      int64
	KeyType string
	OwnPass int
	Blob    []byte
}

// PrivateKeyRows returns every private key of live items.
func (d *DB) PrivateKeyRows(ctx context.Context) ([]PrivateKeyRow, error) {
	rows, err := d.SQL.QueryContext(ctx, `SELECT p.item, k.type, p.ownPass, p.private FROM private_keys p
		JOIN public_keys k ON k.item = p.item JOIN items i ON i.id = p.item WHERE `+d.liveCond("i"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PrivateKeyRow
	for rows.Next() {
		var r PrivateKeyRow
		var typ, priv sql.NullString
		var own sql.NullInt64
		if err := rows.Scan(&r.ID, &typ, &own, &priv); err != nil {
			return nil, err
		}
		r.KeyType, r.OwnPass = typ.String, int(own.Int64)
		if r.Blob, err = b64(priv); err != nil {
			return nil, fmt.Errorf("private key %d: %w", r.ID, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Read runs fn in a transaction that is rolled back: a consistent view
// for lookups through Tx methods.
func (d *DB) Read(ctx context.Context, fn func(*Tx) error) error {
	sqlTx, err := d.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer sqlTx.Rollback()
	return fn(&Tx{Tx: sqlTx})
}

package gcadb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Tx is a write transaction that bumps items.stamp on commit; the snapshot
// cache reloads when MAX(stamp) changes.
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
	defer sqlTx.Rollback()
	return commitWrite(ctx, sqlTx, fn)
}

func commitWrite(ctx context.Context, sqlTx *sql.Tx, fn func(*Tx) error) error {
	tx := &Tx{Tx: sqlTx}
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

// UpdatePrivateKey replaces a stored private key blob and its protection.
func (t *Tx) UpdatePrivateKey(ctx context.Context, id int64, blob []byte, protection int) error {
	res, err := t.ExecContext(ctx, "UPDATE keys SET private=?, protection=? WHERE item=?", blob, protValue(protection), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("gcadb: key %d not found", id)
	}
	t.Touch(id)
	return nil
}

// SetSetting writes a settings value inside the transaction.
func (t *Tx) SetSetting(ctx context.Context, key, value string) error {
	_, err := t.ExecContext(ctx, "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value=excluded.value",
		key, value)
	return err
}

// DeleteSetting removes a settings value inside the transaction.
func (t *Tx) DeleteSetting(ctx context.Context, key string) error {
	_, err := t.ExecContext(ctx, "DELETE FROM settings WHERE key=?", key)
	return err
}

type clientKey struct{}

// WithClient records who acts (the client address) for the audit log.
func WithClient(ctx context.Context, client string) context.Context {
	return context.WithValue(ctx, clientKey{}, client)
}

// AuditEntry is one row of the audit log.
type AuditEntry struct {
	ID       int64
	At       time.Time
	Action   string // e.g. "key.generate", "cert.revoke"
	ItemID   int64  // 0 = the database itself
	ItemName string
	Detail   string // short, never secret
	Client   string
}

// Audit appends an entry to the audit log in the transaction. The item's
// name is looked up when name is empty, so the log stays readable after
// the item has been purged.
func (t *Tx) Audit(ctx context.Context, action string, itemID int64, detail string) error {
	client, _ := ctx.Value(clientKey{}).(string)
	var item sql.NullInt64
	name := ""
	if itemID != 0 {
		item = sql.NullInt64{Int64: itemID, Valid: true}
		t.QueryRowContext(ctx, "SELECT name FROM items WHERE id=?", itemID).Scan(&name)
	}
	_, err := t.ExecContext(ctx, "INSERT INTO audit (at, action, item, item_name, detail, client) VALUES (?, ?, ?, ?, ?, ?)",
		time.Now().UTC().Format(time.RFC3339Nano), action, item, name, strings.TrimSpace(detail), client)
	return err
}

// Audit appends one entry in a transaction of its own.
func (d *DB) Audit(ctx context.Context, action string, itemID int64, detail string) error {
	return d.Write(ctx, func(tx *Tx) error { return tx.Audit(ctx, action, itemID, detail) })
}

// AuditLog returns entries newest first: all of them (itemID 0) or those
// of one item, at most limit, older than the entry before (0 = newest).
func (d *DB) AuditLog(ctx context.Context, itemID int64, before int64, limit int) ([]AuditEntry, error) {
	q := "SELECT id, at, action, item, item_name, detail, client FROM audit WHERE 1=1"
	var args []any
	if itemID != 0 {
		q += " AND item=?"
		args = append(args, itemID)
	}
	if before > 0 {
		q += " AND id<?"
		args = append(args, before)
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := d.SQL.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at string
		var item sql.NullInt64
		if err := rows.Scan(&e.ID, &at, &e.Action, &item, &e.ItemName, &e.Detail, &e.Client); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339Nano, at)
		e.ItemID = item.Int64
		out = append(out, e)
	}
	return out, rows.Err()
}

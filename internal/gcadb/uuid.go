package gcadb

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// NewUUID returns a new item UUID: version 7 (RFC 9562), so UUIDs sort by
// creation time, in the canonical lower case form as stored.
func NewUUID() (string, error) {
	u, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("gcadb: new uuid: %w", err)
	}
	return u.String(), nil
}

// CanonicalUUID checks an item UUID and returns it as stored: lower case
// with hyphens. Other spellings uuid.Parse accepts (upper case, braces,
// urn:uuid:) are normalised.
func CanonicalUUID(s string) (string, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return "", fmt.Errorf("gcadb: invalid uuid %q", s)
	}
	return u.String(), nil
}

// ItemIDByUUID returns the row ID of the item with this UUID, also of one
// in the trash; database/sql's ErrNoRows when there is none.
func (d *DB) ItemIDByUUID(ctx context.Context, id string) (int64, error) {
	return itemIDByUUID(ctx, d.SQL, id)
}

// ItemIDByUUID returns the row ID of the item with this UUID inside the
// transaction.
func (t *Tx) ItemIDByUUID(ctx context.Context, id string) (int64, error) {
	return itemIDByUUID(ctx, t, id)
}

func itemIDByUUID(ctx context.Context, q querier, id string) (int64, error) {
	c, err := CanonicalUUID(id)
	if err != nil {
		return 0, err
	}
	var row int64
	err = q.QueryRowContext(ctx, "SELECT id FROM items WHERE uuid=?", c).Scan(&row)
	return row, err
}

// ItemUUID returns the UUID of an item, also of one in the trash.
func (t *Tx) ItemUUID(ctx context.Context, id int64) (string, error) {
	var u string
	err := t.QueryRowContext(ctx, "SELECT uuid FROM items WHERE id=?", id).Scan(&u)
	return u, err
}

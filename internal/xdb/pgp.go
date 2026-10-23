package xdb

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
)

// PGPCert is a row of gca_pgp: the OpenPGP certificate (transferable
// public key, binary) whose primary key is the key item KeyID. Subkeys are
// other key items with the same public key material; secrets stay in
// private_keys.
type PGPCert struct {
	KeyID       int64
	Fingerprint string // upper case hex
	Cert        []byte
}

func (d *DB) loadPGP(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	if d.GoCA == 0 {
		return nil // an XCA database not converted yet
	}
	rows, err := tx.QueryContext(ctx, `SELECT g.item, g.fingerprint, g.cert FROM gca_pgp g
		JOIN items i ON i.id = g.item WHERE i.del=0 ORDER BY g.item`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		c := &PGPCert{}
		var fpr, cert sql.NullString
		if err := rows.Scan(&c.KeyID, &fpr, &cert); err != nil {
			return err
		}
		c.Fingerprint = fpr.String
		if c.Cert, err = b64(cert); err != nil {
			return fmt.Errorf("OpenPGP certificate of key %d: %w", c.KeyID, err)
		}
		s.PGP = append(s.PGP, c)
	}
	return rows.Err()
}

// SetPGPCert stores or replaces the OpenPGP certificate of a key.
func (t *Tx) SetPGPCert(ctx context.Context, c PGPCert) error {
	var n int
	if err := t.QueryRowContext(ctx, "SELECT COUNT(*) FROM items WHERE id=? AND type=? AND del=0", c.KeyID, TypeKey).Scan(&n); err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("xdb: key %d not found", c.KeyID)
	}
	if _, err := t.ExecContext(ctx, "DELETE FROM gca_pgp WHERE item=?", c.KeyID); err != nil {
		return err
	}
	if _, err := t.ExecContext(ctx, "INSERT INTO gca_pgp (item, fingerprint, cert) VALUES (?, ?, ?)",
		c.KeyID, c.Fingerprint, base64.StdEncoding.EncodeToString(c.Cert)); err != nil {
		return err
	}
	t.Touch(c.KeyID)
	return nil
}

// DeletePGPCert removes the OpenPGP certificate of a key, keeping the key.
func (t *Tx) DeletePGPCert(ctx context.Context, keyID int64) error {
	if _, err := t.ExecContext(ctx, "DELETE FROM gca_pgp WHERE item=?", keyID); err != nil {
		return err
	}
	t.Touch(keyID)
	return nil
}

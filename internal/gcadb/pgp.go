package gcadb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// PGPCert is the OpenPGP certificate (transferable public key, binary)
// whose primary key is the key item KeyID. Subkeys are other key items
// with the same public key material; secrets stay with the keys.
type PGPCert struct {
	KeyID       int64
	Fingerprint string // upper case hex
	Cert        []byte
}

func loadPGP(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT g.key, g.fingerprint, g.cert FROM pgp g
		JOIN items i ON i.id = g.key WHERE i.trashed IS NULL ORDER BY g.key`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		c := &PGPCert{}
		if err := rows.Scan(&c.KeyID, &c.Fingerprint, &c.Cert); err != nil {
			return err
		}
		s.PGP = append(s.PGP, c)
	}
	return rows.Err()
}

// SetPGPCert stores or replaces the OpenPGP certificate of a live key.
func (t *Tx) SetPGPCert(ctx context.Context, c PGPCert) error {
	var n int
	if err := t.QueryRowContext(ctx, "SELECT COUNT(*) FROM items WHERE id=? AND type='key' AND trashed IS NULL", c.KeyID).Scan(&n); err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("gcadb: key %d not found", c.KeyID)
	}
	if _, err := t.ExecContext(ctx, `INSERT INTO pgp (key, fingerprint, cert) VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET fingerprint=excluded.fingerprint, cert=excluded.cert`,
		c.KeyID, c.Fingerprint, c.Cert); err != nil {
		return err
	}
	t.Touch(c.KeyID)
	return nil
}

// DeletePGPCert removes the OpenPGP certificate of a key, keeping the key.
func (t *Tx) DeletePGPCert(ctx context.Context, keyID int64) error {
	if _, err := t.ExecContext(ctx, "DELETE FROM pgp WHERE key=?", keyID); err != nil {
		return err
	}
	t.Touch(keyID)
	return nil
}

// PGPCert returns the stored certificate of a key, nil if it has none.
func (t *Tx) PGPCert(ctx context.Context, keyID int64) ([]byte, error) {
	var cert []byte
	err := t.QueryRowContext(ctx, "SELECT cert FROM pgp WHERE key=?", keyID).Scan(&cert)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return cert, err
}

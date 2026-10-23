package store

import (
	"context"
	"fmt"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// PrepareReport says what PrepareAfterLogin changed.
type PrepareReport struct {
	Backup        string // path of the backup taken, "" if none was needed
	UpgradedFrom  int    // schema setting before the upgrade, 0 if none
	ConvertedKeys int    // legacy 3DES keys re-encrypted as PKCS#8
	OwnPassLegacy int    // legacy keys with their own password, left as they are
	Strengthened  int    // PKCS#8 keys re-encrypted with pki.PBKDF2Iterations
}

// PrepareAfterLogin runs after a successful database login. It converts an
// XCA database (schema 5 to 8) or an older go-ca database to the current
// go-ca schema and re-encrypts private keys still in XCA's legacy 3DES form
// as PKCS#8. Keys under the database password whose PBKDF2 iteration count
// is below pki.PBKDF2Iterations (XCA writes 2048) are re-encrypted with the
// current count. All of this rewrites the file, so a backup is taken first
// (once). Keys with their own password cannot be converted without it and
// are left alone; they get the current count when their password is set.
func (h *Handle) PrepareAfterLogin(ctx context.Context, password []byte) (PrepareReport, error) {
	h.prepMu.Lock()
	defer h.prepMu.Unlock()
	var rep PrepareReport
	rows, err := h.DB.PrivateKeyRows(ctx)
	if err != nil {
		return rep, err
	}
	// Re-encrypt before the backup and the write transaction: each key costs
	// a full PBKDF2 run in each direction, and a weak key that does not open
	// with the database password must not cause a backup on every login.
	type update struct {
		row  xdb.PrivateKeyRow
		blob []byte
	}
	var updates []update
	reencrypt := func(r xdb.PrivateKeyRow) (bool, error) {
		pw := password
		if r.OwnPass == xdb.PassBogus {
			pw = []byte("Bogus")
		}
		key, _, err := pki.DecryptPrivateKey(r.Blob, r.KeyType, pw)
		if err != nil {
			return false, err
		}
		blob, err := pki.EncryptPrivateKey(key, pw)
		if err != nil {
			return false, err
		}
		updates = append(updates, update{r, blob})
		return true, nil
	}
	for _, r := range rows {
		if r.OwnPass == xdb.PassPIN {
			continue
		}
		if pki.IsEncryptedPKCS8(r.Blob) {
			n, ok := pki.PKCS8Iterations(r.Blob)
			if !ok || n >= pki.PBKDF2Iterations || r.OwnPass == xdb.PassPrivate {
				continue
			}
			if done, _ := reencrypt(r); done { // optional: a key that does not open stays as it is
				rep.Strengthened++
			}
			continue
		}
		if r.OwnPass == xdb.PassPrivate {
			rep.OwnPassLegacy++
			continue
		}
		if _, err := reencrypt(r); err != nil {
			return rep, fmt.Errorf("legacy key %d: %w", r.ID, err)
		}
		rep.ConvertedKeys++
	}
	if h.DB.Current() && len(updates) == 0 {
		return rep, nil
	}
	if rep.Backup, err = h.Backup(ctx); err != nil {
		return rep, err
	}
	if !h.DB.Current() {
		from, err := h.DB.Upgrade(ctx)
		if err != nil {
			return rep, fmt.Errorf("schema upgrade from %d: %w (backup: %s)", from, err, rep.Backup)
		}
		rep.UpgradedFrom = from
	}
	if len(updates) > 0 {
		err := h.DB.Write(ctx, func(tx *xdb.Tx) error {
			for _, u := range updates {
				if err := tx.UpdatePrivateKey(ctx, u.row.ID, u.blob, u.row.OwnPass); err != nil {
					return err
				}
			}
			if rep.ConvertedKeys > 0 && rep.OwnPassLegacy == 0 {
				return tx.SetSetting(ctx, "legacy-keys-updated", "yes")
			}
			return nil
		})
		if err != nil {
			return rep, fmt.Errorf("%w (backup: %s)", err, rep.Backup)
		}
	}
	h.changed(ctx)
	return rep, nil
}

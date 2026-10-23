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
	UpgradedFrom  int    // schema before the upgrade, 0 if none
	ConvertedKeys int    // legacy 3DES keys re-encrypted as PKCS#8
	OwnPassLegacy int    // legacy keys with their own password, left as they are
}

// PrepareAfterLogin runs after a successful database login. It upgrades a
// schema 5 to 7 file to schema 8 and re-encrypts private keys still in XCA's
// legacy 3DES form as PKCS#8, as XCA does on open. Both rewrite the file, so
// a backup is taken first (once for both). Keys with their own password
// cannot be converted without it and are left alone, as in XCA.
func (h *Handle) PrepareAfterLogin(ctx context.Context, password []byte) (PrepareReport, error) {
	h.prepMu.Lock()
	defer h.prepMu.Unlock()
	var rep PrepareReport
	rows, err := h.DB.PrivateKeyRows(ctx)
	if err != nil {
		return rep, err
	}
	var legacy []xdb.PrivateKeyRow
	for _, r := range rows {
		if pki.IsEncryptedPKCS8(r.Blob) || r.OwnPass == xdb.PassPIN {
			continue
		}
		if r.OwnPass == xdb.PassPrivate {
			rep.OwnPassLegacy++
			continue
		}
		legacy = append(legacy, r)
	}
	if h.DB.Schema >= xdb.CurrentSchema && len(legacy) == 0 {
		return rep, nil
	}
	if rep.Backup, err = h.Backup(ctx); err != nil {
		return rep, err
	}
	if h.DB.Schema < xdb.CurrentSchema {
		from, err := h.DB.Upgrade(ctx)
		if err != nil {
			return rep, fmt.Errorf("schema upgrade from %d: %w (backup: %s)", from, err, rep.Backup)
		}
		rep.UpgradedFrom = from
	}
	if len(legacy) > 0 {
		err := h.DB.Write(ctx, func(tx *xdb.Tx) error {
			for _, r := range legacy {
				pw := password
				if r.OwnPass == xdb.PassBogus {
					pw = []byte("Bogus")
				}
				key, _, err := pki.DecryptPrivateKey(r.Blob, r.KeyType, pw)
				if err != nil {
					return fmt.Errorf("legacy key %d: %w", r.ID, err)
				}
				blob, err := pki.EncryptPrivateKey(key, pw)
				if err != nil {
					return err
				}
				if err := tx.UpdatePrivateKey(ctx, r.ID, blob, r.OwnPass); err != nil {
					return err
				}
			}
			if rep.OwnPassLegacy == 0 {
				return tx.SetSetting(ctx, "legacy-keys-updated", "yes")
			}
			return nil
		})
		if err != nil {
			return rep, fmt.Errorf("%w (backup: %s)", err, rep.Backup)
		}
		rep.ConvertedKeys = len(legacy)
	}
	h.Invalidate()
	return rep, nil
}

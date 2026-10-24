package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mailsvb/go-ca/internal/vault"
	"github.com/mailsvb/go-ca/internal/xdb"
	"github.com/mailsvb/go-ca/internal/xdbpass"
)

// ConvertReport says what a conversion changed.
type ConvertReport struct {
	Backup        string // path of the backup taken before the conversion
	UpgradedFrom  int    // schema setting before: XCA's schema, or xdb.LockoutSchema
	Converted     int    // keys now sealed with the DEK
	OwnPassLegacy int    // keys with their own password still in an XCA form
	Unopened      int    // keys marked for the database password that it does not open
}

// Conversion is a running or finished conversion of an XCA or older go-ca
// database to the current format. Several logins may wait for the same
// conversion.
type Conversion struct {
	total atomic.Int64
	done  atomic.Int64
	fin   chan struct{}

	mu     sync.Mutex
	kr     *vault.Keyring
	report ConvertReport
	err    error
}

// conversionKeep is how long a finished conversion keeps the keyring for
// logins still waiting on it.
const conversionKeep = 5 * time.Minute

// ErrConversionExpired means a login waited too long for its conversion.
var ErrConversionExpired = errors.New("the conversion finished too long ago; log in again")

func (c *Conversion) expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.kr != nil {
		c.kr.Wipe()
		c.kr = nil
		if c.err == nil {
			c.err = ErrConversionExpired
		}
	}
}

// Progress returns how many keys have been converted of how many.
func (c *Conversion) Progress() (done, total int) {
	return int(c.done.Load()), int(c.total.Load())
}

// Finished is closed when the conversion has ended.
func (c *Conversion) Finished() <-chan struct{} { return c.fin }

// Result returns, once Finished is closed, a copy of the database's
// keyring for one session, the report and the error.
func (c *Conversion) Result() (*vault.Keyring, ConvertReport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.report, c.err
	}
	if c.kr == nil {
		return nil, c.report, errors.New("the conversion has not finished")
	}
	return c.kr.Clone(), c.report, nil
}

// VerifyLegacyPassword checks password against XCA's password hash of a
// database that still has to be converted.
func (h *Handle) VerifyLegacyPassword(ctx context.Context, password []byte) (bool, error) {
	if h.DB.Current() {
		return false, errors.New("the database is already converted")
	}
	stored, err := h.DB.Setting(ctx, "pwhash")
	if err != nil {
		return false, err
	}
	ok, _ := xdbpass.Verify(stored, password)
	return ok, nil
}

// StartConversion converts the database in the background with password
// (already checked with VerifyLegacyPassword) and the Argon2id cost p, or
// returns the conversion that is already running or has succeeded. The
// conversion holds its own reference to the handle until it ends.
func (h *Handle) StartConversion(password []byte, p vault.Params) *Conversion {
	h.convMu.Lock()
	defer h.convMu.Unlock()
	if h.conv != nil {
		select {
		case <-h.conv.fin:
			h.conv.mu.Lock()
			ok := h.conv.err == nil
			h.conv.mu.Unlock()
			if ok {
				return h.conv
			}
		default:
			return h.conv
		}
	}
	c := &Conversion{fin: make(chan struct{})}
	h.conv = c
	h.store.mu.Lock()
	h.refs++
	h.store.mu.Unlock()
	pw := append([]byte(nil), password...)
	go func() {
		defer h.Release()
		defer clear(pw)
		kr, rep, err := h.convert(context.Background(), pw, p, c)
		c.mu.Lock()
		c.kr, c.report, c.err = kr, rep, err
		c.mu.Unlock()
		close(c.fin)
		// Waiting logins pick up their copy within seconds; the DEK must
		// not stay in memory beyond that.
		time.AfterFunc(conversionKeep, c.expire)
		if err != nil {
			slog.Error("database conversion failed", "db", h.Name, "err", err, "backup", rep.Backup)
			return
		}
		slog.Info("database converted", "db", h.Name, "backup", rep.Backup, "upgraded_from", rep.UpgradedFrom,
			"converted_keys", rep.Converted, "own_password_legacy", rep.OwnPassLegacy, "unopened", rep.Unopened)
	}()
	return c
}

// Convert runs a conversion and waits for it (tests and tools).
func (h *Handle) Convert(ctx context.Context, password []byte, p vault.Params) (*vault.Keyring, ConvertReport, error) {
	c := h.StartConversion(password, p)
	select {
	case <-c.fin:
		return c.Result()
	case <-ctx.Done():
		return nil, ConvertReport{}, ctx.Err()
	}
}

// convert turns an XCA database (schema 5 to 8) or an older go-ca database
// into the current format: every key under the database password (or XCA's
// "Bogus" password) is decrypted and sealed with a new DEK, which is
// wrapped with a key derived from password. Keys with their own password
// stay as they are until their password opens them. A key marked for the
// database password that the password does not open keeps its blob and is
// marked as having its own password, so whoever knows its password can
// still use it. Everything is written in one transaction after a backup.
func (h *Handle) convert(ctx context.Context, password []byte, p vault.Params, c *Conversion) (*vault.Keyring, ConvertReport, error) {
	var rep ConvertReport
	if h.DB.Current() {
		return nil, rep, errors.New("the database is already converted")
	}
	rows, err := h.DB.PrivateKeyRows(ctx, true)
	if err != nil {
		return nil, rep, err
	}
	for _, r := range rows {
		if r.OwnPass == xdb.PassCommon || r.OwnPass == xdb.PassBogus {
			c.total.Add(1)
		}
	}
	kr := vault.NewKeyring(p)
	fail := func(err error) (*vault.Keyring, ConvertReport, error) {
		kr.Wipe()
		return nil, rep, err
	}
	type update struct {
		id   int64
		blob []byte
		own  int
	}
	var updates []update
	for _, r := range rows {
		switch r.OwnPass {
		case xdb.PassPIN:
			continue
		case xdb.PassPrivate:
			if !vault.IsSealed(r.Blob) {
				rep.OwnPassLegacy++
			}
			continue
		}
		pw := password
		if r.OwnPass == xdb.PassBogus {
			pw = []byte("Bogus")
		}
		der, err := legacyDER(r.Blob, r.KeyType, pw)
		c.done.Add(1)
		if err != nil {
			slog.Warn("key does not open with the database password; it now needs its own password",
				"db", h.Name, "id", r.ID, "deleted", r.Deleted, "err", err)
			updates = append(updates, update{r.ID, r.Blob, xdb.PassPrivate})
			rep.Unopened++
			continue
		}
		blob, err := kr.Seal(der, r.Public)
		clear(der)
		if err != nil {
			return fail(err)
		}
		updates = append(updates, update{r.ID, blob, xdb.PassCommon})
		rep.Converted++
	}
	kdf, dek, err := kr.Wrap(password, p)
	if err != nil {
		return fail(err)
	}
	if rep.Backup, err = h.Backup(ctx); err != nil {
		return fail(err)
	}
	rep.UpgradedFrom, err = h.DB.Convert(ctx, func(tx *xdb.Tx) error {
		for _, u := range updates {
			if err := tx.UpdatePrivateKey(ctx, u.id, u.blob, u.own); err != nil {
				return err
			}
		}
		for k, v := range map[string]string{"kdf": kdf, "dek": dek, "legacy-keys-updated": "yes"} {
			if err := tx.SetSetting(ctx, k, v); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fail(fmt.Errorf("conversion: %w (backup: %s)", err, rep.Backup))
	}
	h.vacuum(ctx)
	h.changed(ctx)
	return kr, rep, nil
}

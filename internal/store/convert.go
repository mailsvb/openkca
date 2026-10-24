package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/flock"

	"github.com/mailsvb/openkca/internal/gcadb"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/vault"
	"github.com/mailsvb/openkca/internal/xcaimport"
)

// ConvertReport says what an import changed.
type ConvertReport struct {
	Target        string // name of the new go-ca database
	Items         int
	Trashed       int // items XCA had marked deleted, now in the trash
	Skipped       []string
	Converted     int      // keys now sealed with the DEK
	OwnPassLegacy int      // keys with their own password still in an XCA form
	Unopened      int      // keys for the database password that it does not open
	Removed       []string // the imported XCA file
}

// Conversion is a running or finished import of an XCA database (.xdb) into a new go-ca database. Several logins may wait for
// the same conversion.
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

// Result returns, once Finished is closed, a copy of the new database's
// keyring for one session, the report (with the new database's name) and
// the error.
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

// StartImport checks password against an .xdb file (name ends with .xdb)
// and imports it in the background into a new go-ca database with the
// Argon2id cost p, or returns the import of that file already running.
// When the new database has been verified, the .xdb file and its backups
// are deleted. A wrong password returns pki.ErrWrongPassword.
func (s *Store) StartImport(ctx context.Context, name string, password []byte, p vault.Params) (*Conversion, error) {
	info, err := s.Lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	if !info.XCA || info.Status != Upgradable {
		return nil, fmt.Errorf("%s cannot be imported (%s)", name, info.Status)
	}
	src, err := xcaimport.Open(ctx, info.Path)
	if err != nil {
		return nil, err
	}
	ok, err := src.Unlock(ctx, password)
	if err != nil || !ok {
		src.Close()
		if err == nil {
			err = pki.ErrWrongPassword
		}
		return nil, err
	}
	discard := func() { src.Close() }
	s.importMu.Lock()
	defer s.importMu.Unlock()
	if c, ok := s.imports[info.Path]; ok {
		select {
		case <-c.fin:
			c.mu.Lock()
			failed := c.err != nil
			c.mu.Unlock()
			if !failed {
				discard()
				return c, nil
			}
		default:
			discard()
			return c, nil
		}
	}
	lk := flock.New(info.Path + ".lock")
	if locked, err := lk.TryLock(); err != nil || !locked {
		discard()
		if err == nil {
			err = ErrLocked
		}
		return nil, err
	}
	c := &Conversion{fin: make(chan struct{})}
	s.imports[info.Path] = c
	pw := append([]byte(nil), password...)
	go func() {
		defer clear(pw)
		nk, rep, err := s.runImport(context.Background(), info, src, pw, p, c)
		src.Close()
		lk.Unlock()
		if err == nil {
			os.Remove(info.Path + ".lock")
		}
		c.mu.Lock()
		c.kr, c.report, c.err = nk, rep, err
		c.mu.Unlock()
		close(c.fin)
		time.AfterFunc(conversionKeep, func() {
			c.expire()
			s.importMu.Lock()
			if s.imports[info.Path] == c {
				delete(s.imports, info.Path)
			}
			s.importMu.Unlock()
		})
		if err != nil {
			slog.Error("database import failed", "file", info.Name, "err", err)
			return
		}
		slog.Info("database imported", "file", info.Name, "db", rep.Target, "items", rep.Items, "trashed", rep.Trashed,
			"converted_keys", rep.Converted, "own_password_legacy", rep.OwnPassLegacy,
			"unopened", rep.Unopened, "skipped", len(rep.Skipped), "removed", strings.Join(rep.Removed, ", "))
		for _, sk := range rep.Skipped {
			slog.Warn("item not imported", "file", info.Name, "item", sk)
		}
	}()
	return c, nil
}

// Import runs an import and waits for it (tests and tools).
func (s *Store) Import(ctx context.Context, name string, password []byte, p vault.Params) (*vault.Keyring, ConvertReport, error) {
	c, err := s.StartImport(ctx, name, password, p)
	if err != nil {
		return nil, ConvertReport{}, err
	}
	select {
	case <-c.fin:
		return c.Result()
	case <-ctx.Done():
		return nil, ConvertReport{}, ctx.Err()
	}
}

func (s *Store) runImport(ctx context.Context, info Info, src *xcaimport.Source, password []byte,
	p vault.Params, c *Conversion) (*vault.Keyring, ConvertReport, error) {
	var rep ConvertReport
	f, err := s.tempFile("import")
	if err != nil {
		return nil, rep, err
	}
	tmp := f.Name()
	f.Close()
	defer os.Remove(tmp)
	if err := os.Chmod(tmp, 0o600); err != nil {
		return nil, rep, err
	}
	db, err := sql.Open("sqlite", dsn(tmp, false))
	if err != nil {
		return nil, rep, err
	}
	db.SetMaxOpenConns(1)
	nk, ir, err := src.Import(ctx, db, password, p, nil, func(done, total int) {
		c.total.Store(int64(total))
		c.done.Store(int64(done))
	})
	if err == nil {
		_, err = db.ExecContext(ctx, "VACUUM")
	}
	if cerr := db.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		if nk != nil {
			nk.Wipe()
		}
		return nil, rep, err
	}
	rep = ConvertReport{Items: ir.Items, Trashed: ir.Trashed, Skipped: ir.Skipped, Converted: ir.Converted,
		OwnPassLegacy: ir.OwnPassLegacy, Unopened: ir.Unopened}
	fail := func(err error) (*vault.Keyring, ConvertReport, error) {
		nk.Wipe()
		return nil, rep, err
	}
	if err := verifyImport(ctx, tmp, password, nk, ir.Items); err != nil {
		return fail(fmt.Errorf("verifying the imported database: %w", err))
	}
	base := strings.TrimSuffix(info.Name, ExtXCA)
	if rep.Target, err = s.placeUnique(tmp, base, ExtGCA, info.Path); err != nil {
		return fail(err)
	}
	// A first backup of the new database, before the original goes.
	if err := s.backupFile(ctx, filepath.Join(s.Dir, rep.Target+ExtGCA), rep.Target); err != nil {
		slog.Error("backup of the imported database failed", "db", rep.Target, "err", err)
	}
	// The new database is in place and verified: the XCA file goes.
	if err := os.Remove(info.Path); err != nil {
		slog.Error("removing the imported file failed", "file", info.Path, "err", err)
	} else {
		rep.Removed = append(rep.Removed, info.Name)
	}
	return nk, rep, nil
}

// verifyImport reopens a freshly written database: the schema is current,
// every item is there, every link resolves, the password opens the DEK
// and the DEK opens every key sealed with it.
func verifyImport(ctx context.Context, path string, password []byte, kr *vault.Keyring, items int) error {
	st, _, _, detail := Classify(ctx, path, true)
	if st != Supported {
		return fmt.Errorf("status %s %s", st, detail)
	}
	db, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		return err
	}
	defer db.Close()
	d, err := gcadb.Open(ctx, db)
	if err != nil {
		return err
	}
	counts, err := d.Counts(ctx)
	if err != nil {
		return err
	}
	n := 0
	for _, c := range counts {
		n += c
	}
	if n != items {
		return fmt.Errorf("%d items written, %d found", items, n)
	}
	var fk int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pragma_foreign_key_check").Scan(&fk); err != nil || fk != 0 {
		return fmt.Errorf("%d broken links (%v)", fk, err)
	}
	kdf, err := d.Setting(ctx, "kdf")
	if err != nil {
		return err
	}
	dek, err := d.Setting(ctx, "dek")
	if err != nil {
		return err
	}
	check, err := vault.Unwrap(kdf, dek, password)
	if err != nil {
		return fmt.Errorf("the password does not open the new database: %w", err)
	}
	check.Wipe()
	rows, err := d.PrivateKeyRows(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.Protection != gcadb.ProtDEK {
			continue
		}
		der, err := kr.Open(r.Blob, r.Public)
		if err != nil {
			return fmt.Errorf("key %d: %w", r.ID, err)
		}
		clear(der)
	}
	return nil
}

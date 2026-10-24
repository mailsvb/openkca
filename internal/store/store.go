// Package store manages the data folder: it classifies files, lists the
// databases in it and hands out shared handles to open databases. It is the
// only package that opens database files.
package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/mailsvb/go-ca/internal/index"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// Status is the classifier's verdict for one file.
type Status string

const (
	Supported  Status = "supported"  // a go-ca database of the current schema
	Upgradable Status = "upgradable" // XCA schema 5 to 8 or an older go-ca schema: converted after login
	Outdated   Status = "outdated"   // XCA schema below 5: refused
	Newer      Status = "newer"      // a newer XCA or go-ca schema: refused
	Legacy     Status = "legacy"     // pre-2.0 XCA binary format: refused
	Invalid    Status = "invalid"    // not an XCA or go-ca database
)

// Openable reports whether a database with this status can be logged into.
func (s Status) Openable() bool { return s == Supported || s == Upgradable }

var (
	legacyMagic = []byte{0xca, 0xdb, 0x19, 0x69}
	sqliteMagic = []byte("SQLite format 3\x00")
)

// Info describes one database file in the data folder.
type Info struct {
	Name    string // file name without .xdb
	Path    string
	Size    int64
	ModTime time.Time
	Status  Status
	Schema  int    // XCA schema, xdb.LockoutSchema for a go-ca database
	GoCA    int    // go-ca schema, 0 for an XCA database
	Detail  string // why a file is invalid
}

// Version is the pair of schema settings of a database file.
type Version struct{ Schema, GoCA int }

// dsn builds a modernc.org/sqlite connection string, with SQLite's default
// rollback journal. secure_delete overwrites deleted content, so replaced
// or deleted key blobs do not linger in free pages.
func dsn(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(0)")
	q.Add("_pragma", "secure_delete(1)")
	if readOnly {
		q.Set("mode", "ro")
	}
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
}

// Classify inspects one file. deep selects PRAGMA integrity_check (uploads)
// instead of quick_check (scans).
func Classify(ctx context.Context, path string, deep bool) (Status, Version, string) {
	var ver Version
	st, detail := classify(ctx, path, deep, &ver)
	return st, ver, detail
}

func classify(ctx context.Context, path string, deep bool, ver *Version) (Status, string) {
	f, err := os.Open(path)
	if err != nil {
		return Invalid, err.Error()
	}
	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	f.Close()
	head = head[:n]
	if bytes.HasPrefix(head, legacyMagic) {
		return Legacy, ""
	}
	if !bytes.Equal(head, sqliteMagic) {
		return Invalid, "not an SQLite database"
	}
	db, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		return Invalid, err.Error()
	}
	defer db.Close()
	check := "PRAGMA quick_check"
	if deep {
		check = "PRAGMA integrity_check"
	}
	var res string
	if err := db.QueryRowContext(ctx, check).Scan(&res); err != nil {
		return Invalid, err.Error()
	}
	if res != "ok" {
		return Invalid, "integrity check: " + res
	}
	var rows int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM settings WHERE key_='schema'").Scan(&rows); err != nil || rows == 0 {
		return Invalid, "no schema setting"
	}
	v, g, err := xdb.ReadVersion(ctx, db)
	if err != nil {
		return Invalid, "invalid schema setting"
	}
	*ver = Version{v, g}
	switch {
	case v == xdb.LockoutSchema && g > xdb.CurrentSchema, v != xdb.LockoutSchema && v > xdb.XCASchema:
		return Newer, ""
	case v < 5:
		return Outdated, ""
	}
	if v != xdb.LockoutSchema || g < xdb.CurrentSchema {
		// XCA's password hash checks the password before the conversion.
		if !hasSetting(ctx, db, "pwhash") {
			return Invalid, "no password hash"
		}
		return Upgradable, ""
	}
	if !hasSetting(ctx, db, "kdf") || !hasSetting(ctx, db, "dek") {
		return Invalid, "no key encryption settings"
	}
	return Supported, ""
}

func hasSetting(ctx context.Context, db *sql.DB, key string) bool {
	var v sql.NullString
	err := db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key_=?", key).Scan(&v)
	return err == nil && strings.TrimSpace(v.String) != ""
}

// Store is the data folder and the registry of open databases.
type Store struct {
	Dir string

	mu   sync.Mutex
	open map[string]*Handle
}

// New returns a Store for dir, creating dir if needed.
func New(dir string) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	return &Store{Dir: abs, open: map[string]*Handle{}}, nil
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidName reports whether name (without .xdb) is an acceptable database name.
func ValidName(name string) bool {
	return nameRE.MatchString(name) && !strings.HasPrefix(name, ".")
}

// Scan lists the *.xdb files directly in the data folder. Symlinks,
// subfolders and hidden files are ignored.
func (s *Store) Scan(ctx context.Context) ([]Info, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".xdb")
		if !ok || !e.Type().IsRegular() || !ValidName(name) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		path := filepath.Join(s.Dir, e.Name())
		st, v, detail := Classify(ctx, path, false)
		out = append(out, Info{Name: name, Path: path, Size: fi.Size(), ModTime: fi.ModTime(),
			Status: st, Schema: v.Schema, GoCA: v.GoCA, Detail: detail})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// Lookup classifies a single database by name.
func (s *Store) Lookup(ctx context.Context, name string) (Info, error) {
	if !ValidName(name) {
		return Info{}, os.ErrNotExist
	}
	path := filepath.Join(s.Dir, name+".xdb")
	fi, err := os.Lstat(path)
	if err != nil {
		return Info{}, err
	}
	if !fi.Mode().IsRegular() {
		return Info{}, os.ErrNotExist
	}
	st, v, detail := Classify(ctx, path, false)
	return Info{Name: name, Path: path, Size: fi.Size(), ModTime: fi.ModTime(), Status: st, Schema: v.Schema, GoCA: v.GoCA,
		Detail: detail}, nil
}

// ErrLocked means another go-ca process serves the database.
var ErrLocked = errors.New("database is in use by another go-ca process")

// Handle is a shared, reference counted open database.
type Handle struct {
	Name string
	DB   *xdb.DB

	store *Store
	lock  *flock.Flock
	refs  int

	mu     sync.Mutex
	snap   *xdb.Snapshot
	convMu sync.Mutex // guards conv
	conv   *Conversion
}

// Acquire opens the named database or returns the already open handle. Each
// Acquire must be paired with Release.
func (s *Store) Acquire(ctx context.Context, name string) (*Handle, error) {
	info, err := s.Lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	if !info.Status.Openable() {
		return nil, fmt.Errorf("database %s is %s", name, info.Status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.open[info.Path]; ok {
		h.refs++
		return h, nil
	}
	lk := flock.New(info.Path + ".lock")
	locked, err := lk.TryLock()
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, ErrLocked
	}
	sqlDB, err := sql.Open("sqlite", dsn(info.Path, false))
	if err != nil {
		lk.Unlock()
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1) // serialises writes
	d, err := xdb.Open(ctx, sqlDB)
	if err != nil {
		sqlDB.Close()
		lk.Unlock()
		return nil, err
	}
	h := &Handle{Name: name, DB: d, store: s, lock: lk, refs: 1}
	s.open[info.Path] = h
	return h, nil
}

// Release drops one reference and closes the database with the last one.
func (h *Handle) Release() {
	s := h.store
	s.mu.Lock()
	h.refs--
	if h.refs > 0 {
		s.mu.Unlock()
		return
	}
	for k, v := range s.open {
		if v == h {
			delete(s.open, k)
		}
	}
	h.DB.SQL.Close()
	h.lock.Unlock()
	s.mu.Unlock()
	// A finished conversion's keyring must not outlive the database.
	h.convMu.Lock()
	if h.conv != nil {
		h.conv.expire()
	}
	h.convMu.Unlock()
}

// Snapshot returns the cached objects, reloading them when MAX(stamp)
// changed.
func (h *Handle) Snapshot(ctx context.Context) (*xdb.Snapshot, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	stamp, err := h.DB.MaxStamp(ctx)
	if err != nil {
		return nil, err
	}
	if h.snap != nil && h.snap.Stamp == stamp {
		return h.snap, nil
	}
	snap, err := h.DB.Load(ctx)
	if err != nil {
		return nil, err
	}
	h.snap = snap
	// Every reload means something changed: keep the per-CA index files
	// current.
	if err := index.Write(h.store.Dir, h.Name, snap); err != nil {
		slog.Error("writing index files failed", "db", h.Name, "err", err)
	}
	return snap, nil
}

// changed drops the cached snapshot and reloads it at once, which also
// rewrites the index files.
func (h *Handle) changed(ctx context.Context) {
	h.Invalidate()
	if _, err := h.Snapshot(ctx); err != nil {
		slog.Error("reload after change failed", "db", h.Name, "err", err)
	}
}

// Invalidate drops the cached snapshot.
func (h *Handle) Invalidate() {
	h.mu.Lock()
	h.snap = nil
	h.mu.Unlock()
}

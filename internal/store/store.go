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

	"github.com/mailsvb/go-ca/internal/cadir"
	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/index"
	"github.com/mailsvb/go-ca/internal/xcaimport"
)

// Status is the classifier's verdict for one file.
type Status string

const (
	Supported  Status = "supported"  // a go-ca database (.gca) of the current schema
	Upgradable Status = "upgradable" // an XCA or older go-ca database (.xdb): imported after login
	Outdated   Status = "outdated"   // XCA schema below 5: refused
	Newer      Status = "newer"      // a newer XCA or go-ca schema: refused
	Legacy     Status = "legacy"     // pre-2.0 XCA binary format: refused
	Invalid    Status = "invalid"    // not an XCA or go-ca database
)

// Openable reports whether a database with this status can be logged into.
func (s Status) Openable() bool { return s == Supported || s == Upgradable }

// File extensions: go-ca databases, and XCA databases (or go-ca's former
// XCA based ones) waiting to be imported.
const (
	ExtGCA = ".gca"
	ExtXCA = ".xdb"
)

var sqliteMagic = []byte("SQLite format 3\x00")

// Info describes one database file in the data folder.
type Info struct {
	Name    string // a go-ca database's name (file name without .gca), or an XCA file's name with .xdb
	Path    string
	Size    int64
	ModTime time.Time
	Status  Status
	XCA     bool   // an .xdb file to import
	Schema  int    // go-ca's schema, or XCA's (xcaimport.LockoutSchema for go-ca's former format)
	GoCA    int    // go-ca's former schema of an .xdb file, 0 for XCA's own
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
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "secure_delete(1)")
	if readOnly {
		q.Set("mode", "ro")
	}
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
}

// Classify inspects one file by its content: a go-ca database, or a file
// xcaimport reads. deep selects PRAGMA integrity_check (uploads) instead
// of quick_check (scans).
func Classify(ctx context.Context, path string, deep bool) (st Status, xca bool, v Version, detail string) {
	f, err := os.Open(path)
	if err != nil {
		return Invalid, false, v, err.Error()
	}
	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	f.Close()
	if bytes.Equal(head[:n], sqliteMagic) {
		if st, v, detail, ok := classifyGCA(ctx, path, deep); ok {
			return st, false, v, detail
		}
	}
	info, err := xcaimport.Inspect(ctx, path, deep)
	if err != nil {
		return Invalid, true, v, err.Error()
	}
	v = Version{info.Schema, info.GoCA}
	switch info.Kind {
	case xcaimport.KindXCA, xcaimport.KindGoCA:
		return Upgradable, true, v, ""
	case xcaimport.KindOld:
		return Outdated, true, v, ""
	case xcaimport.KindNewer:
		return Newer, true, v, ""
	case xcaimport.KindLegacy:
		return Legacy, true, v, ""
	}
	return Invalid, true, v, "unknown format"
}

// classifyGCA classifies a go-ca database; ok is false when the file is
// not one.
func classifyGCA(ctx context.Context, path string, deep bool) (st Status, v Version, detail string, ok bool) {
	db, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		return Invalid, v, err.Error(), false
	}
	defer db.Close()
	schema, gca, err := gcadb.ReadSchema(ctx, db)
	if !gca {
		return Invalid, v, "", false
	}
	v.Schema = schema
	if err != nil {
		return Invalid, v, err.Error(), true
	}
	check := "PRAGMA quick_check"
	if deep {
		check = "PRAGMA integrity_check"
	}
	var res string
	if err := db.QueryRowContext(ctx, check).Scan(&res); err != nil {
		return Invalid, v, err.Error(), true
	}
	if res != "ok" {
		return Invalid, v, "integrity check: " + res, true
	}
	if schema > gcadb.Schema {
		return Newer, v, "", true
	}
	if schema == 3 {
		// Schema 3 had no item UUIDs and is not migrated.
		return Invalid, v, "go-ca schema 3 (before item UUIDs) is no longer supported", true
	}
	if schema < gcadb.Schema {
		return Invalid, v, "unknown go-ca schema", true
	}
	for _, k := range []string{"kdf", "dek"} {
		var val string
		if err := db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=?", k).Scan(&val); err != nil || val == "" {
			return Invalid, v, "no key encryption settings", true
		}
	}
	return Supported, v, "", true
}

// Store is the data folder and the registry of open databases.
type Store struct {
	Dir string

	mu   sync.Mutex
	open map[string]*Handle

	importMu sync.Mutex
	imports  map[string]*Conversion // by source path
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
	return &Store{Dir: abs, open: map[string]*Handle{}, imports: map[string]*Conversion{}}, nil
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidName reports whether name is an acceptable go-ca database name
// (without .gca).
func ValidName(name string) bool {
	lower := strings.ToLower(name)
	return nameRE.MatchString(name) && !strings.HasPrefix(name, ".") &&
		!strings.HasSuffix(lower, ExtGCA) && !strings.HasSuffix(lower, ExtXCA)
}

// IsXCAName reports whether name addresses an .xdb file ("ca.xdb").
func IsXCAName(name string) bool {
	base, ok := strings.CutSuffix(name, ExtXCA)
	return ok && ValidName(base)
}

// path returns the file of a database name, "" for an invalid name.
func (s *Store) path(name string) string {
	switch {
	case IsXCAName(name):
		return filepath.Join(s.Dir, name)
	case ValidName(name):
		return filepath.Join(s.Dir, name+ExtGCA)
	}
	return ""
}

// Scan lists the .gca and .xdb files directly in the data folder.
// Symlinks, subfolders and hidden files are ignored.
func (s *Store) Scan(ctx context.Context) ([]Info, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, e := range entries {
		var name string
		if base, ok := strings.CutSuffix(e.Name(), ExtGCA); ok && ValidName(base) {
			name = base
		} else if IsXCAName(e.Name()) {
			name = e.Name()
		} else {
			continue
		}
		if !e.Type().IsRegular() {
			continue
		}
		if info, err := s.Lookup(ctx, name); err == nil {
			out = append(out, info)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// Lookup classifies a single database by name.
func (s *Store) Lookup(ctx context.Context, name string) (Info, error) {
	path := s.path(name)
	if path == "" {
		return Info{}, os.ErrNotExist
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return Info{}, err
	}
	if !fi.Mode().IsRegular() {
		return Info{}, os.ErrNotExist
	}
	st, xca, v, detail := Classify(ctx, path, false)
	if xca != IsXCAName(name) && st.Openable() {
		// a go-ca database named .xdb or the reverse: not opened by name
		st, detail = Invalid, "file extension does not match the content"
	}
	return Info{Name: name, Path: path, Size: fi.Size(), ModTime: fi.ModTime(), Status: st, XCA: xca,
		Schema: v.Schema, GoCA: v.GoCA, Detail: detail}, nil
}

// ErrLocked means another go-ca process serves the database.
var ErrLocked = errors.New("database is in use by another go-ca process")

// Handle is a shared, reference counted open database.
type Handle struct {
	Name string
	DB   *gcadb.DB

	store *Store
	lock  *flock.Flock
	refs  int

	mu   sync.Mutex
	snap *gcadb.Snapshot
}

// Acquire opens the named database or returns the already open handle. Each
// Acquire must be paired with Release.
func (s *Store) Acquire(ctx context.Context, name string) (*Handle, error) {
	info, err := s.Lookup(ctx, name)
	if err != nil {
		return nil, err
	}
	if info.Status != Supported || info.XCA {
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
	d, err := gcadb.Open(ctx, sqlDB)
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
}

// Snapshot returns the cached objects, reloading them when MAX(stamp)
// changed.
func (h *Handle) Snapshot(ctx context.Context) (*gcadb.Snapshot, error) {
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

// CADir returns the folder of a CA of this database by its authority ID
// (gcadb.Authority.UUID): <data-dir>/ca/<database>/<authority ID>/. It
// holds the CA's index files and is the place for any other file go-ca
// keeps per CA; a renewal with the same key keeps it. The folder is not
// created.
func (h *Handle) CADir(authorityID string) (string, error) {
	return cadir.Path(h.store.Dir, h.Name, authorityID)
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

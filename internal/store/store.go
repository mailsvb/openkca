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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"
	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/mailsvb/go-ca/internal/xdb"
)

// Status is the classifier's verdict for one file.
type Status string

const (
	Supported  Status = "supported"  // schema 8
	Upgradable Status = "upgradable" // schema 5 to 7: opened as is, upgraded in phase 2
	Outdated   Status = "outdated"   // schema below 5: refused
	Newer      Status = "newer"      // schema above 8: refused
	Legacy     Status = "legacy"     // pre-2.0 binary format: refused
	Invalid    Status = "invalid"    // not an XCA database
)

// CurrentSchema is the schema version this tool reads and writes.
const CurrentSchema = 8

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
	Schema  int
	Detail  string // why a file is invalid
}

// dsn builds a modernc.org/sqlite connection string. Journal mode stays at
// SQLite's default rollback journal, as desktop XCA expects.
func dsn(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(0)")
	if readOnly {
		q.Set("mode", "ro")
	}
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
}

// Classify inspects one file. deep selects PRAGMA integrity_check (uploads)
// instead of quick_check (scans).
func Classify(ctx context.Context, path string, deep bool) (Status, int, string) {
	f, err := os.Open(path)
	if err != nil {
		return Invalid, 0, err.Error()
	}
	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	f.Close()
	head = head[:n]
	if bytes.HasPrefix(head, legacyMagic) {
		return Legacy, 0, ""
	}
	if !bytes.Equal(head, sqliteMagic) {
		return Invalid, 0, "not an SQLite database"
	}
	db, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		return Invalid, 0, err.Error()
	}
	defer db.Close()
	check := "PRAGMA quick_check"
	if deep {
		check = "PRAGMA integrity_check"
	}
	var res string
	if err := db.QueryRowContext(ctx, check).Scan(&res); err != nil {
		return Invalid, 0, err.Error()
	}
	if res != "ok" {
		return Invalid, 0, "integrity check: " + res
	}
	var schema, pwhash sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key_='schema'").Scan(&schema); err != nil {
		return Invalid, 0, "no schema setting"
	}
	v, err := strconv.Atoi(strings.TrimSpace(schema.String))
	if err != nil {
		return Invalid, 0, "invalid schema setting"
	}
	switch {
	case v > CurrentSchema:
		return Newer, v, ""
	case v < 5:
		return Outdated, v, ""
	}
	if err := db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key_='pwhash'").Scan(&pwhash); err != nil || pwhash.String == "" {
		return Invalid, v, "no password hash"
	}
	if v < CurrentSchema {
		return Upgradable, v, ""
	}
	return Supported, v, ""
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
		st, schema, detail := Classify(ctx, path, false)
		out = append(out, Info{Name: name, Path: path, Size: fi.Size(), ModTime: fi.ModTime(),
			Status: st, Schema: schema, Detail: detail})
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
	st, schema, detail := Classify(ctx, path, false)
	return Info{Name: name, Path: path, Size: fi.Size(), ModTime: fi.ModTime(), Status: st, Schema: schema, Detail: detail}, nil
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

	mu   sync.Mutex
	snap *xdb.Snapshot
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
	defer s.mu.Unlock()
	h.refs--
	if h.refs > 0 {
		return
	}
	for k, v := range s.open {
		if v == h {
			delete(s.open, k)
		}
	}
	h.DB.SQL.Close()
	h.lock.Unlock()
}

// Snapshot returns the cached objects, reloading them when MAX(stamp)
// changed, for example because desktop XCA wrote to the same file.
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
	return snap, nil
}

// Invalidate drops the cached snapshot.
func (h *Handle) Invalidate() {
	h.mu.Lock()
	h.snap = nil
	h.mu.Unlock()
}

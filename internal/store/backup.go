package store

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// KeepBackups is how many backups per database are kept.
const KeepBackups = 10

// BackupDir is where backups are written, inside the state folder.
func (s *Store) BackupDir() string { return filepath.Join(s.Dir, ".go-ca", "backup") }

var backupSuffix = regexp.MustCompile(`^\.(\d{14})(-\d+)?\.xdb$`)

// Backup writes a consistent copy of the open database to
// .go-ca/backup/<name>.<yyyyMMddHHmmss>.xdb (SQLite's VACUUM INTO, which
// reads inside one transaction) and deletes all but the newest KeepBackups
// backups of that database. It returns the backup's path.
func (h *Handle) Backup(ctx context.Context) (string, error) {
	dir := h.store.BackupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	stamp := time.Now().UTC().Format("20060102150405")
	// Within one second, number further backups after the highest number
	// in use, so that names never repeat and order stays intact.
	path := filepath.Join(dir, h.Name+"."+stamp+".xdb")
	existing, err := h.store.Backups(h.Name)
	if err != nil {
		return "", err
	}
	next := -1
	for _, p := range existing {
		rest := strings.TrimPrefix(filepath.Base(p), h.Name)
		if m := backupSuffix.FindStringSubmatch(rest); m != nil && m[1] == stamp {
			n := 0
			if m[2] != "" {
				n, _ = strconv.Atoi(m[2][1:])
			}
			next = max(next, n)
		}
	}
	if next >= 0 {
		path = filepath.Join(dir, fmt.Sprintf("%s.%s-%d.xdb", h.Name, stamp, next+1))
	}
	if _, err := h.DB.SQL.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return "", fmt.Errorf("backup: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", err
	}
	return path, h.store.rotateBackups(h.Name)
}

// Backups lists the backup files of one database, newest first.
func (s *Store) Backups(name string) ([]string, error) {
	entries, err := os.ReadDir(s.BackupDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	type entry struct {
		path  string
		stamp string
		seq   int
	}
	var found []entry
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name(), name)
		m := backupSuffix.FindStringSubmatch(rest)
		if !ok || m == nil || !e.Type().IsRegular() {
			continue
		}
		seq := 0
		if m[2] != "" {
			seq, _ = strconv.Atoi(m[2][1:])
		}
		found = append(found, entry{filepath.Join(s.BackupDir(), e.Name()), m[1], seq})
	}
	sort.Slice(found, func(i, j int) bool { // newest first
		if found[i].stamp != found[j].stamp {
			return found[i].stamp > found[j].stamp
		}
		return found[i].seq > found[j].seq
	})
	out := make([]string, len(found))
	for i, e := range found {
		out[i] = e.path
	}
	return out, nil
}

func (s *Store) rotateBackups(name string) error {
	all, err := s.Backups(name)
	if err != nil {
		return err
	}
	for _, p := range all[min(len(all), KeepBackups):] {
		if err := os.Remove(p); err != nil {
			return err
		}
	}
	return nil
}

// vacuum rebuilds the database file after keys were re-encrypted, so that
// no page of the file holds an old ciphertext. Failure is logged: the data
// is intact either way.
func (h *Handle) vacuum(ctx context.Context) {
	if _, err := h.DB.SQL.ExecContext(ctx, "VACUUM"); err != nil {
		slog.Warn("vacuum failed", "db", h.Name, "err", err)
	}
}

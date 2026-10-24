package store

import (
	"context"
	"database/sql"
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

// Backup retention: the database options backup_keep (count) and
// backup_days (age, 0 = no limit), with these defaults and bounds. The
// newest backup is always kept.
const (
	DefaultBackupKeep = 10
	DefaultBackupDays = 90
	MaxBackupKeep     = 100
	MaxBackupDays     = 3650
)

// BackupDir is where backups are written, inside the state folder.
func (s *Store) BackupDir() string { return filepath.Join(s.Dir, ".openkca", "backup") }

var backupSuffix = regexp.MustCompile(`^\.(\d{14})(-\d+)?(\.okca|\.xdb)$`)

// Backup writes a consistent copy of the open database to
// .openkca/backup/<name>.<yyyyMMddHHmmss>.okca (SQLite's VACUUM INTO, which
// reads inside one transaction) and applies the retention options. It
// returns the backup's path.
func (h *Handle) Backup(ctx context.Context) (string, error) {
	dir := h.store.BackupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	stamp := time.Now().UTC().Format("20060102150405")
	// Within one second, number further backups after the highest number
	// in use, so that names never repeat and order stays intact.
	path := filepath.Join(dir, h.Name+"."+stamp+ExtOKCA)
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
		path = filepath.Join(dir, fmt.Sprintf("%s.%s-%d%s", h.Name, stamp, next+1, ExtOKCA))
	}
	if _, err := h.DB.SQL.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return "", fmt.Errorf("backup: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", err
	}
	keep, days := h.retention(ctx)
	return path, h.store.rotateBackups(h.Name, keep, days, time.Now())
}

// backupFile writes a backup of a database file that is not open.
func (s *Store) backupFile(ctx context.Context, path, name string) error {
	dir := s.BackupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		return err
	}
	defer db.Close()
	dst := filepath.Join(dir, name+"."+time.Now().UTC().Format("20060102150405")+ExtOKCA)
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", dst); err != nil {
		return err
	}
	return os.Chmod(dst, 0o600)
}

// retention reads backup_keep and backup_days.
func (h *Handle) retention(ctx context.Context) (keep, days int) {
	keep, days = DefaultBackupKeep, DefaultBackupDays
	if v, err := h.DB.Setting(ctx, "backup_keep"); err == nil && v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= MaxBackupKeep {
			keep = n
		}
	}
	if v, err := h.DB.Setting(ctx, "backup_days"); err == nil && v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= MaxBackupDays {
			days = n
		}
	}
	return keep, days
}

// Backups lists the backup files of one go-ca database, newest first.
func (s *Store) Backups(name string) ([]string, error) { return s.backupsWithExt(name, ExtOKCA) }

func (s *Store) backupsWithExt(name, ext string) ([]string, error) {
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
		if !ok || m == nil || m[3] != ext || !e.Type().IsRegular() {
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

// rotateBackups keeps the newest keep backups, and of those only the ones
// at most days old (days 0: no age limit); the newest always stays.
func (s *Store) rotateBackups(name string, keep, days int, now time.Time) error {
	all, err := s.Backups(name)
	if err != nil {
		return err
	}
	cutoff := now.UTC().AddDate(0, 0, -days).Format("20060102150405")
	for i, p := range all {
		if i == 0 {
			continue
		}
		old := false
		if days > 0 {
			rest := strings.TrimPrefix(filepath.Base(p), name)
			if m := backupSuffix.FindStringSubmatch(rest); m != nil && m[1] < cutoff {
				old = true
			}
		}
		if i >= keep || old {
			if err := os.Remove(p); err != nil {
				return err
			}
		}
	}
	return nil
}

// PurgeBackups deletes every backup of the database; after a password
// change they would still open with the old password.
func (h *Handle) PurgeBackups() (int, error) {
	all, err := h.store.Backups(h.Name)
	if err != nil {
		return 0, err
	}
	for i, p := range all {
		if err := os.Remove(p); err != nil {
			return i, err
		}
	}
	return len(all), nil
}

// vacuum rebuilds the database file after keys were re-encrypted or
// items purged, so that no page of the file holds old content. Failure is
// logged: the data is intact either way.
func (h *Handle) vacuum(ctx context.Context) {
	if _, err := h.DB.SQL.ExecContext(ctx, "VACUUM"); err != nil {
		slog.Warn("vacuum failed", "db", h.Name, "err", err)
	}
}

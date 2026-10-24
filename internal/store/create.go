package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mailsvb/go-ca/internal/vault"
	"github.com/mailsvb/go-ca/internal/xdb"
)

var (
	// ErrExists means a database of that name already exists.
	ErrExists = errors.New("a database with this name already exists")
	// ErrBadName means the name does not match [A-Za-z0-9._-]{1,64}.
	ErrBadName = errors.New("invalid database name")
	// ErrTooLarge means an upload exceeded the size limit.
	ErrTooLarge = errors.New("upload too large")
)

// RejectedError reports why an uploaded file was not stored.
type RejectedError struct {
	Status Status
	Detail string
}

func (e *RejectedError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("file refused: %s (%s)", e.Status, e.Detail)
	}
	return "file refused: " + string(e.Status)
}

// tempFile creates a hidden temporary file in the data folder, so that the
// final rename is atomic and the scan never lists a half-written database.
func (s *Store) tempFile(kind string) (*os.File, error) {
	return os.CreateTemp(s.Dir, ".tmp-"+kind+"-*.xdb")
}

// place moves tmp to name.xdb without overwriting an existing file: link
// fails if the target exists, which closes the race between check and rename.
func (s *Store) place(tmp, name string) error {
	final := filepath.Join(s.Dir, name+".xdb")
	if err := os.Link(tmp, final); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return err
	}
	return os.Remove(tmp)
}

// MinPasswordLen is the shortest database password accepted for new
// databases and password changes.
const MinPasswordLen = 8

// ErrShortPassword means a database password is shorter than MinPasswordLen.
var ErrShortPassword = fmt.Errorf("the database password must have at least %d characters", MinPasswordLen)

// Create writes a new, empty database protected by password with the
// Argon2id cost p.
func (s *Store) Create(ctx context.Context, name string, password []byte, p vault.Params) error {
	if !ValidName(name) {
		return ErrBadName
	}
	if len(password) < MinPasswordLen {
		return ErrShortPassword
	}
	if _, err := os.Lstat(filepath.Join(s.Dir, name+".xdb")); err == nil {
		return ErrExists
	}
	kr := vault.NewKeyring(p)
	defer kr.Wipe()
	kdf, dek, err := kr.Wrap(password, p)
	if err != nil {
		return err
	}
	f, err := s.tempFile("create")
	if err != nil {
		return err
	}
	tmp := f.Name()
	f.Close()
	defer os.Remove(tmp)
	db, err := sql.Open("sqlite", dsn(tmp, false))
	if err != nil {
		return err
	}
	err = xdb.Create(ctx, db, map[string]string{"kdf": kdf, "dek": dek})
	if cerr := db.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return s.place(tmp, name)
}

// SanitizeName turns an uploaded file name into a valid database name.
func SanitizeName(filename string) string {
	base := filepath.Base(strings.ReplaceAll(filename, "\\", "/"))
	base = strings.TrimSuffix(base, filepath.Ext(base))
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	name := strings.TrimLeft(b.String(), ".")
	if len(name) > 60 { // room for a -N suffix
		name = name[:60]
	}
	if name == "" || strings.Trim(name, "_") == "" {
		name = "imported"
	}
	return name
}

// Import stores an uploaded database after validating it. It returns the
// name it was stored under (with -1, -2, … appended on collision).
func (s *Store) Import(ctx context.Context, filename string, r io.Reader, maxSize int64) (string, error) {
	f, err := s.tempFile("import")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	n, err := io.Copy(f, io.LimitReader(r, maxSize+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > maxSize {
		return "", ErrTooLarge
	}
	st, _, detail := Classify(ctx, tmp, true)
	if !st.Openable() {
		return "", &RejectedError{Status: st, Detail: detail}
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return "", err
	}
	base := SanitizeName(filename)
	for i := 0; i < 1000; i++ {
		name := base
		if i > 0 {
			name = base + "-" + strconv.Itoa(i)
		}
		err := s.place(tmp, name)
		if err == nil {
			return name, nil
		}
		if !errors.Is(err, ErrExists) {
			return "", err
		}
	}
	return "", ErrExists
}

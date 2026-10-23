// Package auth implements the server login: the server password, server
// sessions with CSRF tokens, login rate limiting and the TLS certificate.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
)

// StateDir is the folder inside the data folder that holds server state.
const StateDir = ".go-ca"

const passwordFile = "server-password"

// argon2id parameters (RFC 9106 second recommended option, 64 MiB).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

// ErrNoPassword means no server password has been set yet.
var ErrNoPassword = errors.New("no server password set; run: go-ca set-password --data-dir <dir>")

// HashPassword returns an encoded argon2id hash.
func HashPassword(pw []byte) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	key := argon2.IDKey(pw, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		enc.EncodeToString(salt), enc.EncodeToString(key))
}

// CheckPassword verifies pw against an encoded argon2id hash.
func CheckPassword(encoded string, pw []byte) bool {
	parts := strings.Split(strings.TrimSpace(encoded), "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var v int
	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m > 1<<22 || t > 100 || p == 0 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[4])
	want, err2 := enc.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey(pw, salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// PasswordPath is where the server password hash is stored.
func PasswordPath(dataDir string) string {
	return filepath.Join(dataDir, StateDir, passwordFile)
}

// SavePassword stores the hash of pw in the state folder.
func SavePassword(dataDir string, pw []byte) error {
	if err := os.MkdirAll(filepath.Join(dataDir, StateDir), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(PasswordPath(dataDir), []byte(HashPassword(pw)+"\n"), 0o600)
}

// LoadPassword reads the stored hash.
func LoadPassword(dataDir string) (string, error) {
	b, err := os.ReadFile(PasswordPath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNoPassword
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Package auth implements the server login: the server password, server
// sessions with CSRF tokens, login rate limiting and the TLS certificate.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
)

// StateDir is the folder inside the data folder that holds server state.
const StateDir = ".openkca"

// argon2id parameters (RFC 9106 second recommended option, 64 MiB).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
)

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

type argonHash struct {
	salt, key []byte
	m, t      uint32
	p         uint8
}

// parseHash decodes an encoded argon2id hash, refusing costs beyond what a
// login may take.
func parseHash(encoded string) (argonHash, bool) {
	var h argonHash
	parts := strings.Split(strings.TrimSpace(encoded), "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return h, false
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return h, false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.m, &h.t, &h.p); err != nil || h.m > 1<<22 || h.t > 100 || h.p == 0 {
		return h, false
	}
	enc := base64.RawStdEncoding
	var err1, err2 error
	h.salt, err1 = enc.DecodeString(parts[4])
	h.key, err2 = enc.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(h.key) == 0 {
		return h, false
	}
	return h, true
}

// ValidHash reports whether encoded is an argon2id hash CheckPassword can
// use, as HashPassword makes them.
func ValidHash(encoded string) bool {
	_, ok := parseHash(encoded)
	return ok
}

// CheckPassword verifies pw against an encoded argon2id hash.
func CheckPassword(encoded string, pw []byte) bool {
	h, ok := parseHash(encoded)
	if !ok {
		return false
	}
	got := argon2.IDKey(pw, h.salt, h.t, h.m, h.p, uint32(len(h.key)))
	return subtle.ConstantTimeCompare(got, h.key) == 1
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

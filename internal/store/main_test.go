package store

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/vault"
)

// TestMain lowers the PBKDF2 iteration count for encrypted exports, the
// PKCS#12 one and the Argon2id cost of new databases: the real values make
// every operation cost a noticeable fraction of a second, which adds up
// over the suite. pki's, codec's and vault's tests check the real values.
func TestMain(m *testing.M) {
	pki.PBKDF2Iterations = 2048
	codec.PKCS12Iterations = 2048
	vault.Default = testKDF
	os.Exit(m.Run())
}

var testKDF = vault.Params{MemoryKiB: 64, Time: 1, Threads: 1}

// testPassword protects databases the tests create; the XCA fixtures use
// fixturePassword.
var (
	testPassword    = []byte("password")
	fixturePassword = []byte("secret")
)

var (
	keyringsMu sync.Mutex
	keyrings   = map[*Handle]*vault.Keyring{}
)

// krOf returns the keyring of an open handle: a database the test created
// opens with testPassword, an imported XCA fixture with fixturePassword.
func krOf(t *testing.T, h *Handle) *vault.Keyring {
	t.Helper()
	keyringsMu.Lock()
	defer keyringsMu.Unlock()
	if kr, ok := keyrings[h]; ok {
		return kr
	}
	ctx := context.Background()
	kr, err := h.Unlock(ctx, testPassword)
	if err != nil {
		kr, err = h.Unlock(ctx, fixturePassword)
	}
	if err != nil {
		t.Fatalf("keyring of %s: %v", h.Name, err)
	}
	keyrings[h] = kr
	t.Cleanup(func() {
		keyringsMu.Lock()
		delete(keyrings, h)
		keyringsMu.Unlock()
	})
	return kr
}

// setKR replaces the keyring krOf returns for h (after a password change).
func setKR(h *Handle, kr *vault.Keyring) {
	keyringsMu.Lock()
	keyrings[h] = kr
	keyringsMu.Unlock()
}

func openRO(path string) (*sql.DB, error) { return sql.Open("sqlite", dsn(path, true)) }

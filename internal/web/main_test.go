package web

import (
	"os"
	"testing"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/vault"
)

// TestMain lowers the PBKDF2 iteration count for new encrypted keys and
// the PKCS#12 one for exports: the real counts make every stored key and
// every PKCS#12 file cost a noticeable fraction of a second, which adds up
// over the suite. pki's and codec's tests check the real counts.
func TestMain(m *testing.M) {
	pki.PBKDF2Iterations = 2048
	codec.PKCS12Iterations = 2048
	vault.Default = vault.Params{MemoryKiB: 64, Time: 1, Threads: 1}
	os.Exit(m.Run())
}

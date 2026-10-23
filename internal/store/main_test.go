package store

import (
	"os"
	"testing"

	"github.com/mailsvb/go-ca/internal/pki"
)

// TestMain lowers the PBKDF2 iteration count for new encrypted keys: the
// real count makes every stored key cost a noticeable fraction of a second,
// which adds up over the suite. pki's tests check the real count.
func TestMain(m *testing.M) {
	pki.PBKDF2Iterations = 2048
	os.Exit(m.Run())
}

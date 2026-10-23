package pki

import (
	"os"
	"testing"
)

// defaultIterations is PBKDF2Iterations as shipped; TestMain lowers the
// count to keep the suite fast.
var defaultIterations = PBKDF2Iterations

func TestMain(m *testing.M) {
	PBKDF2Iterations = 2048
	os.Exit(m.Run())
}

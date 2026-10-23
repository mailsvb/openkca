package pki

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestGenerateDHParams(t *testing.T) {
	var tried atomic.Int64
	start := time.Now()
	b, err := GenerateDHParams(context.Background(), 1024, &tried)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("1024 bit in %s, %d candidates", time.Since(start), tried.Load())
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	f := filepath.Join(t.TempDir(), "dh.pem")
	os.WriteFile(f, b, 0o600)
	if out, err := exec.Command("openssl", "dhparam", "-in", f, "-check", "-noout").CombinedOutput(); err != nil {
		t.Fatalf("openssl dhparam -check: %v\n%s", err, out)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := GenerateDHParams(ctx, 4096, nil); err == nil {
		t.Fatal("cancel ignored")
	}
}

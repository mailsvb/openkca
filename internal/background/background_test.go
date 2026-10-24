package background

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/store"
	"github.com/mailsvb/openkca/internal/vault"
)

var testKDF = vault.Params{MemoryKiB: 64, Time: 1, Threads: 1}

func newStore(t *testing.T, names ...string) *store.Store {
	t.Helper()
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var conf []store.Configured
	for _, n := range names {
		if err := s.Create(context.Background(), n, []byte("password-"+n), testKDF); err != nil {
			t.Fatal(err)
		}
		conf = append(conf, store.Configured{Label: strings.ToUpper(n), Path: filepath.Join(s.Dir, n+".okca"), Background: true})
	}
	if _, err := s.Configure(context.Background(), conf); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOpenAndClose(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "one", "two", "three")
	h, err := Open(ctx, s, []string{"one", "two", "three"}, map[string][]byte{
		"one": []byte("password-one"), "three": []byte("password-three")})
	if err != nil {
		t.Fatal(err)
	}
	dbs := h.Databases()
	if len(dbs) != 2 || dbs[0].Name != "one" || dbs[0].Label != "ONE" || dbs[1].Name != "three" {
		t.Fatalf("databases = %+v", dbs)
	}
	if h.Get("two") != nil || h.Get("one") == nil {
		t.Fatal("Get")
	}
	d := h.Get("one")
	kr := d.Keyring()
	if kr == nil {
		t.Fatal("no keyring")
	}
	// The keyring opens keys: seal and open a blob with it.
	blob, err := kr.Seal([]byte("pkcs8"), []byte("spki"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := kr.Open(blob, []byte("spki")); err != nil || string(got) != "pkcs8" {
		t.Fatalf("open = %q, %v", got, err)
	}
	// A web session shares the open handle and unlocks with the password.
	hd, err := s.Acquire(ctx, "one")
	if err != nil {
		t.Fatal(err)
	}
	if hd != d.Handle {
		t.Fatal("web session got another handle")
	}
	if _, err := hd.Unlock(ctx, []byte("wrong")); err == nil {
		t.Fatal("wrong password accepted")
	}
	hd.Release()
	log, err := d.Handle.AuditLog(ctx, 0, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range log {
		if e.Action == "database.unlock" && e.Detail == "background" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no background unlock in the audit log: %+v", log)
	}
	h.Close()
	if d.Keyring() != nil || h.Get("one") != nil {
		t.Fatal("not closed")
	}
	// all references are gone: the file lock is free again
	hd, err = s.Acquire(ctx, "one")
	if err != nil {
		t.Fatal(err)
	}
	hd.Release()
	if _, err := os.Stat(filepath.Join(s.Dir, "one.okca.lock")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestOpenWrongPassword(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "one", "two")
	_, err := Open(ctx, s, []string{"one", "two"}, map[string][]byte{
		"one": []byte("password-one"), "two": []byte("nope")})
	if err == nil || !strings.Contains(err.Error(), `"TWO"`) || !strings.Contains(err.Error(), "password is wrong") {
		t.Fatalf("err = %v", err)
	}
	// "one" was released again: a second Open works
	h, err := Open(ctx, s, []string{"one"}, map[string][]byte{"one": []byte("password-one")})
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
}

func TestNilHolder(t *testing.T) {
	var h *Holder
	if h.Get("x") != nil || h.Databases() != nil {
		t.Fatal("nil holder")
	}
	h.Close()
}

// TestRunSignsCRLs: the background loop signs every CA's first CRL and a
// new one right after a revocation made in a web session.
func TestRunSignsCRLs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := newStore(t, "one")
	h, err := Open(ctx, s, []string{"one"}, map[string][]byte{"one": []byte("password-one")})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	// A web session issues a CA and a leaf.
	web, err := s.Acquire(ctx, "one")
	if err != nil {
		t.Fatal(err)
	}
	defer web.Release()
	kr, err := web.Unlock(ctx, []byte("password-one"))
	if err != nil {
		t.Fatal(err)
	}
	issue := func(name string, signer int64, ca bool) int64 {
		ext := pki.ExtSpec{CA: 2, AuthKey: true}
		if ca {
			ext = pki.ExtSpec{CA: 1, SubKey: true, KeyUse: 1<<5 | 1<<6}
		}
		id, err := web.Issue(ctx, store.IssueParams{Name: name, Subject: []pki.DNAttr{{Name: "CN", Value: name}},
			NewKey: &pki.KeySpec{Type: "EC", Curve: "P-256"}, SignerID: signer, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().AddDate(1, 0, 0), Hash: "sha256", Ext: ext}, kr)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	rootID := issue("Root", 0, true)
	done := make(chan struct{})
	go func() { h.Run(ctx); close(done) }()
	crlEntries := func() int {
		snap, _ := web.Snapshot(ctx)
		for _, c := range snap.Certs {
			if c.ID == rootID {
				dir, _ := web.CADir(c.Authority.UUID)
				der, err := os.ReadFile(filepath.Join(dir, "crl.der"))
				if err != nil {
					return -1
				}
				l, err := x509.ParseRevocationList(der)
				if err != nil {
					return -1
				}
				return len(l.RevokedCertificateEntries)
			}
		}
		return -1
	}
	waitFor := func(want int) {
		t.Helper()
		for range 100 {
			if crlEntries() == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("CRL entries %d, want %d", crlEntries(), want)
	}
	waitFor(0)
	leafID := issue("leaf", rootID, false)
	if err := web.Revoke(ctx, leafID, store.Revocation{Reason: 1}); err != nil {
		t.Fatal(err)
	}
	waitFor(1)
	cancel()
	<-done
}

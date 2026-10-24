package store

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/mailsvb/openkca/internal/gcadb"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/vault"
)

const fixtures = "../../testdata/xdb"

// copyFixtures copies the fixture databases into a temp data folder so tests
// never modify the committed files.
func copyFixtures(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		src, err := os.Open(filepath.Join(fixtures, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		dst, err := os.Create(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(dst, src); err != nil {
			t.Fatal(err)
		}
		src.Close()
		dst.Close()
	}
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestScan(t *testing.T) {
	s := copyFixtures(t)
	if err := s.Create(context.Background(), "native", testPassword, testKDF); err != nil {
		t.Fatal(err)
	}
	infos, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Status{
		"garbage.xdb": Invalid, "legacy.xdb": Legacy, "md5.xdb": Upgradable, "newer.xdb": Newer,
		"sample.xdb": Upgradable, "schema8.xdb": Upgradable, "variants.xdb": Upgradable, "native": Supported,
	}
	if len(infos) != len(want) {
		t.Fatalf("got %d databases, want %d: %+v", len(infos), len(want), infos)
	}
	for _, in := range infos {
		if in.Status != want[in.Name] || in.XCA != (in.Name != "native") {
			t.Errorf("%s: status %s, XCA %v, want %s (%s)", in.Name, in.Status, in.XCA, want[in.Name], in.Detail)
		}
	}
}

// load opens a database by name; an XCA fixture of that name is imported
// first (with fixturePassword).
func load(t *testing.T, s *Store, name string) (*Handle, *gcadb.Snapshot) {
	t.Helper()
	ctx := context.Background()
	var kr *vault.Keyring
	if _, err := s.Lookup(ctx, name); err != nil {
		var rep ConvertReport
		if kr, rep, err = s.Import(ctx, name+ExtXCA, fixturePassword, testKDF); err != nil {
			t.Fatalf("import %s: %v", name, err)
		}
		if rep.Target != name {
			t.Fatalf("imported as %s", rep.Target)
		}
	}
	h, err := s.Acquire(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Release)
	if kr != nil {
		setKR(h, kr)
		t.Cleanup(func() {
			keyringsMu.Lock()
			delete(keyrings, h)
			keyringsMu.Unlock()
		})
	}
	snap, err := h.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return h, snap
}

func TestImportedSnapshot(t *testing.T) {
	s := copyFixtures(t)
	h, snap := load(t, s, "sample")
	if len(snap.Keys) != 10 || len(snap.Certs) != 7 || len(snap.Requests) != 1 || len(snap.CRLs) != 2 || len(snap.Templates) != 3 {
		t.Fatalf("counts: keys %d certs %d reqs %d crls %d templates %d",
			len(snap.Keys), len(snap.Certs), len(snap.Requests), len(snap.CRLs), len(snap.Templates))
	}
	for _, c := range snap.Certs {
		cert, err := x509.ParseCertificate(c.DER)
		if err != nil {
			t.Fatal(err)
		}
		if c.KeyID == 0 || c.IssuerID == 0 {
			t.Errorf("cert %s: key %d, issuer %d", c.Name, c.KeyID, c.IssuerID)
		}
		var fpr, subject, issuer []byte
		h.DB.SQL.QueryRow("SELECT fingerprint, subject, issuer_name FROM certs WHERE item=?", c.ID).Scan(&fpr, &subject, &issuer)
		if !bytes.Equal(fpr, gcadb.Fingerprint(c.DER)) || !bytes.Equal(subject, cert.RawSubject) || !bytes.Equal(issuer, cert.RawIssuer) {
			t.Errorf("cert %s: stored columns differ", c.Name)
		}
	}
	for _, r := range snap.Requests {
		if r.KeyID == 0 {
			t.Errorf("request %s has no key", r.Name)
		}
	}
	for _, c := range snap.CRLs {
		if c.IssuerID == 0 {
			t.Errorf("crl %s has no issuer", c.Name)
		}
	}
	if len(snap.Revocations) != 1 || snap.Revocations[0].Serial != "2003" {
		t.Errorf("revocations: %+v", snap.Revocations)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "sample.xdb")); !os.IsNotExist(err) {
		t.Errorf("the XCA file is still there: %v", err)
	}
	log, _ := h.AuditLog(context.Background(), 0, 0, 10)
	if len(log) == 0 || log[len(log)-1].Action != "database.import" {
		t.Errorf("audit %+v", log)
	}
}

func TestDecryptAllKeys(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	for _, tc := range []struct {
		db        string
		ownPass   map[string]string
		wantCount int
	}{
		{db: "sample", wantCount: 10},
		{db: "variants", ownPass: map[string]string{"mail": "mailpass"}, wantCount: 9},
	} {
		h, snap := load(t, s, tc.db)
		kr := krOf(t, h)
		n := 0
		for _, k := range snap.Keys {
			if !k.HasPrivate {
				continue
			}
			n++
			var kp KeyPasswords
			if p, ok := tc.ownPass[k.Name]; ok {
				if k.Protection != gcadb.ProtPassword || !k.Legacy {
					t.Errorf("%s/%s: protection %d legacy %v", tc.db, k.Name, k.Protection, k.Legacy)
				}
				if _, err := h.unlock(ctx, k.ID, k.KeyType, kr, nil); !errors.Is(err, ErrNeedKeyPassword) {
					t.Errorf("%s/%s: opened without its password: %v", tc.db, k.Name, err)
				}
				kp = KeyPasswords{k.ID: []byte(p)}
			} else if k.Protection != gcadb.ProtDEK {
				t.Errorf("%s/%s: protection %d", tc.db, k.Name, k.Protection)
			}
			priv, err := h.unlock(ctx, k.ID, k.KeyType, kr, kp)
			if err != nil {
				t.Errorf("%s/%s (%s): %v", tc.db, k.Name, k.KeyType, err)
				continue
			}
			if ok, err := pki.MatchesPublic(priv, k.Public); !ok || err != nil {
				t.Errorf("%s/%s: private key does not match public key (%v)", tc.db, k.Name, err)
			}
		}
		if n != tc.wantCount {
			t.Errorf("%s: %d private keys, want %d", tc.db, n, tc.wantCount)
		}
	}
}

func TestDescribeAll(t *testing.T) {
	s := copyFixtures(t)
	_, snap := load(t, s, "sample")
	for _, c := range snap.Certs {
		info := pki.DescribeCert(c.DER)
		if info.ParseError != "" {
			t.Errorf("%s: %s", c.Name, info.ParseError)
		}
		if info.Serial != c.Serial {
			t.Errorf("%s: serial %s, stored %s", c.Name, info.Serial, c.Serial)
		}
		if info.IsCA != c.CA {
			t.Errorf("%s: CA %v, stored %v", c.Name, info.IsCA, c.CA)
		}
	}
	for _, k := range snap.Keys {
		info := pki.DescribePublicKey(k.Public)
		if info.Bits != k.Len {
			t.Errorf("key %s (%s): %d bits, stored %d", k.Name, info.Algorithm, info.Bits, k.Len)
		}
	}
	for _, r := range snap.Requests {
		if info := pki.DescribeRequest(r.DER); info.ParseError != "" || !info.SignatureOK {
			t.Errorf("request %s: %+v", r.Name, info)
		}
	}
	for _, c := range snap.CRLs {
		if info := pki.DescribeCRL(c.DER); info.ParseError != "" {
			t.Errorf("crl %s: %s", c.Name, info.ParseError)
		}
	}
	for _, tp := range snap.Templates {
		if tp.Data == nil || len(tp.Data.Settings) == 0 {
			t.Errorf("template %s: %+v", tp.Name, tp.Data)
		}
	}
}

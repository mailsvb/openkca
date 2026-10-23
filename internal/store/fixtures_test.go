package store

import (
	"context"
	"crypto/x509"
	b64 "encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/tmpl"
	"github.com/mailsvb/go-ca/internal/xdb"
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
	infos, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Status{
		"garbage": Invalid, "legacy": Legacy, "md5": Upgradable, "newer": Newer,
		"sample": Upgradable, "schema8": Upgradable, "variants": Upgradable,
	}
	if len(infos) != len(want) {
		t.Fatalf("got %d databases, want %d: %+v", len(infos), len(want), infos)
	}
	for _, in := range infos {
		if in.Status != want[in.Name] {
			t.Errorf("%s: status %s, want %s (%s)", in.Name, in.Status, want[in.Name], in.Detail)
		}
	}
}

func load(t *testing.T, s *Store, name string) (*Handle, *xdb.Snapshot) {
	t.Helper()
	h, err := s.Acquire(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Release)
	snap, err := h.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return h, snap
}

func TestSnapshotAndHashes(t *testing.T) {
	s := copyFixtures(t)
	_, snap := load(t, s, "sample")
	if len(snap.Keys) != 10 || len(snap.Certs) != 7 || len(snap.Requests) != 1 || len(snap.CRLs) != 2 || len(snap.Templates) != 3 {
		t.Fatalf("counts: keys %d certs %d reqs %d crls %d templates %d",
			len(snap.Keys), len(snap.Certs), len(snap.Requests), len(snap.CRLs), len(snap.Templates))
	}
	keyHash := map[int64]int64{}
	for _, k := range snap.Keys {
		if got := xdb.Hash(k.Public); got != k.Hash {
			t.Errorf("key %s: hash %d, stored %d", k.Name, got, k.Hash)
		}
		keyHash[k.ID] = k.Hash
	}
	for _, c := range snap.Certs {
		if got := xdb.Hash(c.DER); got != c.Hash {
			t.Errorf("cert %s: hash %d, stored %d", c.Name, got, c.Hash)
		}
		cert, err := x509.ParseCertificate(c.DER)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := xdb.NameHash(cert.RawIssuer); got != c.IssHash {
			t.Errorf("cert %s: iss_hash %d, stored %d", c.Name, got, c.IssHash)
		}
		if c.KeyID == 0 {
			t.Errorf("cert %s has no key", c.Name)
		}
	}
	// subj_hash and key_hash live in x509super
	rows, err := s.open[filepath.Join(s.Dir, "sample.xdb")].DB.SQL.Query(
		`SELECT x.subj_hash, x.key_hash, COALESCE(c.cert, r.request) FROM x509super x
		 LEFT JOIN certs c ON c.item = x.item LEFT JOIN requests r ON r.item = x.item`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var subj, kh int64
		var b64 string
		if err := rows.Scan(&subj, &kh, &b64); err != nil {
			t.Fatal(err)
		}
		n++
		der, _ := base64Decode(b64)
		var rawSubject, spki []byte
		if c, err := x509.ParseCertificate(der); err == nil {
			rawSubject, spki = c.RawSubject, c.RawSubjectPublicKeyInfo
		} else if r, err := x509.ParseCertificateRequest(der); err == nil {
			rawSubject, spki = r.RawSubject, r.RawSubjectPublicKeyInfo
		} else {
			t.Fatal(err)
		}
		if got, _ := xdb.NameHash(rawSubject); got != subj {
			t.Errorf("subj_hash %d, computed %d", subj, got)
		}
		if got := xdb.Hash(spki); got != kh {
			t.Errorf("key_hash %d, computed %d", kh, got)
		}
	}
	if n != 8 {
		t.Errorf("x509super rows %d", n)
	}
	for _, c := range snap.CRLs {
		if got := xdb.Hash(c.DER); got != c.Hash {
			t.Errorf("crl %s: hash %d, stored %d", c.Name, got, c.Hash)
		}
		crl, err := x509.ParseRevocationList(c.DER)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := xdb.NameHash(crl.RawIssuer); got != c.IssHash {
			t.Errorf("crl %s: iss_hash %d, stored %d", c.Name, got, c.IssHash)
		}
	}
	if len(snap.Revocations) != 1 || snap.Revocations[0].Serial != "2003" {
		t.Errorf("revocations: %+v", snap.Revocations)
	}
}

func TestDecryptAllKeys(t *testing.T) {
	s := copyFixtures(t)
	for _, tc := range []struct {
		db        string
		legacy    map[string]bool
		ownPass   map[string]string
		wantCount int
	}{
		{db: "sample", wantCount: 10},
		{db: "variants", legacy: map[string]bool{"www": true}, ownPass: map[string]string{"mail": "mailpass"}, wantCount: 9},
	} {
		h, snap := load(t, s, tc.db)
		n := 0
		for _, k := range snap.Keys {
			if !k.HasPrivate {
				continue
			}
			n++
			blob, own, err := h.DB.PrivateKey(context.Background(), k.ID)
			if err != nil {
				t.Fatal(err)
			}
			pw := "secret"
			if p, ok := tc.ownPass[k.Name]; ok {
				if own != xdb.PassPrivate {
					t.Errorf("%s/%s: ownPass %d", tc.db, k.Name, own)
				}
				if _, _, err := pki.DecryptPrivateKey(blob, k.KeyType, []byte(pw)); !errors.Is(err, pki.ErrWrongPassword) {
					t.Errorf("%s/%s: database password accepted: %v", tc.db, k.Name, err)
				}
				pw = p
			}
			priv, legacy, err := pki.DecryptPrivateKey(blob, k.KeyType, []byte(pw))
			if err != nil {
				t.Errorf("%s/%s (%s): %v", tc.db, k.Name, k.KeyType, err)
				continue
			}
			if legacy != tc.legacy[k.Name] {
				t.Errorf("%s/%s: legacy=%v", tc.db, k.Name, legacy)
			}
			if ok, err := pki.MatchesPublic(priv, k.Public); !ok || err != nil {
				t.Errorf("%s/%s: private key does not match public key (%v)", tc.db, k.Name, err)
			}
			if _, _, err := pki.DecryptPrivateKey(blob, k.KeyType, []byte("wrong")); !errors.Is(err, pki.ErrWrongPassword) {
				t.Errorf("%s/%s: wrong password gives %v", tc.db, k.Name, err)
			}
		}
		if n != tc.wantCount {
			t.Errorf("%s: %d private keys, want %d", tc.db, n, tc.wantCount)
		}
	}
}

func base64Decode(s string) ([]byte, error) { return b64.StdEncoding.DecodeString(s) }

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
		if _, err := tmpl.Decode(tp.Blob, tp.Version); err != nil {
			t.Errorf("template %s: %v", tp.Name, err)
		}
	}
}

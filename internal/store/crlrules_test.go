package store

import (
	"context"
	"crypto/x509"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/vault"
)

// revocationOf returns the revocation of serial under caID.
func revOf(snap *gcadb.Snapshot, caID int64, serial string) *gcadb.Revocation {
	for _, r := range snap.Revocations {
		if r.CAID == caID && r.Serial == serial {
			return r
		}
	}
	return nil
}

func TestRevocationExpiryAndPurge(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "ca", testPassword, vault.Default); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "ca")
	rootID, _ := h.Issue(ctx, params("Root", 0), krOf(t, h))
	leafID, err := h.Issue(ctx, params("leaf", rootID), krOf(t, h))
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := h.Snapshot(ctx)
	leaf := findCert(snap, leafID)
	if err := h.Revoke(ctx, leafID, Revocation{Reason: 1}); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	r := revOf(snap, rootID, leaf.Serial)
	info := pki.DescribeCert(leaf.DER)
	if r == nil || !r.CertKnown || !r.Expires.Equal(info.NotAfter.UTC().Truncate(time.Second)) {
		t.Fatalf("revocation %+v, want expiry %v", r, info.NotAfter)
	}
	// The rule: on the CRL until 30 days after expiry.
	if !r.OnCRL(info.NotAfter.Add(29*24*time.Hour)) || r.OnCRL(info.NotAfter.Add(31*24*time.Hour)) {
		t.Fatal("30 day grace")
	}

	// In the trash the certificate is still known; purged, the recorded
	// expiry keeps it on the CRL.
	if err := h.Delete(ctx, leafID); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if r = revOf(snap, rootID, leaf.Serial); r == nil || !r.CertKnown || !r.OnCRL(time.Now()) {
		t.Fatalf("in the trash: %+v", r)
	}
	if _, err := h.Purge(ctx, []int64{leafID}); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if r = revOf(snap, rootID, leaf.Serial); r == nil || r.CertKnown || r.Expires.IsZero() || !r.OnCRL(time.Now()) {
		t.Fatalf("purged: %+v", r)
	}

	// A revocation without a known certificate (from before schema 5) is
	// not published.
	if err := h.DB.Write(ctx, func(tx *gcadb.Tx) error {
		return tx.PutRevocation(ctx, gcadb.Revocation{CAID: rootID, Serial: "0ABC", Date: time.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	h.Invalidate()
	snap, _ = h.Snapshot(ctx)
	if r = revOf(snap, rootID, "0ABC"); r == nil || r.CertKnown || r.OnCRL(time.Now()) {
		t.Fatalf("unknown serial: %+v", r)
	}

	// The CRL lists the purged certificate but not the unknown serial, and
	// a newer generated CRL replaces the older one.
	var crlIDs []int64
	for i := 0; i < 2; i++ {
		snap, _ = h.Snapshot(ctx)
		id, err := h.GenerateCRL(ctx, rootID, DefaultCRLOptions(snap, findCert(snap, rootID)), krOf(t, h), nil)
		if err != nil {
			t.Fatal(err)
		}
		crlIDs = append(crlIDs, id)
	}
	snap, _ = h.Snapshot(ctx)
	var gen []*gcadb.CRL
	for _, c := range snap.CRLs {
		if c.IssuerID == rootID {
			gen = append(gen, c)
		}
	}
	if len(gen) != 1 || gen[0].ID != crlIDs[1] || gen[0].Num != 2 {
		t.Fatalf("generated CRLs %+v", gen)
	}
	l, err := x509.ParseRevocationList(gen[0].DER)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.RevokedCertificateEntries) != 1 || pki.SerialHex(l.RevokedCertificateEntries[0].SerialNumber) != leaf.Serial {
		t.Fatalf("CRL entries %+v", l.RevokedCertificateEntries)
	}
}

func TestMigrateSchema4(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "old", testPassword, vault.Default); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "old")
	rootID, _ := h.Issue(ctx, params("Root", 0), krOf(t, h))
	leafID, _ := h.Issue(ctx, params("leaf", rootID), krOf(t, h))
	if err := h.Revoke(ctx, leafID, Revocation{Reason: 1}); err != nil {
		t.Fatal(err)
	}
	snap, _ := h.Snapshot(ctx)
	serial := findCert(snap, leafID).Serial
	h.Release()

	// Turn the file back into schema 4.
	path := filepath.Join(s.Dir, "old.gca")
	db, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"DROP INDEX certs_issuer_serial",
		"ALTER TABLE revocations DROP COLUMN expires",
		"UPDATE settings SET value='4' WHERE key='schema'",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(stmt, err)
		}
	}
	db.Close()
	if st, _, v, _ := Classify(ctx, path, true); st != Supported || v.Schema != 4 {
		t.Fatalf("schema 4 classified %s %d", st, v.Schema)
	}
	before, _ := s.Backups("old")

	h, err = s.Acquire(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	if v, _ := h.DB.Setting(ctx, "schema"); v != "5" {
		t.Fatalf("schema after open %q", v)
	}
	if after, _ := s.Backups("old"); len(after) != len(before)+1 {
		t.Fatalf("no backup before the migration: %d -> %d", len(before), len(after))
	}
	snap, err = h.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r := revOf(snap, rootID, serial); r == nil || !r.CertKnown || r.Expires.IsZero() {
		t.Fatalf("revocation after migration %+v", r)
	}
	var exp sql.NullString
	h.DB.SQL.QueryRow("SELECT expires FROM revocations WHERE serial=?", serial).Scan(&exp)
	if !exp.Valid {
		t.Fatal("expires not filled by the migration")
	}
}

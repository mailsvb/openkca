package store

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/vault"
)

// revocationOf returns the revocation of serial under caID.
func revOf(snap *db.Snapshot, caID int64, serial string) *db.Revocation {
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

	// A revocation without a known certificate (as an XCA import can bring) is
	// not published.
	if err := h.DB.Write(ctx, func(tx *db.Tx) error {
		return tx.PutRevocation(ctx, db.Revocation{CAID: rootID, Serial: "0ABC", Date: time.Now()})
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
	var gen []*db.CRL
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

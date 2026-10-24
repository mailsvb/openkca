package store

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/vault"
)

func TestCAOperations(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	pw := testPassword
	if err := s.Create(ctx, "ca", pw, vault.Default); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "ca")
	rootID, _ := h.Issue(ctx, params("Root", 0), krOf(t, h))
	subP := params("Sub", rootID)
	subID, _ := h.Issue(ctx, subP, krOf(t, h))
	leafP := params("leaf", subID)
	leafP.Ext = pki.ExtSpec{CA: 2, AuthKey: true}
	leafID, err := h.Issue(ctx, leafP, krOf(t, h))
	if err != nil {
		t.Fatal(err)
	}
	leaf2ID, _ := h.Issue(ctx, leafP, krOf(t, h))

	// Revoke, unrevoke, revoke again
	inval := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	if err := h.Revoke(ctx, leafID, Revocation{Reason: 1, InvalDate: inval}); err != nil {
		t.Fatal(err)
	}
	if err := h.Revoke(ctx, leaf2ID, Revocation{Reason: 4}); err != nil {
		t.Fatal(err)
	}
	if err := h.Unrevoke(ctx, leaf2ID); err != nil {
		t.Fatal(err)
	}
	if err := h.Revoke(ctx, rootID, Revocation{}); err == nil {
		t.Fatal("a self-signed certificate was revoked")
	}
	// A serial that is not in the database, then edited
	if err := h.SetRevocation(ctx, subID, "0x0A:BC", Revocation{Reason: 5}); err != nil {
		t.Fatal(err)
	}
	snap, _ := h.Snapshot(ctx)
	var date time.Time
	for _, r := range snap.Revocations {
		if r.Serial == "0ABC" {
			date = r.Date
		}
	}
	time.Sleep(1100 * time.Millisecond)
	if err := h.SetRevocation(ctx, subID, "abc", Revocation{Reason: 3}); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if len(snap.Revocations) != 2 {
		t.Fatalf("revocations %+v", snap.Revocations)
	}
	for _, r := range snap.Revocations {
		if r.Serial == "0ABC" && (r.ReasonBit != 3 || !r.Date.Equal(date)) {
			t.Fatalf("edit changed date or kept reason: %+v", r)
		}
	}

	// CRL with defaults
	sub := findCert(snap, subID)
	opts := DefaultCRLOptions(snap, sub)
	if opts.Number != 1 || opts.NextUpdate.Sub(opts.ThisUpdate) != 30*24*time.Hour {
		t.Fatalf("defaults %+v", opts)
	}
	crlID, err := h.GenerateCRL(ctx, subID, opts, krOf(t, h), nil)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	sub = findCert(snap, subID)
	var crlDER []byte
	for _, c := range snap.CRLs {
		if c.ID == crlID {
			crlDER = c.DER
			if c.IssuerID != subID || c.Num != 1 {
				t.Fatalf("crl row %+v", c)
			}
		}
	}
	l, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	sc, _ := x509.ParseCertificate(sub.DER)
	if l.CheckSignatureFrom(sc) != nil || len(l.RevokedCertificateEntries) != 2 {
		t.Fatalf("crl entries %d", len(l.RevokedCertificateEntries))
	}
	if sub.Authority.CRLNo != 1 || sub.Authority.CRLExpire.Year() == 9999 {
		t.Fatalf("authority %+v", sub.Authority)
	}
	for _, r := range snap.Revocations {
		if r.CRLNo != 1 {
			t.Fatalf("revocation crlNo %+v", r)
		}
	}
	if DefaultCRLOptions(snap, sub).Number != 2 {
		t.Fatal("next CRL number")
	}
	if err := h.SetCAProperties(ctx, subID, 7, 0); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if d := DefaultCRLOptions(snap, findCert(snap, subID)); d.NextUpdate.Sub(d.ThisUpdate) != 7*24*time.Hour {
		t.Fatal("crlDays not used")
	}

	// Index file, in the CA's folder named after its authority ID, which
	// for a new CA is its certificate's UUID
	subAuth := findCert(snap, subID).Authority.UUID
	if subAuth != findCert(snap, subID).UUID {
		t.Fatalf("authority ID %s of a new CA", subAuth)
	}
	subDir, err := h.CADir(subAuth)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(s.Dir, "ca", "ca", subAuth); subDir != want {
		t.Fatalf("CA folder %s, want %s", subDir, want)
	}
	idx, err := os.ReadFile(filepath.Join(subDir, "index.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(idx)), "\n")
	if len(lines) != 3 {
		t.Fatalf("index:\n%s", idx)
	}
	leaf := findCert(snap, leafID)
	var revLine string
	for _, ln := range lines {
		if strings.Contains(ln, "\t"+leaf.Serial+"\t") {
			revLine = ln
		}
	}
	if !strings.HasPrefix(revLine, "R\t") || !strings.Contains(revLine, ",keyCompromise\t") || !strings.HasSuffix(revLine, "/C=DE/O=Test/CN=leaf") {
		t.Fatalf("index line %q", revLine)
	}
	if b, _ := os.ReadFile(filepath.Join(subDir, "index.txt.attr")); string(b) != "unique_subject = no\n" {
		t.Fatal("index.txt.attr")
	}
	ocspCheck(t, h, s, snap, subID, leaf.Serial, "revoked")
	ocspCheck(t, h, s, snap, subID, findCert(snap, leaf2ID).Serial, "good")

	// Renew the leaf, revoking the old one
	newLeaf, err := h.Renew(ctx, leaf2ID, RenewOptions{NotBefore: time.Now(), NotAfter: time.Now().AddDate(2, 0, 0),
		Revoke: &Revocation{Reason: pki.ReasonSuperseded}}, krOf(t, h), nil)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	nl, ol := findCert(snap, newLeaf), findCert(snap, leaf2ID)
	if nl.Serial == ol.Serial || nl.IssuerID != subID || nl.KeyID != ol.KeyID || nl.Source != 6 {
		t.Fatalf("renewed leaf %+v", nl)
	}
	revoked := false
	for _, r := range snap.Revocations {
		revoked = revoked || (r.Serial == ol.Serial && r.ReasonBit == 4)
	}
	if !revoked {
		t.Fatal("old certificate not revoked")
	}
	// Renew the intermediate CA, keeping the serial and replacing the old one:
	// children and revocations move to the new certificate.
	newSub, err := h.Renew(ctx, subID, RenewOptions{NotBefore: time.Now(), NotAfter: time.Now().AddDate(5, 0, 0),
		KeepSerial: true, Replace: true}, krOf(t, h), nil)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if findCert(snap, subID) != nil || findCert(snap, leafID).IssuerID != newSub || findCert(snap, newSub).Serial != sub.Serial {
		t.Fatal("CA renewal did not hand over its certificates")
	}
	n := 0
	for _, r := range snap.Revocations {
		if r.CAID == newSub {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("revocations after CA renewal: %d", n)
	}
	// The renewed CA is a new item but takes over the authority ID and with
	// it the folder; the replaced one in the trash keeps the ID and cannot
	// be restored while the renewed one is live.
	if c := findCert(snap, newSub); c.UUID == subAuth || c.Authority.UUID != subAuth {
		t.Fatalf("renewed CA: uuid %s, authority %s", c.UUID, c.Authority.UUID)
	}
	if b, err := os.ReadFile(filepath.Join(subDir, "index.txt")); err != nil || strings.Count("\n"+string(b), "\nR\t") != 3 ||
		!strings.Contains(string(b), "\t"+nl.Serial+"\t") {
		t.Fatalf("index of the renewed CA: %q %v", b, err)
	}
	if err := h.Restore(ctx, subID); !errors.Is(err, gcadb.ErrAuthorityInUse) {
		t.Fatalf("restored the replaced CA: %v", err)
	}
}

// ocspCheck asks "openssl ocsp -index" about a serial and expects status.
func ocspCheck(t *testing.T, h *Handle, s *Store, snap interface{}, caID int64, serial, status string) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	sn, _ := h.Snapshot(context.Background())
	ca := findCert(sn, caID)
	k := findKey(sn, ca.KeyID)
	key, err := h.unlock(context.Background(), k.ID, k.KeyType, krOf(t, h), nil)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := pki.MarshalPKCS8(key)
	dir := t.TempDir()
	caPEM, keyPEM := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	os.WriteFile(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.DER}), 0o644)
	os.WriteFile(keyPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	run := func(args ...string) string {
		out, err := exec.Command("openssl", append([]string{"ocsp"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("openssl ocsp %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	req, resp := filepath.Join(dir, "req.der"), filepath.Join(dir, "resp.der")
	run("-issuer", caPEM, "-serial", "0x"+serial, "-reqout", req, "-no_nonce")
	caDir, err := h.CADir(ca.Authority.UUID)
	if err != nil {
		t.Fatal(err)
	}
	run("-index", filepath.Join(caDir, "index.txt"), "-rsigner", caPEM, "-rkey", keyPEM,
		"-CA", caPEM, "-reqin", req, "-respout", resp)
	if out := run("-respin", resp, "-resp_text", "-noverify"); !strings.Contains(out, "Cert Status: "+status) {
		t.Fatalf("OCSP status for %s is not %s:\n%s", serial, status, out)
	}
}

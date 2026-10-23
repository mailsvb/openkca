package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mailsvb/go-ca/internal/pki"
)

// TestWriteForXCA writes a database populated by go-ca for inspection with
// desktop XCA (testdata/gen/check-with-xca.sh). It only runs when
// GOCA_XCA_DIR is set.
func TestWriteForXCA(t *testing.T) {
	dir := os.Getenv("GOCA_XCA_DIR")
	if dir == "" {
		t.Skip("GOCA_XCA_DIR not set")
	}
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pw := []byte("secret")
	os.Remove(dir + "/goca.xdb")
	if err := s.Create(ctx, "goca", pw); err != nil {
		t.Fatal(err)
	}
	h, err := s.Acquire(ctx, "goca")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	root, err := h.Issue(ctx, params("GoCA Root", 0), pw)
	if err != nil {
		t.Fatal(err)
	}
	rsa := params("GoCA RSA Sub", root)
	rsa.NewKey = &pki.KeySpec{Type: "RSA", Bits: 2048}
	sub, err := h.Issue(ctx, rsa, pw)
	if err != nil {
		t.Fatal(err)
	}
	rp := params("host.example.org", 0)
	rp.Request, rp.Ext = true, pki.ExtSpec{SubAltName: "DNS:copycn", KeyUse: 1 | 4, EKU: []string{"serverAuth"}}
	req, err := h.Issue(ctx, rp, pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Issue(ctx, IssueParams{Name: "host.example.org", FromReqID: req, ReqSubject: true, CopyReqExt: true,
		SignerID: sub, NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0), Hash: "sha256",
		Ext: pki.ExtSpec{CA: 2, SubKey: true, AuthKey: true}}, pw); err != nil {
		t.Fatal(err)
	}
	ed := params("ed25519 client", sub)
	ed.NewKey, ed.Ext = &pki.KeySpec{Type: "Ed25519"}, pki.ExtSpec{CA: 2, EKU: []string{"clientAuth"}, AuthKey: true}
	if _, err := h.Issue(ctx, ed, pw); err != nil {
		t.Fatal(err)
	}
	k, err := h.GenerateKey(ctx, "spare key", pki.KeySpec{Type: "EC", Curve: "P-521"}, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Rename(ctx, k, "spare key (renamed)", "comment from go-ca"); err != nil {
		t.Fatal(err)
	}
}

// TestWriteRevocationsForXCA revokes certificates in a database XCA wrote
// and generates a CRL with go-ca, for check-with-xca.sh.
func TestWriteRevocationsForXCA(t *testing.T) {
	dir := os.Getenv("GOCA_XCA_DIR")
	if dir == "" {
		t.Skip("GOCA_XCA_DIR not set")
	}
	src, err := os.ReadFile("../../testdata/xdb/schema8.xdb")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/revoked.xdb", src, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	h, err := s.Acquire(ctx, "revoked")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Release()
	pw := []byte("secret")
	// www.example.org (item 7) and mail.example.org (item 9) under Example Issuing CA (item 5)
	if err := h.Revoke(ctx, 7, Revocation{Reason: 1, InvalDate: time.Now().Add(-24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Renew(ctx, 9, RenewOptions{NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		Revoke: &Revocation{Reason: 4}}, pw, nil); err != nil {
		t.Fatal(err)
	}
	snap, _ := h.Snapshot(ctx)
	opts := DefaultCRLOptions(snap, findCert(snap, 5))
	opts.Name = "CRL by go-ca"
	if _, err := h.GenerateCRL(ctx, 5, opts, pw, nil); err != nil {
		t.Fatal(err)
	}
}

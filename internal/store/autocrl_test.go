package store

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/publish"
	"github.com/mailsvb/go-ca/internal/vault"
)

func TestSignDueCRLs(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "auto", testPassword, vault.Default); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "auto")
	kr := krOf(t, h)
	rootID, _ := h.Issue(ctx, params("Root", 0), kr)
	subID, _ := h.Issue(ctx, params("Sub", rootID), kr)
	leafP := params("leaf", subID)
	leafP.Ext = pki.ExtSpec{CA: 2, AuthKey: true}
	leafID, _ := h.Issue(ctx, leafP, kr)
	now := time.Now()

	// Every CA without a CRL gets one.
	signed, err := h.SignDueCRLs(ctx, kr, now)
	if err != nil || len(signed) != 2 {
		t.Fatalf("first run signed %v: %v", signed, err)
	}
	if signed, _ = h.SignDueCRLs(ctx, kr, now); len(signed) != 0 {
		t.Fatalf("nothing due, signed %v", signed)
	}
	// The CRL is published in the CA folder.
	snap, _ := h.Snapshot(ctx)
	sub := findCert(snap, subID)
	dir, _ := h.CADir(sub.Authority.UUID)
	der, err := os.ReadFile(filepath.Join(dir, publish.CRLFile))
	if err != nil {
		t.Fatal(err)
	}
	if l, err := x509.ParseRevocationList(der); err != nil || l.Number.Int64() != 1 || len(l.RevokedCertificateEntries) != 0 {
		t.Fatalf("published CRL: %v", err)
	}
	if l, _ := x509.ParseRevocationList(der); l.NextUpdate.Sub(l.ThisUpdate) != 7*24*time.Hour {
		t.Fatalf("sub CA interval %v", l.NextUpdate.Sub(l.ThisUpdate))
	}
	if b, _ := os.ReadFile(filepath.Join(dir, publish.CertFile)); string(b) != string(sub.DER) {
		t.Fatal("CA certificate not published")
	}

	// A revocation makes the sub CA's CRL due, and only that one.
	if err := h.Revoke(ctx, leafID, Revocation{Reason: 1}); err != nil {
		t.Fatal(err)
	}
	if signed, _ = h.SignDueCRLs(ctx, kr, now); len(signed) != 1 || signed[0] != subID {
		t.Fatalf("after revoke signed %v", signed)
	}
	der, _ = os.ReadFile(filepath.Join(dir, publish.CRLFile))
	if l, _ := x509.ParseRevocationList(der); l.Number.Int64() != 2 || len(l.RevokedCertificateEntries) != 1 {
		t.Fatal("published CRL after revoke")
	}
	// Editing the invalidity date is a change too; the same state is not.
	if err := h.Revoke(ctx, leafID, Revocation{Reason: 1, InvalDate: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if signed, _ = h.SignDueCRLs(ctx, kr, now); len(signed) != 1 {
		t.Fatalf("after edit signed %v", signed)
	}
	if signed, _ = h.SignDueCRLs(ctx, kr, now); len(signed) != 0 {
		t.Fatalf("stable state signed %v", signed)
	}
	// Half the validity: the root's 180 days.
	if signed, _ = h.SignDueCRLs(ctx, kr, now.Add(4*24*time.Hour)); len(signed) != 1 || signed[0] != subID {
		t.Fatalf("after 4 days signed %v", signed)
	}
	if signed, _ = h.SignDueCRLs(ctx, kr, now.Add(91*24*time.Hour)); len(signed) != 2 {
		t.Fatalf("after 91 days signed %v", signed)
	}
	// Unrevoke removes the entry.
	if err := h.Unrevoke(ctx, leafID); err != nil {
		t.Fatal(err)
	}
	if signed, _ = h.SignDueCRLs(ctx, kr, time.Now()); len(signed) != 1 {
		t.Fatalf("after unrevoke signed %v", signed)
	}
	// Only one generated CRL per CA is kept.
	snap, _ = h.Snapshot(ctx)
	n := 0
	for _, c := range snap.CRLs {
		if c.IssuerID == subID {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d CRLs of the sub CA", n)
	}

	// A CA key with its own password is never signed automatically.
	sub = findCert(snap, subID)
	if err := h.SetKeyPassword(ctx, sub.KeyID, kr, nil, []byte("own-password")); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if st := AutoCRLState(snap, findCert(snap, subID)); st != AutoCRLOwnPass {
		t.Fatalf("state %s", st)
	}
	if signed, _ = h.SignDueCRLs(ctx, kr, now.Add(100*24*time.Hour)); len(signed) != 1 || signed[0] != rootID {
		t.Fatalf("own password key signed %v", signed)
	}
	// SignCRLNow takes its password.
	if _, err := h.SignCRLNow(ctx, subID, kr, KeyPasswords{sub.KeyID: []byte("own-password")}); err != nil {
		t.Fatal(err)
	}
	if st := AutoCRLState(snap, findCert(snap, rootID)); st != AutoCRLOn {
		t.Fatalf("root state %s", st)
	}
	_ = gcadb.ProtDEK
}

// TestWatch: changes through a handle signal its watchers without blocking.
func TestWatch(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "w", testPassword, vault.Default); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "w")
	ch := h.Watch()
	h.Issue(ctx, params("Root", 0), krOf(t, h))
	h.Issue(ctx, params("Root2", 0), krOf(t, h)) // a second signal while one is pending
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("no signal")
	}
	select {
	case <-ch:
		t.Fatal("more than one pending signal")
	default:
	}
}

// TestPublishedExtensions: PubCDP/PubAIA resolve to the issuer's published
// URLs (dropping free-text duplicates); self-signed certificates get
// neither; a renewal can point an old certificate at the current URLs.
func TestPublishedExtensions(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	s.BaseURLs = []string{"http://ext.example", "http://int.lan:8080"}
	if err := s.Create(ctx, "pub", testPassword, vault.Default); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "pub")
	kr := krOf(t, h)
	rootP := params("Root", 0)
	rootP.Ext.PubCDP, rootP.Ext.PubAIA = true, true
	rootID, err := h.Issue(ctx, rootP, kr)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := h.Snapshot(ctx)
	root := findCert(snap, rootID)
	rc, _ := x509.ParseCertificate(root.DER)
	if len(rc.CRLDistributionPoints) != 0 || len(rc.IssuingCertificateURL) != 0 {
		t.Fatal("self-signed certificate with CDP/AIA")
	}
	id := root.Authority.UUID
	leafP := params("leaf", rootID)
	leafP.Ext = pki.ExtSpec{CA: 2, PubCDP: true, PubAIA: true,
		CRLDist:    "URI:http://ext.example/" + id + ".crl, URI:http://other.example/x.crl",
		AuthInfAcc: "OCSP;URI:http://ocsp.example"}
	leafID, err := h.Issue(ctx, leafP, kr)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	lc, _ := x509.ParseCertificate(findCert(snap, leafID).DER)
	wantCDP := "http://ext.example/" + id + ".crl http://int.lan:8080/" + id + ".crl http://other.example/x.crl"
	if got := strings.Join(lc.CRLDistributionPoints, " "); got != wantCDP {
		t.Fatalf("CDP %s", got)
	}
	if got := strings.Join(lc.IssuingCertificateURL, " "); got != "http://ext.example/"+id+".crt http://int.lan:8080/"+id+".crt" {
		t.Fatalf("AIA %s", got)
	}
	if len(lc.OCSPServer) != 1 {
		t.Fatal("OCSP entry lost")
	}

	// Unchecked: nothing published.
	plainP := params("plain", rootID)
	plainP.Ext = pki.ExtSpec{CA: 2}
	plainID, _ := h.Issue(ctx, plainP, kr)
	snap, _ = h.Snapshot(ctx)
	pc, _ := x509.ParseCertificate(findCert(snap, plainID).DER)
	if len(pc.CRLDistributionPoints) != 0 || len(pc.IssuingCertificateURL) != 0 {
		t.Fatal("unchecked boxes added CDP/AIA")
	}

	// Renewing with the boxes checked after a base URL change.
	s.BaseURLs = []string{"http://new.example"}
	newID, err := h.Renew(ctx, leafID, RenewOptions{NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0),
		PubCDP: true, PubAIA: true}, kr, nil)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	nc, _ := x509.ParseCertificate(findCert(snap, newID).DER)
	if got := strings.Join(nc.CRLDistributionPoints, " "); got != "http://new.example/"+id+".crl http://other.example/x.crl" {
		t.Fatalf("renewed CDP %s", got)
	}
	if got := strings.Join(nc.IssuingCertificateURL, " "); got != "http://new.example/"+id+".crt" {
		t.Fatalf("renewed AIA %s", got)
	}
	// Unchecked: copied as it was.
	keptID, _ := h.Renew(ctx, leafID, RenewOptions{NotBefore: time.Now(), NotAfter: time.Now().AddDate(1, 0, 0)}, kr, nil)
	snap, _ = h.Snapshot(ctx)
	kc, _ := x509.ParseCertificate(findCert(snap, keptID).DER)
	if strings.Join(kc.CRLDistributionPoints, " ") != wantCDP {
		t.Fatal("renewal without the boxes changed the CDP")
	}
}

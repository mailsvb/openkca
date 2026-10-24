package store

import (
	"bytes"
	"context"
	"crypto/x509"
	b64 "encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/vault"
)

var caExt = pki.ExtSpec{CA: 1, BCCritical: true, SubKey: true, AuthKey: true, KeyUse: 1<<5 | 1<<6, KUCritical: true}

func params(name string, signer int64) IssueParams {
	return IssueParams{Name: name, Subject: []pki.DNAttr{{Name: "C", Value: "DE"}, {Name: "O", Value: "Test"}, {Name: "CN", Value: name}},
		NewKey: &pki.KeySpec{Type: "EC", Curve: "P-256"}, SignerID: signer, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(1, 0, 0), Hash: "sha256", Ext: caExt}
}

func TestIssueHierarchy(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	pw := testPassword
	if err := s.Create(ctx, "fresh", pw, vault.Default); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "fresh")

	rootID, err := h.Issue(ctx, params("Root", 0), krOf(t, h))
	if err != nil {
		t.Fatal(err)
	}
	p := params("Sub", rootID)
	p.Ext.PathLen = "0"
	subID, err := h.Issue(ctx, p, krOf(t, h))
	if err != nil {
		t.Fatal(err)
	}
	// A CSR with its own new key, then signed by Sub.
	rp := params("www", 0)
	rp.Request = true
	rp.Ext = pki.ExtSpec{SubAltName: "DNS:copycn", KeyUse: 1, EKU: []string{"serverAuth"}}
	reqID, err := h.Issue(ctx, rp, krOf(t, h))
	if err != nil {
		t.Fatal(err)
	}
	lp := IssueParams{Name: "www", FromReqID: reqID, ReqSubject: true, CopyReqExt: true, SignerID: subID,
		NotBefore: time.Now(), NotAfter: time.Now().AddDate(0, 3, 0), Hash: "sha384",
		Ext: pki.ExtSpec{CA: 2, SubKey: true, AuthKey: true}}
	leafID, err := h.Issue(ctx, lp, krOf(t, h))
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := h.Snapshot(ctx)
	root, sub, leaf, req := findCert(snap, rootID), findCert(snap, subID), findCert(snap, leafID), findRequest(snap, reqID)
	if root.IssuerID != rootID || sub.IssuerID != rootID || leaf.IssuerID != subID {
		t.Fatalf("issuers: root %d sub %d leaf %d", root.IssuerID, sub.IssuerID, leaf.IssuerID)
	}
	if root.Authority == nil || sub.Authority == nil || leaf.Authority != nil || root.Authority.CRLDays != 30 {
		t.Fatal("authority rows")
	}
	if !req.Signed || !strings.Contains(req.Comment, "by 'Sub'") || leaf.KeyID == 0 || leaf.KeyID != req.KeyID {
		t.Fatalf("request: signed=%v comment=%q keys %d/%d", req.Signed, req.Comment, leaf.KeyID, req.KeyID)
	}
	lc, _ := x509.ParseCertificate(leaf.DER)
	if len(lc.DNSNames) != 1 || lc.DNSNames[0] != "www" || lc.SignatureAlgorithm != x509.ECDSAWithSHA384 || lc.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("leaf: %v %v %v", lc.DNSNames, lc.SignatureAlgorithm, lc.ExtKeyUsage)
	}
	if len(snap.Keys) != 3 {
		t.Fatalf("keys %d", len(snap.Keys))
	}
	// Stamps rise with every write.
	if !(root.Stamp < sub.Stamp && sub.Stamp < leaf.Stamp) {
		t.Errorf("stamps %d %d %d", root.Stamp, sub.Stamp, leaf.Stamp)
	}

	// Mandatory subject entries are enforced.
	h.SetSettings(ctx, map[string]string{"mandatory_dn": "OU"})
	var miss *MissingAttrError
	if _, err := h.Issue(ctx, params("x", rootID), krOf(t, h)); !errors.As(err, &miss) || miss.Attr != "OU" {
		t.Fatalf("mandatory_dn: %v", err)
	}
	h.SetSettings(ctx, map[string]string{"mandatory_dn": ""})

	// Transform: certificate to request, and deleting/extracting keys.
	if _, err := h.CertToRequest(ctx, subID, krOf(t, h), nil); err != nil {
		t.Fatal(err)
	}
	if err := h.Delete(ctx, leaf.KeyID); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if findCert(snap, leafID).KeyID != 0 || findRequest(snap, reqID).KeyID != 0 {
		t.Fatal("key reference not cleared on delete")
	}
	kid, err := h.ExtractPublicKey(ctx, leafID)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if findCert(snap, leafID).KeyID != kid || findKey(snap, kid).HasPrivate {
		t.Fatal("extracted public key not linked")
	}

	// Deleting the issuing CA orphans its children.
	if err := h.Delete(ctx, subID); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if findCert(snap, subID) != nil || findCert(snap, leafID).IssuerID != 0 || snap.Trashed < 2 {
		t.Fatal("delete CA")
	}

	// Passwords: a change rotates the DEK.
	if _, err := h.ChangeDatabasePassword(ctx, []byte("wrong"), []byte("new password"), testKDF); !errors.Is(err, pki.ErrWrongPassword) {
		t.Fatalf("wrong old password: %v", err)
	}
	oldKR := krOf(t, h)
	rows, _ := h.DB.PrivateKeyRows(ctx)
	nk, err := h.ChangeDatabasePassword(ctx, testPassword, []byte("new password"), testKDF)
	if err != nil {
		t.Fatal(err)
	}
	// secure_delete and VACUUM leave no old ciphertext in the file.
	file, _ := os.ReadFile(filepath.Join(s.Dir, "fresh.xdb"))
	for _, r := range rows {
		if bytes.Contains(file, []byte(b64.StdEncoding.EncodeToString(r.Blob)[:40])) {
			t.Errorf("key %d: old ciphertext still in the file", r.ID)
		}
	}
	// Nor does a deleted key's.
	spare, err := h.GenerateKey(ctx, "to delete", "", pki.KeySpec{Type: "RSA", Bits: 2048}, nk)
	if err != nil {
		t.Fatal(err)
	}
	blob, _, _ := h.DB.PrivateKey(ctx, spare)
	if err := h.Delete(ctx, spare); err != nil {
		t.Fatal(err)
	}
	file, _ = os.ReadFile(filepath.Join(s.Dir, "fresh.xdb"))
	if bytes.Contains(file, []byte(b64.StdEncoding.EncodeToString(blob)[200:260])) {
		t.Error("deleted key's ciphertext still in the file")
	}
	setKR(h, nk)
	if _, err := h.Unlock(ctx, testPassword); !errors.Is(err, pki.ErrWrongPassword) {
		t.Fatalf("old password still opens the database: %v", err)
	}
	if _, err := h.Unlock(ctx, []byte("new password")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Issue(ctx, params("old-dek", rootID), oldKR); err == nil {
		t.Fatal("the old DEK still opens the keys")
	}
	rootKey := findCert(snap, rootID).KeyID
	if err := h.SetKeyPassword(ctx, rootKey, krOf(t, h), nil, []byte("own")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Issue(ctx, params("needs-own", rootID), krOf(t, h)); !errors.Is(err, ErrNeedKeyPassword) {
		t.Fatalf("own password not required: %v", err)
	}
	p = params("with-own", rootID)
	p.KeyPass = KeyPasswords{rootKey: []byte("own")}
	if _, err := h.Issue(ctx, p, krOf(t, h)); err != nil {
		t.Fatal(err)
	}
	if err := h.ResetKeyPassword(ctx, rootKey, krOf(t, h), KeyPasswords{rootKey: []byte("own")}); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	for _, k := range snap.Keys {
		if !k.HasPrivate {
			continue
		}
		blob, own, _ := h.DB.PrivateKey(ctx, k.ID)
		if own != gcadb.ProtDEK || vault.Mode(blob) != vault.ModeDEK {
			t.Errorf("%s ownPass %d, mode %d", k.Name, own, vault.Mode(blob))
		}
		if _, err := h.unlock(ctx, k.ID, k.KeyType, nk, nil); err != nil {
			t.Errorf("%s: %v", k.Name, err)
		}
	}
}

// Issuing with keys and CAs that XCA itself wrote.
func TestIssueWithXCAKeys(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	h, _ := load(t, s, "schema8")
	// Example Issuing CA is item 5 with an EC P-384 key from XCA.
	p := params("leaf-from-xca-ca", 5)
	p.Ext = pki.ExtSpec{CA: 2, AuthKey: true, SubKey: true, SubAltName: "DNS:copycn"}
	id, err := h.Issue(ctx, p, krOf(t, h))
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := h.Snapshot(ctx)
	c := findCert(snap, id)
	ca := findCert(snap, 5)
	cc, _ := x509.ParseCertificate(c.DER)
	cac, _ := x509.ParseCertificate(ca.DER)
	if c.IssuerID != 5 || cc.CheckSignatureFrom(cac) != nil || string(cc.AuthorityKeyId) != string(cac.SubjectKeyId) {
		t.Fatal("not issued by the XCA CA")
	}
	for _, r := range snap.Revocations {
		if r.CAID == 5 && r.Serial == c.Serial {
			t.Fatal("serial collides with a revocation")
		}
	}
}

package store

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// TestNewKeyTypes runs a CA on each new signing algorithm through the
// store: self-signed root, certificates for keys that cannot sign (from
// their SPKI), a request, a CRL, renewal and "to request", with xdb
// linking issuers by signature.
func TestNewKeyTypes(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	pw := []byte("pw")
	if err := s.Create(ctx, "newkeys", pw); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "newkeys")
	cases := []struct {
		ca   pki.KeySpec
		hash string
	}{
		{pki.KeySpec{Type: "RSA", Bits: 2048}, "sha384-pss"},
		{pki.KeySpec{Type: "RSA-PSS", Bits: 2048}, "sha256"},
		{pki.KeySpec{Type: "EC", Curve: "brainpoolP384r1"}, "sha384"},
		{pki.KeySpec{Type: "EC", Curve: "secp256k1"}, "sha256"},
		{pki.KeySpec{Type: "Ed448"}, "sha256"},
		{pki.KeySpec{Type: "ML-DSA", Param: "ML-DSA-65"}, "sha256"},
		{pki.KeySpec{Type: "SLH-DSA", Param: "SLH-DSA-SHAKE-128f"}, "sha256"},
		{pki.KeySpec{Type: "Composite", Param: "MLDSA65-ECDSA-P256-SHA512"}, "sha256"},
	}
	for _, c := range cases {
		name := c.ca.Type + c.ca.Curve + c.ca.Param
		p := params(name, 0)
		p.NewKey, p.Hash = &c.ca, c.hash
		rootID, err := h.Issue(ctx, p, pw)
		if err != nil {
			t.Fatalf("%s: root: %v", name, err)
		}

		// an ML-KEM key generated with its certificate
		lp := params(name+" kem", rootID)
		lp.NewKey, lp.Hash = &pki.KeySpec{Type: "ML-KEM", Param: "ML-KEM-768"}, c.hash
		lp.Ext = pki.ExtSpec{CA: 2, SubKey: true, AuthKey: true, KeyUse: 1 << 4}
		kemID, err := h.Issue(ctx, lp, pw)
		if err != nil {
			t.Fatalf("%s: ML-KEM certificate: %v", name, err)
		}

		// an existing X448 key
		xid, err := h.GenerateKey(ctx, name+" x448", "", pki.KeySpec{Type: "X448"}, pw)
		if err != nil {
			t.Fatal(err)
		}
		xp := lp
		xp.Name, xp.NewKey, xp.KeyID = name+" x448", nil, xid
		x448ID, err := h.Issue(ctx, xp, pw)
		if err != nil {
			t.Fatalf("%s: X448 certificate: %v", name, err)
		}

		// a request with an Ed448 key, signed by the root
		rp := params(name+" req", 0)
		rp.Request, rp.NewKey, rp.Hash = true, &pki.KeySpec{Type: "Ed448"}, c.hash
		rp.Ext = pki.ExtSpec{SubAltName: "DNS:copycn"}
		reqID, err := h.Issue(ctx, rp, pw)
		if err != nil {
			t.Fatalf("%s: request: %v", name, err)
		}
		fp := IssueParams{Name: name + " from req", FromReqID: reqID, ReqSubject: true, CopyReqExt: true, SignerID: rootID,
			NotBefore: time.Now(), NotAfter: time.Now().AddDate(0, 1, 0), Hash: c.hash, Ext: pki.ExtSpec{CA: 2, AuthKey: true}}
		fromReqID, err := h.Issue(ctx, fp, pw)
		if err != nil {
			t.Fatalf("%s: certificate from request: %v", name, err)
		}

		snap, _ := h.Snapshot(ctx)
		root := findCert(snap, rootID)
		if root.IssuerID != rootID || root.KeyID == 0 {
			t.Fatalf("%s: root issuer %d key %d", name, root.IssuerID, root.KeyID)
		}
		for _, id := range []int64{kemID, x448ID, fromReqID} {
			if c := findCert(snap, id); c.IssuerID != rootID || c.KeyID == 0 {
				t.Fatalf("%s: %s: issuer %d key %d", name, c.Name, c.IssuerID, c.KeyID)
			}
		}
		if !findRequest(snap, reqID).Signed {
			t.Errorf("%s: request not marked signed", name)
		}
		if got := pki.HashChoice(root.DER); c.ca.Type == "RSA" && got != c.hash {
			t.Errorf("%s: hash choice %s", name, got)
		}

		// renewal keeps the key exactly; the CRL is linked to the CA
		kem := findCert(snap, kemID)
		newID, err := h.Renew(ctx, kemID, RenewOptions{NotBefore: time.Now(), NotAfter: time.Now().AddDate(2, 0, 0),
			Revoke: &Revocation{Reason: 4}}, pw, nil)
		if err != nil {
			t.Fatalf("%s: renew: %v", name, err)
		}
		snap, _ = h.Snapshot(ctx)
		renewed := findCert(snap, newID)
		oc, _ := pki.ParseCertificate(kem.DER)
		nc, _ := pki.ParseCertificate(renewed.DER)
		if !bytes.Equal(oc.RawSubjectPublicKeyInfo, nc.RawSubjectPublicKeyInfo) || renewed.IssuerID != rootID || renewed.KeyID != kem.KeyID {
			t.Fatalf("%s: renewed certificate differs", name)
		}
		opts := DefaultCRLOptions(snap, root)
		opts.Hash = c.hash
		crlID, err := h.GenerateCRL(ctx, rootID, opts, pw, nil)
		if err != nil {
			t.Fatalf("%s: CRL: %v", name, err)
		}
		snap, _ = h.Snapshot(ctx)
		var crl *xdb.CRL
		for _, l := range snap.CRLs {
			if l.ID == crlID {
				crl = l
			}
		}
		if crl == nil || crl.IssuerID != rootID {
			t.Fatalf("%s: CRL not linked to its CA", name)
		}

		// the root back to a request
		if _, err := h.CertToRequest(ctx, rootID, pw, nil); err != nil {
			t.Fatalf("%s: to request: %v", name, err)
		}
	}
}

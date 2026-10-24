package store

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/vault"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// TestNewKeyTypes runs a CA on each new signing algorithm through the
// store: self-signed root, certificates for keys that cannot sign (from
// their SPKI), a request, a CRL, renewal and "to request", with xdb
// linking issuers by signature.
func TestNewKeyTypes(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	pw := testPassword
	if err := s.Create(ctx, "newkeys", pw, vault.Default); err != nil {
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
		rootID, err := h.Issue(ctx, p, krOf(t, h))
		if err != nil {
			t.Fatalf("%s: root: %v", name, err)
		}

		// an ML-KEM key generated with its certificate
		lp := params(name+" kem", rootID)
		lp.NewKey, lp.Hash = &pki.KeySpec{Type: "ML-KEM", Param: "ML-KEM-768"}, c.hash
		lp.Ext = pki.ExtSpec{CA: 2, SubKey: true, AuthKey: true, KeyUse: 1 << 4}
		kemID, err := h.Issue(ctx, lp, krOf(t, h))
		if err != nil {
			t.Fatalf("%s: ML-KEM certificate: %v", name, err)
		}

		// an existing X448 key
		xid, err := h.GenerateKey(ctx, name+" x448", "", pki.KeySpec{Type: "X448"}, krOf(t, h))
		if err != nil {
			t.Fatal(err)
		}
		xp := lp
		xp.Name, xp.NewKey, xp.KeyID = name+" x448", nil, xid
		x448ID, err := h.Issue(ctx, xp, krOf(t, h))
		if err != nil {
			t.Fatalf("%s: X448 certificate: %v", name, err)
		}

		// a request with an Ed448 key, signed by the root
		rp := params(name+" req", 0)
		rp.Request, rp.NewKey, rp.Hash = true, &pki.KeySpec{Type: "Ed448"}, c.hash
		rp.Ext = pki.ExtSpec{SubAltName: "DNS:copycn"}
		reqID, err := h.Issue(ctx, rp, krOf(t, h))
		if err != nil {
			t.Fatalf("%s: request: %v", name, err)
		}
		fp := IssueParams{Name: name + " from req", FromReqID: reqID, ReqSubject: true, CopyReqExt: true, SignerID: rootID,
			NotBefore: time.Now(), NotAfter: time.Now().AddDate(0, 1, 0), Hash: c.hash, Ext: pki.ExtSpec{CA: 2, AuthKey: true}}
		fromReqID, err := h.Issue(ctx, fp, krOf(t, h))
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
			Revoke: &Revocation{Reason: 4}}, krOf(t, h), nil)
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
		crlID, err := h.GenerateCRL(ctx, rootID, opts, krOf(t, h), nil)
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
		if _, err := h.CertToRequest(ctx, rootID, krOf(t, h), nil); err != nil {
			t.Fatalf("%s: to request: %v", name, err)
		}
	}
}

// TestNewKeyTypesExport exports keys and certificates of the new types in
// every format offered for them; formats that cannot hold them are not
// offered and are refused.
func TestNewKeyTypesExport(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	pw := testPassword
	if err := s.Create(ctx, "newexport", pw, vault.Default); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "newexport")
	rootP := params("export root", 0)
	rootID, err := h.Issue(ctx, rootP, krOf(t, h))
	if err != nil {
		t.Fatal(err)
	}
	specs := []pki.KeySpec{
		{Type: "RSA-PSS", Bits: 2048}, {Type: "EC", Curve: "brainpoolP256r1"}, {Type: "EC", Curve: "secp256k1"},
		{Type: "Ed448"}, {Type: "X448"}, {Type: "X25519"}, {Type: "ML-DSA", Param: "ML-DSA-44"},
		{Type: "SLH-DSA", Param: "SLH-DSA-SHA2-128f"}, {Type: "ML-KEM", Param: "ML-KEM-512"},
		{Type: "Composite", Param: "MLDSA44-Ed25519-SHA512"}, {Type: "CompositeKEM", Param: "MLKEM768-X25519-SHA3-256"},
	}
	for _, spec := range specs {
		name := spec.Type + spec.Curve + spec.Param
		p := params(name, rootID)
		p.NewKey = &spec
		p.Ext = pki.ExtSpec{CA: 2, SubKey: true, AuthKey: true}
		certID, err := h.Issue(ctx, p, krOf(t, h))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		snap, _ := h.Snapshot(ctx)
		keyID := findCert(snap, certID).KeyID
		for _, id := range []int64{keyID, certID} {
			offered := map[int]bool{}
			for _, f := range ExportFormats(snap, []int64{id}) {
				offered[f.ID] = true
				res, err := h.Export(ctx, ExportRequest{Format: f.ID, IDs: []int64{id}, Password: []byte("export"), Keyring: krOf(t, h)})
				if err != nil {
					t.Errorf("%s: item %d format %d (%s): %v", name, id, f.ID, f.Label, err)
					continue
				}
				if len(res.Data) == 0 && f.ID != 16 && f.ID != 40 { // 40: no unusable certificates
					t.Errorf("%s: format %d: empty", name, f.ID)
				}
				// what go-ca writes, it reads back
				if f.Flags&(codec.FPKCS8|codec.FPKCS12) != 0 || f.ID == 20 || f.ID == 21 || f.ID == 25 {
					r := codec.Probe("x."+f.Ext, res.Data, codec.ProbeOptions{Password: []byte("export")})
					if len(r.Objects) == 0 || r.Objects[0].Type == xdb.TypeKey && !bytes.Equal(r.Objects[0].DER, findKey(snap, keyID).Public) {
						t.Errorf("%s: format %d does not read back: %v", name, f.ID, r.Unrecognized)
					}
				}
			}
			// never offered for the new types
			for _, f := range []int{21, 22, 23, 26, 50, 51, 100, 102, 106} {
				if f == 21 && spec.Type == "EC" {
					continue // SEC 1 on every curve
				}
				if offered[f] {
					t.Errorf("%s: format %d offered", name, f)
				}
			}
		}
	}
}

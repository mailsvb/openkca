package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/vault"
)

func TestConnectorIssueCSR(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	if err := s.Create(ctx, "conn", testPassword, vault.Default); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "conn")
	kr := krOf(t, h)
	rootID, err := h.Issue(ctx, params("Root", 0), kr)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := h.Snapshot(ctx)
	now := time.Now()
	if cas := ConnectorCAs(snap, now); len(cas) != 1 || cas[0].ID != rootID {
		t.Fatalf("connector CAs: %v", cas)
	}

	for _, l := range []string{"", "Devices", "-x", "cacerts", "a/b"} {
		if ValidConnectorLabel(l) {
			t.Errorf("label %q accepted", l)
		}
	}
	c := &db.Connector{Type: db.ConnectorEST, Name: "Devices", Label: "devices", CAID: rootID, Enabled: true, Config: "{}"}
	if err := h.SaveConnector(ctx, c, ""); err != nil {
		t.Fatal(err)
	}
	if err := h.SaveConnector(ctx, &db.Connector{Type: db.ConnectorEST, Name: "Again", Label: "devices", Config: "{}"}, ""); !errors.Is(err, db.ErrLabelTaken) {
		t.Fatalf("duplicate label: %v", err)
	}
	snap, _ = h.Snapshot(ctx)
	if p := ConnectorCAProblem(snap, snap.Connector(c.ID), now); p != "" {
		t.Fatalf("CA problem %q", p)
	}

	key, err := pki.GenerateKey(pki.KeySpec{Type: "EC", Curve: "P-256"})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.CreateRequest([]byte{0x30, 0}, nil, key, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	p := CSRIssue{Name: "dev1", CSR: csr, Subject: []pki.DNAttr{{Name: "CN", Value: "dev1.example.com"}},
		Ext: pki.ExtSpec{CA: 2, KeyUse: 1, EKU: []string{"clientAuth"}, SubAltName: "DNS:copycn"}, SignerID: rootID,
		NotBefore: now, NotAfter: now.AddDate(0, 1, 0), ConnectorID: c.ID, Action: "est.enroll", Detail: "devices"}
	id, der, err := h.IssueCSR(ctx, p, kr)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "dev1.example.com" || len(cert.DNSNames) != 1 || cert.IsCA {
		t.Fatalf("issued %v %v", cert.Subject, cert.DNSNames)
	}
	snap, _ = h.Snapshot(ctx)
	got := findCert(snap, id)
	if got == nil || got.KeyID != 0 || got.IssuerID != rootID || got.ConnectorID != c.ID {
		t.Fatalf("stored cert %+v", got)
	}
	if n := IssuedBy(snap, c.ID); len(n) != 1 {
		t.Fatalf("issued by connector: %d", len(n))
	}
	if snap.Connector(c.ID).LastUsed.IsZero() {
		t.Fatal("last use not recorded")
	}
	// A second certificate gets a different serial.
	p.Name = "dev2"
	id2, _, err := h.IssueCSR(ctx, p, kr)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if findCert(snap, id2).Serial == got.Serial {
		t.Fatal("serial reused")
	}

	// A broken signature is refused.
	bad := append([]byte(nil), csr...)
	bad[len(bad)-3] ^= 0xff
	p.CSR = bad
	if _, _, err := h.IssueCSR(ctx, p, kr); err == nil {
		t.Fatal("CSR with a broken signature signed")
	}

	if err := h.DeleteConnector(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if snap.Connector(c.ID) != nil || findCert(snap, id).ConnectorID != 0 {
		t.Fatal("connector not deleted or link kept")
	}
}

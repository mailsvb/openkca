package pki

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateCRL(t *testing.T) {
	for _, kt := range []KeySpec{{Type: "RSA", Bits: 2048}, {Type: "EC", Curve: "P-384"}, {Type: "Ed25519"}} {
		key, _ := GenerateKey(kt)
		ca := issue(t, mustName(t, "CN", "CRL CA "+kt.Type), key, ExtSpec{CA: 1, SubKey: true, KeyUse: 1<<5 | 1<<6,
			SubAltName: "URI:http://ca.example.org"}, nil, nil)
		now := time.Now().Truncate(time.Second)
		der, err := CreateCRL(CRLParams{Issuer: ca, Key: key, Hash: "sha384", ThisUpdate: now, NextUpdate: now.AddDate(0, 0, 30),
			Number: big.NewInt(7), AuthKeyID: true, IssuerAlt: true, Revoked: []Revoked{
				{Serial: big.NewInt(0x2002), Date: now, Reason: 1, WithReason: true, InvalDate: now.Add(-time.Hour)},
				{Serial: big.NewInt(0x1001), Date: now, Reason: 0, WithReason: true},
			}})
		if err != nil {
			t.Fatal(err)
		}
		l, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.CheckSignatureFrom(ca); err != nil {
			t.Fatalf("%s: signature: %v", kt.Type, err)
		}
		if l.Number.Int64() != 7 || len(l.RevokedCertificateEntries) != 2 || l.RevokedCertificateEntries[0].SerialNumber.Int64() != 0x1001 ||
			l.RevokedCertificateEntries[1].ReasonCode != 1 || l.RevokedCertificateEntries[0].ReasonCode != 0 ||
			string(l.AuthorityKeyId) != string(ca.SubjectKeyId) {
			t.Fatalf("%s: content %+v", kt.Type, l)
		}
		var order []string
		for _, e := range l.Extensions {
			order = append(order, e.Id.String())
		}
		if strings.Join(order, " ") != "2.5.29.35 2.5.29.18 2.5.29.20" {
			t.Errorf("extension order %v", order)
		}
		if _, err := exec.LookPath("openssl"); err == nil {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644)
			os.WriteFile(filepath.Join(dir, "crl.der"), der, 0o644)
			out, err := exec.Command("openssl", "crl", "-inform", "DER", "-in", filepath.Join(dir, "crl.der"),
				"-CAfile", filepath.Join(dir, "ca.pem"), "-noout", "-text").CombinedOutput()
			if err != nil || !strings.Contains(string(out), "verify OK") || !strings.Contains(string(out), "Key Compromise") ||
				!strings.Contains(string(out), "Invalidity Date") {
				t.Fatalf("%s: openssl crl: %v\n%s", kt.Type, err, out)
			}
		}
	}
	// Without number and AKI (both optional in XCA)
	key, _ := GenerateKey(KeySpec{Type: "EC", Curve: "P-256"})
	ca := issue(t, mustName(t, "CN", "plain"), key, ExtSpec{}, nil, nil)
	der, err := CreateCRL(CRLParams{Issuer: ca, Key: key, ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if l, err := x509.ParseRevocationList(der); err != nil || len(l.Extensions) != 0 || l.Number != nil {
		t.Fatalf("plain CRL: %v %+v", err, l)
	}
}

package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadPassword(dir); err != ErrNoPassword {
		t.Fatalf("LoadPassword without file: %v", err)
	}
	if err := SavePassword(dir, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	h, err := LoadPassword(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, []byte("correct horse")) || CheckPassword(h, []byte("wrong")) || CheckPassword("garbage", nil) {
		t.Fatal("CheckPassword")
	}
}

func TestSelfIssuedCertificate(t *testing.T) {
	dir := t.TempDir()
	m, err := NewCertManager(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	leaf := m.Leaf()
	if leaf.Subject.CommonName != SelfCN || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "localhost" || len(leaf.IPAddresses) != 2 {
		t.Fatalf("certificate: %v %v %v", leaf.Subject, leaf.DNSNames, leaf.IPAddresses)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d < 364*24*time.Hour || d > 366*24*time.Hour {
		t.Fatalf("validity %v", d)
	}
	// Reused on the next start.
	m2, _ := NewCertManager(dir, "", "")
	if !m2.Leaf().Equal(leaf) {
		t.Fatal("certificate regenerated although still valid")
	}
	// An expired certificate is replaced.
	certFile := filepath.Join(dir, StateDir, "tls.crt")
	writeExpired(t, certFile)
	m3, err := NewCertManager(dir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if m3.Leaf().Equal(leaf) || time.Now().After(m3.Leaf().NotAfter) {
		t.Fatal("expired certificate not regenerated")
	}
}

// writeExpired replaces the stored certificate with an expired one for the
// same key, built from the stored key.
func writeExpired(t *testing.T, certFile string) {
	t.Helper()
	keyPEM, err := os.ReadFile(filepath.Join(filepath.Dir(certFile), "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big1(), NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, publicOf(key), key)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(2, time.Minute)
	l.Fail("a")
	if l.Blocked("a") {
		t.Fatal("blocked after one failure")
	}
	l.Fail("a")
	if !l.Blocked("a") || l.Blocked("b") {
		t.Fatal("limiter")
	}
	l.Reset("a")
	if l.Blocked("a") {
		t.Fatal("reset")
	}
}

func big1() *big.Int { return big.NewInt(1) }

func publicOf(k any) any { return k.(crypto.Signer).Public() }

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/auth"
	"github.com/mailsvb/openkca/internal/config"
)

// writePair writes a self-signed certificate and its key as PEM files.
func writePair(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600)
	return cert, keyFile
}

func flags(set ...string) setupFlags {
	f := setupFlags{set: map[string]bool{}, https: true}
	for _, s := range set {
		f.set[s] = true
	}
	return f
}

func TestSetupUnattended(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf", "config.yaml")
	load := func() *config.Config {
		t.Helper()
		c, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	if _, err := setupUnattended(path, flags("https")); err == nil || !strings.Contains(err.Error(), "no server password") {
		t.Fatalf("without a password: %v", err)
	}
	f := flags("https", "port", "crl-port", "password")
	f.https, f.port, f.crlPort, f.password = false, 8080, 0, "short"
	if _, err := setupUnattended(path, f); err == nil || !strings.Contains(err.Error(), "8 characters") {
		t.Fatalf("short password: %v", err)
	}
	f.password = "serverpass1"
	if changed, err := setupUnattended(path, f); err != nil || !changed {
		t.Fatalf("new file: %v %v", changed, err)
	}
	c := load()
	if g := c.General; g.TLS() || g.Listen != ":8080" || c.CRL.ListenAddr() != "" || !auth.CheckPassword(g.PasswordHash, []byte("serverpass1")) {
		t.Fatalf("new file: %+v %q", g, c.CRL.ListenAddr())
	}

	cert, key := writePair(t, dir)
	f = flags("https", "tls-cert", "tls-key", "copy-tls", "crl-port")
	f.tlsCert, f.tlsKey, f.copyTLS, f.crlPort = cert, key, true, 8080
	if _, err := setupUnattended(path, f); err == nil || !strings.Contains(err.Error(), "different ports") {
		t.Fatalf("same ports: %v", err)
	}
	f.crlPort = 9080
	if changed, err := setupUnattended(path, f); err != nil || !changed {
		t.Fatalf("TLS: %v %v", changed, err)
	}
	c = load()
	if g := c.General; !g.TLS() || g.TLSCert != filepath.Join(dir, "conf", "tls.crt") || g.TLSKey != filepath.Join(dir, "conf", "tls.key") ||
		c.CRL.ListenAddr() != ":9080" || !auth.CheckPassword(g.PasswordHash, []byte("serverpass1")) {
		t.Fatalf("TLS: %+v %q", g, c.CRL.ListenAddr())
	}
	if changed, err := setupUnattended(path, f); err != nil || changed {
		t.Fatalf("again: %v %v", changed, err)
	}

	f = flags("tls-cert", "tls-key")
	f.tlsCert, f.tlsKey = cert, cert
	if _, err := setupUnattended(path, f); err == nil {
		t.Fatal("certificate as key accepted")
	}
	f.tlsCert, f.tlsKey = "", ""
	if _, err := setupUnattended(path, f); err != nil || load().General.TLSCert != "" {
		t.Fatalf("back to self-issued: %v", err)
	}
}

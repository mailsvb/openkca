package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Self-issued certificate parameters (Agreed decisions).
const (
	SelfCN       = "OpenKCA"
	SelfValidity = 365 * 24 * time.Hour
)

// SelfSANs are the names in the self-issued certificate.
var SelfSANs = struct {
	DNS []string
	IP  []net.IP
}{[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}

// CertManager serves either a configured certificate or the self-issued one,
// regenerating the latter once it has expired.
type CertManager struct {
	certFile, keyFile string
	self              bool

	mu   sync.RWMutex
	cert *tls.Certificate
	leaf *x509.Certificate
}

// NewCertManager uses certFile/keyFile when given, otherwise a self-issued
// certificate stored in the state folder.
func NewCertManager(dataDir, certFile, keyFile string) (*CertManager, error) {
	m := &CertManager{certFile: certFile, keyFile: keyFile}
	if certFile == "" {
		m.self = true
		m.certFile = filepath.Join(dataDir, StateDir, "tls.crt")
		m.keyFile = filepath.Join(dataDir, StateDir, "tls.key")
	}
	return m, m.Refresh()
}

// Refresh loads the certificate; a self-issued one is (re)generated when it
// is missing, unreadable or expired.
func (m *CertManager) Refresh() error {
	cert, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
	if err == nil && cert.Leaf != nil && m.self && time.Now().After(cert.Leaf.NotAfter) {
		err = errExpired
	}
	if err != nil {
		if !m.self {
			return err
		}
		slog.Info("generating self-issued TLS certificate", "cn", SelfCN, "file", m.certFile, "reason", err)
		if err := generateSelf(m.certFile, m.keyFile); err != nil {
			return err
		}
		if cert, err = tls.LoadX509KeyPair(m.certFile, m.keyFile); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.cert, m.leaf = &cert, cert.Leaf
	m.mu.Unlock()
	return nil
}

type expiredError struct{}

func (expiredError) Error() string { return "certificate expired" }

var errExpired error = expiredError{}

// Watch checks the certificate daily until stop is closed.
func (m *CertManager) Watch(stop <-chan struct{}) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if err := m.Refresh(); err != nil {
				slog.Error("TLS certificate refresh failed", "err", err)
			}
		}
	}
}

// GetCertificate implements tls.Config.GetCertificate.
func (m *CertManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cert, nil
}

// Leaf returns the current certificate.
func (m *CertManager) Leaf() *x509.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.leaf
}

func generateSelf(certFile, keyFile string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: SelfCN},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(SelfValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              SelfSANs.DNS,
		IPAddresses:           SelfSANs.IP,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return writeFileAtomic(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

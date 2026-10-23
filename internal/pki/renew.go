package pki

import (
	"crypto"
	"crypto/x509"
	"math/big"
	"time"
)

// Renew re-signs a certificate with a new validity and serial, keeping its
// subject, public key, extensions and hash (db_x509::certRenewal). issuer is
// nil for a self-signed certificate.
func Renew(old *x509.Certificate, serial *big.Int, notBefore, notAfter time.Time, issuer *x509.Certificate, key crypto.Signer) ([]byte, error) {
	return CreateCertificate(CertRequest{
		Subject:    old.RawSubject,
		SPKI:       old.RawSubjectPublicKeyInfo, // as it was, for every key type
		Serial:     serial,
		NotBefore:  notBefore,
		NotAfter:   notAfter,
		Extensions: old.Extensions,
		Hash:       HashChoice(old.Raw),
		Issuer:     issuer,
		SignerKey:  key,
	})
}

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/vault"
)

// CSRIssue is a certificate to sign from a CSR that is not stored as a
// request item (a connector's enrollment). The caller has decided the
// subject and extensions; only the CSR's public key is taken over.
type CSRIssue struct {
	Name, Comment string
	CSR           []byte // DER PKCS#10
	Subject       []pki.DNAttr
	Ext           pki.ExtSpec
	SignerID      int64 // CA certificate
	NotBefore     time.Time
	NotAfter      time.Time
	Hash          string // "" = the database's default
	ConnectorID   int64  // recorded as the issuing connector, 0 = none
	Action        string // audit action, "" = cert.issue
	Detail        string // audit detail
}

// IssueCSR signs the CSR's public key with the CA's key under the
// database keyring and stores the certificate without a private key. It
// returns the new item's ID and the certificate.
func (h *Handle) IssueCSR(ctx context.Context, p CSRIssue, kr *vault.Keyring) (int64, []byte, error) {
	if p.Name == "" {
		return 0, nil, errors.New("the internal name must not be empty")
	}
	if p.SignerID == 0 {
		return 0, nil, errors.New("a CA must sign the request")
	}
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return 0, nil, err
	}
	csr, err := pki.ParseCertificateRequest(p.CSR)
	if err != nil {
		return 0, nil, err
	}
	if err := pki.CheckRequestSignature(csr); err != nil {
		return 0, nil, fmt.Errorf("the request's signature is invalid: %w", err)
	}
	spki := csr.RawSubjectPublicKeyInfo
	if _, err := pki.ParsePublicKey(spki); err != nil {
		return 0, nil, fmt.Errorf("OpenKCA cannot issue certificates for this key type: %w", err)
	}
	subject, err := pki.BuildName(p.Subject, snap.Settings["string_opt"])
	if err != nil {
		return 0, nil, err
	}
	if err := checkMandatory(snap, subject); err != nil {
		return 0, nil, err
	}
	ectx, ca, err := extContext(snap, IssueParams{SignerID: p.SignerID}, subject, spki)
	if err != nil {
		return 0, nil, err
	}
	exts, err := pki.BuildExtensions(h.store.withPublished(p.Ext, ca), ectx)
	if err != nil {
		return 0, nil, err
	}
	hash := p.Hash
	if hash == "" {
		hash = Hash(snap)
	}
	cr := pki.CertRequest{Subject: subject, SPKI: spki, NotBefore: p.NotBefore, NotAfter: p.NotAfter,
		Extensions: exts, Hash: hash}
	der, err := h.signCert(ctx, snap, ca, &cr, kr, nil)
	if err != nil {
		return 0, nil, err
	}
	action := p.Action
	if action == "" {
		action = "cert.issue"
	}
	var id int64
	err = h.DB.Write(ctx, func(tx *db.Tx) error {
		if id, err = tx.InsertCert(ctx, db.NewCert{Name: p.Name, Comment: p.Comment, Source: db.SourceGenerated, DER: der}); err != nil {
			return err
		}
		if p.ConnectorID != 0 {
			if err := tx.SetCertConnector(ctx, id, p.ConnectorID); err != nil {
				return err
			}
			if err := tx.TouchConnector(ctx, p.ConnectorID, time.Now()); err != nil {
				return err
			}
		}
		return tx.Audit(ctx, action, id, p.Detail)
	})
	h.changed(ctx)
	if err != nil {
		return 0, nil, err
	}
	return id, der, nil
}

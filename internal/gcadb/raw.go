package gcadb

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/tmpl"
)

// RawItem is a complete item with its ID and links, as an importer writes
// it: nothing is looked up or linked automatically. Links to items that do
// not exist must be 0. An empty UUID gets a new one.
type RawItem struct {
	Item
	Key      *RawKey
	Request  *RawRequest
	Cert     *RawCert
	CRL      *RawCRL
	Template *tmpl.Template
}

// RawKey is the key part of a RawItem.
type RawKey struct {
	Algorithm  string
	Bits       int
	SPKI       []byte
	Protection int
	Private    []byte
}

// RawRequest is the request part of a RawItem.
type RawRequest struct {
	DER    []byte
	KeyID  int64
	Signed bool
}

// RawCert is the certificate part of a RawItem; Authority is set for CAs.
type RawCert struct {
	DER       []byte
	IssuerID  int64
	KeyID     int64
	Authority *Authority
}

// RawCRL is the CRL part of a RawItem.
type RawCRL struct {
	DER      []byte
	IssuerID int64
	Number   int64
}

func link(id int64) sql.NullInt64 { return sql.NullInt64{Int64: id, Valid: id != 0} }

// PutRaw writes an item with its ID, and with its UUID when it has one.
func (t *Tx) PutRaw(ctx context.Context, r RawItem) error {
	var trashed any
	if !r.Trashed.IsZero() {
		trashed = fmtTime(r.Trashed)
	}
	uid, err := rawUUID(r.UUID)
	if err != nil {
		return fmt.Errorf("item %d: %w", r.ID, err)
	}
	if _, err := t.ExecContext(ctx, `INSERT INTO items (id, uuid, type, name, comment, source, created, trashed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, r.ID, uid, TypeName(r.Type), r.Name, r.Comment, SourceName(r.Source), fmtTime(r.Date), trashed); err != nil {
		return fmt.Errorf("item %d: %w", r.ID, err)
	}
	switch {
	case r.Type == TypeKey && r.Key != nil:
		k := r.Key
		prot := k.Protection
		if k.Private == nil && prot != ProtToken {
			prot = ProtNone
		}
		_, err = t.ExecContext(ctx, `INSERT INTO keys (item, algorithm, bits, spki, fingerprint, protection, private)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, r.ID, k.Algorithm, k.Bits, k.SPKI, Fingerprint(k.SPKI), protValue(prot), k.Private)
	case r.Type == TypeRequest && r.Request != nil:
		req, perr := pki.ParseCertificateRequest(r.Request.DER)
		if perr != nil {
			return fmt.Errorf("request %d: %w", r.ID, perr)
		}
		_, err = t.ExecContext(ctx, `INSERT INTO requests (item, der, fingerprint, subject, key_fingerprint, key, signed)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, r.ID, r.Request.DER, Fingerprint(r.Request.DER), req.RawSubject,
			Fingerprint(req.RawSubjectPublicKeyInfo), link(r.Request.KeyID), r.Request.Signed)
	case r.Type == TypeCert && r.Cert != nil:
		c, perr := pki.ParseCertificate(r.Cert.DER)
		if perr != nil {
			return fmt.Errorf("certificate %d: %w", r.ID, perr)
		}
		a := r.Cert.Authority
		if _, err = t.ExecContext(ctx, `INSERT INTO certs (item, der, fingerprint, subject, issuer_name, key_fingerprint,
			serial, issuer, key, ca, not_before, not_after) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.ID, r.Cert.DER, Fingerprint(r.Cert.DER), c.RawSubject, c.RawIssuer, Fingerprint(c.RawSubjectPublicKeyInfo),
			SerialHex(c.SerialNumber), link(r.Cert.IssuerID), link(r.Cert.KeyID), a != nil,
			fmtTime(c.NotBefore), fmtTime(c.NotAfter)); err == nil && a != nil {
			days := a.CRLDays
			if days == 0 {
				days = 30
			}
			auth := uid // a new authority ID is the certificate's UUID
			if a.UUID != "" {
				if auth, err = CanonicalUUID(a.UUID); err != nil {
					return fmt.Errorf("certificate %d: %w", r.ID, err)
				}
			}
			_, err = t.ExecContext(ctx, `INSERT INTO authorities (cert, uuid, template, crl_number, crl_days, crl_next, dn_policy)
				VALUES (?, ?, ?, ?, ?, ?, ?)`, r.ID, auth, link(a.TemplateID), a.CRLNo, days, optTime(a.CRLExpire), a.DNPolicy)
		}
	case r.Type == TypeCRL && r.CRL != nil:
		var issuerName []byte
		if l, perr := x509.ParseRevocationList(r.CRL.DER); perr == nil {
			issuerName = l.RawIssuer
		} else {
			return fmt.Errorf("CRL %d: %w", r.ID, perr)
		}
		_, err = t.ExecContext(ctx, "INSERT INTO crls (item, der, fingerprint, issuer_name, issuer, number) VALUES (?, ?, ?, ?, ?, ?)",
			r.ID, r.CRL.DER, Fingerprint(r.CRL.DER), issuerName, link(r.CRL.IssuerID), r.CRL.Number)
	case r.Type == TypeTemplate && r.Template != nil:
		j, jerr := encodeTemplate(r.Template)
		if jerr != nil {
			return jerr
		}
		_, err = t.ExecContext(ctx, "INSERT INTO templates (item, data) VALUES (?, ?)", r.ID, j)
	default:
		return errors.New("gcadb: raw item without its content")
	}
	if err != nil {
		return fmt.Errorf("item %d: %w", r.ID, err)
	}
	return nil
}

func rawUUID(s string) (string, error) {
	if s == "" {
		return NewUUID()
	}
	return CanonicalUUID(s)
}

// PutRevocation writes a revocation as it is.
func (t *Tx) PutRevocation(ctx context.Context, r Revocation) error {
	var crlNo sql.NullInt64
	if r.CRLNo != 0 {
		crlNo = sql.NullInt64{Int64: r.CRLNo, Valid: true}
	}
	_, err := t.ExecContext(ctx, `INSERT INTO revocations (ca, serial, date, invalidity, reason, crl_number) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (ca, serial) DO NOTHING`, r.CAID, r.Serial, fmtTime(r.Date), optTime(r.InvalDate), r.ReasonBit, crlNo)
	return err
}

// PutPGPCert writes an OpenPGP certificate of an imported key, also one in
// the trash.
func (t *Tx) PutPGPCert(ctx context.Context, c PGPCert) error {
	_, err := t.ExecContext(ctx, "INSERT INTO pgp (key, fingerprint, cert) VALUES (?, ?, ?)", c.KeyID, c.Fingerprint, c.Cert)
	return err
}

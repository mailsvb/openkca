package store

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/vault"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// Revocation describes a revocation entered in the UI.
type Revocation struct {
	Reason    int
	InvalDate time.Time // zero = none
}

func (h *Handle) issuerOf(snap *xdb.Snapshot, certID int64) (*xdb.Cert, *xdb.Cert, error) {
	c := findCert(snap, certID)
	if c == nil {
		return nil, nil, errors.New("certificate not found")
	}
	if c.IssuerID == 0 || c.IssuerID == c.ID {
		return c, nil, errors.New("the issuer of this certificate is not in the database")
	}
	return c, findCert(snap, c.IssuerID), nil
}

// Revoke records the revocation of a certificate at its issuer.
func (h *Handle) Revoke(ctx context.Context, certID int64, r Revocation) error {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return err
	}
	c, ca, err := h.issuerOf(snap, certID)
	if err != nil {
		return err
	}
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		return tx.Revoke(ctx, ca.ID, xdb.RevocationRow{Serial: c.Serial, Date: time.Now(), InvalDate: r.InvalDate, Reason: r.Reason})
	})
	h.changed(ctx)
	return err
}

// Unrevoke removes a certificate's revocation.
func (h *Handle) Unrevoke(ctx context.Context, certID int64) error {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return err
	}
	c, ca, err := h.issuerOf(snap, certID)
	if err != nil {
		return err
	}
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error { return tx.Unrevoke(ctx, ca.ID, c.Serial) })
	h.changed(ctx)
	return err
}

// NormalizeSerial turns user input (hex, optional 0x and colons) into XCA's
// stored serial form.
func NormalizeSerial(s string) (string, error) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	s = strings.NewReplacer(":", "", " ", "").Replace(s)
	n, ok := new(big.Int).SetString(s, 16)
	if !ok || n.Sign() < 0 {
		return "", errors.New("invalid serial number")
	}
	return pki.SerialHex(n), nil
}

// SetRevocation adds or edits a revocation of any serial under a CA
// (XCA's "Manage revocations"); an edit keeps date and CRL number.
func (h *Handle) SetRevocation(ctx context.Context, caID int64, serial string, r Revocation) error {
	serial, err := NormalizeSerial(serial)
	if err != nil {
		return err
	}
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return err
	}
	if ca := findCert(snap, caID); ca == nil || !ca.CA {
		return errors.New("not a CA certificate")
	}
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		return tx.Revoke(ctx, caID, xdb.RevocationRow{Serial: serial, Date: time.Now(), InvalDate: r.InvalDate, Reason: r.Reason})
	})
	h.changed(ctx)
	return err
}

// DeleteRevocation removes a revocation entry of a CA.
func (h *Handle) DeleteRevocation(ctx context.Context, caID int64, serial string) error {
	err := h.DB.Write(ctx, func(tx *xdb.Tx) error { return tx.Unrevoke(ctx, caID, serial) })
	h.changed(ctx)
	return err
}

// SetCAProperties sets the days until the next CRL and the default template.
func (h *Handle) SetCAProperties(ctx context.Context, caID int64, crlDays int, templateID int64) error {
	if crlDays < 1 || crlDays > 36500 {
		return errors.New("the CRL interval must be between 1 and 36500 days")
	}
	err := h.DB.Write(ctx, func(tx *xdb.Tx) error { return tx.SetCAProperties(ctx, caID, crlDays, templateID) })
	h.changed(ctx)
	return err
}

// CRLOptions are the choices of the CRL dialog.
type CRLOptions struct {
	Name       string
	ThisUpdate time.Time
	NextUpdate time.Time
	Hash       string
	SetNumber  bool
	Number     int64
	WithReason bool
	AuthKeyID  bool
	IssuerAlt  bool
}

// DefaultCRLOptions mirrors XCA's crljob defaults for a CA.
func DefaultCRLOptions(snap *xdb.Snapshot, ca *xdb.Cert) CRLOptions {
	now := time.Now().UTC().Truncate(time.Minute)
	days := 30
	var num int64 = 1
	if ca.Authority != nil {
		if ca.Authority.CRLDays > 0 {
			days = ca.Authority.CRLDays
		}
		num = ca.Authority.CRLNo + 1
	}
	hash := snap.Settings["default_hash"]
	if hash == "" {
		hash = "sha256"
	}
	return CRLOptions{Name: ca.Name, ThisUpdate: now, NextUpdate: now.AddDate(0, 0, days), Hash: hash,
		SetNumber: true, Number: num, WithReason: true, AuthKeyID: true, IssuerAlt: true}
}

// GenerateCRL signs a CRL over all revocations of the CA and stores it.
func (h *Handle) GenerateCRL(ctx context.Context, caID int64, o CRLOptions, kr *vault.Keyring, kp KeyPasswords) (int64, error) {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	ca := findCert(snap, caID)
	if ca == nil || !ca.CA {
		return 0, errors.New("not a CA certificate")
	}
	k := findKey(snap, ca.KeyID)
	if k == nil || !k.HasPrivate {
		return 0, errors.New("the private key of the CA is not in the database")
	}
	key, err := h.unlock(ctx, k.ID, k.KeyType, kr, kp)
	if err != nil {
		return 0, err
	}
	cc, err := pki.ParseCertificate(ca.DER)
	if err != nil {
		return 0, err
	}
	p := pki.CRLParams{Issuer: cc, Key: key, Hash: o.Hash, ThisUpdate: o.ThisUpdate, NextUpdate: o.NextUpdate,
		AuthKeyID: o.AuthKeyID, IssuerAlt: o.IssuerAlt}
	if o.SetNumber {
		if o.Number < 1 {
			return 0, errors.New("the CRL number must be positive")
		}
		p.Number = big.NewInt(o.Number)
	}
	for _, r := range snap.Revocations {
		if r.CAID != caID {
			continue
		}
		serial, ok := new(big.Int).SetString(strings.TrimPrefix(r.Serial, "-"), 16)
		if !ok {
			continue
		}
		if strings.HasPrefix(r.Serial, "-") {
			serial.Neg(serial)
		}
		p.Revoked = append(p.Revoked, pki.Revoked{Serial: serial, Date: r.Date, InvalDate: r.InvalDate,
			Reason: r.ReasonBit, WithReason: o.WithReason})
	}
	der, err := pki.CreateCRL(p)
	if err != nil {
		return 0, err
	}
	name := o.Name
	if name == "" {
		name = ca.Name
	}
	var id int64
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		num := int64(0)
		if o.SetNumber {
			num = o.Number
		}
		id, err = tx.InsertCRL(ctx, xdb.NewCRL{Name: name, Source: 2, DER: der, CAID: caID, Number: num, NextTime: o.NextUpdate})
		return err
	})
	h.changed(ctx)
	return id, err
}

// RenewOptions are the choices of XCA's renewal dialog (CertExtend).
type RenewOptions struct {
	NotBefore  time.Time
	NotAfter   time.Time
	NoExpiry   bool
	KeepSerial bool
	Revoke     *Revocation // revoke the old certificate (not for self-signed)
	Replace    bool        // delete the old certificate
}

// Renew issues a renewed copy of a certificate.
func (h *Handle) Renew(ctx context.Context, certID int64, o RenewOptions, kr *vault.Keyring, kp KeyPasswords) (int64, error) {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	old := findCert(snap, certID)
	if old == nil {
		return 0, errors.New("certificate not found")
	}
	self := old.IssuerID == old.ID
	signer := old
	if !self {
		if signer = findCert(snap, old.IssuerID); signer == nil {
			return 0, errors.New("the issuer of this certificate is not in the database")
		}
	}
	k := findKey(snap, signer.KeyID)
	if k == nil || !k.HasPrivate {
		return 0, errors.New("the private key of the issuer is not in the database")
	}
	key, err := h.unlock(ctx, k.ID, k.KeyType, kr, kp)
	if err != nil {
		return 0, err
	}
	oc, err := pki.ParseCertificate(old.DER)
	if err != nil {
		return 0, err
	}
	var issuer *x509.Certificate
	if !self {
		if issuer, err = pki.ParseCertificate(signer.DER); err != nil {
			return 0, err
		}
	}
	serial := oc.SerialNumber
	if !o.KeepSerial {
		used := usedSerials(snap, signer)
		serialLen, _ := strconv.Atoi(snap.Settings["serial_len"])
		for i := 0; ; i++ {
			if i > 100 {
				return 0, errors.New("failed to find an unused serial number")
			}
			if serial, err = pki.RandomSerial(serialLen); err != nil {
				return 0, err
			}
			if !used[pki.SerialHex(serial)] {
				break
			}
		}
	}
	na := o.NotAfter
	if o.NoExpiry {
		na = pki.NoExpiry
	}
	der, err := pki.Renew(oc, serial, o.NotBefore, na, issuer, key)
	if err != nil {
		return 0, err
	}
	var id int64
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		if id, err = tx.InsertCert(ctx, xdb.NewCert{Name: old.Name, Comment: old.Comment, Source: 6, DER: der}); err != nil {
			return err
		}
		if o.Revoke != nil && !self {
			if err := tx.Revoke(ctx, signer.ID, xdb.RevocationRow{Serial: old.Serial, Date: time.Now(),
				InvalDate: o.Revoke.InvalDate, Reason: o.Revoke.Reason}); err != nil {
				return err
			}
		}
		if o.Replace {
			return tx.Delete(ctx, old.ID)
		}
		return nil
	})
	h.changed(ctx)
	return id, err
}

package xdb

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"time"
)

var oidInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}

// Duplicate describes an item already in the database.
type Duplicate struct {
	ID         int64
	Name       string
	HasPrivate bool // keys only
	Date       string
}

// FindDuplicate looks up an item of type typ with the same content (XCA's
// getByReference): the same DER for certificates, requests and CRLs, the
// same public key for keys.
func (t *Tx) FindDuplicate(ctx context.Context, typ int, der []byte) (*Duplicate, error) {
	var q string
	switch typ {
	case TypeKey:
		q = `SELECT i.id, i.name, i.date, k."public", (SELECT COUNT(*) FROM private_keys p WHERE p.item=i.id)
			FROM public_keys k JOIN items i ON i.id=k.item WHERE i.del=0 AND k.hash=?`
	case TypeCert:
		q = "SELECT i.id, i.name, i.date, c.cert, 0 FROM certs c JOIN items i ON i.id=c.item WHERE i.del=0 AND c.hash=?"
	case TypeRequest:
		q = "SELECT i.id, i.name, i.date, r.request, 0 FROM requests r JOIN items i ON i.id=r.item WHERE i.del=0 AND r.hash=?"
	case TypeCRL:
		q = "SELECT i.id, i.name, i.date, c.crl, 0 FROM crls c JOIN items i ON i.id=c.item WHERE i.del=0 AND c.hash=?"
	default:
		return nil, nil
	}
	rows, err := t.QueryContext(ctx, q, Hash(der))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d Duplicate
		var date, blob sql.NullString
		var priv int
		if err := rows.Scan(&d.ID, &d.Name, &date, &blob, &priv); err != nil {
			return nil, err
		}
		if b, err := b64(blob); err == nil && bytes.Equal(b, der) {
			d.HasPrivate, d.Date = priv > 0, date.String
			return &d, nil
		}
	}
	return nil, rows.Err()
}

// CompleteKey adds the private part to a key stored as public key only
// (db_key::insert extends it; XCA replaces the item, this keeps its ID).
func (t *Tx) CompleteKey(ctx context.Context, id int64, private []byte, ownPass int, comment string) error {
	if _, err := t.ExecContext(ctx, "INSERT INTO private_keys (item, ownPass, private) VALUES (?, ?, ?)",
		id, ownPass, b64enc(private)); err != nil {
		return err
	}
	if _, err := t.ExecContext(ctx, "UPDATE items SET comment=? WHERE id=?", comment, id); err != nil {
		return err
	}
	t.Touch(id)
	return nil
}

// Comment returns an item's comment.
func (t *Tx) Comment(ctx context.Context, id int64) (string, error) {
	var c sql.NullString
	err := t.QueryRowContext(ctx, "SELECT comment FROM items WHERE id=?", id).Scan(&c)
	return c.String, err
}

// InsertImportedCRL stores a CRL from a file (db_crl::insert): its issuer
// is the CA certificate with the CRL's issuer name whose key verifies it,
// and the CA's revocation list is extended by the CRL's entries it does not
// have yet (db_crl::revokeCerts). It returns the new ID and the issuer (0
// when unknown).
func (t *Tx) InsertImportedCRL(ctx context.Context, name, comment string, der []byte) (int64, int64, error) {
	l, err := x509.ParseRevocationList(der)
	if err != nil {
		return 0, 0, err
	}
	issHash, err := NameHash(l.RawIssuer)
	if err != nil {
		return 0, 0, err
	}
	cands, err := t.certsWhere(ctx, "c.ca=1 AND c.item IN (SELECT item FROM x509super WHERE subj_hash=?)", issHash)
	if err != nil {
		return 0, 0, err
	}
	var issuer sql.NullInt64
	for _, c := range cands {
		if bytes.Equal(c.cert.RawSubject, l.RawIssuer) && l.CheckSignatureFrom(c.cert) == nil {
			issuer = sql.NullInt64{Int64: c.id, Valid: true}
			break
		}
	}
	if !issuer.Valid {
		// CheckSignatureFrom insists on CA key usage; fall back to the
		// bare signature check, as OpenSSL's X509_CRL_verify.
		for _, c := range cands {
			if bytes.Equal(c.cert.RawSubject, l.RawIssuer) &&
				c.cert.CheckSignature(l.SignatureAlgorithm, l.RawTBSRevocationList, l.Signature) == nil {
				issuer = sql.NullInt64{Int64: c.id, Valid: true}
				break
			}
		}
	}
	var num int64
	if l.Number != nil && l.Number.IsInt64() {
		num = l.Number.Int64()
	}
	id, err := t.insertItem(ctx, name, TypeCRL, 1, comment)
	if err != nil {
		return 0, 0, err
	}
	if _, err := t.ExecContext(ctx, "INSERT INTO crls (item, hash, num, iss_hash, issuer, crl) VALUES (?, ?, ?, ?, ?, ?)",
		id, Hash(der), num, issHash, issuer, b64enc(der)); err != nil {
		return 0, 0, err
	}
	if !issuer.Valid {
		return id, 0, nil
	}
	for _, e := range l.RevokedCertificateEntries {
		serial := serialHex(&x509.Certificate{SerialNumber: e.SerialNumber})
		var n int
		if err := t.QueryRowContext(ctx, "SELECT COUNT(*) FROM revocations WHERE caId=? AND serial=?", issuer.Int64, serial).Scan(&n); err != nil {
			return 0, 0, err
		}
		if n > 0 {
			continue
		}
		inval := UndefinedTime
		for _, x := range e.Extensions {
			var tm time.Time
			if x.Id.Equal(oidInvalidityDate) {
				if _, err := asn1.UnmarshalWithParams(x.Value, &tm, "generalized"); err == nil {
					inval = plainTime(tm)
				}
			}
		}
		if _, err := t.ExecContext(ctx, "INSERT INTO revocations (caId, serial, date, invaldate, crlNo, reasonBit) VALUES (?, ?, ?, ?, NULL, ?)",
			issuer.Int64, serial, plainTime(e.RevocationTime), inval, e.ReasonCode); err != nil {
			return 0, 0, err
		}
		if err := t.touchCertsWithSerial(ctx, issuer.Int64, serial); err != nil {
			return 0, 0, err
		}
	}
	return id, issuer.Int64, nil
}

package xdb

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// These inserts follow XCA's pki_*::insertSqlData and db_x509::inToCont so
// that rows written here are indistinguishable from XCA's own.

var b64enc = base64.StdEncoding.EncodeToString

// nextID mirrors pki_base::insertSql: MAX(id)+1, deleted items included.
func (t *Tx) nextID(ctx context.Context) (int64, error) {
	var id sql.NullInt64
	if err := t.QueryRowContext(ctx, "SELECT MAX(id) + 1 FROM items").Scan(&id); err != nil {
		return 0, err
	}
	if !id.Valid || id.Int64 < 1 {
		return 1, nil
	}
	return id.Int64, nil
}

func (t *Tx) insertItem(ctx context.Context, name string, typ, source int, comment string) (int64, error) {
	id, err := t.nextID(ctx)
	if err != nil {
		return 0, err
	}
	_, err = t.ExecContext(ctx, "INSERT INTO items (id, name, type, date, source, comment) VALUES (?, ?, ?, ?, ?, ?)",
		id, name, typ, time.Now().UTC().Format(TimeLayout), source, comment)
	return id, err
}

// AppendComment adds an XCA style "(message)" line to a comment.
func AppendComment(current, msg string) string {
	if current != "" && !strings.HasSuffix(current, "\n") {
		current += "\n"
	}
	return current + "(" + msg + ")\n"
}

// NewKey is a key to insert.
type NewKey struct {
	Name, Comment string
	Source        int
	KeyType       string // public_keys.type, e.g. RSA, EC, ED25
	Len           int
	SPKI          []byte // DER SubjectPublicKeyInfo
	Private       []byte // encrypted PKCS#8, nil for a public key only
	OwnPass       int
}

// InsertKey stores a key and links certificates and requests that use it
// and have no key yet (pki_key::insertSqlData).
func (t *Tx) InsertKey(ctx context.Context, k NewKey) (int64, error) {
	id, err := t.insertItem(ctx, k.Name, TypeKey, k.Source, k.Comment)
	if err != nil {
		return 0, err
	}
	h := Hash(k.SPKI)
	rows, err := t.QueryContext(ctx, `SELECT x.item, COALESCE(c.cert, r.request) FROM x509super x
		LEFT JOIN certs c ON c.item = x.item LEFT JOIN requests r ON r.item = x.item
		WHERE x.key_hash=? AND x.pkey IS NULL`, h)
	if err != nil {
		return 0, err
	}
	var link []int64
	for rows.Next() {
		var item int64
		var b sql.NullString
		if err := rows.Scan(&item, &b); err != nil {
			rows.Close()
			return 0, err
		}
		if der, err := b64(b); err == nil && bytes.Equal(spkiOf(der), k.SPKI) {
			link = append(link, item)
		}
	}
	rows.Close()
	for _, item := range link {
		if _, err := t.ExecContext(ctx, "UPDATE x509super SET pkey=? WHERE item=?", id, item); err != nil {
			return 0, err
		}
		t.Touch(item)
	}
	if _, err := t.ExecContext(ctx, `INSERT INTO public_keys (item, type, hash, len, "public") VALUES (?, ?, ?, ?, ?)`,
		id, k.KeyType, h, k.Len, b64enc(k.SPKI)); err != nil {
		return 0, err
	}
	if k.Private != nil {
		if _, err := t.ExecContext(ctx, "INSERT INTO private_keys (item, ownPass, private) VALUES (?, ?, ?)",
			id, k.OwnPass, b64enc(k.Private)); err != nil {
			return 0, err
		}
	}
	return id, nil
}

// spkiOf returns the SubjectPublicKeyInfo of a DER certificate or request.
func spkiOf(der []byte) []byte {
	if c, err := x509.ParseCertificate(der); err == nil {
		return c.RawSubjectPublicKeyInfo
	}
	if r, err := x509.ParseCertificateRequest(der); err == nil {
		return r.RawSubjectPublicKeyInfo
	}
	return nil
}

// lookupKey finds the key item for a public key (pki_x509super::lookupKey).
func (t *Tx) lookupKey(ctx context.Context, spki []byte) (sql.NullInt64, error) {
	rows, err := t.QueryContext(ctx, `SELECT k.item, k."public" FROM public_keys k JOIN items i ON i.id = k.item
		WHERE k.hash=? AND `+liveCondFor(t)+` ORDER BY k.item`, Hash(spki))
	if err != nil {
		return sql.NullInt64{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var pub sql.NullString
		if err := rows.Scan(&id, &pub); err != nil {
			return sql.NullInt64{}, err
		}
		if b, err := b64(pub); err == nil && bytes.Equal(b, spki) {
			return sql.NullInt64{Int64: id, Valid: true}, nil
		}
	}
	return sql.NullInt64{}, rows.Err()
}

func liveCondFor(*Tx) string { return "i.del=0" }

func (t *Tx) insertX509Super(ctx context.Context, id int64, rawSubject, spki []byte) (sql.NullInt64, error) {
	subj, err := NameHash(rawSubject)
	if err != nil {
		return sql.NullInt64{}, err
	}
	key, err := t.lookupKey(ctx, spki)
	if err != nil {
		return key, err
	}
	_, err = t.ExecContext(ctx, "INSERT INTO x509super (item, subj_hash, pkey, key_hash) VALUES (?, ?, ?, ?)",
		id, subj, key, Hash(spki))
	return key, err
}

// NewRequest is a certificate request to insert.
type NewRequest struct {
	Name, Comment string
	Source        int
	DER           []byte
	Signed        bool
}

// InsertRequest stores a PKCS#10 request (pki_x509req::insertSqlData).
func (t *Tx) InsertRequest(ctx context.Context, r NewRequest) (int64, error) {
	req, err := x509.ParseCertificateRequest(r.DER)
	if err != nil {
		return 0, err
	}
	id, err := t.insertItem(ctx, r.Name, TypeRequest, r.Source, r.Comment)
	if err != nil {
		return 0, err
	}
	if _, err := t.insertX509Super(ctx, id, req.RawSubject, req.RawSubjectPublicKeyInfo); err != nil {
		return 0, err
	}
	signed := 0
	if r.Signed {
		signed = 1
	}
	_, err = t.ExecContext(ctx, "INSERT INTO requests (item, hash, signed, request) VALUES (?, ?, ?, ?)",
		id, Hash(r.DER), signed, b64enc(r.DER))
	return id, err
}

// NewCert is a certificate to insert.
type NewCert struct {
	Name, Comment string
	Source        int
	DER           []byte
	TemplateID    int64 // CA's default template (authority.template), 0 = none
	CRLDays       int   // 0 = XCA's default of 30
}

type certRow struct {
	id   int64
	cert *x509.Certificate
}

// certsWhere loads live certificates matching a condition.
func (t *Tx) certsWhere(ctx context.Context, cond string, args ...any) ([]certRow, error) {
	rows, err := t.QueryContext(ctx, `SELECT c.item, c.cert FROM certs c JOIN items i ON i.id = c.item
		WHERE i.del=0 AND `+cond, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []certRow
	for rows.Next() {
		var id int64
		var b sql.NullString
		if err := rows.Scan(&id, &b); err != nil {
			return nil, err
		}
		der, err := b64(b)
		if err != nil {
			continue
		}
		if c, err := x509.ParseCertificate(der); err == nil {
			out = append(out, certRow{id, c})
		}
	}
	return out, rows.Err()
}

// signedBy checks a signature without crypto/x509's CA and key usage rules,
// as OpenSSL's X509_verify used by XCA does.
func signedBy(child, parent *x509.Certificate) bool {
	return parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature) == nil
}

// findIssuer returns the certificate that signed c, preferring the one
// valid longest; exclude skips an item (one being deleted).
func (t *Tx) findIssuer(ctx context.Context, c *x509.Certificate, exclude int64) (sql.NullInt64, error) {
	issHash, err := NameHash(c.RawIssuer)
	if err != nil {
		return sql.NullInt64{}, err
	}
	cands, err := t.certsWhere(ctx, "c.item IN (SELECT item FROM x509super WHERE subj_hash=?) AND c.item<>?", issHash, exclude)
	if err != nil {
		return sql.NullInt64{}, err
	}
	var best *certRow
	for i := range cands {
		p := &cands[i]
		if bytes.Equal(p.cert.RawSubject, c.RawIssuer) && signedBy(c, p.cert) &&
			(best == nil || p.cert.NotAfter.After(best.cert.NotAfter)) {
			best = p
		}
	}
	if best == nil {
		return sql.NullInt64{}, nil
	}
	return sql.NullInt64{Int64: best.id, Valid: true}, nil
}

// UndefinedTime is XCA's "no date" value.
const UndefinedTime = "99991231235959Z"

// InsertCert stores a certificate (pki_x509::insertSqlData) and then, like
// db_x509::inToCont, adopts certificates and CRLs it signed that had no
// issuer yet.
func (t *Tx) InsertCert(ctx context.Context, n NewCert) (int64, error) {
	c, err := x509.ParseCertificate(n.DER)
	if err != nil {
		return 0, err
	}
	id, err := t.insertItem(ctx, n.Name, TypeCert, n.Source, n.Comment)
	if err != nil {
		return 0, err
	}
	if _, err := t.insertX509Super(ctx, id, c.RawSubject, c.RawSubjectPublicKeyInfo); err != nil {
		return 0, err
	}
	var issuer sql.NullInt64
	if bytes.Equal(c.RawIssuer, c.RawSubject) && signedBy(c, c) {
		issuer = sql.NullInt64{Int64: id, Valid: true}
	} else if issuer, err = t.findIssuer(ctx, c, id); err != nil {
		return 0, err
	}
	issHash, err := NameHash(c.RawIssuer)
	if err != nil {
		return 0, err
	}
	isCA := c.BasicConstraintsValid && c.IsCA
	ca := 0
	if isCA {
		ca = 1
	}
	if _, err := t.ExecContext(ctx, "INSERT INTO certs (item, hash, iss_hash, serial, issuer, ca, cert) VALUES (?, ?, ?, ?, ?, ?, ?)",
		id, Hash(n.DER), issHash, serialHex(c), issuer, ca, b64enc(n.DER)); err != nil {
		return 0, err
	}
	if !isCA {
		return id, nil
	}
	days := n.CRLDays
	if days == 0 {
		days = 30
	}
	var tmpl sql.NullInt64
	if n.TemplateID != 0 {
		tmpl = sql.NullInt64{Int64: n.TemplateID, Valid: true}
	}
	if _, err := t.ExecContext(ctx, "INSERT INTO authority (item, template, crlExpire, crlNo, crlDays) VALUES (?, ?, ?, 0, ?)",
		id, tmpl, UndefinedTime, days); err != nil {
		return 0, err
	}
	if err := t.takeOver(ctx, id, c); err != nil {
		return 0, err
	}
	return id, t.adoptChildren(ctx, id, c)
}

// takeOver implements the first part of db_x509::inToCont: another CA
// certificate with the same name and key that expires no later than the new
// one hands over its issued certificates and its revocations (a renewed CA).
func (t *Tx) takeOver(ctx context.Context, newID int64, c *x509.Certificate) error {
	subj, err := NameHash(c.RawSubject)
	if err != nil {
		return err
	}
	others, err := t.certsWhere(ctx, `c.ca=1 AND c.item<>? AND c.item IN
		(SELECT item FROM x509super WHERE subj_hash=? AND key_hash=?)`, newID, subj, Hash(c.RawSubjectPublicKeyInfo))
	if err != nil {
		return err
	}
	for _, o := range others {
		if !bytes.Equal(o.cert.RawSubject, c.RawSubject) || !bytes.Equal(o.cert.RawSubjectPublicKeyInfo, c.RawSubjectPublicKeyInfo) ||
			c.NotAfter.Before(o.cert.NotAfter) {
			continue
		}
		children, err := t.certsWhere(ctx, "c.issuer=? AND c.item<>?", o.id, o.id)
		if err != nil {
			return err
		}
		for _, ch := range children {
			if signedBy(ch.cert, c) {
				if _, err := t.ExecContext(ctx, "UPDATE certs SET issuer=? WHERE item=?", newID, ch.id); err != nil {
					return err
				}
				t.Touch(ch.id)
			}
		}
		// merge revocations that the new CA does not have yet
		if _, err := t.ExecContext(ctx, `INSERT INTO revocations (caId, serial, date, invaldate, crlNo, reasonBit)
			SELECT ?, serial, date, invaldate, crlNo, reasonBit FROM revocations r WHERE caId=?
			AND NOT EXISTS (SELECT 1 FROM revocations x WHERE x.caId=? AND x.serial=r.serial)`, newID, o.id, newID); err != nil {
			return err
		}
	}
	return nil
}

func serialHex(c *x509.Certificate) string {
	s := c.SerialNumber
	h := strings.ToUpper(fmt.Sprintf("%x", new(big.Int).Abs(s).Bytes()))
	if h == "" {
		h = "0"
	}
	if s.Sign() < 0 {
		h = "-" + h
	}
	return h
}

// adoptChildren sets issuer on certificates and CRLs that ca signed and
// that have no issuer yet.
func (t *Tx) adoptChildren(ctx context.Context, caID int64, ca *x509.Certificate) error {
	subj, err := NameHash(ca.RawSubject)
	if err != nil {
		return err
	}
	orphans, err := t.certsWhere(ctx, "c.iss_hash=? AND c.issuer IS NULL AND c.item<>?", subj, caID)
	if err != nil {
		return err
	}
	for _, o := range orphans {
		if bytes.Equal(o.cert.RawIssuer, ca.RawSubject) && signedBy(o.cert, ca) {
			if _, err := t.ExecContext(ctx, "UPDATE certs SET issuer=? WHERE item=?", caID, o.id); err != nil {
				return err
			}
			t.Touch(o.id)
		}
	}
	rows, err := t.QueryContext(ctx, `SELECT c.item, c.crl FROM crls c JOIN items i ON i.id = c.item
		WHERE i.del=0 AND c.iss_hash=? AND c.issuer IS NULL`, subj)
	if err != nil {
		return err
	}
	var crls []int64
	for rows.Next() {
		var id int64
		var b sql.NullString
		if err := rows.Scan(&id, &b); err != nil {
			rows.Close()
			return err
		}
		der, err := b64(b)
		if err != nil {
			continue
		}
		if l, err := x509.ParseRevocationList(der); err == nil &&
			ca.CheckSignature(l.SignatureAlgorithm, l.RawTBSRevocationList, l.Signature) == nil {
			crls = append(crls, id)
		}
	}
	rows.Close()
	for _, id := range crls {
		if _, err := t.ExecContext(ctx, "UPDATE crls SET issuer=? WHERE item=?", caID, id); err != nil {
			return err
		}
		t.Touch(id)
	}
	return nil
}

// Rename sets name and comment (db_base: UPDATE items SET name=?, comment=?).
func (t *Tx) Rename(ctx context.Context, id int64, name, comment string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("the internal name must not be empty")
	}
	res, err := t.ExecContext(ctx, "UPDATE items SET name=?, comment=? WHERE id=? AND del=0", name, comment, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	t.Touch(id)
	return nil
}

// MarkSigned sets or clears requests.signed.
func (t *Tx) MarkSigned(ctx context.Context, id int64, signed bool) error {
	v := 0
	if signed {
		v = 1
	}
	if _, err := t.ExecContext(ctx, "UPDATE requests SET signed=? WHERE item=?", v, id); err != nil {
		return err
	}
	t.Touch(id)
	return nil
}

// Delete removes an item's detail rows and marks it deleted, as XCA's
// pki_*::deleteSqlData followed by pki_base::deleteSql. Certificates it
// had issued are re-linked to another issuer if one exists.
func (t *Tx) Delete(ctx context.Context, id int64) error {
	var typ int
	if err := t.QueryRowContext(ctx, "SELECT type FROM items WHERE id=? AND del=0", id).Scan(&typ); err != nil {
		return err
	}
	var stmts []string
	switch typ {
	case TypeKey:
		stmts = []string{"DELETE FROM private_keys WHERE item=?", "DELETE FROM public_keys WHERE item=?",
			"DELETE FROM tokens WHERE item=?", "DELETE FROM token_mechanism WHERE item=?"}
		var users []int64
		rows, err := t.QueryContext(ctx, "SELECT item FROM x509super WHERE pkey=?", id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var u int64
			rows.Scan(&u)
			users = append(users, u)
		}
		rows.Close()
		if _, err := t.ExecContext(ctx, "UPDATE x509super SET pkey=NULL WHERE pkey=?", id); err != nil {
			return err
		}
		for _, u := range users {
			t.Touch(u)
		}
	case TypeRequest:
		stmts = []string{"DELETE FROM x509super WHERE item=?", "DELETE FROM requests WHERE item=?"}
	case TypeCert:
		children, err := t.certsWhere(ctx, "c.issuer=? AND c.item<>?", id, id)
		if err != nil {
			return err
		}
		stmts = []string{"DELETE FROM x509super WHERE item=?", "DELETE FROM certs WHERE item=?",
			"DELETE FROM authority WHERE item=?", "UPDATE crls SET issuer=NULL WHERE issuer=?",
			"UPDATE certs SET issuer=NULL WHERE issuer=?", "DELETE FROM revocations WHERE caId=?"}
		if t.hasTable(ctx, "takeys") {
			stmts = append(stmts, "DELETE FROM takeys WHERE item=?")
		}
		for _, s := range stmts {
			if _, err := t.ExecContext(ctx, s, id); err != nil {
				return err
			}
		}
		stmts = nil
		for _, ch := range children {
			parent, err := t.findIssuer(ctx, ch.cert, id)
			if err != nil {
				return err
			}
			if parent.Valid {
				if _, err := t.ExecContext(ctx, "UPDATE certs SET issuer=? WHERE item=?", parent, ch.id); err != nil {
					return err
				}
			}
			t.Touch(ch.id)
		}
	case TypeCRL:
		stmts = []string{"DELETE FROM crls WHERE item=?"}
	case TypeTemplate:
		stmts = []string{"DELETE FROM templates WHERE item=?"}
	default:
		return fmt.Errorf("cannot delete items of type %d", typ)
	}
	for _, s := range stmts {
		if _, err := t.ExecContext(ctx, s, id); err != nil {
			return err
		}
	}
	if _, err := t.ExecContext(ctx, "UPDATE items SET del=1 WHERE id=?", id); err != nil {
		return err
	}
	t.Touch(id)
	return nil
}

func (t *Tx) hasTable(ctx context.Context, name string) bool {
	var n int
	t.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n)
	return n > 0
}

// TemplateVersion is the template format written (TMPL_VERSION).
const TemplateVersion = 10

// InsertTemplate stores a template (pki_temp::insertSqlData).
func (t *Tx) InsertTemplate(ctx context.Context, name, comment string, source int, blob []byte) (int64, error) {
	id, err := t.insertItem(ctx, name, TypeTemplate, source, comment)
	if err != nil {
		return 0, err
	}
	_, err = t.ExecContext(ctx, "INSERT INTO templates (item, version, template) VALUES (?, ?, ?)", id, TemplateVersion, b64enc(blob))
	return id, err
}

// UpdateTemplate replaces a template's content, name and comment.
func (t *Tx) UpdateTemplate(ctx context.Context, id int64, name, comment string, blob []byte) error {
	res, err := t.ExecContext(ctx, "UPDATE templates SET version=?, template=? WHERE item=?", TemplateVersion, b64enc(blob), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	return t.Rename(ctx, id, name, comment)
}

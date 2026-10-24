package gcadb

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/tmpl"
)

func (t *Tx) insertItem(ctx context.Context, name string, typ, source int, comment string) (int64, error) {
	id, err := NewUUID()
	if err != nil {
		return 0, err
	}
	res, err := t.ExecContext(ctx, "INSERT INTO items (uuid, type, name, comment, source, created) VALUES (?, ?, ?, ?, ?, ?)",
		id, TypeName(typ), name, comment, SourceName(source), fmtTime(time.Now()))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// AppendComment adds a "(message)" line to a comment.
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
	KeyType       string // algorithm
	Len           int
	SPKI          []byte // DER SubjectPublicKeyInfo
	Private       []byte // sealed private key, nil for a public key only
	Protection    int
}

// InsertKey stores a key and links live certificates and requests that use
// it and have no key yet.
func (t *Tx) InsertKey(ctx context.Context, k NewKey) (int64, error) {
	id, err := t.insertItem(ctx, k.Name, TypeKey, k.Source, k.Comment)
	if err != nil {
		return 0, err
	}
	prot := k.Protection
	if k.Private == nil && prot != ProtToken {
		prot = ProtNone
	}
	if _, err := t.ExecContext(ctx, `INSERT INTO keys (item, algorithm, bits, spki, fingerprint, protection, private)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, id, k.KeyType, k.Len, k.SPKI, Fingerprint(k.SPKI), protValue(prot), k.Private); err != nil {
		return 0, err
	}
	return id, t.linkKey(ctx, id, k.SPKI)
}

// linkKey points certificates and requests without a (live) key at key id.
func (t *Tx) linkKey(ctx context.Context, id int64, spki []byte) error {
	fpr := Fingerprint(spki)
	for _, table := range []string{"certs", "requests"} {
		rows, err := t.QueryContext(ctx, `SELECT x.item FROM `+table+` x
			LEFT JOIN items k ON k.id = x.key AND k.trashed IS NULL
			WHERE x.key_fingerprint=? AND k.id IS NULL`, fpr)
		if err != nil {
			return err
		}
		var ids []int64
		for rows.Next() {
			var item int64
			if err := rows.Scan(&item); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, item)
		}
		rows.Close()
		for _, item := range ids {
			if _, err := t.ExecContext(ctx, "UPDATE "+table+" SET key=? WHERE item=?", id, item); err != nil {
				return err
			}
			t.Touch(item)
		}
	}
	return nil
}

// lookupKey finds the live key item for a public key.
func (t *Tx) lookupKey(ctx context.Context, spki []byte) (sql.NullInt64, error) {
	rows, err := t.QueryContext(ctx, `SELECT k.item, k.spki FROM keys k JOIN items i ON i.id = k.item
		WHERE k.fingerprint=? AND i.trashed IS NULL ORDER BY k.item`, Fingerprint(spki))
	if err != nil {
		return sql.NullInt64{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var pub []byte
		if err := rows.Scan(&id, &pub); err != nil {
			return sql.NullInt64{}, err
		}
		if bytes.Equal(pub, spki) {
			return sql.NullInt64{Int64: id, Valid: true}, nil
		}
	}
	return sql.NullInt64{}, rows.Err()
}

// NewRequest is a certificate request to insert.
type NewRequest struct {
	Name, Comment string
	Source        int
	DER           []byte
	Signed        bool
}

// InsertRequest stores a PKCS#10 request, linked to its key.
func (t *Tx) InsertRequest(ctx context.Context, r NewRequest) (int64, error) {
	req, err := pki.ParseCertificateRequest(r.DER)
	if err != nil {
		return 0, err
	}
	id, err := t.insertItem(ctx, r.Name, TypeRequest, r.Source, r.Comment)
	if err != nil {
		return 0, err
	}
	key, err := t.lookupKey(ctx, req.RawSubjectPublicKeyInfo)
	if err != nil {
		return 0, err
	}
	_, err = t.ExecContext(ctx, `INSERT INTO requests (item, der, fingerprint, subject, key_fingerprint, key, signed)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, id, r.DER, Fingerprint(r.DER), req.RawSubject, Fingerprint(req.RawSubjectPublicKeyInfo),
		key, r.Signed)
	return id, err
}

// NewCert is a certificate to insert.
type NewCert struct {
	Name, Comment string
	Source        int
	DER           []byte
	TemplateID    int64 // CA's default template, 0 = none
	CRLDays       int   // 0 = the default of 30
}

type certRow struct {
	id   int64
	cert *x509.Certificate
}

// certsWhere loads live certificates matching a condition on certs c.
func (t *Tx) certsWhere(ctx context.Context, cond string, args ...any) ([]certRow, error) {
	rows, err := t.QueryContext(ctx, `SELECT c.item, c.der FROM certs c JOIN items i ON i.id = c.item
		WHERE i.trashed IS NULL AND `+cond, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []certRow
	for rows.Next() {
		var id int64
		var der []byte
		if err := rows.Scan(&id, &der); err != nil {
			return nil, err
		}
		if c, err := pki.ParseCertificate(der); err == nil {
			out = append(out, certRow{id, c})
		}
	}
	return out, rows.Err()
}

// signedBy checks a signature without crypto/x509's CA and key usage rules,
// as OpenSSL's X509_verify does, for every algorithm pki verifies.
func signedBy(child, parent *x509.Certificate) bool {
	return pki.CheckCertSignature(parent, child) == nil
}

// findIssuer returns the live certificate that signed c, preferring the
// one valid longest; exclude skips an item (one being trashed).
func (t *Tx) findIssuer(ctx context.Context, c *x509.Certificate, exclude int64) (sql.NullInt64, error) {
	cands, err := t.certsWhere(ctx, "c.subject=? AND c.item<>?", c.RawIssuer, exclude)
	if err != nil {
		return sql.NullInt64{}, err
	}
	var best *certRow
	for i := range cands {
		p := &cands[i]
		if signedBy(c, p.cert) && (best == nil || p.cert.NotAfter.After(best.cert.NotAfter)) {
			best = p
		}
	}
	if best == nil {
		return sql.NullInt64{}, nil
	}
	return sql.NullInt64{Int64: best.id, Valid: true}, nil
}

// SerialHex returns a certificate's serial as stored: upper case hex, with
// a minus sign when negative.
func SerialHex(n *big.Int) string {
	h := strings.ToUpper(fmt.Sprintf("%x", new(big.Int).Abs(n).Bytes()))
	if h == "" {
		h = "0"
	}
	if n.Sign() < 0 {
		h = "-" + h
	}
	return h
}

// InsertCert stores a certificate, linked to its issuer and key, and then
// adopts certificates and CRLs it signed that had no issuer yet.
func (t *Tx) InsertCert(ctx context.Context, n NewCert) (int64, error) {
	c, err := pki.ParseCertificate(n.DER)
	if err != nil {
		return 0, err
	}
	id, err := t.insertItem(ctx, n.Name, TypeCert, n.Source, n.Comment)
	if err != nil {
		return 0, err
	}
	key, err := t.lookupKey(ctx, c.RawSubjectPublicKeyInfo)
	if err != nil {
		return 0, err
	}
	isCA := c.BasicConstraintsValid && c.IsCA
	if _, err := t.ExecContext(ctx, `INSERT INTO certs (item, der, fingerprint, subject, issuer_name, key_fingerprint,
		serial, key, ca, not_before, not_after) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, n.DER, Fingerprint(n.DER), c.RawSubject, c.RawIssuer, Fingerprint(c.RawSubjectPublicKeyInfo),
		SerialHex(c.SerialNumber), key, isCA, fmtTime(c.NotBefore), fmtTime(c.NotAfter)); err != nil {
		return 0, err
	}
	var issuer sql.NullInt64
	if bytes.Equal(c.RawIssuer, c.RawSubject) && signedBy(c, c) {
		issuer = sql.NullInt64{Int64: id, Valid: true}
	} else if issuer, err = t.findIssuer(ctx, c, id); err != nil {
		return 0, err
	}
	if issuer.Valid {
		if _, err := t.ExecContext(ctx, "UPDATE certs SET issuer=? WHERE item=?", issuer, id); err != nil {
			return 0, err
		}
	}
	if !isCA {
		return id, nil
	}
	days := n.CRLDays
	if days == 0 {
		if days, err = t.defaultCRLDays(ctx, issuer.Valid && issuer.Int64 == id); err != nil {
			return 0, err
		}
	}
	var tmplID sql.NullInt64
	if n.TemplateID != 0 {
		tmplID = sql.NullInt64{Int64: n.TemplateID, Valid: true}
	}
	// A new CA's authority ID is its certificate's UUID; takeOver may
	// replace it with the one of the CA it renews.
	if _, err := t.ExecContext(ctx, `INSERT INTO authorities (cert, uuid, template, crl_days)
		SELECT ?, uuid, ?, ? FROM items WHERE id=?`, id, tmplID, days, id); err != nil {
		return 0, err
	}
	if err := t.takeOver(ctx, id, c); err != nil {
		return 0, err
	}
	return id, t.adoptChildren(ctx, id, c)
}

// takeOver: another CA certificate with the same name and key that expires
// no later than the new one hands over its issued certificates and its
// revocations (a renewed CA).
//
// The new CA also takes over the authority ID (the CA folder) of the one
// valid longest among them. A CA that hands over its authority ID and is
// still live when the transaction commits gets a new one (see Tx.settle);
// one moved to the trash in the same transaction (a renewal replacing the
// old certificate) keeps it and cannot be restored while the new CA is
// live.
func (t *Tx) takeOver(ctx context.Context, newID int64, c *x509.Certificate) error {
	others, err := t.certsWhere(ctx, "c.ca=1 AND c.item<>? AND c.subject=? AND c.key_fingerprint=?",
		newID, c.RawSubject, Fingerprint(c.RawSubjectPublicKeyInfo))
	if err != nil {
		return err
	}
	var from *certRow
	for i := range others {
		o := &others[i]
		if !bytes.Equal(o.cert.RawSubjectPublicKeyInfo, c.RawSubjectPublicKeyInfo) || c.NotAfter.Before(o.cert.NotAfter) {
			continue
		}
		if from == nil || o.cert.NotAfter.After(from.cert.NotAfter) || (o.cert.NotAfter.Equal(from.cert.NotAfter) && o.id > from.id) {
			from = o
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
		if _, err := t.ExecContext(ctx, `INSERT INTO revocations (ca, serial, date, invalidity, reason, crl_number, expires)
			SELECT ?, serial, date, invalidity, reason, crl_number, expires FROM revocations WHERE ca=?
			ON CONFLICT (ca, serial) DO NOTHING`, newID, o.id); err != nil {
			return err
		}
	}
	if from == nil {
		return nil
	}
	var auth string
	if err := t.QueryRowContext(ctx, "SELECT uuid FROM authorities WHERE cert=?", from.id).Scan(&auth); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil // a CA certificate without an authority row
		}
		return err
	}
	if _, err := t.ExecContext(ctx, "UPDATE authorities SET uuid=? WHERE cert=?", auth, newID); err != nil {
		return err
	}
	// The renewal is the same CA: it keeps the CRL interval and default
	// template, and its CRL numbers continue.
	if _, err := t.ExecContext(ctx, `UPDATE authorities SET
		crl_days = (SELECT crl_days FROM authorities WHERE cert=?),
		crl_number = MAX(crl_number, (SELECT crl_number FROM authorities WHERE cert=?)),
		template = COALESCE(template, (SELECT template FROM authorities WHERE cert=?))
		WHERE cert=?`, from.id, from.id, from.id, newID); err != nil {
		return err
	}
	// Every other CA with this authority ID (the one renewed, and CAs it
	// took the ID over from itself) must give it up if it stays live.
	rows, err := t.QueryContext(ctx, "SELECT cert FROM authorities WHERE uuid=? AND cert<>?", auth, newID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		t.displaced = append(t.displaced, id)
	}
	return rows.Err()
}

// Defaults of the CRL interval of new CAs; the database settings
// crl_days_root and crl_days_sub override them.
const (
	DefaultCRLDaysRoot = 180
	DefaultCRLDaysSub  = 7
	MaxCRLDays         = 36500
)

// defaultCRLDays is the CRL interval of a new root (self-signed) or
// subordinate CA from the database settings.
func (t *Tx) defaultCRLDays(ctx context.Context, root bool) (int, error) {
	key, days := "crl_days_sub", DefaultCRLDaysSub
	if root {
		key, days = "crl_days_root", DefaultCRLDaysRoot
	}
	v, err := querySetting(ctx, t, key)
	if err != nil {
		return 0, err
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= MaxCRLDays {
		days = n
	}
	return days, nil
}

// adoptChildren sets the issuer of live certificates and CRLs that ca
// signed and whose issuer is unknown or in the trash.
func (t *Tx) adoptChildren(ctx context.Context, caID int64, ca *x509.Certificate) error {
	orphans, err := t.certsWhere(ctx, `c.issuer_name=? AND c.item<>? AND
		(c.issuer IS NULL OR c.issuer IN (SELECT id FROM items WHERE trashed IS NOT NULL))`, ca.RawSubject, caID)
	if err != nil {
		return err
	}
	for _, o := range orphans {
		if signedBy(o.cert, ca) {
			if _, err := t.ExecContext(ctx, "UPDATE certs SET issuer=? WHERE item=?", caID, o.id); err != nil {
				return err
			}
			t.Touch(o.id)
		}
	}
	rows, err := t.QueryContext(ctx, `SELECT l.item, l.der FROM crls l JOIN items i ON i.id = l.item
		WHERE i.trashed IS NULL AND l.issuer_name=? AND
		(l.issuer IS NULL OR l.issuer IN (SELECT id FROM items WHERE trashed IS NOT NULL))`, ca.RawSubject)
	if err != nil {
		return err
	}
	var crls []int64
	for rows.Next() {
		var id int64
		var der []byte
		if err := rows.Scan(&id, &der); err != nil {
			rows.Close()
			return err
		}
		if l, err := x509.ParseRevocationList(der); err == nil && pki.CheckCRLSignature(ca, l) == nil {
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

// Rename sets name and comment of a live item.
func (t *Tx) Rename(ctx context.Context, id int64, name, comment string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("the internal name must not be empty")
	}
	res, err := t.ExecContext(ctx, "UPDATE items SET name=?, comment=? WHERE id=? AND trashed IS NULL", name, comment, id)
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
	if _, err := t.ExecContext(ctx, "UPDATE requests SET signed=? WHERE item=?", signed, id); err != nil {
		return err
	}
	t.Touch(id)
	return nil
}

func (t *Tx) itemType(ctx context.Context, id int64, trashed bool) (int, error) {
	cond := "trashed IS NULL"
	if trashed {
		cond = "trashed IS NOT NULL"
	}
	var typ string
	if err := t.QueryRowContext(ctx, "SELECT type FROM items WHERE id=? AND "+cond, id).Scan(&typ); err != nil {
		return 0, err
	}
	return typeOf(typ), nil
}

// Trash moves a live item to the trash. Links to it stay and read as
// unknown while it is there; certificates a trashed CA issued are re-linked
// to another live issuer if one signed them too.
func (t *Tx) Trash(ctx context.Context, id int64) error {
	typ, err := t.itemType(ctx, id, false)
	if err != nil {
		return err
	}
	if _, err := t.ExecContext(ctx, "UPDATE items SET trashed=? WHERE id=?", fmtTime(time.Now()), id); err != nil {
		return err
	}
	t.Touch(id)
	switch typ {
	case TypeCert:
		children, err := t.certsWhere(ctx, "c.issuer=? AND c.item<>?", id, id)
		if err != nil {
			return err
		}
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
	case TypeKey:
		return t.touchUsers(ctx, id)
	}
	return nil
}

// touchUsers marks certificates and requests of a key as changed.
func (t *Tx) touchUsers(ctx context.Context, keyID int64) error {
	rows, err := t.QueryContext(ctx, "SELECT item FROM certs WHERE key=? UNION SELECT item FROM requests WHERE key=?", keyID, keyID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return err
		}
		t.Touch(id)
	}
	return rows.Err()
}

// Restore takes an item out of the trash and links it again: a key to
// certificates and requests without a key, a CA to certificates and CRLs
// without a live issuer.
func (t *Tx) Restore(ctx context.Context, id int64) error {
	typ, err := t.itemType(ctx, id, true)
	if err != nil {
		return err
	}
	if typ == TypeCert {
		if err := t.checkAuthorityFree(ctx, id); err != nil {
			return err
		}
	}
	if _, err := t.ExecContext(ctx, "UPDATE items SET trashed=NULL WHERE id=?", id); err != nil {
		return err
	}
	t.Touch(id)
	switch typ {
	case TypeKey:
		var spki []byte
		if err := t.QueryRowContext(ctx, "SELECT spki FROM keys WHERE item=?", id).Scan(&spki); err != nil {
			return err
		}
		if err := t.linkKey(ctx, id, spki); err != nil {
			return err
		}
		return t.touchUsers(ctx, id)
	case TypeCert:
		var der []byte
		if err := t.QueryRowContext(ctx, "SELECT der FROM certs WHERE item=?", id).Scan(&der); err != nil {
			return err
		}
		c, err := pki.ParseCertificate(der)
		if err != nil {
			return err
		}
		if c.BasicConstraintsValid && c.IsCA {
			return t.adoptChildren(ctx, id, c)
		}
	}
	return nil
}

// ErrAuthorityInUse: a CA in the trash cannot be restored because a live
// CA (its renewal) holds its authority ID.
var ErrAuthorityInUse = errors.New("gcadb: a live CA holds this CA's authority ID")

// checkAuthorityFree fails with ErrAuthorityInUse when another live CA
// holds the authority ID of certificate id.
func (t *Tx) checkAuthorityFree(ctx context.Context, id int64) error {
	var n int
	err := t.QueryRowContext(ctx, `SELECT COUNT(*) FROM authorities a JOIN authorities o ON o.uuid = a.uuid AND o.cert <> a.cert
		JOIN items i ON i.id = o.cert WHERE a.cert=? AND i.trashed IS NULL`, id).Scan(&n)
	if err != nil {
		return err
	}
	if n > 0 {
		return ErrAuthorityInUse
	}
	return nil
}

// Purge removes an item in the trash for good; its rows go with it
// (revocations of a CA, the OpenPGP certificate of a key) and links to it
// are cleared.
func (t *Tx) Purge(ctx context.Context, id int64) error {
	if _, err := t.itemType(ctx, id, true); err != nil {
		return err
	}
	if err := t.touchUsers(ctx, id); err != nil {
		return err
	}
	_, err := t.ExecContext(ctx, "DELETE FROM items WHERE id=? AND trashed IS NOT NULL", id)
	return err
}

// TemplateVersion is the version of XCA's template format the templates'
// settings follow (TMPL_VERSION).
const TemplateVersion = tmpl.Version

// InsertTemplate stores a template.
func (t *Tx) InsertTemplate(ctx context.Context, name, comment string, source int, data *tmpl.Template) (int64, error) {
	j, err := encodeTemplate(data)
	if err != nil {
		return 0, err
	}
	id, err := t.insertItem(ctx, name, TypeTemplate, source, comment)
	if err != nil {
		return 0, err
	}
	_, err = t.ExecContext(ctx, "INSERT INTO templates (item, data) VALUES (?, ?)", id, j)
	return id, err
}

// UpdateTemplate replaces a template's content, name and comment.
func (t *Tx) UpdateTemplate(ctx context.Context, id int64, name, comment string, data *tmpl.Template) error {
	j, err := encodeTemplate(data)
	if err != nil {
		return err
	}
	res, err := t.ExecContext(ctx, "UPDATE templates SET data=? WHERE item=?", j, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	return t.Rename(ctx, id, name, comment)
}

// Duplicate describes a live item with the same content.
type Duplicate struct {
	ID         int64
	Name       string
	HasPrivate bool // keys only
	Date       time.Time
}

// FindDuplicate looks up a live item of type typ with the same content:
// the same DER for certificates, requests and CRLs, the same public key
// for keys.
func (t *Tx) FindDuplicate(ctx context.Context, typ int, der []byte) (*Duplicate, error) {
	var q string
	switch typ {
	case TypeKey:
		q = "SELECT i.id, i.name, i.created, x.spki, x.private IS NOT NULL FROM keys x JOIN items i ON i.id=x.item"
	case TypeCert:
		q = "SELECT i.id, i.name, i.created, x.der, 0 FROM certs x JOIN items i ON i.id=x.item"
	case TypeRequest:
		q = "SELECT i.id, i.name, i.created, x.der, 0 FROM requests x JOIN items i ON i.id=x.item"
	case TypeCRL:
		q = "SELECT i.id, i.name, i.created, x.der, 0 FROM crls x JOIN items i ON i.id=x.item"
	default:
		return nil, nil
	}
	rows, err := t.QueryContext(ctx, q+" WHERE i.trashed IS NULL AND x.fingerprint=?", Fingerprint(der))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d Duplicate
		var created sql.NullString
		var blob []byte
		if err := rows.Scan(&d.ID, &d.Name, &created, &blob, &d.HasPrivate); err != nil {
			return nil, err
		}
		if bytes.Equal(blob, der) {
			d.Date = parseTime(created)
			return &d, nil
		}
	}
	return nil, rows.Err()
}

// CompleteKey adds the private part to a key stored as public key only.
func (t *Tx) CompleteKey(ctx context.Context, id int64, private []byte, protection int, comment string) error {
	res, err := t.ExecContext(ctx, "UPDATE keys SET private=?, protection=? WHERE item=? AND private IS NULL",
		private, protValue(protection), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("gcadb: key %d already has a private part", id)
	}
	if _, err := t.ExecContext(ctx, "UPDATE items SET comment=? WHERE id=?", comment, id); err != nil {
		return err
	}
	t.Touch(id)
	return nil
}

// Comment returns an item's comment.
func (t *Tx) Comment(ctx context.Context, id int64) (string, error) {
	var c string
	err := t.QueryRowContext(ctx, "SELECT comment FROM items WHERE id=?", id).Scan(&c)
	return c, err
}

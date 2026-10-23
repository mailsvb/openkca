// Package xdb reads and writes go-ca's SQLite database format: XCA's
// schema 8 plus go-ca's own tables, with a schema setting XCA refuses. It
// also upgrades XCA databases to it. It is the only package that issues
// SQL against a database file.
package xdb

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Item types (enum pki_type in lib/pki_base.h).
const (
	TypeKey       = 1
	TypeRequest   = 2
	TypeCert      = 3
	TypeCRL       = 4
	TypeTemplate  = 5
	TypeSmartcard = 7
)

// Item sources (enum pki_source).
var sourceNames = map[int]string{
	0: "unknown", 1: "imported", 2: "generated", 3: "transformed",
	4: "token", 5: "legacy_db", 6: "renewed",
}

// SourceName returns the XCA name of an items.source value.
func SourceName(s int) string {
	if n, ok := sourceNames[s]; ok {
		return n
	}
	return "unknown"
}

// Password types of private_keys.ownPass (enum passType).
const (
	PassCommon  = 0 // database password
	PassPrivate = 1 // the key's own password
	PassBogus   = 2 // the literal password "Bogus"
	PassPIN     = 3 // token PIN
)

// TimeLayout is the CHAR(15) GeneralizedTime format XCA stores dates in.
const TimeLayout = "20060102150405Z"

// ParseTime parses an XCA date column. "99991231235959Z" is XCA's marker for
// "no well-defined expiration" and is returned as is.
func ParseTime(s string) (time.Time, error) {
	return time.Parse(TimeLayout, strings.TrimSpace(s))
}

// Item is one row of the items table.
type Item struct {
	ID      int64
	Name    string
	Type    int
	Source  int
	Date    time.Time
	Comment string
	Stamp   int64
}

// Key is a public key, with information about its private part.
type Key struct {
	Item
	KeyType    string // RSA, DSA, EC, ED25 (CHAR(4))
	Len        int
	Hash       int64
	Public     []byte // DER SubjectPublicKeyInfo
	HasPrivate bool
	OwnPass    int
	Token      bool
}

// Revocation is a row of the revocations table.
type Revocation struct {
	CAID      int64
	Serial    string
	Date      time.Time
	InvalDate time.Time
	CRLNo     int64
	ReasonBit int
}

// Authority holds a CA's bookkeeping (authority table).
type Authority struct {
	TemplateID int64 // 0 = none
	CRLExpire  time.Time
	CRLNo      int64
	CRLDays    int
	DNPolicy   string
}

// Cert is a certificate.
type Cert struct {
	Item
	Hash      int64
	IssHash   int64
	Serial    string
	IssuerID  int64 // 0 = unknown issuer
	CA        bool
	DER       []byte
	KeyID     int64 // 0 = no key in the database
	Authority *Authority
}

// Request is a PKCS#10 certificate signing request.
type Request struct {
	Item
	Hash   int64
	Signed bool
	DER    []byte
	KeyID  int64
}

// CRL is a certificate revocation list.
type CRL struct {
	Item
	Hash     int64
	Num      int64
	IssHash  int64
	IssuerID int64
	DER      []byte
}

// Template is an XCA template in its stored binary form.
type Template struct {
	Item
	Version int
	Blob    []byte
}

// Snapshot is everything listed in the UI, read in one transaction.
type Snapshot struct {
	Stamp       int64
	Schema      int
	Settings    map[string]string
	Keys        []*Key
	Requests    []*Request
	Certs       []*Cert
	CRLs        []*CRL
	Templates   []*Template
	Revocations []*Revocation
	PGP         []*PGPCert
	Deleted     int // items marked deleted, not listed
}

// DB wraps an open database.
type DB struct {
	SQL    *sql.DB
	Schema int // the "schema" setting: XCA's schema, LockoutSchema for go-ca
	GoCA   int // go-ca's schema ("gca_schema"), 0 for an XCA database
}

// Open wraps an already opened *sql.DB and reads its schema versions.
func Open(ctx context.Context, db *sql.DB) (*DB, error) {
	v, g, err := ReadVersion(ctx, db)
	if err != nil {
		return nil, err
	}
	return &DB{SQL: db, Schema: v, GoCA: g}, nil
}

// ReadVersion returns the "schema" and "gca_schema" settings (0 when
// gca_schema is absent).
func ReadVersion(ctx context.Context, db *sql.DB) (schema, goca int, err error) {
	s, err := querySetting(ctx, db, "schema")
	if err != nil {
		return 0, 0, err
	}
	if schema, err = strconv.Atoi(strings.TrimSpace(s)); err != nil {
		return 0, 0, fmt.Errorf("xdb: invalid schema %q", s)
	}
	if schema != LockoutSchema {
		return schema, 0, nil
	}
	g, err := querySetting(ctx, db, "gca_schema")
	if err != nil {
		return 0, 0, err
	}
	if goca, err = strconv.Atoi(strings.TrimSpace(g)); err != nil || goca < 1 {
		return 0, 0, fmt.Errorf("xdb: invalid gca_schema %q", g)
	}
	return schema, goca, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func querySetting(ctx context.Context, q querier, key string) (string, error) {
	var v sql.NullString
	err := q.QueryRowContext(ctx, "SELECT value FROM settings WHERE key_=?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v.String, err
}

// Setting returns one settings value ("" when absent).
func (d *DB) Setting(ctx context.Context, key string) (string, error) {
	return querySetting(ctx, d.SQL, key)
}

// SetSetting writes one settings value (used for the pwhash upgrade).
func (d *DB) SetSetting(ctx context.Context, key, value string) error {
	return d.Write(ctx, func(tx *Tx) error { return tx.SetSetting(ctx, key, value) })
}

// MaxStamp returns MAX(items.stamp); it changes with every committed
// change to an item.
func (d *DB) MaxStamp(ctx context.Context) (int64, error) {
	var s sql.NullInt64
	err := d.SQL.QueryRowContext(ctx, "SELECT MAX(stamp) FROM items").Scan(&s)
	return s.Int64, err
}

func (d *DB) liveCond(alias string) string {
	if d.Schema < 7 { // items.del arrived with schema 7
		return "1=1"
	}
	return alias + ".del=0"
}

func b64(s sql.NullString) ([]byte, error) {
	if !s.Valid {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s.String), ""))
}

func parseOptTime(s sql.NullString) time.Time {
	if !s.Valid {
		return time.Time{}
	}
	t, _ := ParseTime(s.String)
	return t
}

func scanItem(it *Item, date sql.NullString) {
	it.Date = parseOptTime(date)
}

// Load reads all live objects in one read transaction.
func (d *DB) Load(ctx context.Context) (*Snapshot, error) {
	tx, err := d.SQL.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	s := &Snapshot{Schema: d.Schema, Settings: map[string]string{}}
	steps := []func(context.Context, *sql.Tx, *Snapshot) error{
		d.loadSettings, d.loadKeys, d.loadRequests, d.loadCerts, d.loadCRLs, d.loadTemplates, d.loadRevocations, d.loadPGP, d.loadMeta,
	}
	for _, f := range steps {
		if err := f(ctx, tx, s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

const itemCols = "i.id, i.name, i.type, i.source, i.date, i.comment, i.stamp"

func scanItemCols(it *Item, date, comment *sql.NullString) []any {
	return []any{&it.ID, &it.Name, &it.Type, &it.Source, date, comment, &it.Stamp}
}

func (d *DB) loadSettings(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, "SELECT key_, value FROM settings")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var v sql.NullString
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		s.Settings[k] = v.String
	}
	return rows.Err()
}

func (d *DB) loadKeys(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+itemCols+`, k.type, k.len, k.hash, k."public",
		p.ownPass, p.item IS NOT NULL, t.item IS NOT NULL
		FROM public_keys k JOIN items i ON i.id = k.item
		LEFT JOIN private_keys p ON p.item = k.item
		LEFT JOIN tokens t ON t.item = k.item
		WHERE `+d.liveCond("i")+` ORDER BY i.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		k := &Key{}
		var date, comment, typ, pub sql.NullString
		var length, hash, own sql.NullInt64
		dest := append(scanItemCols(&k.Item, &date, &comment), &typ, &length, &hash, &pub, &own, &k.HasPrivate, &k.Token)
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		scanItem(&k.Item, date)
		k.Comment = strings.TrimRight(comment.String, "\n")
		k.KeyType = strings.TrimSpace(typ.String)
		k.Len, k.Hash, k.OwnPass = int(length.Int64), hash.Int64, int(own.Int64)
		if k.Public, err = b64(pub); err != nil {
			return fmt.Errorf("key %d: %w", k.ID, err)
		}
		s.Keys = append(s.Keys, k)
	}
	return rows.Err()
}

func (d *DB) loadRequests(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+itemCols+`, r.hash, r.signed, r.request, x.pkey
		FROM requests r JOIN items i ON i.id = r.item
		LEFT JOIN x509super x ON x.item = r.item
		WHERE `+d.liveCond("i")+` ORDER BY i.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		r := &Request{}
		var date, comment, der sql.NullString
		var hash, signed, pkey sql.NullInt64
		dest := append(scanItemCols(&r.Item, &date, &comment), &hash, &signed, &der, &pkey)
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		scanItem(&r.Item, date)
		r.Comment = strings.TrimRight(comment.String, "\n")
		r.Hash, r.Signed, r.KeyID = hash.Int64, signed.Int64 != 0, pkey.Int64
		if r.DER, err = b64(der); err != nil {
			return fmt.Errorf("request %d: %w", r.ID, err)
		}
		s.Requests = append(s.Requests, r)
	}
	return rows.Err()
}

func (d *DB) loadCerts(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+itemCols+`, c.hash, c.iss_hash, c.serial, c.issuer, c.ca, c.cert,
		x.pkey, a.item IS NOT NULL, a.template, a.crlExpire, a.crlNo, a.crlDays, a.dnPolicy
		FROM certs c JOIN items i ON i.id = c.item
		LEFT JOIN x509super x ON x.item = c.item
		LEFT JOIN authority a ON a.item = c.item
		WHERE `+d.liveCond("i")+` ORDER BY i.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		c := &Cert{}
		var date, comment, serial, der, crlExpire, dnPolicy sql.NullString
		var hash, issHash, issuer, ca, pkey, tmpl, crlNo, crlDays sql.NullInt64
		var hasAuth bool
		dest := append(scanItemCols(&c.Item, &date, &comment), &hash, &issHash, &serial, &issuer, &ca, &der,
			&pkey, &hasAuth, &tmpl, &crlExpire, &crlNo, &crlDays, &dnPolicy)
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		scanItem(&c.Item, date)
		c.Comment = strings.TrimRight(comment.String, "\n")
		c.Hash, c.IssHash, c.Serial = hash.Int64, issHash.Int64, serial.String
		c.IssuerID, c.CA, c.KeyID = issuer.Int64, ca.Int64 != 0, pkey.Int64
		if c.DER, err = b64(der); err != nil {
			return fmt.Errorf("certificate %d: %w", c.ID, err)
		}
		if hasAuth {
			c.Authority = &Authority{TemplateID: tmpl.Int64, CRLExpire: parseOptTime(crlExpire),
				CRLNo: crlNo.Int64, CRLDays: int(crlDays.Int64), DNPolicy: dnPolicy.String}
		}
		s.Certs = append(s.Certs, c)
	}
	return rows.Err()
}

func (d *DB) loadCRLs(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+itemCols+`, c.hash, c.num, c.iss_hash, c.issuer, c.crl
		FROM crls c JOIN items i ON i.id = c.item
		WHERE `+d.liveCond("i")+` ORDER BY i.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		c := &CRL{}
		var date, comment, der sql.NullString
		var hash, num, issHash, issuer sql.NullInt64
		dest := append(scanItemCols(&c.Item, &date, &comment), &hash, &num, &issHash, &issuer, &der)
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		scanItem(&c.Item, date)
		c.Comment = strings.TrimRight(comment.String, "\n")
		c.Hash, c.Num, c.IssHash, c.IssuerID = hash.Int64, num.Int64, issHash.Int64, issuer.Int64
		if c.DER, err = b64(der); err != nil {
			return fmt.Errorf("crl %d: %w", c.ID, err)
		}
		s.CRLs = append(s.CRLs, c)
	}
	return rows.Err()
}

func (d *DB) loadTemplates(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+itemCols+`, t.version, t.template
		FROM templates t JOIN items i ON i.id = t.item
		WHERE `+d.liveCond("i")+` ORDER BY i.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		t := &Template{}
		var date, comment, blob sql.NullString
		var version sql.NullInt64
		dest := append(scanItemCols(&t.Item, &date, &comment), &version, &blob)
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		scanItem(&t.Item, date)
		t.Comment = strings.TrimRight(comment.String, "\n")
		t.Version = int(version.Int64)
		if t.Blob, err = b64(blob); err != nil {
			return fmt.Errorf("template %d: %w", t.ID, err)
		}
		s.Templates = append(s.Templates, t)
	}
	return rows.Err()
}

func (d *DB) loadRevocations(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT caId, serial, date, invaldate, crlNo, reasonBit FROM revocations ORDER BY caId, serial`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		r := &Revocation{}
		var serial, date, inval sql.NullString
		var caID, crlNo, reason sql.NullInt64
		if err := rows.Scan(&caID, &serial, &date, &inval, &crlNo, &reason); err != nil {
			return err
		}
		r.CAID, r.Serial, r.CRLNo, r.ReasonBit = caID.Int64, serial.String, crlNo.Int64, int(reason.Int64)
		r.Date, r.InvalDate = parseOptTime(date), parseOptTime(inval)
		s.Revocations = append(s.Revocations, r)
	}
	return rows.Err()
}

func (d *DB) loadMeta(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(stamp), 0) FROM items").Scan(&s.Stamp); err != nil {
		return err
	}
	if d.Schema >= 7 {
		return tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM items WHERE del<>0").Scan(&s.Deleted)
	}
	return nil
}

// PrivateKey returns the stored, encrypted private key blob and its ownPass.
func (d *DB) PrivateKey(ctx context.Context, keyID int64) (blob []byte, ownPass int, err error) {
	var priv sql.NullString
	err = d.SQL.QueryRowContext(ctx, "SELECT private, ownPass FROM private_keys WHERE item=?", keyID).Scan(&priv, &ownPass)
	if err != nil {
		return nil, 0, err
	}
	blob, err = b64(priv)
	return blob, ownPass, err
}

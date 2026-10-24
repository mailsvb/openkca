package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mailsvb/openkca/internal/tmpl"
)

// Item types.
const (
	TypeKey      = 1
	TypeRequest  = 2
	TypeCert     = 3
	TypeCRL      = 4
	TypeTemplate = 5
)

var typeNames = map[int]string{TypeKey: "key", TypeRequest: "request", TypeCert: "cert", TypeCRL: "crl", TypeTemplate: "template"}

// TypeName returns the stored name of an item type ("key", "cert", ...).
func TypeName(t int) string { return typeNames[t] }

func typeOf(name string) int {
	for t, n := range typeNames {
		if n == name {
			return t
		}
	}
	return 0
}

// Item sources.
const (
	SourceUnknown     = 0
	SourceImported    = 1
	SourceGenerated   = 2
	SourceTransformed = 3
	SourceToken       = 4
	SourceLegacyDB    = 5
	SourceRenewed     = 6
)

var sourceNames = map[int]string{
	SourceUnknown: "unknown", SourceImported: "imported", SourceGenerated: "generated", SourceTransformed: "transformed",
	SourceToken: "token", SourceLegacyDB: "legacy_db", SourceRenewed: "renewed",
}

// SourceName returns the stored name of an item source.
func SourceName(s int) string {
	if n, ok := sourceNames[s]; ok {
		return n
	}
	return "unknown"
}

func sourceOf(name string) int {
	for s, n := range sourceNames {
		if n == name {
			return s
		}
	}
	return SourceUnknown
}

// Protection of a private key (keys.protection).
const (
	ProtNone     = 0 // public key only
	ProtDEK      = 1 // sealed with the database's DEK
	ProtPassword = 2 // the key's own password
	ProtToken    = 3 // on a security token, not stored
)

var protNames = map[int]string{ProtDEK: "dek", ProtPassword: "password", ProtToken: "token"}

func protOf(s sql.NullString) int {
	for p, n := range protNames {
		if n == s.String {
			return p
		}
	}
	return ProtNone
}

func protValue(p int) any {
	if n, ok := protNames[p]; ok {
		return n
	}
	return nil
}

// sealedMagic starts a key sealed by package vault; any other blob of a
// key with its own password is still in one of XCA's forms.
var sealedMagic = []byte{'G', 'C', 'K', 1}

const timeLayout = time.RFC3339

func fmtTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(timeLayout) }

func optTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return fmtTime(t)
}

func parseTime(s sql.NullString) time.Time {
	if !s.Valid {
		return time.Time{}
	}
	t, _ := time.Parse(timeLayout, s.String)
	return t
}

// Fingerprint is the SHA-256 of a DER object, as stored.
func Fingerprint(der []byte) []byte {
	h := sha256.Sum256(der)
	return h[:]
}

// Item is one row of the items table.
type Item struct {
	ID      int64  // row ID, links rows inside the database
	UUID    string // the item's identity outside the database; never changes
	Name    string
	Type    int
	Source  int
	Date    time.Time
	Comment string
	Stamp   int64
	Trashed time.Time // zero while not in the trash
}

// Key is a public key, with information about its private part.
type Key struct {
	Item
	KeyType    string // algorithm, e.g. RSA, EC, ED25519, ML-DSA
	Len        int
	Public     []byte // DER SubjectPublicKeyInfo
	HasPrivate bool
	Protection int
	Token      bool // the private key is on a security token
	Legacy     bool // a key with its own password still in an XCA form
}

// Revocation is a row of the revocations table.
type Revocation struct {
	CAID      int64
	Serial    string // upper case hex
	Date      time.Time
	InvalDate time.Time // zero = none
	CRLNo     int64
	ReasonBit int
	// Expires is when the revoked certificate expires: from the
	// certificate when it is in the database (live or in the trash), else
	// as recorded at revocation time; zero when the certificate is unknown.
	Expires   time.Time
	CertKnown bool // the certificate is in the database (live or in the trash)
}

// CRLGrace is how long a revocation stays on the CRL after its
// certificate expired.
const CRLGrace = 30 * 24 * time.Hour

// OnCRL reports whether the revocation is published on the CA's CRL at
// now: its certificate is known (in the database, or its expiry was
// recorded when it was revoked) and expired at most CRLGrace ago.
func (r *Revocation) OnCRL(now time.Time) bool {
	return !r.Expires.IsZero() && !now.After(r.Expires.Add(CRLGrace))
}

// Authority holds a CA's bookkeeping.
type Authority struct {
	UUID       string    // authority ID: names the CA's folder, kept across renewals
	TemplateID int64     // 0 = none
	CRLExpire  time.Time // next update of the last CRL, zero = no CRL yet
	CRLNo      int64
	CRLDays    int
	DNPolicy   string
}

// Cert is a certificate.
type Cert struct {
	Item
	Serial    string
	IssuerID  int64 // 0 = unknown issuer (or in the trash)
	CA        bool
	DER       []byte
	KeyID     int64 // 0 = no key in the database
	Authority *Authority
}

// Request is a PKCS#10 certificate signing request.
type Request struct {
	Item
	Signed bool
	DER    []byte
	KeyID  int64
}

// CRL is a certificate revocation list.
type CRL struct {
	Item
	Num      int64
	IssuerID int64
	DER      []byte
}

// Template is a certificate template.
type Template struct {
	Item
	Data *tmpl.Template
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
	Trashed     int // items in the trash, not listed
}

// DB wraps an open go-ca database.
type DB struct {
	SQL *sql.DB
}

// Open wraps an already opened *sql.DB of a current go-ca database.
func Open(ctx context.Context, db *sql.DB) (*DB, error) {
	s, own, err := ReadSchema(ctx, db)
	if err != nil {
		return nil, err
	}
	if !own || s != Schema {
		return nil, fmt.Errorf("db: not a go-ca database of schema %d", Schema)
	}
	return &DB{SQL: db}, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func querySetting(ctx context.Context, q querier, key string) (string, error) {
	var v string
	err := q.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// Setting returns one settings value ("" when absent).
func (d *DB) Setting(ctx context.Context, key string) (string, error) {
	return querySetting(ctx, d.SQL, key)
}

// SetSetting writes one settings value.
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

// Load reads all live objects in one read transaction. References to
// items in the trash read as 0.
func (d *DB) Load(ctx context.Context) (*Snapshot, error) {
	tx, err := d.SQL.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	s := &Snapshot{Schema: Schema, Settings: map[string]string{}}
	steps := []func(context.Context, *sql.Tx, *Snapshot) error{
		loadSettings, loadKeys, loadRequests, loadCerts, loadCRLs, loadTemplates, loadRevocations, loadPGP, loadMeta,
	}
	for _, f := range steps {
		if err := f(ctx, tx, s); err != nil {
			return nil, err
		}
	}
	return s, nil
}

const itemCols = "i.id, i.uuid, i.name, i.type, i.source, i.created, i.comment, i.stamp, i.trashed"

func itemDest(it *Item, typ, source, created, trashed *sql.NullString) []any {
	return []any{&it.ID, &it.UUID, &it.Name, typ, source, created, &it.Comment, &it.Stamp, trashed}
}

func finishItem(it *Item, typ, source, created, trashed sql.NullString) {
	it.Type, it.Source = typeOf(typ.String), sourceOf(source.String)
	it.Date, it.Trashed = parseTime(created), parseTime(trashed)
	it.Comment = strings.TrimRight(it.Comment, "\n")
}

// live joins a link column to its target when that is not in the trash.
func live(alias, col string) string {
	return fmt.Sprintf("LEFT JOIN items %s ON %s.id = %s AND %s.trashed IS NULL", alias, alias, col, alias)
}

func loadSettings(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, "SELECT key, value FROM settings")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		s.Settings[k] = v
	}
	return rows.Err()
}

func loadKeys(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+itemCols+`, k.algorithm, k.bits, k.spki, k.protection,
		k.private IS NOT NULL, k.protection = 'password' AND substr(k.private, 1, 4) <> ?
		FROM keys k JOIN items i ON i.id = k.item WHERE i.trashed IS NULL ORDER BY i.id`, sealedMagic)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		k := &Key{}
		var typ, source, created, trashed, prot sql.NullString
		var legacy sql.NullBool
		dest := append(itemDest(&k.Item, &typ, &source, &created, &trashed), &k.KeyType, &k.Len, &k.Public, &prot,
			&k.HasPrivate, &legacy)
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		finishItem(&k.Item, typ, source, created, trashed)
		k.Protection = protOf(prot)
		k.Token = k.Protection == ProtToken
		k.Legacy = legacy.Bool
		s.Keys = append(s.Keys, k)
	}
	return rows.Err()
}

func loadRequests(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+itemCols+`, r.signed, r.der, lk.id
		FROM requests r JOIN items i ON i.id = r.item `+live("lk", "r.key")+`
		WHERE i.trashed IS NULL ORDER BY i.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		r := &Request{}
		var typ, source, created, trashed sql.NullString
		var key sql.NullInt64
		dest := append(itemDest(&r.Item, &typ, &source, &created, &trashed), &r.Signed, &r.DER, &key)
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		finishItem(&r.Item, typ, source, created, trashed)
		r.KeyID = key.Int64
		s.Requests = append(s.Requests, r)
	}
	return rows.Err()
}

func loadCerts(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+itemCols+`, c.serial, li.id, c.ca, c.der, lk.id,
		a.cert IS NOT NULL, a.uuid, lt.id, a.crl_next, a.crl_number, a.crl_days, a.dn_policy
		FROM certs c JOIN items i ON i.id = c.item
		`+live("li", "c.issuer")+` `+live("lk", "c.key")+`
		LEFT JOIN authorities a ON a.cert = c.item `+live("lt", "a.template")+`
		WHERE i.trashed IS NULL ORDER BY i.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		c := &Cert{}
		var typ, source, created, trashed, authUUID, crlNext, dnPolicy sql.NullString
		var issuer, key, tmplID, crlNo, crlDays sql.NullInt64
		var hasAuth bool
		dest := append(itemDest(&c.Item, &typ, &source, &created, &trashed), &c.Serial, &issuer, &c.CA, &c.DER, &key,
			&hasAuth, &authUUID, &tmplID, &crlNext, &crlNo, &crlDays, &dnPolicy)
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		finishItem(&c.Item, typ, source, created, trashed)
		c.IssuerID, c.KeyID = issuer.Int64, key.Int64
		if hasAuth {
			c.Authority = &Authority{UUID: authUUID.String, TemplateID: tmplID.Int64, CRLExpire: parseTime(crlNext), CRLNo: crlNo.Int64,
				CRLDays: int(crlDays.Int64), DNPolicy: dnPolicy.String}
		}
		s.Certs = append(s.Certs, c)
	}
	return rows.Err()
}

func loadCRLs(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+itemCols+`, l.number, li.id, l.der
		FROM crls l JOIN items i ON i.id = l.item `+live("li", "l.issuer")+`
		WHERE i.trashed IS NULL ORDER BY i.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		c := &CRL{}
		var typ, source, created, trashed sql.NullString
		var issuer sql.NullInt64
		dest := append(itemDest(&c.Item, &typ, &source, &created, &trashed), &c.Num, &issuer, &c.DER)
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		finishItem(&c.Item, typ, source, created, trashed)
		c.IssuerID = issuer.Int64
		s.CRLs = append(s.CRLs, c)
	}
	return rows.Err()
}

func loadTemplates(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT `+itemCols+`, t.data
		FROM templates t JOIN items i ON i.id = t.item WHERE i.trashed IS NULL ORDER BY i.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		t := &Template{}
		var typ, source, created, trashed sql.NullString
		var data string
		dest := append(itemDest(&t.Item, &typ, &source, &created, &trashed), &data)
		if err := rows.Scan(dest...); err != nil {
			return err
		}
		finishItem(&t.Item, typ, source, created, trashed)
		if t.Data, err = decodeTemplate(data); err != nil {
			return fmt.Errorf("template %d: %w", t.ID, err)
		}
		s.Templates = append(s.Templates, t)
	}
	return rows.Err()
}

func loadRevocations(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT r.ca, r.serial, r.date, r.invalidity, r.crl_number, r.reason,
		r.expires, `+certExpirySQL+`
		FROM revocations r JOIN items i ON i.id = r.ca WHERE i.trashed IS NULL ORDER BY r.ca, r.serial`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		r := &Revocation{}
		var date, inval, expires, certExpiry sql.NullString
		var crlNo sql.NullInt64
		if err := rows.Scan(&r.CAID, &r.Serial, &date, &inval, &crlNo, &r.ReasonBit, &expires, &certExpiry); err != nil {
			return err
		}
		r.CRLNo, r.Date, r.InvalDate = crlNo.Int64, parseTime(date), parseTime(inval)
		r.CertKnown = certExpiry.Valid
		if r.Expires = parseTime(certExpiry); r.Expires.IsZero() {
			r.Expires = parseTime(expires)
		}
		s.Revocations = append(s.Revocations, r)
	}
	return rows.Err()
}

func loadMeta(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(stamp), 0) FROM items").Scan(&s.Stamp); err != nil {
		return err
	}
	return tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM items WHERE trashed IS NOT NULL").Scan(&s.Trashed)
}

// templateJSON is a template as stored: the subject as DER and XCA's
// template settings, which the editor and the .xca export understand.
type templateJSON struct {
	Subject  []byte            `json:"subject"`
	Settings map[string]string `json:"settings"`
}

func encodeTemplate(t *tmpl.Template) (string, error) {
	j := templateJSON{Subject: t.Subject, Settings: t.Settings}
	if j.Settings == nil {
		j.Settings = map[string]string{}
	}
	b, err := json.Marshal(j)
	return string(b), err
}

func decodeTemplate(s string) (*tmpl.Template, error) {
	var j templateJSON
	if err := json.Unmarshal([]byte(s), &j); err != nil {
		return nil, err
	}
	if j.Settings == nil {
		j.Settings = map[string]string{}
	}
	return &tmpl.Template{Subject: j.Subject, Settings: j.Settings}, nil
}

// StoredKey is a private key row with its public key.
type StoredKey struct {
	Blob       []byte
	Protection int
	Public     []byte // DER SubjectPublicKeyInfo
	KeyType    string
}

// StoredPrivateKey returns the stored private key of a key item, also of
// one in the trash.
func (d *DB) StoredPrivateKey(ctx context.Context, keyID int64) (*StoredKey, error) {
	var k StoredKey
	var prot sql.NullString
	err := d.SQL.QueryRowContext(ctx, `SELECT private, protection, spki, algorithm FROM keys
		WHERE item=? AND private IS NOT NULL`, keyID).Scan(&k.Blob, &prot, &k.Public, &k.KeyType)
	if err != nil {
		return nil, err
	}
	k.Protection = protOf(prot)
	return &k, nil
}

// PrivateKeyRow is one stored private key.
type PrivateKeyRow struct {
	ID         int64
	KeyType    string
	Protection int
	Blob       []byte
	Public     []byte
	Trashed    bool
}

// PrivateKeyRows returns every stored private key, also of keys in the
// trash.
func (d *DB) PrivateKeyRows(ctx context.Context) ([]PrivateKeyRow, error) {
	rows, err := d.SQL.QueryContext(ctx, `SELECT k.item, k.algorithm, k.protection, k.private, k.spki, i.trashed IS NOT NULL
		FROM keys k JOIN items i ON i.id = k.item WHERE k.private IS NOT NULL ORDER BY k.item`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PrivateKeyRow
	for rows.Next() {
		var r PrivateKeyRow
		var prot sql.NullString
		if err := rows.Scan(&r.ID, &r.KeyType, &prot, &r.Blob, &r.Public, &r.Trashed); err != nil {
			return nil, err
		}
		r.Protection = protOf(prot)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Trash lists the items in the trash, most recently trashed first.
func (d *DB) Trash(ctx context.Context) ([]Item, error) {
	rows, err := d.SQL.QueryContext(ctx, `SELECT `+itemCols+` FROM items i WHERE i.trashed IS NOT NULL
		ORDER BY i.trashed DESC, i.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		var typ, source, created, trashed sql.NullString
		if err := rows.Scan(itemDest(&it, &typ, &source, &created, &trashed)...); err != nil {
			return nil, err
		}
		finishItem(&it, typ, source, created, trashed)
		out = append(out, it)
	}
	return out, rows.Err()
}

// Counts returns the number of items per type, trash included (used to
// verify an import).
func (d *DB) Counts(ctx context.Context) (map[int]int, error) {
	rows, err := d.SQL.QueryContext(ctx, "SELECT type, COUNT(*) FROM items GROUP BY type")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[typeOf(t)] = n
	}
	return out, rows.Err()
}

// PrivateKey returns the stored private key blob of a key item and its
// protection.
func (d *DB) PrivateKey(ctx context.Context, keyID int64) ([]byte, int, error) {
	k, err := d.StoredPrivateKey(ctx, keyID)
	if err != nil {
		return nil, 0, err
	}
	return k.Blob, k.Protection, nil
}

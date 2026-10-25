// Package xcaimport reads XCA databases (.xdb, schema 5 to 8) and writes
// their content into a new OpenKCA database. It is the only package that knows
// XCA's schema; the source file is only ever opened read-only.
//
// Item IDs are kept, so every link (issuer, key, CA template, revocation)
// carries over. Items XCA marked deleted go to the trash. Keys under the
// database password (or XCA's "Bogus" password) are decrypted and sealed
// with a new DEK. Keys with their own password keep their blob until that
// password opens them.
package xcaimport

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/tmpl"
	"github.com/mailsvb/openkca/internal/vault"
	"github.com/mailsvb/openkca/internal/xdbpass"
)

// XCA's schema versions this package reads.
const (
	MinSchema = 5
	MaxSchema = 8
)

// XCA's item types and password types.
const (
	xcaKey      = 1
	xcaRequest  = 2
	xcaCert     = 3
	xcaCRL      = 4
	xcaTemplate = 5

	passCommon  = 0
	passPrivate = 1
	passBogus   = 2
	passPIN     = 3
)

// xcaTime is the CHAR(15) GeneralizedTime XCA stores dates in;
// "99991231235959Z" means "none".
const xcaTime = "20060102150405Z"

func parseXCATime(s sql.NullString) time.Time {
	if !s.Valid {
		return time.Time{}
	}
	t, err := time.Parse(xcaTime, strings.TrimSpace(s.String))
	if err != nil || t.Year() >= 9999 {
		return time.Time{}
	}
	return t
}

var legacyMagic = []byte{0xca, 0xdb, 0x19, 0x69}

// Kind is what Inspect found.
type Kind string

const (
	KindXCA    Kind = "xca"    // an XCA database this package reads
	KindOld    Kind = "old"    // XCA schema below 5
	KindNewer  Kind = "newer"  // a newer XCA schema
	KindLegacy Kind = "legacy" // pre-2.0 XCA binary format
)

// Info describes a source file.
type Info struct {
	Kind   Kind
	Schema int // XCA's schema
}

// Importable reports whether Import reads the file.
func (i Info) Importable() bool { return i.Kind == KindXCA }

func dsn(path string) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Set("mode", "ro")
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
}

// Inspect classifies an .xdb file. deep runs PRAGMA integrity_check instead
// of quick_check.
func Inspect(ctx context.Context, path string, deep bool) (Info, error) {
	var info Info
	f, err := os.Open(path)
	if err != nil {
		return info, err
	}
	head := make([]byte, 16)
	n, _ := io.ReadFull(f, head)
	f.Close()
	if bytes.HasPrefix(head[:n], legacyMagic) {
		info.Kind = KindLegacy
		return info, nil
	}
	if string(head[:n]) != "SQLite format 3\x00" {
		return info, errors.New("not an SQLite database")
	}
	xdb, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return info, err
	}
	defer xdb.Close()
	check := "PRAGMA quick_check"
	if deep {
		check = "PRAGMA integrity_check"
	}
	var res string
	if err := xdb.QueryRowContext(ctx, check).Scan(&res); err != nil {
		return info, err
	}
	if res != "ok" {
		return info, errors.New("integrity check: " + res)
	}
	s, err := setting(ctx, xdb, "schema")
	if err != nil || s == "" {
		return info, errors.New("no schema setting")
	}
	if info.Schema, err = strconv.Atoi(strings.TrimSpace(s)); err != nil {
		return info, errors.New("invalid schema setting")
	}
	switch {
	case info.Schema > MaxSchema:
		info.Kind = KindNewer
	case info.Schema < MinSchema:
		info.Kind = KindOld
	default:
		info.Kind = KindXCA
	}
	if info.Importable() {
		if pw, _ := setting(ctx, xdb, "pwhash"); pw == "" {
			return info, errors.New("no password hash")
		}
	}
	return info, nil
}

func setting(ctx context.Context, xdb *sql.DB, key string) (string, error) {
	var v sql.NullString
	err := xdb.QueryRowContext(ctx, "SELECT value FROM settings WHERE key_=?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v.String, err
}

// Source is an open source database.
type Source struct {
	Info
	xdb *sql.DB
}

// Open opens an importable .xdb file read-only.
func Open(ctx context.Context, path string) (*Source, error) {
	info, err := Inspect(ctx, path, false)
	if err != nil {
		return nil, err
	}
	if !info.Importable() {
		return nil, fmt.Errorf("xcaimport: %s cannot be imported (%s)", path, info.Kind)
	}
	xdb, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	xdb.SetMaxOpenConns(1)
	return &Source{Info: info, xdb: xdb}, nil
}

// Close closes the source.
func (s *Source) Close() error { return s.xdb.Close() }

// Unlock checks the database password; a wrong password returns false.
func (s *Source) Unlock(ctx context.Context, password []byte) (bool, error) {
	stored, err := setting(ctx, s.xdb, "pwhash")
	if err != nil {
		return false, err
	}
	ok, _ := xdbpass.Verify(stored, password)
	return ok, nil
}

// Report says what Import did.
type Report struct {
	Items         int // items written
	Trashed       int // items XCA had marked deleted, now in the trash
	Skipped       []string
	Converted     int // keys sealed with the DEK
	OwnPassLegacy int // keys with their own password still in an XCA form
	Unopened      int // keys for the database password that it did not open
}

// Progress is called while keys are decrypted.
type Progress func(done, total int)

func b64(s sql.NullString) ([]byte, error) {
	if !s.Valid {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s.String), ""))
}

// internal settings that do not carry over
var dropSettings = map[string]bool{"schema": true, "pwhash": true, "legacy-keys-updated": true,
	// OpenKCA's own key settings never come from the source file.
	"kdf": true, "dek": true, db.SettingArgon2id: true, db.SettingWebAuthnUser: true}

// upgradeDefaults maps options still at XCA's default to OpenKCA's:
// {XCA default, OpenKCA default}.
var upgradeDefaults = map[string][2]string{
	"default_hash": {"sha256", "auto"},
	"serial_len":   {"64", "128"},
}

// DefaultPasswordLabel names the password a database is created with.
const DefaultPasswordLabel = "Password"

// PasswordMethod wraps the keyring's data key with password at cost p as
// the first unlock method of a new database.
func PasswordMethod(kr *vault.Keyring, password []byte, p vault.Params) (db.UnlockMethod, error) {
	id, err := db.NewUUID()
	if err != nil {
		return db.UnlockMethod{}, err
	}
	kdf, wrapped, err := kr.WrapSlot(id, vault.SlotPassword, password, p)
	if err != nil {
		return db.UnlockMethod{}, err
	}
	return db.UnlockMethod{UUID: id, Type: vault.SlotPassword, Label: DefaultPasswordLabel, KDF: kdf, Wrapped: wrapped}, nil
}

// Import writes the source's content into dst, an empty database, with
// password (already checked with Unlock) protecting a new keyring of cost
// p, and settings added to the copied options. It returns the keyring of
// the new database.
func (s *Source) Import(ctx context.Context, dst *sql.DB, password []byte, p vault.Params,
	extra map[string]string, progress Progress) (*vault.Keyring, Report, error) {
	var rep Report
	items, err := s.read(ctx)
	if err != nil {
		return nil, rep, err
	}
	kr := vault.NewKeyring(p)
	fail := func(err error) (*vault.Keyring, Report, error) {
		kr.Wipe()
		return nil, rep, err
	}
	settings := map[string]string{}
	rows, err := s.xdb.QueryContext(ctx, "SELECT key_, value FROM settings")
	if err != nil {
		return fail(err)
	}
	for rows.Next() {
		var k string
		var v sql.NullString
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return fail(err)
		}
		if !dropSettings[strings.TrimSpace(k)] {
			settings[strings.TrimSpace(k)] = v.String
		}
	}
	rows.Close()
	// XCA's defaults give way to OpenKCA's; deliberate other values stay.
	for k, xcaDefault := range upgradeDefaults {
		if settings[k] == xcaDefault[0] {
			settings[k] = xcaDefault[1]
		}
	}
	for k, v := range extra {
		settings[k] = v
	}
	method, err := PasswordMethod(kr, password, p)
	if err != nil {
		return fail(err)
	}
	settings[db.SettingArgon2id] = vault.FormatCost(p)

	// Keys first: decrypting is the slow part.
	total := 0
	for _, it := range items.keys {
		if it.own == passCommon || it.own == passBogus {
			total++
		}
	}
	done := 0
	for _, it := range items.keys {
		k := it.raw.Key
		switch it.own {
		case -1: // public key only
		case passPIN:
			k.Protection = db.ProtToken
		case passPrivate:
			k.Protection, k.Private = db.ProtPassword, it.blob
			if !vault.IsSealed(it.blob) {
				rep.OwnPassLegacy++
			}
		default:
			pw := password
			if it.own == passBogus {
				pw = []byte("Bogus")
			}
			der, err := legacyDER(it.blob, it.xcaType, pw)
			done++
			if progress != nil {
				progress(done, total)
			}
			if err != nil {
				// keep it, for whoever knows its password
				k.Protection, k.Private = db.ProtPassword, it.blob
				rep.Unopened++
				break
			}
			sealed, err := kr.Seal(der, k.SPKI)
			clear(der)
			if err != nil {
				return fail(err)
			}
			k.Protection, k.Private = db.ProtDEK, sealed
			rep.Converted++
		}
	}
	if progress != nil {
		progress(total, total)
	}
	err = db.Create(ctx, dst, settings, []db.UnlockMethod{method}, func(tx *db.Tx) error {
		all := make([]db.RawItem, 0, len(items.all))
		for _, it := range items.keys {
			all = append(all, it.raw)
		}
		all = append(all, items.all...)
		for _, r := range all {
			if err := tx.PutRaw(ctx, r); err != nil {
				return err
			}
			rep.Items++
			if !r.Trashed.IsZero() {
				rep.Trashed++
			}
		}
		for _, r := range items.revocations {
			if err := tx.PutRevocation(ctx, r); err != nil {
				return err
			}
		}
		return tx.Audit(ctx, "database.import", 0, fmt.Sprintf("from XCA schema %d: %d items, %d keys converted",
			s.Schema, rep.Items, rep.Converted))
	})
	if err != nil {
		return fail(err)
	}
	rep.Skipped = items.skipped
	return kr, rep, nil
}

// legacyDER decrypts a key in one of XCA's forms to an unencrypted PKCS#8
// PrivateKeyInfo.
func legacyDER(blob []byte, keyType string, password []byte) ([]byte, error) {
	if pki.IsEncryptedPKCS8(blob) {
		return pki.DecryptPKCS8(blob, password)
	}
	key, _, err := pki.DecryptPrivateKey(blob, keyType, password)
	if err != nil {
		return nil, err
	}
	return pki.MarshalPKCS8(key)
}

type keyItem struct {
	raw     db.RawItem
	own     int // XCA's ownPass, -1 without a private key
	blob    []byte
	xcaType string
}

type contents struct {
	keys        []keyItem
	all         []db.RawItem // everything but keys
	revocations []db.Revocation
	skipped     []string
}

func (s *Source) hasTable(ctx context.Context, name string) bool {
	var n int
	s.xdb.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n)
	return n > 0
}

// read loads every item, keeping only links to items of the right type.
func (s *Source) read(ctx context.Context) (*contents, error) {
	c := &contents{}
	del := "0"
	if s.Schema >= 7 {
		del = "i.del"
	}
	now := time.Now()
	types := map[int64]int{}
	base := map[int64]db.Item{}
	rows, err := s.xdb.QueryContext(ctx, "SELECT i.id, i.name, i.type, i.source, i.date, i.comment, "+del+" FROM items i ORDER BY i.id")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var it db.Item
		var name, date, comment sql.NullString
		var typ, source, deleted sql.NullInt64
		if err := rows.Scan(&it.ID, &name, &typ, &source, &date, &comment, &deleted); err != nil {
			rows.Close()
			return nil, err
		}
		it.Name, it.Type, it.Source = name.String, int(typ.Int64), int(source.Int64)
		it.Comment = strings.TrimRight(comment.String, "\n")
		if it.Date = parseXCATime(date); it.Date.IsZero() {
			it.Date = now
		}
		if deleted.Int64 != 0 {
			it.Trashed = now
		}
		if it.Type >= xcaKey && it.Type <= xcaTemplate {
			types[it.ID] = it.Type
			base[it.ID] = it
		}
	}
	rows.Close()
	ref := func(id sql.NullInt64, want int) int64 {
		if id.Valid && types[id.Int64] == want {
			return id.Int64
		}
		return 0
	}
	skip := func(id int64, what string, err error) {
		c.skipped = append(c.skipped, fmt.Sprintf("%s %d (%s): %v", what, id, base[id].Name, err))
		delete(types, id)
	}

	// Keys
	tokens := map[int64]bool{}
	if s.hasTable(ctx, "tokens") {
		trows, err := s.xdb.QueryContext(ctx, "SELECT item FROM tokens")
		if err != nil {
			return nil, err
		}
		for trows.Next() {
			var id int64
			trows.Scan(&id)
			tokens[id] = true
		}
		trows.Close()
	}
	rows, err = s.xdb.QueryContext(ctx, `SELECT k.item, k.type, k."public", p.ownPass, p.private, p.item IS NOT NULL
		FROM public_keys k LEFT JOIN private_keys p ON p.item = k.item ORDER BY k.item`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var typ, pub, priv sql.NullString
		var own sql.NullInt64
		var hasPriv bool
		if err := rows.Scan(&id, &typ, &pub, &own, &priv, &hasPriv); err != nil {
			rows.Close()
			return nil, err
		}
		if types[id] != xcaKey {
			continue
		}
		spki, err := b64(pub)
		if err == nil {
			_, err = pki.ParsePublicKey(spki)
		}
		if err != nil {
			skip(id, "key", err)
			continue
		}
		code, bits := pki.StoredKeyType(spki)
		ki := keyItem{raw: db.RawItem{Item: base[id], Key: &db.RawKey{Algorithm: pki.KeyTypeText(code), Bits: bits, SPKI: spki}},
			own: -1, xcaType: strings.TrimSpace(typ.String)}
		switch {
		case tokens[id] || own.Int64 == passPIN:
			ki.own = passPIN
		case hasPriv:
			if ki.blob, err = b64(priv); err != nil || len(ki.blob) == 0 {
				skip(id, "key", fmt.Errorf("private key: %v", err))
				continue
			}
			ki.own = int(own.Int64)
		}
		ki.raw.Type = db.TypeKey
		c.keys = append(c.keys, ki)
	}
	rows.Close()

	// Templates
	rows, err = s.xdb.QueryContext(ctx, "SELECT item, version, template FROM templates ORDER BY item")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var version sql.NullInt64
		var blob sql.NullString
		if err := rows.Scan(&id, &version, &blob); err != nil {
			rows.Close()
			return nil, err
		}
		if types[id] != xcaTemplate {
			continue
		}
		b, err := b64(blob)
		var t *tmpl.Template
		if err == nil {
			t, err = tmpl.Decode(b, int(version.Int64))
		}
		if err != nil {
			skip(id, "template", err)
			continue
		}
		c.all = append(c.all, db.RawItem{Item: withType(base[id], db.TypeTemplate), Template: t})
	}
	rows.Close()

	// Requests and certificates link to keys through x509super.
	pkey := map[int64]sql.NullInt64{}
	rows, err = s.xdb.QueryContext(ctx, "SELECT item, pkey FROM x509super")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var k sql.NullInt64
		rows.Scan(&id, &k)
		pkey[id] = k
	}
	rows.Close()

	rows, err = s.xdb.QueryContext(ctx, "SELECT item, signed, request FROM requests ORDER BY item")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var signed sql.NullInt64
		var der sql.NullString
		if err := rows.Scan(&id, &signed, &der); err != nil {
			rows.Close()
			return nil, err
		}
		if types[id] != xcaRequest {
			continue
		}
		b, err := b64(der)
		if err == nil {
			_, err = pki.ParseCertificateRequest(b)
		}
		if err != nil {
			skip(id, "request", err)
			continue
		}
		c.all = append(c.all, db.RawItem{Item: withType(base[id], db.TypeRequest),
			Request: &db.RawRequest{DER: b, KeyID: ref(pkey[id], xcaKey), Signed: signed.Int64 != 0}})
	}
	rows.Close()

	type certIn struct {
		id     int64
		issuer sql.NullInt64
		raw    db.RawItem
	}
	var certs []certIn
	rows, err = s.xdb.QueryContext(ctx, `SELECT c.item, c.issuer, c.cert, a.item IS NOT NULL, a.template, a.crlExpire,
		a.crlNo, a.crlDays, a.dnPolicy FROM certs c LEFT JOIN authority a ON a.item = c.item ORDER BY c.item`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var issuer, tmplID, crlNo, crlDays sql.NullInt64
		var der, crlExpire, dnPolicy sql.NullString
		var hasAuth bool
		if err := rows.Scan(&id, &issuer, &der, &hasAuth, &tmplID, &crlExpire, &crlNo, &crlDays, &dnPolicy); err != nil {
			rows.Close()
			return nil, err
		}
		if types[id] != xcaCert {
			continue
		}
		b, err := b64(der)
		if err == nil {
			_, err = pki.ParseCertificate(b)
		}
		if err != nil {
			skip(id, "certificate", err)
			continue
		}
		rc := &db.RawCert{DER: b, KeyID: ref(pkey[id], xcaKey)}
		if hasAuth {
			rc.Authority = &db.Authority{TemplateID: ref(tmplID, xcaTemplate), CRLExpire: parseXCATime(crlExpire),
				CRLNo: crlNo.Int64, CRLDays: int(crlDays.Int64), DNPolicy: dnPolicy.String}
		}
		certs = append(certs, certIn{id, issuer, db.RawItem{Item: withType(base[id], db.TypeCert), Cert: rc}})
	}
	rows.Close()
	// issuers are resolved once every certificate that could be one is known
	for _, ci := range certs {
		ci.raw.Cert.IssuerID = ref(ci.issuer, xcaCert)
		c.all = append(c.all, ci.raw)
	}

	rows, err = s.xdb.QueryContext(ctx, "SELECT item, num, issuer, crl FROM crls ORDER BY item")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		var num, issuer sql.NullInt64
		var der sql.NullString
		if err := rows.Scan(&id, &num, &issuer, &der); err != nil {
			rows.Close()
			return nil, err
		}
		if types[id] != xcaCRL {
			continue
		}
		b, err := b64(der)
		if err == nil {
			_, err = x509.ParseRevocationList(b)
		}
		if err != nil {
			skip(id, "CRL", err)
			continue
		}
		c.all = append(c.all, db.RawItem{Item: withType(base[id], db.TypeCRL),
			CRL: &db.RawCRL{DER: b, IssuerID: ref(issuer, xcaCert), Number: num.Int64}})
	}
	rows.Close()

	rows, err = s.xdb.QueryContext(ctx, "SELECT caId, serial, date, invaldate, crlNo, reasonBit FROM revocations")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var ca, crlNo, reason sql.NullInt64
		var serial, date, inval sql.NullString
		if err := rows.Scan(&ca, &serial, &date, &inval, &crlNo, &reason); err != nil {
			rows.Close()
			return nil, err
		}
		if ref(ca, xcaCert) == 0 || strings.TrimSpace(serial.String) == "" {
			continue
		}
		d := parseXCATime(date)
		if d.IsZero() {
			d = now
		}
		c.revocations = append(c.revocations, db.Revocation{CAID: ca.Int64, Serial: strings.ToUpper(strings.TrimSpace(serial.String)),
			Date: d, InvalDate: parseXCATime(inval), CRLNo: crlNo.Int64, ReasonBit: int(reason.Int64)})
	}
	rows.Close()

	return c, nil
}

func withType(it db.Item, typ int) db.Item {
	it.Type = typ
	return it
}

// Package xcaimport reads XCA databases (.xdb, schema 5 to 8) and go-ca's
// former XCA based databases (go-ca schema 1 and 2) and writes their
// content into a new go-ca database. It is the only package that knows
// XCA's schema; the source file is only ever opened read-only.
//
// Item IDs are kept, so every link (issuer, key, CA template, revocation)
// carries over. Items XCA marked deleted go to the trash. Keys under the
// database password (or XCA's "Bogus" password) are decrypted and sealed
// with a new DEK; a go-ca schema 2 database keeps its DEK and its sealed
// keys unchanged. Keys with their own password keep their blob until that
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

	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/tmpl"
	"github.com/mailsvb/go-ca/internal/vault"
	"github.com/mailsvb/go-ca/internal/xdbpass"
)

// XCA's schema versions this package reads.
const (
	MinSchema = 5
	MaxSchema = 8
	// LockoutSchema is the "schema" setting of go-ca's XCA based format;
	// gca_schema then holds go-ca's version (1 or 2).
	LockoutSchema = 1000
	MaxGoCA       = 2
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
	KindGoCA   Kind = "goca"   // a go-ca schema 1 or 2 database
	KindOld    Kind = "old"    // XCA schema below 5
	KindNewer  Kind = "newer"  // a newer XCA or go-ca schema
	KindLegacy Kind = "legacy" // pre-2.0 XCA binary format
)

// Info describes a source file.
type Info struct {
	Kind   Kind
	Schema int // XCA's schema, or LockoutSchema
	GoCA   int // go-ca's schema for KindGoCA
}

// Importable reports whether Import reads the file.
func (i Info) Importable() bool { return i.Kind == KindXCA || i.Kind == KindGoCA }

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
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return info, err
	}
	defer db.Close()
	check := "PRAGMA quick_check"
	if deep {
		check = "PRAGMA integrity_check"
	}
	var res string
	if err := db.QueryRowContext(ctx, check).Scan(&res); err != nil {
		return info, err
	}
	if res != "ok" {
		return info, errors.New("integrity check: " + res)
	}
	s, err := setting(ctx, db, "schema")
	if err != nil || s == "" {
		return info, errors.New("no schema setting")
	}
	if info.Schema, err = strconv.Atoi(strings.TrimSpace(s)); err != nil {
		return info, errors.New("invalid schema setting")
	}
	switch {
	case info.Schema == LockoutSchema:
		g, _ := setting(ctx, db, "gca_schema")
		if info.GoCA, err = strconv.Atoi(strings.TrimSpace(g)); err != nil || info.GoCA < 1 {
			return info, errors.New("invalid gca_schema setting")
		}
		info.Kind = KindGoCA
		if info.GoCA > MaxGoCA {
			info.Kind = KindNewer
		}
	case info.Schema > MaxSchema:
		info.Kind = KindNewer
	case info.Schema < MinSchema:
		info.Kind = KindOld
	default:
		info.Kind = KindXCA
	}
	if info.Importable() {
		pw, _ := setting(ctx, db, "pwhash")
		kdf, _ := setting(ctx, db, "kdf")
		if pw == "" && kdf == "" {
			return info, errors.New("no password hash")
		}
	}
	return info, nil
}

func setting(ctx context.Context, db *sql.DB, key string) (string, error) {
	var v sql.NullString
	err := db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key_=?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v.String, err
}

// Source is an open source database.
type Source struct {
	Info
	db *sql.DB
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
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return &Source{Info: info, db: db}, nil
}

// Close closes the source.
func (s *Source) Close() error { return s.db.Close() }

// Unlock checks the database password. For a go-ca schema 2 database it
// returns its keyring; otherwise the keyring is nil and Import creates
// one. A wrong password returns ok false.
func (s *Source) Unlock(ctx context.Context, password []byte) (ok bool, kr *vault.Keyring, err error) {
	if s.Kind == KindGoCA && s.GoCA >= 2 {
		kdf, err := setting(ctx, s.db, "kdf")
		if err != nil {
			return false, nil, err
		}
		dek, err := setting(ctx, s.db, "dek")
		if err != nil {
			return false, nil, err
		}
		kr, err := vault.Unwrap(kdf, dek, password)
		if errors.Is(err, vault.ErrWrongPassword) {
			return false, nil, nil
		}
		return err == nil, kr, err
	}
	stored, err := setting(ctx, s.db, "pwhash")
	if err != nil {
		return false, nil, err
	}
	ok, _ = xdbpass.Verify(stored, password)
	return ok, nil, nil
}

// Report says what Import did.
type Report struct {
	Items         int // items written
	Trashed       int // items XCA had marked deleted, now in the trash
	Skipped       []string
	Converted     int // keys sealed with the DEK
	Kept          int // sealed keys copied unchanged (go-ca schema 2)
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
var dropSettings = map[string]bool{"schema": true, "pwhash": true, "gca_schema": true, "legacy-keys-updated": true,
	"kdf": true, "dek": true}

// Import writes the source's content into dst, an empty database, with
// password (already checked with Unlock), the keyring Unlock returned (nil
// for a new one, with cost p) and settings added to the copied options.
// It returns the keyring of the new database.
func (s *Source) Import(ctx context.Context, dst *sql.DB, password []byte, kr *vault.Keyring, p vault.Params,
	extra map[string]string, progress Progress) (*vault.Keyring, Report, error) {
	var rep Report
	items, err := s.read(ctx)
	if err != nil {
		return nil, rep, err
	}
	fresh := kr == nil
	if fresh {
		kr = vault.NewKeyring(p)
	}
	fail := func(err error) (*vault.Keyring, Report, error) {
		if fresh {
			kr.Wipe()
		}
		return nil, rep, err
	}
	settings := map[string]string{}
	rows, err := s.db.QueryContext(ctx, "SELECT key_, value FROM settings")
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
	for k, v := range extra {
		settings[k] = v
	}
	if fresh {
		kdf, dek, err := kr.Wrap(password, p)
		if err != nil {
			return fail(err)
		}
		settings["kdf"], settings["dek"] = kdf, dek
	} else {
		for _, k := range []string{"kdf", "dek"} {
			if settings[k], err = setting(ctx, s.db, k); err != nil {
				return fail(err)
			}
		}
	}

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
			k.Protection = gcadb.ProtToken
		case passPrivate:
			k.Protection, k.Private = gcadb.ProtPassword, it.blob
			if !vault.IsSealed(it.blob) {
				rep.OwnPassLegacy++
			}
		default:
			if !fresh {
				if vault.Mode(it.blob) != vault.ModeDEK {
					return fail(fmt.Errorf("key %d is not sealed with the database's DEK", it.raw.ID))
				}
				k.Protection, k.Private = gcadb.ProtDEK, it.blob
				rep.Kept++
				break
			}
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
				k.Protection, k.Private = gcadb.ProtPassword, it.blob
				rep.Unopened++
				break
			}
			sealed, err := kr.Seal(der, k.SPKI)
			clear(der)
			if err != nil {
				return fail(err)
			}
			k.Protection, k.Private = gcadb.ProtDEK, sealed
			rep.Converted++
		}
	}
	if progress != nil {
		progress(total, total)
	}
	err = gcadb.Create(ctx, dst, settings, func(tx *gcadb.Tx) error {
		all := make([]gcadb.RawItem, 0, len(items.all))
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
		for _, c := range items.pgp {
			if err := tx.PutPGPCert(ctx, c); err != nil {
				return err
			}
		}
		detail := fmt.Sprintf("from %s schema %d", s.Kind, s.Schema)
		if s.Kind == KindGoCA {
			detail = fmt.Sprintf("from go-ca schema %d", s.GoCA)
		}
		return tx.Audit(ctx, "database.import", 0, fmt.Sprintf("%s: %d items, %d keys converted, %d kept",
			detail, rep.Items, rep.Converted, rep.Kept))
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
	raw     gcadb.RawItem
	own     int // XCA's ownPass, -1 without a private key
	blob    []byte
	xcaType string
}

type contents struct {
	keys        []keyItem
	all         []gcadb.RawItem // everything but keys
	revocations []gcadb.Revocation
	pgp         []gcadb.PGPCert
	skipped     []string
}

func (s *Source) hasTable(ctx context.Context, name string) bool {
	var n int
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n)
	return n > 0
}

// read loads every item, keeping only links to items of the right type.
func (s *Source) read(ctx context.Context) (*contents, error) {
	c := &contents{}
	del := "0"
	if s.Kind == KindGoCA || s.Schema >= 7 {
		del = "i.del"
	}
	now := time.Now()
	types := map[int64]int{}
	base := map[int64]gcadb.Item{}
	rows, err := s.db.QueryContext(ctx, "SELECT i.id, i.name, i.type, i.source, i.date, i.comment, "+del+" FROM items i ORDER BY i.id")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var it gcadb.Item
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
		trows, err := s.db.QueryContext(ctx, "SELECT item FROM tokens")
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
	rows, err = s.db.QueryContext(ctx, `SELECT k.item, k.type, k."public", p.ownPass, p.private, p.item IS NOT NULL
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
		ki := keyItem{raw: gcadb.RawItem{Item: base[id], Key: &gcadb.RawKey{Algorithm: pki.KeyTypeText(code), Bits: bits, SPKI: spki}},
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
		ki.raw.Type = gcadb.TypeKey
		c.keys = append(c.keys, ki)
	}
	rows.Close()

	// Templates
	rows, err = s.db.QueryContext(ctx, "SELECT item, version, template FROM templates ORDER BY item")
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
		c.all = append(c.all, gcadb.RawItem{Item: withType(base[id], gcadb.TypeTemplate), Template: t})
	}
	rows.Close()

	// Requests and certificates link to keys through x509super.
	pkey := map[int64]sql.NullInt64{}
	rows, err = s.db.QueryContext(ctx, "SELECT item, pkey FROM x509super")
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

	rows, err = s.db.QueryContext(ctx, "SELECT item, signed, request FROM requests ORDER BY item")
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
		c.all = append(c.all, gcadb.RawItem{Item: withType(base[id], gcadb.TypeRequest),
			Request: &gcadb.RawRequest{DER: b, KeyID: ref(pkey[id], xcaKey), Signed: signed.Int64 != 0}})
	}
	rows.Close()

	type certIn struct {
		id     int64
		issuer sql.NullInt64
		raw    gcadb.RawItem
	}
	var certs []certIn
	rows, err = s.db.QueryContext(ctx, `SELECT c.item, c.issuer, c.cert, a.item IS NOT NULL, a.template, a.crlExpire,
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
		rc := &gcadb.RawCert{DER: b, KeyID: ref(pkey[id], xcaKey)}
		if hasAuth {
			rc.Authority = &gcadb.Authority{TemplateID: ref(tmplID, xcaTemplate), CRLExpire: parseXCATime(crlExpire),
				CRLNo: crlNo.Int64, CRLDays: int(crlDays.Int64), DNPolicy: dnPolicy.String}
		}
		certs = append(certs, certIn{id, issuer, gcadb.RawItem{Item: withType(base[id], gcadb.TypeCert), Cert: rc}})
	}
	rows.Close()
	// issuers are resolved once every certificate that could be one is known
	for _, ci := range certs {
		ci.raw.Cert.IssuerID = ref(ci.issuer, xcaCert)
		c.all = append(c.all, ci.raw)
	}

	rows, err = s.db.QueryContext(ctx, "SELECT item, num, issuer, crl FROM crls ORDER BY item")
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
		c.all = append(c.all, gcadb.RawItem{Item: withType(base[id], gcadb.TypeCRL),
			CRL: &gcadb.RawCRL{DER: b, IssuerID: ref(issuer, xcaCert), Number: num.Int64}})
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx, "SELECT caId, serial, date, invaldate, crlNo, reasonBit FROM revocations")
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
		c.revocations = append(c.revocations, gcadb.Revocation{CAID: ca.Int64, Serial: strings.ToUpper(strings.TrimSpace(serial.String)),
			Date: d, InvalDate: parseXCATime(inval), CRLNo: crlNo.Int64, ReasonBit: int(reason.Int64)})
	}
	rows.Close()

	if s.Kind == KindGoCA && s.hasTable(ctx, "gca_pgp") {
		rows, err = s.db.QueryContext(ctx, "SELECT item, fingerprint, cert FROM gca_pgp")
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id int64
			var fpr, cert sql.NullString
			if err := rows.Scan(&id, &fpr, &cert); err != nil {
				rows.Close()
				return nil, err
			}
			b, err := b64(cert)
			if err != nil || types[id] != xcaKey {
				continue
			}
			c.pgp = append(c.pgp, gcadb.PGPCert{KeyID: id, Fingerprint: fpr.String, Cert: b})
		}
		rows.Close()
	}
	return c, nil
}

func withType(it gcadb.Item, typ int) gcadb.Item {
	it.Type = typ
	return it
}

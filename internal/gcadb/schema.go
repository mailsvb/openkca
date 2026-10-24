// Package gcadb reads and writes go-ca's database files (.gca): SQLite
// with go-ca's own schema. It is the only package that issues SQL against
// a go-ca database; reading XCA's files is package xcaimport's job.
//
// The schema stores DER objects as BLOBs with SHA-256 fingerprints, links
// items with foreign keys (certificate to issuer and key, request to key,
// CRL to issuer, CA to default template, revocation to CA), keeps deleted
// items in a trash until they are purged, protects private keys with
// package vault, stores templates as JSON and records changes in an
// append-only audit table.
package gcadb

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

// ApplicationID is SQLite's application_id of a go-ca database ("gca1").
const ApplicationID = 0x67636131

// Schema is the version this package writes (the "schema" setting).
// Versions 1 and 2 were go-ca's XCA based format, read by xcaimport.
const Schema = 3

var ddl = []string{
	`CREATE TABLE settings (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	) WITHOUT ROWID`,
	`CREATE TABLE items (
		id      INTEGER PRIMARY KEY AUTOINCREMENT,
		type    TEXT NOT NULL CHECK (type IN ('key', 'request', 'cert', 'crl', 'template')),
		name    TEXT NOT NULL,
		comment TEXT NOT NULL DEFAULT '',
		source  TEXT NOT NULL DEFAULT 'unknown',
		created TEXT NOT NULL,
		stamp   INTEGER NOT NULL DEFAULT 0,
		trashed TEXT
	)`,
	`CREATE INDEX items_type ON items (type, trashed)`,
	`CREATE TABLE keys (
		item        INTEGER PRIMARY KEY REFERENCES items (id) ON DELETE CASCADE,
		algorithm   TEXT NOT NULL,
		bits        INTEGER NOT NULL,
		spki        BLOB NOT NULL,
		fingerprint BLOB NOT NULL,
		protection  TEXT CHECK (protection IN ('dek', 'password', 'token')),
		private     BLOB,
		CHECK (private IS NULL OR protection IN ('dek', 'password'))
	)`,
	`CREATE INDEX keys_fingerprint ON keys (fingerprint)`,
	`CREATE TABLE templates (
		item INTEGER PRIMARY KEY REFERENCES items (id) ON DELETE CASCADE,
		data TEXT NOT NULL
	)`,
	`CREATE TABLE requests (
		item            INTEGER PRIMARY KEY REFERENCES items (id) ON DELETE CASCADE,
		der             BLOB NOT NULL,
		fingerprint     BLOB NOT NULL,
		subject         BLOB NOT NULL,
		key_fingerprint BLOB NOT NULL,
		key             INTEGER REFERENCES keys (item) ON DELETE SET NULL,
		signed          INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX requests_fingerprint ON requests (fingerprint)`,
	`CREATE INDEX requests_key_fingerprint ON requests (key_fingerprint)`,
	`CREATE TABLE certs (
		item            INTEGER PRIMARY KEY REFERENCES items (id) ON DELETE CASCADE,
		der             BLOB NOT NULL,
		fingerprint     BLOB NOT NULL,
		subject         BLOB NOT NULL,
		issuer_name     BLOB NOT NULL,
		key_fingerprint BLOB NOT NULL,
		serial          TEXT NOT NULL,
		issuer          INTEGER REFERENCES certs (item) ON DELETE SET NULL,
		key             INTEGER REFERENCES keys (item) ON DELETE SET NULL,
		ca              INTEGER NOT NULL DEFAULT 0,
		not_before      TEXT NOT NULL,
		not_after       TEXT NOT NULL
	)`,
	`CREATE INDEX certs_fingerprint ON certs (fingerprint)`,
	`CREATE INDEX certs_subject ON certs (subject)`,
	`CREATE INDEX certs_issuer_name ON certs (issuer_name)`,
	`CREATE INDEX certs_key_fingerprint ON certs (key_fingerprint)`,
	`CREATE INDEX certs_issuer ON certs (issuer)`,
	`CREATE TABLE authorities (
		cert       INTEGER PRIMARY KEY REFERENCES certs (item) ON DELETE CASCADE,
		template   INTEGER REFERENCES templates (item) ON DELETE SET NULL,
		crl_number INTEGER NOT NULL DEFAULT 0,
		crl_days   INTEGER NOT NULL DEFAULT 30,
		crl_next   TEXT,
		dn_policy  TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE crls (
		item        INTEGER PRIMARY KEY REFERENCES items (id) ON DELETE CASCADE,
		der         BLOB NOT NULL,
		fingerprint BLOB NOT NULL,
		issuer_name BLOB NOT NULL,
		issuer      INTEGER REFERENCES certs (item) ON DELETE SET NULL,
		number      INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX crls_fingerprint ON crls (fingerprint)`,
	`CREATE INDEX crls_issuer_name ON crls (issuer_name)`,
	`CREATE TABLE revocations (
		ca         INTEGER NOT NULL REFERENCES certs (item) ON DELETE CASCADE,
		serial     TEXT NOT NULL,
		date       TEXT NOT NULL,
		invalidity TEXT,
		reason     INTEGER NOT NULL DEFAULT 0,
		crl_number INTEGER,
		PRIMARY KEY (ca, serial)
	) WITHOUT ROWID`,
	`CREATE TABLE pgp (
		key         INTEGER PRIMARY KEY REFERENCES keys (item) ON DELETE CASCADE,
		fingerprint TEXT NOT NULL,
		cert        BLOB NOT NULL
	)`,
	`CREATE TABLE audit (
		id        INTEGER PRIMARY KEY AUTOINCREMENT,
		at        TEXT NOT NULL,
		action    TEXT NOT NULL,
		item      INTEGER,
		item_name TEXT NOT NULL DEFAULT '',
		detail    TEXT NOT NULL DEFAULT '',
		client    TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX audit_item ON audit (item)`,
	// The log is append-only.
	`CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END`,
	`CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END`,
}

// Create writes the schema and the given settings into an empty database
// in one transaction, with every statement inside fn (the importer's) in
// the same transaction when fn is not nil.
func Create(ctx context.Context, db *sql.DB, settings map[string]string, fn func(*Tx) error) error {
	sqlTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer sqlTx.Rollback()
	for _, stmt := range ddl {
		if _, err := sqlTx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("gcadb: create: %w", err)
		}
	}
	if _, err := sqlTx.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id = %d", ApplicationID)); err != nil {
		return err
	}
	if _, err := sqlTx.ExecContext(ctx, "INSERT INTO settings (key, value) VALUES ('schema', ?)", strconv.Itoa(Schema)); err != nil {
		return err
	}
	for k, v := range settings {
		if _, err := sqlTx.ExecContext(ctx, "INSERT INTO settings (key, value) VALUES (?, ?)", k, v); err != nil {
			return err
		}
	}
	if fn == nil {
		return sqlTx.Commit()
	}
	// Imported rows keep their IDs; links may point forward until the end.
	if _, err := sqlTx.ExecContext(ctx, "PRAGMA defer_foreign_keys = ON"); err != nil {
		return err
	}
	return commitWrite(ctx, sqlTx, fn)
}

// ReadSchema returns the "schema" setting and whether the file carries
// go-ca's application ID.
func ReadSchema(ctx context.Context, db *sql.DB) (schema int, gca bool, err error) {
	var app int64
	if err := db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
		return 0, false, err
	}
	if app != ApplicationID {
		return 0, false, nil
	}
	var v string
	if err := db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='schema'").Scan(&v); err != nil {
		return 0, true, err
	}
	s, err := strconv.Atoi(v)
	if err != nil {
		return 0, true, fmt.Errorf("gcadb: invalid schema %q", v)
	}
	return s, true, nil
}

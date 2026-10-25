package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Settings of the unlock methods.
const (
	// SettingArgon2id is the database's Argon2id cost for new and changed
	// passwords and for keys with their own password, in package vault's
	// kdf form without a salt: "argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>".
	SettingArgon2id = "argon2id"
	// SettingWebAuthnUser is the database's WebAuthn user handle (base64).
	SettingWebAuthnUser = "webauthn_user"
)

// UnlockMethod is one way to unlock a database: a password, a security
// key, a passkey or the backup code. Wrapped is the database's data key
// wrapped by the method (package vault); the WebAuthn fields are set for
// security keys and passkeys only.
type UnlockMethod struct {
	ID       int64
	UUID     string
	Type     string
	Label    string
	Created  time.Time
	LastUsed time.Time // zero: never used
	KDF      string
	Wrapped  []byte

	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
	PRFSalt      []byte
	Transports   string
	AAGUID       []byte
	Flags        byte // the authenticator data flags at registration (backup eligibility)
}

// WebAuthn reports whether the method is a security key or a passkey.
func (m *UnlockMethod) WebAuthn() bool { return m.CredentialID != nil }

const methodCols = `id, uuid, type, label, created, last_used, kdf, wrapped,
	credential_id, public_key, sign_count, prf_salt, transports, aaguid, flags`

func scanMethod(sc interface{ Scan(...any) error }) (UnlockMethod, error) {
	var m UnlockMethod
	var created string
	var last sql.NullString
	var count, flags int64
	err := sc.Scan(&m.ID, &m.UUID, &m.Type, &m.Label, &created, &last, &m.KDF, &m.Wrapped,
		&m.CredentialID, &m.PublicKey, &count, &m.PRFSalt, &m.Transports, &m.AAGUID, &flags)
	if err != nil {
		return m, err
	}
	m.Created = parseTime(sql.NullString{String: created, Valid: true})
	m.LastUsed = parseTime(last)
	m.SignCount = uint32(count)
	m.Flags = byte(flags)
	return m, nil
}

func queryMethods(ctx context.Context, q querier, where string, args ...any) ([]UnlockMethod, error) {
	rows, err := q.QueryContext(ctx, "SELECT "+methodCols+" FROM unlock_methods "+where+
		" ORDER BY last_used IS NULL, last_used DESC, id", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UnlockMethod
	for rows.Next() {
		m, err := scanMethod(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// UnlockMethods returns the database's unlock methods, the most recently
// used first.
func (d *DB) UnlockMethods(ctx context.Context) ([]UnlockMethod, error) {
	return queryMethods(ctx, d.SQL, "")
}

// UnlockMethods returns the unlock methods inside the transaction.
func (t *Tx) UnlockMethods(ctx context.Context) ([]UnlockMethod, error) {
	return queryMethods(ctx, t, "")
}

// UnlockMethodsOfType returns the methods of one type, the most recently
// used first.
func (d *DB) UnlockMethodsOfType(ctx context.Context, typ string) ([]UnlockMethod, error) {
	return queryMethods(ctx, d.SQL, "WHERE type=?", typ)
}

// ErrNoMethod is returned when an unlock method does not exist.
var ErrNoMethod = errors.New("db: no such unlock method")

func oneMethod(ms []UnlockMethod, err error) (*UnlockMethod, error) {
	if err != nil {
		return nil, err
	}
	if len(ms) == 0 {
		return nil, ErrNoMethod
	}
	return &ms[0], nil
}

// UnlockMethod returns the method with this UUID.
func (d *DB) UnlockMethod(ctx context.Context, id string) (*UnlockMethod, error) {
	return oneMethod(queryMethods(ctx, d.SQL, "WHERE uuid=?", id))
}

// UnlockMethodByCredential returns the security key or passkey with this
// WebAuthn credential ID.
func (d *DB) UnlockMethodByCredential(ctx context.Context, credID []byte) (*UnlockMethod, error) {
	return oneMethod(queryMethods(ctx, d.SQL, "WHERE credential_id=?", credID))
}

func insertUnlockMethod(ctx context.Context, q interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}, m *UnlockMethod) error {
	if m.UUID == "" {
		id, err := NewUUID()
		if err != nil {
			return err
		}
		m.UUID = id
	}
	if m.Created.IsZero() {
		m.Created = time.Now()
	}
	res, err := q.ExecContext(ctx, `INSERT INTO unlock_methods (uuid, type, label, created, last_used, kdf, wrapped,
		credential_id, public_key, sign_count, prf_salt, transports, aaguid, flags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.UUID, m.Type, m.Label, fmtTime(m.Created), optTime(m.LastUsed), m.KDF, m.Wrapped,
		m.CredentialID, m.PublicKey, int64(m.SignCount), m.PRFSalt, m.Transports, m.AAGUID, int64(m.Flags))
	if err != nil {
		return err
	}
	m.ID, err = res.LastInsertId()
	return err
}

// InsertUnlockMethod adds a method; an empty UUID gets a new one and a
// zero Created the current time. m.ID and m.UUID are set.
func (t *Tx) InsertUnlockMethod(ctx context.Context, m *UnlockMethod) error {
	return insertUnlockMethod(ctx, t, m)
}

func changed(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNoMethod
	}
	return nil
}

// RewrapUnlockMethod replaces a method's kdf recipe and wrapped data key.
func (t *Tx) RewrapUnlockMethod(ctx context.Context, id, kdf string, wrapped []byte) error {
	return changed(t.ExecContext(ctx, "UPDATE unlock_methods SET kdf=?, wrapped=? WHERE uuid=?", kdf, wrapped, id))
}

// RenameUnlockMethod sets a method's label.
func (t *Tx) RenameUnlockMethod(ctx context.Context, id, label string) error {
	return changed(t.ExecContext(ctx, "UPDATE unlock_methods SET label=? WHERE uuid=?", label, id))
}

// DeleteUnlockMethod removes a method.
func (t *Tx) DeleteUnlockMethod(ctx context.Context, id string) error {
	return changed(t.ExecContext(ctx, "DELETE FROM unlock_methods WHERE uuid=?", id))
}

// TouchUnlockMethod records a successful use of a method and, for a
// security key or passkey, its signature counter.
func (t *Tx) TouchUnlockMethod(ctx context.Context, id string, signCount uint32) error {
	return changed(t.ExecContext(ctx, "UPDATE unlock_methods SET last_used=?, sign_count=? WHERE uuid=?",
		fmtTime(time.Now()), int64(signCount), id))
}

// MethodTypes returns the types of a database's unlock methods with their
// count, read straight from the file (the database list shows them before
// login).
func MethodTypes(ctx context.Context, q *sql.DB) (map[string]int, error) {
	rows, err := q.QueryContext(ctx, "SELECT type, COUNT(*) FROM unlock_methods GROUP BY type")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, rows.Err()
}

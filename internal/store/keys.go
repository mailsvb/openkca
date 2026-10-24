package store

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/vault"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// ErrNotConverted means a database still has to be converted to go-ca's
// current format before its keys can be used.
var ErrNotConverted = errors.New("the database has not been converted to the current format")

// Unlock opens the DEK of a current database with the database password.
// A wrong password returns pki.ErrWrongPassword.
func (h *Handle) Unlock(ctx context.Context, password []byte) (*vault.Keyring, error) {
	if !h.DB.Current() {
		return nil, ErrNotConverted
	}
	kdf, err := h.DB.Setting(ctx, "kdf")
	if err != nil {
		return nil, err
	}
	dek, err := h.DB.Setting(ctx, "dek")
	if err != nil {
		return nil, err
	}
	return vault.Unwrap(kdf, dek, password)
}

// KDFParams returns the Argon2id cost of a current database.
func (h *Handle) KDFParams(ctx context.Context) (vault.Params, error) {
	kdf, err := h.DB.Setting(ctx, "kdf")
	if err != nil {
		return vault.Params{}, err
	}
	p, _, err := vault.ParseKDF(kdf)
	return p, err
}

// legacyDER decrypts a key in one of XCA's forms (encrypted PKCS#8 or the
// legacy 3DES form) to an unencrypted PKCS#8 PrivateKeyInfo. Encrypted
// PKCS#8 is decrypted without parsing the key, so keys of algorithms go-ca
// cannot compute with survive.
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

// keyDER returns the unencrypted PKCS#8 PrivateKeyInfo of a stored key.
// The caller clears it. A key with its own password still in an XCA form
// is re-sealed in go-ca's form once its password has opened it.
func (h *Handle) keyDER(ctx context.Context, keyID int64, keyType string, kr *vault.Keyring, kp KeyPasswords) ([]byte, error) {
	sk, err := h.DB.StoredPrivateKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoPrivateKey, err)
	}
	switch sk.OwnPass {
	case xdb.PassPIN:
		return nil, errors.New("the key is on a security token, which go-ca does not access")
	case xdb.PassPrivate:
		pw := kp[keyID]
		if len(pw) == 0 {
			return nil, ErrNeedKeyPassword
		}
		if vault.Mode(sk.Blob) == vault.ModePassword {
			der, err := vault.OpenWithPassword(sk.Blob, sk.Public, pw)
			if errors.Is(err, vault.ErrWrongPassword) {
				return nil, ErrNeedKeyPassword
			}
			return der, err
		}
		der, err := legacyDER(sk.Blob, keyType, pw)
		if errors.Is(err, pki.ErrWrongPassword) {
			return nil, ErrNeedKeyPassword
		}
		if err != nil {
			return nil, err
		}
		h.upgradeOwnPassword(ctx, keyID, sk.Public, der, pw, kr)
		return der, nil
	}
	if kr == nil {
		return nil, vault.ErrLocked
	}
	if vault.Mode(sk.Blob) != vault.ModeDEK {
		return nil, fmt.Errorf("key %d is not stored in go-ca's format", keyID)
	}
	return kr.Open(sk.Blob, sk.Public)
}

// upgradeOwnPassword re-seals a key with its own password from an XCA form
// into go-ca's form. Failure only costs the upgrade, so it is logged.
func (h *Handle) upgradeOwnPassword(ctx context.Context, keyID int64, spki, der, pw []byte, kr *vault.Keyring) {
	p := vault.Default
	if kr != nil {
		p = kr.Params()
	}
	blob, err := vault.SealWithPassword(der, spki, pw, p)
	if err == nil {
		err = h.DB.Write(ctx, func(tx *xdb.Tx) error { return tx.UpdatePrivateKey(ctx, keyID, blob, xdb.PassPrivate) })
	}
	if err != nil {
		slog.Warn("upgrading a key with its own password failed", "db", h.Name, "id", keyID, "err", err)
		return
	}
	slog.Info("key with its own password upgraded to go-ca's format", "db", h.Name, "id", keyID)
	h.changed(ctx)
}

// unlock decrypts and parses the private key of item keyID.
func (h *Handle) unlock(ctx context.Context, keyID int64, keyType string, kr *vault.Keyring, kp KeyPasswords) (crypto.Signer, error) {
	der, err := h.keyDER(ctx, keyID, keyType, kr, kp)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	return pki.ParsePKCS8(der)
}

// sealKey encodes key and seals it with the DEK.
func sealKey(kr *vault.Keyring, key crypto.Signer, spki []byte) ([]byte, error) {
	der, err := pki.MarshalPKCS8(key)
	if err != nil {
		return nil, fmt.Errorf("pkcs8: %w", err)
	}
	defer clear(der)
	return kr.Seal(der, spki)
}

// CheckKey decrypts a key and reports its algorithm and whether it
// matches its public key. password is the key's own password (ignored for
// other keys); a wrong one returns ErrNeedKeyPassword.
func (h *Handle) CheckKey(ctx context.Context, k *xdb.Key, kr *vault.Keyring, password []byte) (algorithm string, ok bool, err error) {
	var kp KeyPasswords
	if len(password) > 0 {
		kp = KeyPasswords{k.ID: password}
	}
	priv, err := h.unlock(ctx, k.ID, k.KeyType, kr, kp)
	if err != nil {
		return "", false, err
	}
	ok, err = pki.MatchesPublic(priv, k.Public)
	return pki.KeyAlgorithm(priv), ok, err
}

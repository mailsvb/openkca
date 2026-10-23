package store

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/tmpl"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// Dump writes every item of the database as a ZIP archive laid out like
// XCA's "Dump database": folders keys, requests, certificates, crls and
// templates with one PEM file per item, named after the item
// (get_dump_filename). Private keys are written encrypted with the
// database password, as XCA does; keys with their own password keep it.
func (h *Handle) Dump(ctx context.Context, w io.Writer, dbPass []byte) error {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return err
	}
	z := zip.NewWriter(w)
	root := FileName(h.Name) + "/"
	used := map[string]bool{}
	now := time.Now()
	file := func(dir, name, ext string, data []byte) error {
		base := root + dir + "/" + FileName(name)
		fn := base + ext
		for n := 1; used[strings.ToLower(fn)] && n < 1000; n++ {
			fn = base + "_" + strconv.Itoa(n) + ext
		}
		used[strings.ToLower(fn)] = true
		f, err := z.CreateHeader(&zip.FileHeader{Name: fn, Method: zip.Deflate, Modified: now})
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		return err
	}
	for _, d := range []string{"keys", "requests", "certificates", "crls", "templates"} {
		if _, err := z.CreateHeader(&zip.FileHeader{Name: root + d + "/", Modified: now}); err != nil {
			return err
		}
	}
	for _, k := range snap.Keys {
		data, err := h.dumpKey(ctx, k, dbPass)
		if err != nil {
			return err
		}
		if err := file("keys", k.Name, ".pem", data); err != nil {
			return err
		}
	}
	for _, r := range snap.Requests {
		if err := file("requests", r.Name, ".csr", codec.PEM(codec.PEMRequest, r.DER)); err != nil {
			return err
		}
	}
	for _, c := range snap.Certs {
		if err := file("certificates", c.Name, ".crt", codec.PEM(codec.PEMCert, c.DER)); err != nil {
			return err
		}
	}
	for _, l := range snap.CRLs {
		if err := file("crls", l.Name, ".crl", codec.PEM(codec.PEMCRL, l.DER)); err != nil {
			return err
		}
	}
	for _, t := range snap.Templates {
		dt, err := tmpl.Decode(t.Blob, t.Version)
		if err != nil {
			continue
		}
		if err := file("templates", t.Name, ".xca", codec.XCATemplate(t.Name, t.Comment, dt)); err != nil {
			return err
		}
	}
	return z.Close()
}

// dumpKey is pki_evp::writeDefault: traditional PEM encrypted with the
// database password. Keys go-ca cannot re-encrypt (own password, curves Go
// does not support) are written as the stored encrypted PKCS#8.
func (h *Handle) dumpKey(ctx context.Context, k *xdb.Key, dbPass []byte) ([]byte, error) {
	if !k.HasPrivate {
		return codec.PEM(codec.PEMPublicKey, k.Public), nil
	}
	if k.Token {
		return codec.PEM(codec.PEMPublicKey, k.Public), nil
	}
	if s, err := h.unlock(ctx, k.ID, k.KeyType, dbPass, nil); err == nil {
		if codec.KeyTypeName(s.Public()) != "Ed25519" {
			return codec.PrivatePEM(s, dbPass)
		}
	} else if !errors.Is(err, ErrNeedKeyPassword) {
		if _, err := codec.ParsePublic(k.Public); err == nil {
			return nil, err
		}
	}
	blob, own, err := h.DB.PrivateKey(ctx, k.ID)
	if err != nil {
		return nil, err
	}
	if own == xdb.PassCommon || own == xdb.PassPrivate {
		return codec.PEM(codec.PEMEncrypted, blob), nil
	}
	// "Bogus" keys: re-encrypt with the database password
	der, err := h.privateDER(ctx, k, dbPass, nil)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	return codec.PKCS8PEM(der, dbPass)
}

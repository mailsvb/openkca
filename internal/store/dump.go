package store

import (
	"archive/zip"
	"context"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/tmpl"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// Dump writes every item of the database as a ZIP archive laid out like
// XCA's "Dump database": folders keys, requests, certificates, crls and
// templates with one PEM file per item, named after the item
// (get_dump_filename). Private keys are written encrypted with the
// database password, as XCA does but as encrypted PKCS#8; keys with their
// own password keep it.
// OpenPGP certificates are written next to their primary keys as armored
// public keys.
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
	for _, v := range pgpViews(snap) {
		k := findKey(snap, v.Primary())
		if k == nil {
			continue
		}
		data, err := codec.PGPArmor(codec.PGPPublicBlock, v.Cert.Cert, v.Info.Version)
		if err != nil {
			return err
		}
		if err := file("keys", k.Name, ".asc", data); err != nil {
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

// dumpKey writes a private key encrypted with the database password, as
// XCA's pki_evp::writeDefault does, but as encrypted PKCS#8 (PBES2 with
// pki.PBKDF2Iterations) instead of XCA's traditional PEM: that one derives
// its key with a single MD5 round, which would make the dump an easy way to
// guess the database password. A stored key that is already encrypted that
// way is written as it is, without decrypting it; keys with their own
// password keep it.
func (h *Handle) dumpKey(ctx context.Context, k *xdb.Key, dbPass []byte) ([]byte, error) {
	if !k.HasPrivate || k.Token {
		return codec.PEM(codec.PEMPublicKey, k.Public), nil
	}
	blob, own, err := h.DB.PrivateKey(ctx, k.ID)
	if err != nil {
		return nil, err
	}
	if own == xdb.PassPrivate {
		return codec.PEM(codec.PEMEncrypted, blob), nil
	}
	if n, ok := pki.PKCS8Iterations(blob); ok && n >= pki.PBKDF2Iterations && own == xdb.PassCommon {
		return codec.PEM(codec.PEMEncrypted, blob), nil
	}
	der, err := h.privateDER(ctx, k, dbPass, nil)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	return codec.PKCS8PEM(der, dbPass)
}

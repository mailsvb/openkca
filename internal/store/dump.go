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
	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/vault"
)

// Dump writes every item of the database as a ZIP archive laid out like
// XCA's "Dump database": folders keys, requests, certificates, crls and
// templates with one PEM file per item, named after the item
// (get_dump_filename). Private keys are written as encrypted PKCS#8 under
// exportPass; keys with their own password that cannot be written that
// way are listed in keys/OWN-PASSWORD.txt with only their public key.
// OpenPGP certificates are written next to their primary keys as armored
// public keys.
func (h *Handle) Dump(ctx context.Context, w io.Writer, kr *vault.Keyring, exportPass []byte) error {
	if len(exportPass) == 0 {
		return errors.New("the dump needs a password for the private keys")
	}
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
	var ownPass []string
	for _, k := range snap.Keys {
		data, own, err := h.dumpKey(ctx, k, kr, exportPass)
		if err != nil {
			return err
		}
		if own {
			ownPass = append(ownPass, k.Name)
		}
		if err := file("keys", k.Name, ".pem", data); err != nil {
			return err
		}
	}
	if len(ownPass) > 0 {
		note := "These keys have their own password and are stored in a form only go-ca reads.\n" +
			"Their files hold the public key only; export each key on its own with its password.\n\n" +
			strings.Join(ownPass, "\n") + "\n"
		if err := file("keys", "OWN-PASSWORD", ".txt", []byte(note)); err != nil {
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
		if err := file("templates", t.Name, ".xca", codec.XCATemplate(t.Name, t.Comment, t.Data)); err != nil {
			return err
		}
	}
	err = z.Close()
	h.auditIf(ctx, err, "database.dump", 0, "%d keys, %d certificates", len(snap.Keys), len(snap.Certs))
	return err
}

// dumpKey writes a private key under the export password as encrypted
// PKCS#8 (PBES2 with pki.PBKDF2Iterations), as XCA's "Dump database" does
// with the database password. A key with its own password is written as
// it is when that is a standard encrypted PKCS#8 file; otherwise (go-ca's
// own format, or XCA's legacy form, which no other program reads) only its
// public key is written and ownPass reports it.
func (h *Handle) dumpKey(ctx context.Context, k *gcadb.Key, kr *vault.Keyring, exportPass []byte) (data []byte, ownPass bool, err error) {
	if !k.HasPrivate || k.Token {
		return codec.PEM(codec.PEMPublicKey, k.Public), false, nil
	}
	sk, err := h.DB.StoredPrivateKey(ctx, k.ID)
	if err != nil {
		return nil, false, err
	}
	if sk.Protection == gcadb.ProtPassword {
		if pki.IsEncryptedPKCS8(sk.Blob) {
			return codec.PEM(codec.PEMEncrypted, sk.Blob), false, nil
		}
		return codec.PEM(codec.PEMPublicKey, k.Public), true, nil
	}
	der, err := h.privateDER(ctx, k, kr, nil)
	if err != nil {
		return nil, false, err
	}
	defer clear(der)
	data, err = codec.PKCS8PEM(der, exportPass)
	return data, false, err
}

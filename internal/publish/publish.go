// Package publish keeps the files go-ca publishes for each CA in its CA
// folder (package cadir), for the plain HTTP server (package pubserve) and
// for anyone who serves the folder otherwise:
//
//	<data-dir>/ca/<database>/<authority ID>/ca.crt   the CA certificate (DER)
//	<data-dir>/ca/<database>/<authority ID>/crl.der  the CA's newest CRL (DER)
//
// Files are only replaced, never removed: a CA in the trash, or one whose
// CRL items were deleted, keeps serving what it published last, since
// certificates out there still point to it. It is the only package that
// writes these files.
package publish

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"

	"github.com/mailsvb/openkca/internal/cadir"
	"github.com/mailsvb/openkca/internal/db"
)

// File names in a CA folder.
const (
	CertFile = "ca.crt"
	CRLFile  = "crl.der"
)

// Write publishes the certificate and the newest CRL of every live CA in
// the snapshot. A file is only rewritten when its content changes.
func Write(dir, dbName string, snap *db.Snapshot) error {
	newest := NewestCRLs(snap)
	for _, ca := range snap.Certs {
		if !ca.CA || ca.Authority == nil {
			continue
		}
		folder, err := cadir.Path(dir, dbName, ca.Authority.UUID)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(folder, 0o700); err != nil {
			return err
		}
		if err := writeIfChanged(filepath.Join(folder, CertFile), ca.DER); err != nil {
			return err
		}
		if l := newest[ca.ID]; l != nil {
			if err := writeIfChanged(filepath.Join(folder, CRLFile), l.DER); err != nil {
				return err
			}
		}
	}
	return nil
}

// NewestCRLs returns each CA's newest CRL (latest thisUpdate, then the
// higher CRL number, then the later item) by CA ID.
func NewestCRLs(snap *db.Snapshot) map[int64]*db.CRL {
	type best struct {
		crl *db.CRL
		l   *x509.RevocationList
	}
	out := map[int64]best{}
	for _, c := range snap.CRLs {
		if c.IssuerID == 0 {
			continue
		}
		l, err := x509.ParseRevocationList(c.DER)
		if err != nil {
			continue
		}
		b, ok := out[c.IssuerID]
		if !ok || l.ThisUpdate.After(b.l.ThisUpdate) ||
			(l.ThisUpdate.Equal(b.l.ThisUpdate) && (c.Num > b.crl.Num || (c.Num == b.crl.Num && c.ID > b.crl.ID))) {
			out[c.IssuerID] = best{c, l}
		}
	}
	res := map[int64]*db.CRL{}
	for id, b := range out {
		res[id] = b.crl
	}
	return res
}

func writeIfChanged(path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

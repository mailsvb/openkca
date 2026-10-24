// Package cadir lays out the folders in which go-ca keeps a CA's files on
// disk (its OpenSSL index and any other per-CA data):
//
//	<data-dir>/ca/<database>/<authority ID>/
//
// The folder is named after the CA's authority ID (package db): the
// UUID of the CA certificate, kept by a renewal with the same subject and
// key. Renaming or renewing a CA keeps its folder, and a CA taken out of
// the trash finds its files again.
package cadir

import (
	"fmt"
	"path/filepath"

	"github.com/google/uuid"
)

// Root is the folder below the data folder that holds every CA folder.
const Root = "ca"

// Base returns the folder holding the CA folders of one database.
func Base(dataDir, db string) string { return filepath.Join(dataDir, Root, db) }

// Path returns the folder of one CA by its authority ID. The ID must be a
// UUID in canonical form (lower case with hyphens, as db stores it), so
// that it is always one plain path element.
func Path(dataDir, db, authorityID string) (string, error) {
	if !IsUUID(authorityID) {
		return "", fmt.Errorf("cadir: invalid authority ID %q", authorityID)
	}
	return filepath.Join(Base(dataDir, db), authorityID), nil
}

// IsUUID reports whether a folder name is a UUID in canonical form, i.e.
// a CA folder.
func IsUUID(name string) bool {
	u, err := uuid.Parse(name)
	return err == nil && u.String() == name
}

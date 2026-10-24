// Package cadir lays out the folders in which go-ca keeps a CA's files on
// disk (its OpenSSL index and any other per-CA data):
//
//	<data-dir>/ca/<database>/<CA UUID>/
//
// The folder is named after the CA certificate's item UUID, which never
// changes, so renaming a CA keeps its folder, and a CA taken out of the
// trash finds its files again.
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

// Path returns the folder of one CA. The UUID must be in canonical form
// (lower case with hyphens, as gcadb stores it), so that it is always one
// plain path element.
func Path(dataDir, db, caUUID string) (string, error) {
	if !IsUUID(caUUID) {
		return "", fmt.Errorf("cadir: invalid CA uuid %q", caUUID)
	}
	return filepath.Join(Base(dataDir, db), caUUID), nil
}

// IsUUID reports whether a folder name is a UUID in canonical form, i.e.
// a CA folder.
func IsUUID(name string) bool {
	u, err := uuid.Parse(name)
	return err == nil && u.String() == name
}

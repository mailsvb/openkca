package store

import (
	"slices"
	"strconv"

	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
)

// Defaults of options a database may not set. Databases imported from
// XCA that kept XCA's defaults (SHA-256, 64 bit) get these too.
const (
	DefaultSerialLen = 128
	DefaultHash      = pki.HashAuto
)

// SerialLen is the length of new serial numbers in bits (option
// serial_len).
func SerialLen(snap *gcadb.Snapshot) int {
	if n, err := strconv.Atoi(snap.Settings["serial_len"]); err == nil && n >= 64 && n <= 160 && n%8 == 0 {
		return n
	}
	return DefaultSerialLen
}

// Hash is the signature hash choice for new certificates, requests and
// CRLs (option default_hash).
func Hash(snap *gcadb.Snapshot) string {
	if h := snap.Settings["default_hash"]; slices.Contains(pki.HashChoices, h) {
		return h
	}
	return DefaultHash
}

// Expert reports whether the database shows expert fields (option
// expert): post-quantum keys, signature hash, Netscape and further
// extensions.
func Expert(snap *gcadb.Snapshot) bool {
	return snap.Settings["expert"] == "yes"
}

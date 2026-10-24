// Package index writes an OpenSSL "ca" style certificate index per CA, as
// used by "openssl ocsp -index": index.txt and index.txt.attr in the CA's
// folder, <data-dir>/ca/<database>/<CA UUID>/ (package cadir). It is the
// only package that writes index files.
package index

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/cadir"
	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
)

// openssl ca knows these reasons in the revocation field (apps/ca.c).
var opensslReasons = map[int]string{0: "unspecified", 1: "keyCompromise", 2: "CACompromise", 3: "affiliationChanged",
	4: "superseded", 5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL"}

// indexTime formats a time like OpenSSL's ASN1 time strings: UTCTime
// (YYMMDDHHMMSSZ) until 2049, GeneralizedTime from 2050.
func indexTime(t time.Time) string {
	t = t.UTC()
	if t.Year() < 2050 {
		return t.Format("060102150405Z")
	}
	return t.Format("20060102150405Z")
}

// oneline renders a name like X509_NAME_oneline: "/C=DE/O=Org/CN=Name",
// with bytes outside printable ASCII escaped as \xHH.
func oneline(der []byte) string {
	entries, err := pki.ParseName(der)
	if err != nil {
		return "/"
	}
	var b strings.Builder
	for _, e := range entries {
		b.WriteString("/" + e.Short + "=")
		for _, c := range []byte(e.Value) {
			if c < 0x20 || c > 0x7e {
				fmt.Fprintf(&b, "\\x%02X", c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}

// Entry renders one index line for a certificate.
func Entry(c *gcadb.Cert, rev *gcadb.Revocation, now time.Time) string {
	info := pki.DescribeCert(c.DER)
	status, revField := "V", ""
	switch {
	case rev != nil:
		status = "R"
		revField = indexTime(rev.Date)
		if r, ok := opensslReasons[rev.ReasonBit]; ok && rev.ReasonBit != 0 {
			revField += "," + r
		}
	case now.Before(info.NotBefore) || (!info.NoExpiry && now.After(info.NotAfter)):
		status = "E"
	}
	subject := oneline(subjectOf(c))
	return fmt.Sprintf("%s\t%s\t%s\t%s\tunknown\t%s\n", status, indexTime(info.NotAfter), revField, c.Serial, subject)
}

func subjectOf(c *gcadb.Cert) []byte {
	if raw, err := pki.RawSubject(c.DER); err == nil {
		return raw
	}
	return nil
}

// Files are the files this package writes into a CA folder.
var Files = []string{"index.txt", "index.txt.attr"}

func isIndexFile(name string) bool {
	for _, f := range Files {
		if name == f {
			return true
		}
	}
	return false
}

// Write rewrites the index files of every CA in the snapshot, each in its
// CA folder (package cadir). Folders of CAs that are no longer live (in the
// trash or purged) are removed if they hold nothing but index files;
// other files there are left alone.
func Write(dir, db string, snap *gcadb.Snapshot) error {
	base := cadir.Base(dir, db)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return err
	}
	revs := map[string]*gcadb.Revocation{}
	for _, r := range snap.Revocations {
		revs[fmt.Sprint(r.CAID, "/", r.Serial)] = r
	}
	var cas []*gcadb.Cert
	for _, c := range snap.Certs {
		if c.CA {
			cas = append(cas, c)
		}
	}
	sort.Slice(cas, func(i, j int) bool { return cas[i].ID < cas[j].ID })
	live := map[string]bool{}
	now := time.Now()
	for _, ca := range cas {
		folder, err := cadir.Path(dir, db, ca.UUID)
		if err != nil {
			return err
		}
		live[ca.UUID] = true
		var lines []string
		for _, c := range snap.Certs {
			if c.IssuerID == ca.ID && c.ID != ca.ID {
				lines = append(lines, Entry(c, revs[fmt.Sprint(ca.ID, "/", c.Serial)], now))
			}
		}
		// Revocations of serials not in the database (added by hand)
		known := map[string]bool{}
		for _, c := range snap.Certs {
			if c.IssuerID == ca.ID {
				known[c.Serial] = true
			}
		}
		for _, r := range snap.Revocations {
			if r.CAID == ca.ID && !known[r.Serial] {
				rf := indexTime(r.Date)
				if n, ok := opensslReasons[r.ReasonBit]; ok && r.ReasonBit != 0 {
					rf += "," + n
				}
				lines = append(lines, fmt.Sprintf("R\t%s\t%s\t%s\tunknown\t%s\n", indexTime(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)), rf, r.Serial, "/"))
			}
		}
		if err := os.MkdirAll(folder, 0o700); err != nil {
			return err
		}
		if err := writeAtomic(filepath.Join(folder, "index.txt"), []byte(strings.Join(lines, ""))); err != nil {
			return err
		}
		if err := writeAtomic(filepath.Join(folder, "index.txt.attr"), []byte("unique_subject = no\n")); err != nil {
			return err
		}
	}
	entries, _ := os.ReadDir(base)
	for _, e := range entries {
		// Only CA folders; anything else in the database's folder is not ours.
		if !e.IsDir() || !cadir.IsUUID(e.Name()) || live[e.Name()] {
			continue
		}
		folder := filepath.Join(base, e.Name())
		files, _ := os.ReadDir(folder)
		onlyIndex := true
		for _, f := range files {
			if !isIndexFile(f.Name()) {
				onlyIndex = false
			}
		}
		if onlyIndex {
			os.RemoveAll(folder)
		}
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Package index writes an OpenSSL "ca" style certificate index per CA, as
// used by "openssl ocsp -index": <data-dir>/index/<database>/<CA>/index.txt
// and index.txt.attr. It is the only package that writes index files.
package index

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

func folderName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := strings.TrimLeft(b.String(), ".")
	if s == "" {
		s = "ca"
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// Write rewrites the index files of every CA in the snapshot under
// dir/<db>. Folders of CAs that no longer exist are removed if they hold
// nothing but index files.
func Write(dir, db string, snap *gcadb.Snapshot) error {
	base := filepath.Join(dir, "index", db)
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
	used := map[string]bool{}
	now := time.Now()
	for _, ca := range cas {
		name := folderName(ca.Name)
		if used[name] {
			name = fmt.Sprintf("%s-%d", name, ca.ID)
		}
		used[name] = true
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
		folder := filepath.Join(base, name)
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
		if !e.IsDir() || used[e.Name()] {
			continue
		}
		folder := filepath.Join(base, e.Name())
		files, _ := os.ReadDir(folder)
		onlyIndex := true
		for _, f := range files {
			if f.Name() != "index.txt" && f.Name() != "index.txt.attr" {
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

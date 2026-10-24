package web

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/i18n"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/store"
)

var (
	tagRE      = regexp.MustCompile(`(?s)<[^>]*>`)
	entityRE   = regexp.MustCompile(`&[a-zA-Z]+;|&#[0-9]+;`)
	letterRE   = regexp.MustCompile(`\p{L}`)
	attrTextRE = regexp.MustCompile(`(?i)\b(title|placeholder|alt|aria-label)="([^"]*)"`)
	actionRE   = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	tKeyRE     = regexp.MustCompile(`\bT "([a-z0-9_.]+)"`)
)

// TestNoLiteralText fails on any user-visible text in a template that does
// not come from the message catalog: template actions are masked, then tags
// are removed and no letters may remain; text attributes are checked too.
func TestNoLiteralText(t *testing.T) {
	files, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		src, _ := fs.ReadFile(templateFS, f)
		masked := actionRE.ReplaceAllString(string(src), "\x00")
		for _, m := range attrTextRE.FindAllStringSubmatch(masked, -1) {
			if letterRE.MatchString(m[2]) {
				t.Errorf("%s: literal %s=%q", f, m[1], m[2])
			}
		}
		visible := entityRE.ReplaceAllString(tagRE.ReplaceAllString(masked, " "), " ")
		for _, line := range strings.Split(visible, "\n") {
			if letterRE.MatchString(line) {
				t.Errorf("%s: literal text %q", f, strings.TrimSpace(line))
			}
		}
	}
}

// TestMessageKeys checks that every key the templates and handlers use
// exists in the English catalog.
func TestMessageKeys(t *testing.T) {
	cat, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	files, _ := fs.Glob(templateFS, "templates/*.html")
	for _, f := range files {
		src, _ := fs.ReadFile(templateFS, f)
		for _, m := range tKeyRE.FindAllStringSubmatch(string(src), -1) {
			keys = append(keys, m[1])
		}
	}
	goKeyRE := regexp.MustCompile(`"((?:login|dblogin|error|keycheck|status|private|options|databases|tab|editor|newkey|newsshkey|sshkey|newpgpkey|pgpkey|dbpw|item|keypw|create|import|ca|rev|crlgen|renew|oid)\.[a-z_.]*[a-z])"`)
	gofiles, _ := filepath.Glob("*.go")
	for _, f := range gofiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, _ := os.ReadFile(f)
		for _, m := range goKeyRE.FindAllStringSubmatch(string(src), -1) {
			keys = append(keys, m[1])
		}
	}
	for _, tab := range append(tabs, "options") {
		keys = append(keys, "tab."+tab)
	}
	for _, cols := range columns {
		for _, c := range cols {
			keys = append(keys, c.Label)
		}
	}
	for _, o := range optionKeys {
		keys = append(keys, o.label)
	}
	for _, st := range []store.Status{store.Supported, store.Upgradable, store.Outdated, store.Newer, store.Legacy, store.Invalid} {
		keys = append(keys, "dbstatus."+string(st))
		if !st.Openable() {
			keys = append(keys, "dbstatus.help."+string(st))
		}
	}
	for _, k := range []string{"key", "cert", "request", "crl", "template"} {
		keys = append(keys, "kind."+k)
	}
	for _, k := range []string{"unknown", "imported", "generated", "transformed", "token", "legacy_db", "renewed"} {
		keys = append(keys, "source."+k)
	}
	for _, r := range []string{"unspecified", "keyCompromise", "CACompromise", "affiliationChanged", "superseded",
		"cessationOfOperation", "certificateHold", "removeFromCRL", "privilegeWithdrawn", "AACompromise"} {
		keys = append(keys, "reason."+r)
	}
	keys = append(keys, "val.yes", "val.no")
	for _, h := range pki.Hashes {
		keys = append(keys, "hash."+h)
	}
	for _, k := range []string{"attribute", "extension", "eku", "signature", "curve", "policy", "other"} {
		keys = append(keys, "oid.kind."+k)
	}
	for _, k := range []string{"cert", "request", "template"} {
		keys = append(keys, "editor.title."+k, "editor.heading."+k, "editor.create."+k)
	}
	for _, k := range []string{"key", "cert", "request", "crl", "template"} {
		keys = append(keys, "actions.delete.warn."+k)
	}
	for _, k := range []string{"created", "saved", "keypw", "revoked", "unrevoked"} {
		keys = append(keys, "item.notice."+k)
	}
	for _, k := range []string{"noname", "extract", "keypass", "torequest", "totemplate"} {
		keys = append(keys, "item.error."+k)
	}
	for _, u := range []string{"%", "D", "W"} {
		keys = append(keys, "unit.sym."+u)
	}
	for _, f := range sshFlavors {
		keys = append(keys, "sshkey.flavor."+f, "sshkey.flavor."+f+".help")
	}
	for _, f := range pgpFlavors {
		keys = append(keys, "pgpkey.flavor."+f, "pgpkey.flavor."+f+".help")
	}
	for _, v := range pgpVersions {
		keys = append(keys, "pgpkey.version."+v)
	}
	for _, e := range pgpExpiries {
		keys = append(keys, "pgpkey.expiry."+e)
	}
	for _, u := range append(pgpUsages, codec.PGPCertify) {
		keys = append(keys, "pgpkey.usage."+u)
	}
	for _, n := range []string{"created", "subkey", "removed"} {
		keys = append(keys, "pgpkey.notice."+n)
	}
	keys = append(keys, "keypw.error.mismatch", "keypw.error.current", "list.deleted.notice",
		"converted.ownpass", "dump.error.password", "converting.title")
	for _, k := range keys {
		if !cat.Has(k) {
			t.Errorf("message key %q missing from locales/en.json", k)
		}
	}
}

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseFull(t *testing.T) {
	base := t.TempDir()
	c, err := Parse([]byte(`
general:
  data_dir: data
  listen: "127.0.0.1:9443"
  tls_cert: tls/cert.pem
  tls_key: /etc/go-ca/key.pem
  idle_timeout: 45m
  max_upload_mb: 64
  password_hash: " $argon2id$x "
crl:
  listen: "127.0.0.1:8081"
  base_urls:
    - http://pki.example.org/
    - http://pki.lan:8080/pki
databases:
  - name: Home Lab CA
    type: file
    path: homelab.gca
    password: secret
  - name: Archive
    path: old/archive.gca
`), base)
	if err != nil {
		t.Fatal(err)
	}
	g := c.General
	if g.DataDir != filepath.Join(base, "data") || g.Listen != "127.0.0.1:9443" || g.IdleTimeout != 45*time.Minute ||
		g.MaxUploadMB != 64 || g.PasswordHash != "$argon2id$x" {
		t.Fatalf("general = %+v", g)
	}
	if g.TLSCert != filepath.Join(base, "tls/cert.pem") || g.TLSKey != "/etc/go-ca/key.pem" {
		t.Fatalf("tls = %q %q", g.TLSCert, g.TLSKey)
	}
	if len(c.Databases) != 2 {
		t.Fatalf("databases = %+v", c.Databases)
	}
	d0, d1 := c.Databases[0], c.Databases[1]
	if d0.Path != filepath.Join(base, "data", "homelab.gca") || !d0.Background() {
		t.Fatalf("db0 = %+v", d0)
	}
	if d1.Type != TypeFile || d1.Path != filepath.Join(base, "data", "old", "archive.gca") || d1.Background() {
		t.Fatalf("db1 = %+v", d1)
	}
	if !c.HasPasswords() {
		t.Fatal("HasPasswords = false")
	}
	if c.CRL.ListenAddr() != "127.0.0.1:8081" || strings.Join(c.CRL.BaseURLs, " ") != "http://pki.example.org http://pki.lan:8080/pki" {
		t.Fatalf("crl = %q %v", c.CRL.ListenAddr(), c.CRL.BaseURLs)
	}
}

func TestCRLListen(t *testing.T) {
	for yaml, want := range map[string]string{
		"":                            DefaultCRLListen,
		"crl:\n  base_urls: []\n":     DefaultCRLListen,
		"crl:\n  listen: \"\"\n":      "",
		"crl:\n  listen: \":9000\"\n": ":9000",
	} {
		c, err := Parse([]byte("general:\n  data_dir: d\n"+yaml), "/b")
		if err != nil {
			t.Fatal(err)
		}
		if got := c.CRL.ListenAddr(); got != want {
			t.Errorf("%q: listen %q, want %q", yaml, got, want)
		}
	}
}

func TestParseDefaults(t *testing.T) {
	c, err := Parse([]byte("general:\n  data_dir: /srv/ca\n"), "/etc")
	if err != nil {
		t.Fatal(err)
	}
	g := c.General
	if g.DataDir != "/srv/ca" || g.Listen != DefaultListen || g.IdleTimeout != DefaultIdleTimeout || g.MaxUploadMB != DefaultMaxUploadMB {
		t.Fatalf("general = %+v", g)
	}
	if len(c.Databases) != 0 || c.HasPasswords() {
		t.Fatalf("databases = %+v", c.Databases)
	}
}

func TestParseErrors(t *testing.T) {
	gen := "general:\n  data_dir: d\n"
	db := func(s string) string { return gen + "databases:\n" + s }
	for _, tc := range []struct{ yaml, want string }{
		{"", "data_dir is required"},
		{"general:\n  data_dir: d\n  listn: x\n", "field listn not found"},
		{"general:\n  data_dir: d\n  tls_cert: c\n", "go together"},
		{"general:\n  data_dir: d\n  idle_timeout: 10s\n", "at least 1m"},
		{"general:\n  data_dir: d\n  idle_timeout: soon\n", "time.Duration"},
		{"general:\n  data_dir: d\n  max_upload_mb: -1\n", "max_upload_mb"},
		{db("  - path: a.gca\n"), "name is required"},
		{db("  - name: A\n    path: a.gca\n  - name: A\n    path: b.gca\n"), "name already used"},
		{db("  - name: A\n    type: ldap\n    path: a.gca\n"), "unknown type"},
		{db("  - name: A\n"), "path is required"},
		{db("  - name: A\n    path: /abs/a.gca\n"), "relative"},
		{db("  - name: A\n    path: ../a.gca\n"), "inside"},
		{db("  - name: A\n    path: x/../../a.gca\n"), "inside"},
		{db("  - name: A\n    path: .hidden/a.gca\n"), "hidden"},
		{db("  - name: A\n    path: a.xdb\n"), "XCA"},
		{db("  - name: A\n    path: a.GCA\n"), "lower case"},
		{db("  - name: A\n    path: a.db\n"), ".gca"},
		{db("  - name: A\n    path: a.gca\n  - name: B\n    path: sub/A.gca\n"), "file name"},
		{db("  - name: A\n    path: a.gca\n    passwd: x\n"), "field passwd not found"},
		{gen + "crl:\n  base_urls: [https://pki.example.org]\n", "http://"},
		{gen + "crl:\n  base_urls: [\"http://\"]\n", "no host"},
		{gen + "crl:\n  base_urls: [\"http://x/?a=1\"]\n", "query"},
		{gen + "crl:\n  base_urls: [http://x/, http://x]\n", "twice"},
		{gen + "crl:\n  lisen: x\n", "field lisen not found"},
	} {
		_, err := Parse([]byte(tc.yaml), "/base")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.yaml, err, tc.want)
		}
	}
}

func TestLoadAndPermissions(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing: %v", err)
	}
	p := filepath.Join(dir, "config.yaml")
	body := "general:\n  data_dir: data\ndatabases:\n  - name: A\n    type: file\n    path: a.gca\n    password: pw\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.File != p || c.General.DataDir != filepath.Join(dir, "data") {
		t.Fatalf("config = %+v", c)
	}
	if w := c.CheckPermissions(); !strings.Contains(w, "chmod 600") {
		t.Fatalf("warning = %q", w)
	}
	os.Chmod(p, 0o600)
	if w := c.CheckPermissions(); w != "" {
		t.Fatalf("warning = %q", w)
	}
}

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
  listen: "127.0.0.1:9443"
  tls_cert: tls/cert.pem
  tls_key: /etc/openkca/key.pem
  idle_timeout: 45m
  max_upload_mb: 64
  password_hash: " $argon2id$x "
crl:
  listen: "127.0.0.1:8081"
  base_urls:
    - http://pki.example.org/
    - http://pki.lan:8080/pki
est:
  listen: ":9443"
  client_cert_header: X-SSL-Client-Cert
databases:
  - name: Home Lab CA
    type: file
    path: homelab.okca
    password: secret
  - name: Archive
    path: old/archive.okca
`), base)
	if err != nil {
		t.Fatal(err)
	}
	g := c.General
	if g.DataDir != filepath.Join(base, "data") || g.Listen != "127.0.0.1:9443" || g.IdleTimeout != 45*time.Minute ||
		g.MaxUploadMB != 64 || g.PasswordHash != "$argon2id$x" {
		t.Fatalf("general = %+v", g)
	}
	if g.TLSCert != filepath.Join(base, "tls/cert.pem") || g.TLSKey != "/etc/openkca/key.pem" {
		t.Fatalf("tls = %q %q", g.TLSCert, g.TLSKey)
	}
	if len(c.Databases) != 2 {
		t.Fatalf("databases = %+v", c.Databases)
	}
	d0, d1 := c.Databases[0], c.Databases[1]
	if d0.Path != filepath.Join(base, "data", "homelab.okca") || !d0.Background() {
		t.Fatalf("db0 = %+v", d0)
	}
	if d1.Type != TypeFile || d1.Path != filepath.Join(base, "data", "old", "archive.okca") || d1.Background() {
		t.Fatalf("db1 = %+v", d1)
	}
	if !c.HasPasswords() {
		t.Fatal("HasPasswords = false")
	}
	if c.CRL.ListenAddr() != "127.0.0.1:8081" || strings.Join(c.CRL.BaseURLs, " ") != "http://pki.example.org http://pki.lan:8080/pki" {
		t.Fatalf("crl = %q %v", c.CRL.ListenAddr(), c.CRL.BaseURLs)
	}
	if c.EST.Listen != ":9443" || c.EST.ClientCertHeader != "X-SSL-Client-Cert" {
		t.Fatalf("est = %+v", c.EST)
	}
}

func TestCRLListen(t *testing.T) {
	for yaml, want := range map[string]string{
		"":                            DefaultCRLListen,
		"crl:\n  base_urls: []\n":     DefaultCRLListen,
		"crl:\n  listen: \"\"\n":      "",
		"crl:\n  listen: \":9000\"\n": ":9000",
	} {
		c, err := Parse([]byte("general:\n"+yaml), "/b")
		if err != nil {
			t.Fatal(err)
		}
		if got := c.CRL.ListenAddr(); got != want {
			t.Errorf("%q: listen %q, want %q", yaml, got, want)
		}
	}
}

func TestParseDefaults(t *testing.T) {
	c, err := Parse(nil, "/etc")
	if err != nil {
		t.Fatal(err)
	}
	g := c.General
	if g.DataDir != filepath.Join("/etc", DataDirName) || g.Listen != ":9080" || g.TLS() || len(g.Proxies) != 0 ||
		g.IdleTimeout != DefaultIdleTimeout || g.MaxUploadMB != DefaultMaxUploadMB || c.CRL.ListenAddr() != ":9081" {
		t.Fatalf("general = %+v, crl = %q", g, c.CRL.ListenAddr())
	}
	if len(c.Databases) != 0 || c.HasPasswords() || len(c.Warnings) != 0 {
		t.Fatalf("databases = %+v, warnings = %q", c.Databases, c.Warnings)
	}
	if c, err = Parse([]byte("general:\n  https: true\n"), "/etc"); err != nil || !c.General.TLS() {
		t.Fatalf("https: true: %v", err)
	}
}

// The former data_dir key is accepted, ignored and warned about.
func TestLegacyDataDir(t *testing.T) {
	c, err := Parse([]byte("general:\n  data_dir: /srv/ca\ndatabases:\n  - name: A\n    path: a.okca\n"), "/etc/okca")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("/etc/okca", "data"); c.General.DataDir != want || c.Databases[0].Path != filepath.Join(want, "a.okca") {
		t.Fatalf("data folder %q, db %q", c.General.DataDir, c.Databases[0].Path)
	}
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "data_dir") {
		t.Fatalf("warnings = %q", c.Warnings)
	}
}

func TestParseErrors(t *testing.T) {
	gen := "general:\n"
	db := func(s string) string { return gen + "databases:\n" + s }
	for _, tc := range []struct{ yaml, want string }{
		{"general:\n  listn: x\n", "field listn not found"},
		{"general:\n  tls_cert: c\n", "go together"},
		{"general:\n  idle_timeout: 10s\n", "at least 1m"},
		{"general:\n  idle_timeout: soon\n", "time.Duration"},
		{"general:\n  max_upload_mb: -1\n", "max_upload_mb"},
		{db("  - path: a.okca\n"), "name is required"},
		{db("  - name: A\n    path: a.okca\n  - name: A\n    path: b.okca\n"), "name already used"},
		{db("  - name: A\n    type: ldap\n    path: a.okca\n"), "unknown type"},
		{db("  - name: A\n"), "path is required"},
		{db("  - name: A\n    path: /abs/a.okca\n"), "relative"},
		{db("  - name: A\n    path: ../a.okca\n"), "inside"},
		{db("  - name: A\n    path: x/../../a.okca\n"), "inside"},
		{db("  - name: A\n    path: .hidden/a.okca\n"), "hidden"},
		{db("  - name: A\n    path: a.xdb\n"), "XCA"},
		{db("  - name: A\n    path: a.OKCA\n"), "lower case"},
		{db("  - name: A\n    path: a.db\n"), ".okca"},
		{db("  - name: A\n    path: a.okca\n  - name: B\n    path: sub/A.okca\n"), "file name"},
		{db("  - name: A\n    path: a.okca\n    passwd: x\n"), "field passwd not found"},
		{gen + "crl:\n  base_urls: [https://pki.example.org]\n", "http://"},
		{gen + "crl:\n  base_urls: [\"http://\"]\n", "no host"},
		{gen + "crl:\n  base_urls: [\"http://x/?a=1\"]\n", "query"},
		{gen + "crl:\n  base_urls: [http://x/, http://x]\n", "twice"},
		{gen + "crl:\n  lisen: x\n", "field lisen not found"},
		{gen + "est:\n  listen: \"9443\"\n", "est.listen"},
		{gen + "est:\n  client_cert_header: \"X: y\"\n", "est.client_cert_header"},
		{gen + "  https: no-thanks\n", "into bool"},
		{gen + "  trusted_proxies: [proxy.lan]\n", "trusted_proxies[0]"},
		{gen + "  trusted_proxies: [10.0.0.0/33]\n", "trusted_proxies[0]"},
	} {
		_, err := Parse([]byte(tc.yaml), "/base")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.yaml, err, tc.want)
		}
	}
}

func TestHTTPSAndProxies(t *testing.T) {
	c, err := Parse([]byte(`
general:
  https: false
  trusted_proxies: ["127.0.0.1", " 10.1.2.3/8 ", "::1", "fd00::/8"]
`), "/b")
	if err != nil {
		t.Fatal(err)
	}
	g := c.General
	if g.TLS() {
		t.Fatal("https: false is TLS")
	}
	var got []string
	for _, p := range g.Proxies {
		got = append(got, p.String())
	}
	if strings.Join(got, " ") != "127.0.0.1/32 10.0.0.0/8 ::1/128 fd00::/8" {
		t.Fatalf("proxies = %v", got)
	}
	// TLS files may stay configured while they are not used
	if _, err := Parse([]byte("general:\n  https: false\n  tls_cert: c\n  tls_key: k\n"), "/b"); err != nil {
		t.Fatal(err)
	}
}

func TestPackagedPath(t *testing.T) {
	defer func(p string) { packagedPath = p }(packagedPath)
	packagedPath = ""
	if p, err := DefaultPath(); err != nil || filepath.Base(p) != FileName || PackagedPath() != "" {
		t.Fatalf("plain binary: %q %v", p, err)
	}
	t.Setenv("OKCA_TEST_DIR", "/srv/okca")
	packagedPath = "${OKCA_TEST_DIR}/conf/../config.yaml"
	if p, err := DefaultPath(); err != nil || p != filepath.Clean("/srv/okca/config.yaml") || PackagedPath() != p {
		t.Fatalf("package: %q %v", p, err)
	}
}

func TestLoadAndPermissions(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing: %v", err)
	}
	p := filepath.Join(dir, "config.yaml")
	body := "general:\n  https: false\ndatabases:\n  - name: A\n    type: file\n    path: a.okca\n    password: pw\n"
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

func TestWebAuthn(t *testing.T) {
	parse := func(listen, w string) (*Config, error) {
		return Parse([]byte("general:\n  https: true\n  listen: \""+listen+"\"\n"+w), "/base")
	}
	c, err := parse(":8443", "")
	if err != nil || c.General.WebAuthn.Enabled() {
		t.Fatalf("off by default: %+v %v", c.General.WebAuthn, err)
	}
	c, err = parse(":8443", "  webauthn:\n    rp_id: CA.Example.org\n")
	w := c.General.WebAuthn
	if err != nil || !w.Enabled() || w.RPID != "ca.example.org" || w.RPName != DefaultRPName ||
		len(w.Origins) != 2 || w.Origins[0] != "https://ca.example.org" || w.Origins[1] != "https://ca.example.org:8443" {
		t.Fatalf("defaults: %+v %v", w, err)
	}
	c, err = parse(":443", "  webauthn:\n    rp_id: ca.example.org\n")
	if err != nil || len(c.General.WebAuthn.Origins) != 1 {
		t.Fatalf("port 443: %+v %v", c.General.WebAuthn, err)
	}
	// behind a TLS proxy the listen port is not the one browsers use
	c, err = Parse([]byte("general:\n  listen: \":8080\"\n  webauthn:\n    rp_id: ca.example.org\n"), "/base")
	if err != nil || len(c.General.WebAuthn.Origins) != 1 || c.General.WebAuthn.Origins[0] != "https://ca.example.org" {
		t.Fatalf("plain HTTP: %+v %v", c.General.WebAuthn, err)
	}
	c, err = parse(":8443", "  webauthn:\n    rp_id: example.org\n    rp_name: Lab\n    origins: [\"https://pki.Example.org:9443/\"]\n")
	w = c.General.WebAuthn
	if err != nil || w.RPName != "Lab" || len(w.Origins) != 1 || w.Origins[0] != "https://pki.example.org:9443" {
		t.Fatalf("explicit: %+v %v", w, err)
	}
	for _, bad := range []string{
		"  webauthn:\n    rp_id: 192.168.1.10\n",
		"  webauthn:\n    rp_id: \"[::1]\"\n",
		"  webauthn:\n    rp_id: https://ca.example.org\n",
		"  webauthn:\n    rp_id: ca.example.org:8443\n",
		"  webauthn:\n    rp_name: x\n",
		"  webauthn:\n    rp_id: ca.example.org\n    origins: [\"http://ca.example.org\"]\n",
		"  webauthn:\n    rp_id: ca.example.org\n    origins: [\"https://other.org\"]\n",
		"  webauthn:\n    rp_id: ca.example.org\n    origins: [\"https://evilca.example.org\"]\n",
		"  webauthn:\n    rp_id: ca.example.org\n    origins: [\"https://ca.example.org/path\"]\n",
	} {
		if _, err := parse(":8443", bad); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
}

// Package config reads OpenKCA's YAML configuration file: the server's
// settings (formerly command line options) and the databases OpenKCA keeps
// open.
//
//	general:
//	  data_dir: data                # relative to the config file's folder
//	  listen: ":9443"
//	  https: true                   # false: plain HTTP behind a TLS proxy
//	  tls_cert: ""                  # PEM; empty = self-issued certificate
//	  tls_key: ""
//	  trusted_proxies: []           # proxies whose X-Forwarded-For counts
//	  idle_timeout: 30m
//	  max_upload_mb: 256
//	  password_hash: "$argon2id$…"  # from "openkca set-password"
//	  webauthn:                     # optional: security keys and passkeys
//	    rp_id: ca.example.org       # the host name users open OpenKCA with
//	    rp_name: OpenKCA            # optional, shown by the authenticator
//	    origins:                    # optional; default https://<rp_id>[:port]
//	      - https://ca.example.org:9443
//	crl:
//	  listen: ":9080"               # plain HTTP for CRLs and CA certificates; "" = off
//	  base_urls:                    # offered as CDP/AIA in new certificates
//	    - http://pki.example.org
//	databases:
//	  - name: Home Lab CA           # shown in the web UI
//	    type: file
//	    path: homelab.okca           # relative to data_dir
//	    password: "…"               # optional: open in the background
//
// A database with a password is opened when OpenKCA starts and stays open
// with its keys unlocked, so that OpenKCA can do CA work on its own. Users
// still log into it with the database password in the web UI. A database
// without a password is only listed under its name.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// FileName is the configuration file looked for next to the executable.
const FileName = "config.yaml"

// packagedPath is the configuration file of a package (rpm, MSI), set at
// build time; $VAR and ${VAR} in it are expanded:
//
//	-ldflags "-X github.com/mailsvb/openkca/internal/config.packagedPath=/etc/openkca/config.yaml"
var packagedPath string

// Defaults of the general section.
const (
	DefaultListen      = ":9443"
	DefaultIdleTimeout = 30 * time.Minute
	DefaultMaxUploadMB = 256
)

// TypeFile is the only database type: a .okca file in the data folder.
const TypeFile = "file"

// DefaultCRLListen is the address of the plain HTTP publication server.
const DefaultCRLListen = ":9080"

// CRL configures the publication of CRLs and CA certificates.
type CRL struct {
	// Listen is the address of the plain HTTP server; "" turns it off.
	// Left out, it is DefaultCRLListen.
	Listen *string `yaml:"listen"`
	// BaseURLs are the http:// URLs the server is reachable at, in the
	// order clients should try them; without a trailing slash once parsed.
	BaseURLs []string `yaml:"base_urls"`
}

// ListenAddr returns the publication server's address, "" when off.
func (c CRL) ListenAddr() string {
	if c.Listen == nil {
		return DefaultCRLListen
	}
	return strings.TrimSpace(*c.Listen)
}

// General holds the server settings.
type General struct {
	DataDir string `yaml:"data_dir"`
	Listen  string `yaml:"listen"`
	// HTTPS is false to serve plain HTTP behind a TLS proxy; left out, it
	// is true.
	HTTPS        *bool         `yaml:"https"`
	TLSCert      string        `yaml:"tls_cert"`
	TLSKey       string        `yaml:"tls_key"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
	MaxUploadMB  int64         `yaml:"max_upload_mb"`
	PasswordHash string        `yaml:"password_hash"`
	WebAuthn     WebAuthn      `yaml:"webauthn"`
	// TrustedProxies are the addresses (IP or CIDR) of reverse proxies
	// whose X-Forwarded-For and X-Forwarded-Proto headers are believed.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// Proxies is TrustedProxies parsed.
	Proxies []netip.Prefix `yaml:"-"`
}

// TLS reports whether the web UI is served over HTTPS.
func (g General) TLS() bool { return g.HTTPS == nil || *g.HTTPS }

// WebAuthn configures security keys and passkeys as unlock methods. They
// are bound to RPID, so they are offered only when it is set.
type WebAuthn struct {
	RPID    string   `yaml:"rp_id"`
	RPName  string   `yaml:"rp_name"`
	Origins []string `yaml:"origins"`
}

// Enabled reports whether security keys and passkeys can be used.
func (w WebAuthn) Enabled() bool { return w.RPID != "" }

// DefaultRPName is the relying party name shown by authenticators.
const DefaultRPName = "OpenKCA"

// Database is one database section.
type Database struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Path     string `yaml:"path"`
	Password string `yaml:"password"`
}

// Background reports whether OpenKCA keeps the database open on its own.
func (d Database) Background() bool { return d.Password != "" }

// Config is a parsed and checked configuration. Paths are absolute.
type Config struct {
	File      string // the configuration file
	General   General
	CRL       CRL
	Databases []Database
}

// PackagedPath is the configuration file of the package this binary was
// built for, read by its service; "" for a plain binary.
func PackagedPath() string {
	if packagedPath == "" {
		return ""
	}
	return filepath.Clean(os.ExpandEnv(packagedPath))
}

// DefaultPath is the package's configuration file in a package build,
// otherwise config.yaml in the folder of the running executable.
func DefaultPath() (string, error) {
	if p := PackagedPath(); p != "" {
		return p, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Join(filepath.Dir(exe), FileName), nil
}

// Load reads and checks a configuration file.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("configuration file %s not found; run \"openkca setup\" in a terminal or see config.example.yaml", abs)
		}
		return nil, err
	}
	c, err := Parse(b, filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	c.File = abs
	return c, nil
}

// Parse parses a configuration; relative paths resolve against base.
func Parse(b []byte, base string) (*Config, error) {
	var raw struct {
		General   General    `yaml:"general"`
		CRL       CRL        `yaml:"crl"`
		Databases []Database `yaml:"databases"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	c := &Config{General: raw.General, CRL: raw.CRL, Databases: raw.Databases}
	if err := c.check(base); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) check(base string) error {
	g := &c.General
	if strings.TrimSpace(g.DataDir) == "" {
		return errors.New("general.data_dir is required")
	}
	g.DataDir = resolve(base, g.DataDir)
	if g.Listen == "" {
		g.Listen = DefaultListen
	}
	if (g.TLSCert == "") != (g.TLSKey == "") {
		return errors.New("general.tls_cert and general.tls_key go together")
	}
	if g.TLSCert != "" {
		g.TLSCert, g.TLSKey = resolve(base, g.TLSCert), resolve(base, g.TLSKey)
	}
	switch {
	case g.IdleTimeout == 0:
		g.IdleTimeout = DefaultIdleTimeout
	case g.IdleTimeout < time.Minute:
		return errors.New("general.idle_timeout must be at least 1m")
	}
	switch {
	case g.MaxUploadMB == 0:
		g.MaxUploadMB = DefaultMaxUploadMB
	case g.MaxUploadMB < 0 || g.MaxUploadMB > 1<<20:
		return errors.New("general.max_upload_mb must be between 1 and 1048576")
	}
	g.PasswordHash = strings.TrimSpace(g.PasswordHash)
	g.Proxies = nil
	for i, raw := range g.TrustedProxies {
		p, err := parsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("general.trusted_proxies[%d]: %q is not an IP address or CIDR range", i, raw)
		}
		g.Proxies = append(g.Proxies, p)
	}
	listen := g.Listen
	if !g.TLS() {
		listen = "" // the proxy's port is not known
	}
	if err := g.WebAuthn.check(listen); err != nil {
		return err
	}
	if err := c.CRL.check(); err != nil {
		return err
	}

	names, files := map[string]int{}, map[string]int{}
	for i := range c.Databases {
		d := &c.Databases[i]
		where := fmt.Sprintf("databases[%d]", i)
		d.Name = strings.TrimSpace(d.Name)
		if d.Name == "" {
			return fmt.Errorf("%s: name is required", where)
		}
		where = fmt.Sprintf("%s (%s)", where, d.Name)
		if j, dup := names[d.Name]; dup {
			return fmt.Errorf("%s: name already used by databases[%d]", where, j)
		}
		names[d.Name] = i
		if d.Type == "" {
			d.Type = TypeFile
		}
		if d.Type != TypeFile {
			return fmt.Errorf("%s: unknown type %q (only %q)", where, d.Type, TypeFile)
		}
		p, err := dataPath(g.DataDir, d.Path)
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		d.Path = p
		// The file name without .okca is the database's name in URLs and
		// folders, so it must be unique too.
		stem := strings.ToLower(strings.TrimSuffix(filepath.Base(p), filepath.Ext(p)))
		if j, dup := files[stem]; dup {
			return fmt.Errorf("%s: file name %s already used by databases[%d]", where, filepath.Base(p), j)
		}
		files[stem] = i
	}
	return nil
}

// check validates the base URLs: plain http:// with a host, no query or
// fragment, each once.
func (c *CRL) check() error {
	seen := map[string]bool{}
	for i, raw := range c.BaseURLs {
		where := fmt.Sprintf("crl.base_urls[%d]", i)
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		switch {
		case u.Scheme != "http":
			return fmt.Errorf("%s: %q must be an http:// URL (CRLs and CA certificates are published over plain HTTP)", where, raw)
		case u.Host == "" || u.Hostname() == "":
			return fmt.Errorf("%s: %q has no host", where, raw)
		case u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "":
			return fmt.Errorf("%s: %q must not have a user, query or fragment", where, raw)
		}
		norm := strings.TrimRight(u.String(), "/")
		if seen[norm] {
			return fmt.Errorf("%s: %q is listed twice", where, raw)
		}
		seen[norm] = true
		c.BaseURLs[i] = norm
	}
	return nil
}

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// parsePrefix parses a CIDR range or a single IP address.
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// check validates the WebAuthn section: rp_id a domain name (WebAuthn does
// not work with IP addresses), each origin an https:// URL on rp_id or a
// subdomain of it. Without origins, https://<rp_id> and, for another port
// than 443, https://<rp_id>:<port of listen> are allowed; listen is "" when
// a TLS proxy serves the web UI.
func (w *WebAuthn) check(listen string) error {
	w.RPID = strings.ToLower(strings.TrimSpace(w.RPID))
	w.RPName = strings.TrimSpace(w.RPName)
	if w.RPID == "" {
		if len(w.Origins) > 0 || w.RPName != "" {
			return errors.New("general.webauthn: rp_id is required")
		}
		return nil
	}
	if net.ParseIP(strings.Trim(w.RPID, "[]")) != nil {
		return fmt.Errorf("general.webauthn.rp_id: %q is an IP address; security keys and passkeys need a domain name", w.RPID)
	}
	labels := strings.Split(w.RPID, ".")
	for _, l := range labels {
		if !hostLabel.MatchString(l) {
			return fmt.Errorf("general.webauthn.rp_id: %q is not a domain name (no scheme, port or path)", w.RPID)
		}
	}
	if w.RPName == "" {
		w.RPName = DefaultRPName
	}
	if len(w.Origins) == 0 {
		w.Origins = []string{"https://" + w.RPID}
		if _, port, err := net.SplitHostPort(listen); err == nil && port != "" && port != "443" {
			w.Origins = append(w.Origins, "https://"+net.JoinHostPort(w.RPID, port))
		}
		return nil
	}
	for i, raw := range w.Origins {
		where := fmt.Sprintf("general.webauthn.origins[%d]", i)
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		host := strings.ToLower(u.Hostname())
		switch {
		case u.Scheme != "https":
			return fmt.Errorf("%s: %q must be an https:// URL", where, raw)
		case host != w.RPID && !strings.HasSuffix(host, "."+w.RPID):
			return fmt.Errorf("%s: %q is not on %s or a subdomain of it", where, raw, w.RPID)
		case u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
			return fmt.Errorf("%s: %q must be scheme, host and port only", where, raw)
		}
		w.Origins[i] = "https://" + strings.ToLower(u.Host)
	}
	return nil
}

// dataPath checks a database path from the configuration: relative to the
// data folder, inside it, and a .okca file.
func dataPath(dataDir, p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errors.New("path is required")
	}
	if filepath.IsAbs(p) {
		return "", errors.New("path must be relative to general.data_dir")
	}
	clean := filepath.Clean(filepath.FromSlash(p))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("path must stay inside general.data_dir")
	}
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if strings.HasPrefix(part, ".") {
			return "", errors.New("path must not contain hidden files or folders")
		}
	}
	switch strings.ToLower(filepath.Ext(clean)) {
	case ".okca":
		if filepath.Ext(clean) != ".okca" {
			return "", errors.New("the file extension must be .okca in lower case")
		}
	case ".xdb":
		return "", errors.New("an XCA database (.xdb) cannot be configured: open it once in the web UI to convert it, then configure the .okca file")
	default:
		return "", errors.New("path must name an OpenKCA database (.okca)")
	}
	return filepath.Join(dataDir, clean), nil
}

func resolve(base, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(base, p)
}

// HasPasswords reports whether any database password is configured.
func (c *Config) HasPasswords() bool {
	for _, d := range c.Databases {
		if d.Background() {
			return true
		}
	}
	return false
}

// CheckPermissions returns a warning when the file holds database
// passwords and others than its owner may read it. Windows has ACLs, not
// mode bits: the MSI restricts the folder instead.
func (c *Config) CheckPermissions() string {
	if !c.HasPasswords() || runtime.GOOS == "windows" {
		return ""
	}
	fi, err := os.Stat(c.File)
	if err != nil {
		return ""
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Sprintf("%s holds database passwords and is readable by others (mode %04o); use chmod 600", c.File, fi.Mode().Perm())
	}
	return ""
}

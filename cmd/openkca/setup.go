package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/mailsvb/openkca/internal/auth"
	"github.com/mailsvb/openkca/internal/config"
)

// initialPassword is the file next to the configuration in which the rpm
// package keeps the random server password of the first install.
const initialPassword = "initial-password"

// Names of the TLS files --copy-tls puts next to the configuration.
const (
	copiedCert = "tls.crt"
	copiedKey  = "tls.key"
)

func stdinIsTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// setupFlags are the answers given on the command line. With any of them
// setup asks nothing, for installers and scripts.
type setupFlags struct {
	set           map[string]bool // the flags given
	https         bool
	port, crlPort int
	tlsCert       string
	tlsKey        string
	copyTLS       bool
	password      string
	passwordStdin bool
}

// setup asks for the ports, HTTPS and the server password, or takes them
// from flags, and writes them into the configuration file.
func setup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	f := setupFlags{set: map[string]bool{}}
	fs.BoolVar(&f.https, "https", true, "serve the web UI over HTTPS; false: plain HTTP behind a TLS proxy")
	fs.IntVar(&f.port, "port", 0, "port of the web UI")
	fs.IntVar(&f.crlPort, "crl-port", 0, "port of the plain HTTP CRL server, 0 = off")
	fs.StringVar(&f.tlsCert, "tls-cert", "", "PEM certificate for HTTPS; empty with -tls-key: a self-issued one")
	fs.StringVar(&f.tlsKey, "tls-key", "", "PEM key of -tls-cert")
	fs.BoolVar(&f.copyTLS, "copy-tls", false, "copy -tls-cert and -tls-key next to the configuration file")
	fs.StringVar(&f.password, "password", "", "server password, empty keeps the current one (visible to other processes: prefer -password-stdin)")
	fs.BoolVar(&f.passwordStdin, "password-stdin", false, "read the server password from the first line of stdin")
	path, err := configPath(fs, args)
	if err != nil {
		return err
	}
	fs.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })
	delete(f.set, "config")
	if path, err = filepath.Abs(path); err != nil {
		return err
	}
	_, statErr := os.Stat(path)
	unattended := len(f.set) > 0
	var changed bool
	if unattended {
		changed, err = setupUnattended(path, f)
	} else {
		changed, err = runSetup(path)
	}
	if err != nil || !changed || statErr != nil {
		return err
	}
	return afterSetup(path, unattended)
}

// afterSetup restarts the service reading the configuration at path, if
// there is one and the user agrees, so that the changes take effect.
func afterSetup(path string, unattended bool) error {
	name := installedService(path)
	if name == "" {
		fmt.Fprintln(os.Stderr, "Restart OpenKCA to apply the changes.")
		return nil
	}
	hint := fmt.Sprintf("Restart the %s service to apply the changes: %s", name, restartCommand)
	if unattended || !stdinIsTerminal() {
		fmt.Fprintln(os.Stderr, hint)
		return nil
	}
	restart, err := askYesNo(bufio.NewReader(os.Stdin), "Restart the "+name+" service now", true)
	if err != nil || !restart {
		fmt.Fprintln(os.Stderr, hint)
		return nil
	}
	if err := restartService(name); err != nil {
		return fmt.Errorf("restarting the %s service: %w", name, err)
	}
	fmt.Fprintf(os.Stderr, "Restarted the %s service.\n", name)
	return nil
}

// current is a configuration file as setup finds it.
type current struct {
	path   string
	b      []byte // its text, nil when there is none yet
	values config.Settings
}

// loadCurrent reads the configuration file at path, an absolute path, if
// there is one; its values default to those of a new installation.
func loadCurrent(path string) (*current, error) {
	cur := &current{path: path, values: config.Settings{
		Listen: config.DefaultListen, CRLListen: config.DefaultCRLListen, HTTPS: true}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cur, nil
	}
	if err != nil {
		return nil, withAdminHint(err)
	}
	c, err := config.Parse(b, filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	g := c.General
	cur.b = b
	cur.values = config.Settings{Listen: g.Listen, CRLListen: c.CRL.ListenAddr(), HTTPS: g.TLS(),
		TLSCert: g.TLSCert, TLSKey: g.TLSKey, PasswordHash: g.PasswordHash}
	return cur, nil
}

// withAdminHint adds what to do to a permission error.
func withAdminHint(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w (%s)", err, adminHint)
	}
	return err
}

// runSetup asks whether to use HTTPS and with which certificate, for the
// web UI port, the CRL port and the server password, each defaulting to the
// current value, and writes the configuration file at path, a new one if
// there is none. It reports whether anything changed.
func runSetup(path string) (bool, error) {
	if !stdinIsTerminal() {
		return false, errors.New("setup asks questions: run it in a terminal, or give the answers as flags (openkca setup -h)")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	cur, err := loadCurrent(path)
	if err != nil {
		return false, err
	}
	old := cur.values
	next := old

	in := bufio.NewReader(os.Stdin)
	if next.HTTPS, err = askYesNo(in, "Serve the web UI over HTTPS (no: plain HTTP behind a TLS proxy)", old.HTTPS); err != nil {
		return false, err
	}
	scheme := "plain HTTP"
	if next.HTTPS {
		scheme = "HTTPS"
		if next.TLSCert, next.TLSKey, err = askTLS(in, old.TLSCert, old.TLSKey); err != nil {
			return false, err
		}
	}
	if next.Listen, err = askPort(in, "Web UI port ("+scheme+")", old.Listen, ""); err != nil {
		return false, err
	}
	if next.CRLListen, err = askPort(in, "CRL port (plain HTTP, 0 = off)", old.CRLListen, next.Listen); err != nil {
		return false, err
	}
	var pw []byte
	for {
		prompt := "Server password for the web UI: "
		if old.PasswordHash != "" {
			prompt = "Server password for the web UI (Enter keeps the current one): "
		}
		if pw, err = newPassword(prompt, old.PasswordHash != ""); err == nil {
			break
		}
		if errors.Is(err, io.EOF) {
			return false, err
		}
		fmt.Fprintln(os.Stderr, err)
	}
	if pw != nil {
		next.PasswordHash = auth.HashPassword(pw)
		clear(pw)
	}
	return writeSettings(cur, next)
}

// setupUnattended applies the answers given as flags to the configuration
// file at path, an absolute path; the others keep their current value.
func setupUnattended(path string, f setupFlags) (bool, error) {
	cur, err := loadCurrent(path)
	if err != nil {
		return false, err
	}
	next := cur.values
	if f.set["https"] {
		next.HTTPS = f.https
	}
	if f.set["port"] {
		if f.port < 1 || f.port > 65535 {
			return false, errors.New("-port must be from 1 to 65535")
		}
		if next.Listen, err = withPort(next.Listen, f.port); err != nil {
			return false, err
		}
	}
	if f.set["crl-port"] {
		switch {
		case f.crlPort < 0 || f.crlPort > 65535:
			return false, errors.New("-crl-port must be from 0 (off) to 65535")
		case f.crlPort == 0:
			next.CRLListen = ""
		default:
			addr := next.CRLListen
			if addr == "" {
				addr = config.DefaultCRLListen
			}
			if next.CRLListen, err = withPort(addr, f.crlPort); err != nil {
				return false, err
			}
		}
	}
	if samePort(next.Listen, next.CRLListen) {
		return false, errors.New("the web UI and the CRL server need different ports")
	}

	tlsGiven := f.set["tls-cert"] || f.set["tls-key"] || f.set["copy-tls"]
	switch {
	case tlsGiven && !next.HTTPS:
		fmt.Fprintln(os.Stderr, "HTTPS is off: the TLS certificate and key are ignored.")
	case tlsGiven:
		cert, key := strings.TrimSpace(f.tlsCert), strings.TrimSpace(f.tlsKey)
		if (cert == "") != (key == "") {
			return false, errors.New("-tls-cert and -tls-key go together")
		}
		if cert != "" {
			if cert, key, err = checkPair(cert, key); err != nil {
				return false, err
			}
			if f.copyTLS {
				if cert, key, err = copyPair(filepath.Dir(path), cert, key); err != nil {
					return false, err
				}
			}
		}
		next.TLSCert, next.TLSKey = cert, key
	}

	pw := []byte(f.password)
	if f.passwordStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return false, fmt.Errorf("reading the password from stdin: %w", err)
		}
		pw = []byte(strings.TrimRight(line, "\r\n"))
	}
	defer clear(pw)
	// an empty -password, as an installer passes it, keeps the current one
	switch {
	case len(pw) > 0 || f.passwordStdin:
		if len(pw) < 8 {
			return false, errors.New("the server password must have at least 8 characters")
		}
		if !auth.CheckPassword(next.PasswordHash, pw) {
			next.PasswordHash = auth.HashPassword(pw)
		}
	case next.PasswordHash == "":
		return false, errors.New("there is no server password yet: give one with -password-stdin or -password")
	}
	return writeSettings(cur, next)
}

// writeSettings writes the configuration file of cur with the values of
// next: a new file, or the changed lines only. It reports whether anything
// changed.
func writeSettings(cur *current, next config.Settings) (bool, error) {
	old, path := cur.values, cur.path
	var out []byte
	if cur.b != nil {
		var edits []config.Edit
		add := func(section, key string, from, to any) {
			if from != to {
				edits = append(edits, config.Edit{Section: section, Key: key, Value: to})
			}
		}
		add("general", "listen", old.Listen, next.Listen)
		add("general", "https", old.HTTPS, next.HTTPS)
		// relative TLS files are relative to the configuration's folder
		abs := func(p string) string {
			if p == "" || filepath.IsAbs(p) {
				return p
			}
			return filepath.Join(filepath.Dir(path), p)
		}
		if abs(next.TLSCert) != old.TLSCert || abs(next.TLSKey) != old.TLSKey {
			add("general", "tls_cert", old.TLSCert, next.TLSCert)
			add("general", "tls_key", old.TLSKey, next.TLSKey)
		}
		add("crl", "listen", old.CRLListen, next.CRLListen)
		add("general", "password_hash", old.PasswordHash, next.PasswordHash)
		if len(edits) == 0 {
			fmt.Fprintln(os.Stderr, "Nothing changed.")
			return false, nil
		}
		var err error
		if out, err = config.SetValues(cur.b, edits); err != nil {
			return false, fmt.Errorf("%s: %w", path, err)
		}
	} else {
		out = config.NewFile(next)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return false, withAdminHint(err)
		}
	}
	if _, err := config.Parse(out, filepath.Dir(path)); err != nil {
		return false, fmt.Errorf("%s would not be valid: %w", path, err)
	}
	// An existing file keeps its owner and mode.
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return false, withAdminHint(err)
	}
	fmt.Fprintln(os.Stderr, "Wrote", path)
	if next.PasswordHash != old.PasswordHash {
		initial := filepath.Join(filepath.Dir(path), initialPassword)
		if err := os.Remove(initial); err == nil {
			fmt.Fprintln(os.Stderr, "Removed", initial, "(the password in it is no longer valid)")
		}
	}
	host, port, _ := net.SplitHostPort(next.Listen)
	if host == "" {
		host = "<this host>"
	}
	if next.HTTPS {
		fmt.Fprintf(os.Stderr, "The web UI is at https://%s/\n", net.JoinHostPort(host, port))
	} else {
		fmt.Fprintf(os.Stderr, "The web UI is at http://%s/; put a TLS proxy in front of it and list it in general.trusted_proxies.\n",
			net.JoinHostPort(host, port))
	}
	return true, nil
}

// askYesNo asks a yes/no question; Enter answers def.
func askYesNo(in *bufio.Reader, question string, def bool) (bool, error) {
	choices := "[Y/n]"
	if !def {
		choices = "[y/N]"
	}
	for {
		fmt.Fprintf(os.Stderr, "%s? %s: ", question, choices)
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		fmt.Fprintln(os.Stderr, "Answer y or n.")
	}
}

// askTLS asks for the certificate and key files for HTTPS, "-" for a
// self-issued certificate, until they make a pair.
func askTLS(in *bufio.Reader, cert, key string) (string, string, error) {
	for {
		def := cert
		if def == "" {
			def = "-"
		}
		fmt.Fprintf(os.Stderr, "TLS certificate, a PEM file (- = self-issued) [%s]: ", def)
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return "", "", err
		}
		answer := strings.TrimSpace(line)
		if answer == "" {
			answer = def
		}
		if answer == "-" {
			return "", "", nil
		}
		newKey := key
		if answer != cert || key == "" {
			fmt.Fprintf(os.Stderr, "TLS key of that certificate, a PEM file [%s]: ", key)
			line, err := in.ReadString('\n')
			if err != nil && line == "" {
				return "", "", err
			}
			if k := strings.TrimSpace(line); k != "" {
				newKey = k
			}
		}
		c, k, err := checkPair(answer, newKey)
		if err == nil {
			return c, k, nil
		}
		fmt.Fprintln(os.Stderr, err)
		cert, key = answer, newKey
	}
}

// checkPair checks that the PEM files cert and key hold a certificate and
// its key, and returns their absolute paths.
func checkPair(cert, key string) (string, string, error) {
	if key == "" {
		return "", "", errors.New("the TLS key is missing")
	}
	cert, err := filepath.Abs(cert)
	if err != nil {
		return "", "", err
	}
	if key, err = filepath.Abs(key); err != nil {
		return "", "", err
	}
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		return "", "", fmt.Errorf("%s and %s are no TLS certificate and key: %w", cert, key, err)
	}
	return cert, key, nil
}

// copyPair copies the checked certificate and key into dir and returns
// their names relative to it, as the configuration has them.
func copyPair(dir, cert, key string) (string, string, error) {
	for _, c := range [][2]string{{cert, copiedCert}, {key, copiedKey}} {
		b, err := os.ReadFile(c[0])
		if err != nil {
			return "", "", err
		}
		dst := filepath.Join(dir, c[1])
		// a new file: one there before may have been readable by others
		os.Remove(dst)
		if err := os.WriteFile(dst, b, 0o600); err != nil {
			return "", "", withAdminHint(err)
		}
		clear(b)
		fmt.Fprintln(os.Stderr, "Copied", c[0], "to", dst)
	}
	return copiedCert, copiedKey, nil
}

// withPort returns listen address addr with another port, its host kept.
func withPort(addr string, port int) (string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("listen address %q: %w", addr, err)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// samePort reports whether two listen addresses, "" for off, use one port.
func samePort(a, b string) bool {
	_, pa, errA := net.SplitHostPort(a)
	_, pb, errB := net.SplitHostPort(b)
	return errA == nil && errB == nil && pa == pb
}

// askPort asks for the port of listen address addr ("" is off) and returns
// the address with the new port, its host kept. Port 0 turns the server
// off where off is allowed (other != ""); the port must differ from that of
// address other.
func askPort(in *bufio.Reader, label, addr, other string) (string, error) {
	host, cur := "", "0"
	if addr != "" {
		h, p, err := net.SplitHostPort(addr)
		if err != nil {
			return "", fmt.Errorf("listen address %q: %w", addr, err)
		}
		host, cur = h, p
	}
	_, otherPort, _ := net.SplitHostPort(other)
	for {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, cur)
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		answer := strings.TrimSpace(line)
		if answer == "" {
			answer = cur
		}
		n, err := strconv.Atoi(answer)
		switch {
		case err != nil || n < 0 || n > 65535 || (n == 0 && other == ""):
			fmt.Fprintln(os.Stderr, "Enter a port number from 1 to 65535.")
		case n == 0:
			return "", nil
		case strconv.Itoa(n) == otherPort:
			fmt.Fprintln(os.Stderr, "That is the web UI's port; choose another one.")
		default:
			return net.JoinHostPort(host, strconv.Itoa(n)), nil
		}
	}
}

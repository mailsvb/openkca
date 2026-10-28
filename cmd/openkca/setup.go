package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
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

func stdinIsTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// setup asks for the ports and the server password and writes them into
// the configuration file.
func setup(args []string) error {
	path, err := configPath(flag.NewFlagSet("setup", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	_, statErr := os.Stat(path)
	changed, err := runSetup(path)
	if err != nil || !changed {
		return err
	}
	if statErr == nil {
		fmt.Fprintln(os.Stderr, "Restart OpenKCA to apply the changes (rpm package: sudo systemctl restart openkca).")
	}
	return nil
}

// runSetup asks for the web UI port, the CRL port and the server password,
// each defaulting to the current value, and writes the configuration file
// at path, a new one if there is none. It reports whether anything changed.
func runSetup(path string) (bool, error) {
	if !stdinIsTerminal() {
		return false, errors.New("setup asks questions: run it in a terminal")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	b, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	listen, crlListen, hash := config.DefaultListen, config.DefaultCRLListen, ""
	if exists {
		c, err := config.Parse(b, filepath.Dir(path))
		if err != nil {
			return false, fmt.Errorf("%s: %w", path, err)
		}
		listen, crlListen, hash = c.General.Listen, c.CRL.ListenAddr(), c.General.PasswordHash
	}

	in := bufio.NewReader(os.Stdin)
	newListen, err := askPort(in, "Web UI port (HTTPS)", listen, "")
	if err != nil {
		return false, err
	}
	newCRLListen, err := askPort(in, "CRL port (plain HTTP, 0 = off)", crlListen, newListen)
	if err != nil {
		return false, err
	}
	var pw []byte
	for {
		prompt := "Server password for the web UI: "
		if hash != "" {
			prompt = "Server password for the web UI (Enter keeps the current one): "
		}
		if pw, err = newPassword(prompt, hash != ""); err == nil {
			break
		}
		if errors.Is(err, io.EOF) {
			return false, err
		}
		fmt.Fprintln(os.Stderr, err)
	}
	newHash := hash
	if pw != nil {
		newHash = auth.HashPassword(pw)
		clear(pw)
	}

	var out []byte
	if exists {
		var edits []config.Edit
		if newListen != listen {
			edits = append(edits, config.Edit{Section: "general", Key: "listen", Value: newListen})
		}
		if newCRLListen != crlListen {
			edits = append(edits, config.Edit{Section: "crl", Key: "listen", Value: newCRLListen})
		}
		if newHash != hash {
			edits = append(edits, config.Edit{Section: "general", Key: "password_hash", Value: newHash})
		}
		if len(edits) == 0 {
			fmt.Fprintln(os.Stderr, "Nothing changed.")
			return false, nil
		}
		if out, err = config.SetValues(b, edits); err != nil {
			return false, fmt.Errorf("%s: %w", path, err)
		}
	} else {
		out = config.NewFile(newListen, newCRLListen, newHash)
	}
	if _, err := config.Parse(out, filepath.Dir(path)); err != nil {
		return false, fmt.Errorf("%s would not be valid: %w", path, err)
	}
	// An existing file keeps its owner and mode.
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return false, err
	}
	fmt.Fprintln(os.Stderr, "Wrote", path)
	if newHash != hash {
		initial := filepath.Join(filepath.Dir(path), initialPassword)
		if err := os.Remove(initial); err == nil {
			fmt.Fprintln(os.Stderr, "Removed", initial, "(the password in it is no longer valid)")
		}
	}
	host, port, _ := net.SplitHostPort(newListen)
	if host == "" {
		host = "<this host>"
	}
	fmt.Fprintf(os.Stderr, "The web UI is at https://%s/\n", net.JoinHostPort(host, port))
	return true, nil
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

package config

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Edit sets Key in the top-level Section of a configuration to Value, a
// string or a bool.
type Edit struct {
	Section, Key string
	Value        any
}

// literal returns the YAML text of an edit's value.
func (e Edit) literal() (string, error) {
	switch v := e.Value.(type) {
	case string:
		return strconv.Quote(v), nil
	case bool:
		return strconv.FormatBool(v), nil
	}
	return "", fmt.Errorf("cannot write a %T", e.Value)
}

// SetValues applies edits to a configuration file's text and leaves the
// rest of it, comments and blank lines included, as it is. A string is
// written double-quoted, a bool plain, in place of the old one on its line; a missing key
// is added as the first one of its section, a missing section at the end.
// Only keys on one line in a block section can be set.
func SetValues(b []byte, edits []Edit) ([]byte, error) {
	for _, e := range edits {
		var err error
		if b, err = setValue(b, e); err != nil {
			return nil, fmt.Errorf("%s.%s: %w", e.Section, e.Key, err)
		}
	}
	return b, nil
}

func setValue(b []byte, e Edit) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	quoted, err := e.literal()
	if err != nil {
		return nil, err
	}
	var root *yaml.Node
	if len(doc.Content) > 0 {
		root = doc.Content[0]
		if root.Kind != yaml.MappingNode {
			return nil, errors.New("the configuration is not a mapping")
		}
	}
	sk, sv := lookup(root, e.Section)
	if sk == nil {
		if len(b) > 0 && b[len(b)-1] != '\n' {
			b = append(b, '\n')
		}
		return append(b, fmt.Sprintf("%s:\n  %s: %s\n", e.Section, e.Key, quoted)...), nil
	}
	lines := bytes.SplitAfter(b, []byte("\n"))
	switch {
	case sv.Kind == yaml.ScalarNode && sv.Tag == "!!null":
		// "section:" with nothing below it
		return insertLine(lines, sk.Line, "  "+e.Key+": "+quoted), nil
	case sv.Kind != yaml.MappingNode || sv.Style&yaml.FlowStyle != 0:
		return nil, fmt.Errorf("section %s is not a block mapping; edit it by hand", e.Section)
	}
	k, v := lookup(sv, e.Key)
	if k == nil {
		indent := "  "
		if len(sv.Content) > 0 {
			indent = strings.Repeat(" ", sv.Content[0].Column-1)
		}
		return insertLine(lines, sk.Line, indent+e.Key+": "+quoted), nil
	}
	null := v.Tag == "!!null" && v.Value == ""
	if v.Kind != yaml.ScalarNode || (v.Line != k.Line && !null) || v.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return nil, errors.New("not a value on one line; edit it by hand")
	}
	line := string(lines[k.Line-1])
	start, end, err := valueSpan(line, k)
	if err != nil {
		return nil, err
	}
	if line[start-1] == ':' {
		quoted = " " + quoted // "key:" without a value
	}
	if start == end && start < len(line) && line[start] == '#' {
		quoted += " "
	}
	lines[k.Line-1] = []byte(line[:start] + quoted + line[end:])
	return bytes.Join(lines, nil), nil
}

// lookup returns the key and value nodes of key in mapping m.
func lookup(m *yaml.Node, key string) (k, v *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

// insertLine puts text as a new line after line n (1-based).
func insertLine(lines [][]byte, n int, text string) []byte {
	if !bytes.HasSuffix(lines[n-1], []byte("\n")) {
		lines[n-1] = append(lines[n-1], '\n')
	}
	out := make([][]byte, 0, len(lines)+1)
	out = append(out, lines[:n]...)
	out = append(out, []byte(text+"\n"))
	out = append(out, lines[n:]...)
	return bytes.Join(out, nil)
}

// valueSpan returns the byte range of the value on the line of key k: after
// the colon, without spaces around it and without a trailing comment.
func valueSpan(line string, k *yaml.Node) (start, end int, err error) {
	// yaml columns count characters, not bytes
	runes := []rune(line)
	if k.Column-1 > len(runes) {
		return 0, 0, errors.New("key not found on its line")
	}
	i := len(string(runes[:k.Column-1]))
	switch k.Style {
	case yaml.DoubleQuotedStyle, yaml.SingleQuotedStyle:
		if i = closingQuote(line, i); i < 0 {
			return 0, 0, errors.New("unterminated quoted key")
		}
	default:
		i += len(k.Value)
	}
	for i < len(line) && line[i] == ' ' {
		i++
	}
	if i >= len(line) || line[i] != ':' {
		return 0, 0, errors.New("no colon after the key")
	}
	i++
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	start = i
	switch {
	case i < len(line) && (line[i] == '"' || line[i] == '\''):
		if end = closingQuote(line, i); end < 0 {
			return 0, 0, errors.New("unterminated quoted value")
		}
	default:
		end = len(line)
		if c := strings.Index(line[start:], " #"); c >= 0 {
			end = start + c
		} else if strings.HasPrefix(line[start:], "#") {
			end = start
		}
		end = start + len(strings.TrimRight(line[start:end], " \t\r\n"))
	}
	return start, end, nil
}

// closingQuote returns the index after the quoted string starting at
// line[i], or -1.
func closingQuote(line string, i int) int {
	q := line[i]
	for j := i + 1; j < len(line); j++ {
		switch {
		case q == '"' && line[j] == '\\':
			j++
		case line[j] == q && q == '\'' && j+1 < len(line) && line[j+1] == '\'':
			j++ // '' inside single quotes
		case line[j] == q:
			return j + 1
		}
	}
	return -1
}

// Settings are the values "openkca setup" asks for.
type Settings struct {
	Listen       string // the web UI's address
	CRLListen    string // the CRL server's address, "" = off
	HTTPS        bool
	TLSCert      string // "" = self-issued certificate
	TLSKey       string
	PasswordHash string
}

// NewFile returns a configuration for a new installation with the data
// folder "data" next to it.
func NewFile(s Settings) []byte {
	return []byte(fmt.Sprintf(`# OpenKCA configuration, made by "openkca setup". Every setting is explained
# in config.example.yaml. Restart OpenKCA after a change.
#
# Keep the file readable by its owner only (chmod 600) when it holds
# database passwords.

general:
  # Folder with the .okca and .xdb databases, relative to this file.
  data_dir: data
  # Address to listen on; all interfaces by default.
  listen: %q
  # false serves plain HTTP, for a TLS proxy in front of OpenKCA.
  https: %t
  # PEM certificate and key for HTTPS. Empty: a self-issued certificate.
  tls_cert: %q
  tls_key: %q
  # Reverse proxies (IP or CIDR) whose X-Forwarded-For header names the
  # client, e.g. ["127.0.0.1"]; without them the proxy is the client.
  trusted_proxies: []
  # Hash of the server password that protects the whole web UI.
  # Change it with: openkca setup
  password_hash: %q
  # Host name for security keys and passkeys as unlock methods, e.g.
  # ca.example.org; without it they are not offered.
  webauthn:
    rp_id: ""

# Publication of CRLs and CA certificates over plain HTTP; "" turns it off.
crl:
  listen: %q
  # Where that server is reachable, e.g. http://pki.example.org; without
  # base URLs no CRL distribution point or CA issuer is offered.
  base_urls: []

# Databases OpenKCA knows by name; the files in data_dir are listed anyway.
databases: []
`, s.Listen, s.HTTPS, s.TLSCert, s.TLSKey, s.PasswordHash, s.CRLListen))
}

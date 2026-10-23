package codec

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys exist in old databases
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/tmpl"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// Object is one item found in an imported file.
type Object struct {
	Type     int    // xdb.Type*
	Name     string // suggested internal name
	Comment  string
	DER      []byte // certificate, request or CRL; SubjectPublicKeyInfo for keys
	Private  []byte // keys: unencrypted PKCS#8 PrivateKeyInfo, nil for a public key
	KeyType  string // keys: public_keys.type
	KeyBits  int
	Template *tmpl.Template
	File     string
}

// ProbeOptions supply the names XCA gives objects without one.
type ProbeOptions struct {
	Password []byte
	// KeyName names a key from a file without a usable file name, like
	// pki_key::autoIntName ("2048 bit RSA").
	KeyName func(bits int, keyType string, public bool) string
	// Pasted names an item without subject and file name.
	Pasted string
}

// ProbeResult is what Probe found in one file.
type ProbeResult struct {
	Objects       []Object
	NeedPassword  bool     // an encrypted part could not be read without (the right) password
	Unrecognized  []string // descriptions of parts that were skipped
	PasswordWrong bool
}

// Probe reads all objects of a file in any format XCA imports (PEM with
// any number of blocks, DER certificates, requests, CRLs and keys, PKCS#7,
// PKCS#8, PKCS#12, SSH public and private keys, PVK and XCA templates).
func Probe(filename string, data []byte, o ProbeOptions) ProbeResult {
	p := &prober{file: path.Base(strings.ReplaceAll(filename, `\`, "/")), opts: o}
	if filename == "" {
		p.file = ""
	}
	p.base = p.file
	if i := strings.LastIndexByte(p.base, '.'); i >= 0 {
		p.base = p.base[:i]
	}
	text := bytes.TrimSpace(data)
	switch {
	case bytes.Contains(text, []byte("-----BEGIN ")):
		p.pemFile(data)
	case isSSHLine(text):
		p.sshPublicLines(text)
	default:
		p.der(data)
	}
	return p.res
}

type prober struct {
	file, base string
	opts       ProbeOptions
	res        ProbeResult
}

func (p *prober) skip(format string, args ...any) {
	p.res.Unrecognized = append(p.res.Unrecognized, fmt.Sprintf(format, args...))
}

func (p *prober) add(o Object) {
	o.File = p.file
	p.res.Objects = append(p.res.Objects, o)
}

func (p *prober) password() ([]byte, bool) {
	if len(p.opts.Password) == 0 {
		p.res.NeedPassword = true
		return nil, false
	}
	return p.opts.Password, true
}

func (p *prober) wrongPassword() {
	p.res.NeedPassword, p.res.PasswordWrong = true, true
}

func (p *prober) pemFile(data []byte) {
	for _, b := range decodePEMAll(data) {
		p.pemBlock(b)
	}
	// SSH public key lines next to PEM blocks
	for _, line := range bytes.Split(data, []byte("\n")) {
		if isSSHLine(bytes.TrimSpace(line)) {
			p.sshPublicLines(bytes.TrimSpace(line))
		}
	}
}

func (p *prober) pemBlock(b *pem.Block) {
	switch b.Type {
	case PEMCert, pemX509Cert, pemTrustedCert:
		var raw asn1.RawValue // TRUSTED CERTIFICATE appends OpenSSL's aux data
		if _, err := asn1.Unmarshal(b.Bytes, &raw); err != nil {
			p.skip("%s: %v", b.Type, err)
			return
		}
		p.cert(raw.FullBytes)
	case PEMRequest, pemNewRequest:
		p.request(b.Bytes)
	case PEMCRL:
		p.crl(b.Bytes)
	case PEMPKCS7, "CERTIFICATE CHAIN":
		p.pkcs7(b.Bytes)
	case PEMPublicKey:
		p.publicKey(b.Bytes)
	case "RSA PUBLIC KEY":
		if k, err := x509.ParsePKCS1PublicKey(b.Bytes); err == nil {
			if der, err := x509.MarshalPKIXPublicKey(k); err == nil {
				p.publicKey(der)
				return
			}
		}
		p.skip("%s", b.Type)
	case PEMPrivateKey:
		p.pkcs8(b.Bytes)
	case PEMEncrypted:
		p.encryptedPKCS8(b.Bytes)
	case pemRSAPrivate, pemECPrivate, pemDSAPrivate:
		der := b.Bytes
		//lint:ignore SA1019 reading OpenSSL's traditional encrypted keys
		if x509.IsEncryptedPEMBlock(b) { //nolint:staticcheck
			pw, ok := p.password()
			if !ok {
				return
			}
			var err error
			if der, err = x509.DecryptPEMBlock(b, pw); err != nil { //nolint:staticcheck
				p.wrongPassword()
				return
			}
		}
		p.traditional(b.Type, der)
	case PEMOpenSSHKey:
		p.opensshPrivate(pem.EncodeToMemory(b))
	case PEMTemplate:
		p.template(b.Bytes)
	case "EC PARAMETERS", "DH PARAMETERS", "X9.42 DH PARAMETERS":
		// parameters next to a key: nothing to import
	default:
		p.skip("PEM %q", b.Type)
	}
}

func (p *prober) der(data []byte) {
	if len(data) >= pvkHeaderLen && binary.LittleEndian.Uint32(data) == pvkMagic {
		p.pvk(data)
		return
	}
	if len(data) >= 8 && int(binary.BigEndian.Uint32(data)) == len(data)-8 {
		p.template(data) // a template export without PEM armour
		return
	}
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(data, &raw); err != nil || len(bytes.TrimRight(rest, "\x00\r\n")) > 0 {
		p.skip("unknown file format")
		return
	}
	der := raw.FullBytes
	switch {
	case parses(func() error { _, err := x509.ParseCertificate(der); return err }):
		p.cert(der)
	case parses(func() error { _, err := x509.ParseCertificateRequest(der); return err }):
		p.request(der)
	case parses(func() error { _, err := x509.ParseRevocationList(der); return err }):
		p.crl(der)
	case parses(func() error { _, _, err := ParsePKCS7(der); return err }):
		p.pkcs7(der)
	case isPFX(der):
		p.pkcs12(der)
	case pki.IsEncryptedPKCS8(der):
		p.encryptedPKCS8(der)
	case parses(func() error { _, err := pki.ParsePKCS8(der); return err }) || pkcs8SPKI(der) != nil:
		p.pkcs8(der)
	case parses(func() error { _, err := x509.ParsePKIXPublicKey(der); return err }):
		p.publicKey(der)
	case parses(func() error { _, err := x509.ParsePKCS1PrivateKey(der); return err }):
		p.traditional(pemRSAPrivate, der)
	case parses(func() error { _, err := x509.ParseECPrivateKey(der); return err }):
		p.traditional(pemECPrivate, der)
	case parses(func() error { var k dsaPrivate; _, err := asn1.Unmarshal(der, &k); return err }):
		p.traditional(pemDSAPrivate, der)
	default:
		p.skip("unknown file format")
	}
}

func parses(f func() error) bool { return f() == nil }

func isPFX(der []byte) bool {
	var x pfx
	_, err := asn1.Unmarshal(der, &x)
	return err == nil && x.Version == 3
}

// mostPopular is x509name::getMostPopular: the first CN, emailAddress, OU
// or O, else the first entry.
func mostPopular(name []byte) string {
	entries, err := pki.ParseName(name)
	if err != nil || len(entries) == 0 {
		return ""
	}
	for _, short := range []string{"CN", "emailAddress", "OU", "O"} {
		for _, e := range entries {
			if e.Short == short {
				return e.Value
			}
		}
	}
	return entries[0].Value
}

// x509Name is pki_x509name::autoIntName.
func (p *prober) x509Name(name []byte) string {
	if n := mostPopular(name); n != "" {
		return n
	}
	if p.base != "" {
		return p.base
	}
	return p.opts.Pasted
}

func (p *prober) cert(der []byte) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		p.skip("certificate: %v", err)
		return
	}
	p.add(Object{Type: xdb.TypeCert, Name: p.x509Name(c.RawSubject), DER: der})
}

func (p *prober) request(der []byte) {
	r, err := x509.ParseCertificateRequest(der)
	if err != nil {
		p.skip("request: %v", err)
		return
	}
	p.add(Object{Type: xdb.TypeRequest, Name: p.x509Name(r.RawSubject), DER: der})
}

func (p *prober) crl(der []byte) {
	l, err := x509.ParseRevocationList(der)
	if err != nil {
		p.skip("CRL: %v", err)
		return
	}
	p.add(Object{Type: xdb.TypeCRL, Name: p.x509Name(l.RawIssuer), DER: der})
}

func (p *prober) pkcs7(der []byte) {
	certs, crls, err := ParsePKCS7(der)
	if err != nil {
		p.skip("PKCS#7: %v", err)
		return
	}
	for _, c := range certs {
		p.cert(c)
	}
	for _, c := range crls {
		p.crl(c)
	}
}

func (p *prober) pkcs12(der []byte) {
	pw, _ := p.password()
	if pw == nil {
		// an empty password is common for certificate-only files
		pw = []byte{}
	}
	c, err := ParsePKCS12(der, string(pw))
	if err != nil {
		if errors.Is(err, ErrPassword) {
			if len(p.opts.Password) > 0 {
				p.wrongPassword()
			}
			p.res.NeedPassword = true
			return
		}
		p.skip("PKCS#12: %v", err)
		return
	}
	p.res.NeedPassword = false
	alias := c.Alias
	if c.Cert != nil {
		name := alias
		if name == "" {
			name = p.x509Name(c.Cert.RawSubject)
			alias = name
		}
		p.add(Object{Type: xdb.TypeCert, Name: name, DER: c.Cert.Raw})
	}
	if s, ok := c.Key.(crypto.Signer); ok {
		if der, err := pki.MarshalPKCS8(normalizeKey(s)); err == nil {
			p.privateKey(der, alias+"_key")
		}
	}
	for i, ca := range c.Chain {
		name := p.x509Name(ca.RawSubject)
		if c.Alias != "" {
			name = fmt.Sprintf("%s_ca_%d", c.Alias, i)
		}
		p.add(Object{Type: xdb.TypeCert, Name: name, DER: ca.Raw})
	}
}

func (p *prober) keyName(spki []byte, public bool) (string, string, int) {
	typ, bits := pki.StoredKeyType(spki)
	if p.base != "" {
		return p.base, typ, bits
	}
	if p.opts.KeyName != nil {
		return p.opts.KeyName(bits, typ, public), typ, bits
	}
	return fmt.Sprintf("%d bit %s", bits, typ), typ, bits
}

func (p *prober) publicKey(spki []byte) {
	name, typ, bits := p.keyName(spki, true)
	p.add(Object{Type: xdb.TypeKey, Name: name, DER: spki, KeyType: typ, KeyBits: bits})
}

func (p *prober) privateKey(pkcs8 []byte, name string) {
	spki := pkcs8SPKI(pkcs8)
	if spki == nil {
		p.skip("private key: unsupported algorithm")
		return
	}
	n, typ, bits := p.keyName(spki, false)
	if name == "" || name == "_key" {
		name = n
	}
	p.add(Object{Type: xdb.TypeKey, Name: name, DER: spki, Private: pkcs8, KeyType: typ, KeyBits: bits})
}

func (p *prober) pkcs8(der []byte) { p.privateKey(der, "") }

func (p *prober) encryptedPKCS8(der []byte) {
	pw, ok := p.password()
	if !ok {
		return
	}
	plain, err := pki.DecryptPKCS8(der, pw)
	if err != nil {
		p.wrongPassword()
		return
	}
	p.privateKey(plain, "")
}

func (p *prober) traditional(typ string, der []byte) {
	var key crypto.Signer
	var err error
	switch typ {
	case pemRSAPrivate:
		key, err = x509.ParsePKCS1PrivateKey(der)
	case pemECPrivate:
		if key, err = x509.ParseECPrivateKey(der); err != nil {
			if pk8 := sec1ToPKCS8(der); pk8 != nil {
				p.privateKey(pk8, "") // a curve Go cannot compute with
				return
			}
		}
	case pemDSAPrivate:
		var k dsaPrivate
		if _, err = asn1.Unmarshal(der, &k); err == nil {
			key = dsaFromParts(k.P, k.Q, k.G, k.X)
		}
	}
	if err != nil {
		p.skip("%s: %v", typ, err)
		return
	}
	pk8, err := pki.MarshalPKCS8(key)
	if err != nil {
		p.skip("%s: %v", typ, err)
		return
	}
	p.privateKey(pk8, "")
}

// normalizeKey converts key types returned by x/crypto/ssh and PKCS#12
// parsers into the forms pki uses.
func normalizeKey(k crypto.Signer) crypto.Signer {
	switch v := k.(type) {
	case *ed25519.PrivateKey:
		return *v
	}
	return k
}

func (p *prober) opensshPrivate(pemBytes []byte) {
	raw, err := ssh.ParseRawPrivateKey(pemBytes)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		pw, ok := p.password()
		if !ok {
			return
		}
		if raw, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, pw); err != nil {
			p.wrongPassword()
			return
		}
	}
	if err != nil {
		p.skip("OpenSSH key: %v", err)
		return
	}
	var s crypto.Signer
	switch k := raw.(type) {
	case crypto.Signer:
		s = k
	case *dsa.PrivateKey:
		s = pki.DSAKey{PrivateKey: k}
	default:
		p.skip("OpenSSH key %T", raw)
		return
	}
	der, err := pki.MarshalPKCS8(normalizeKey(s))
	if err != nil {
		p.skip("OpenSSH key: %v", err)
		return
	}
	p.privateKey(der, "")
}

func isSSHLine(b []byte) bool {
	for _, t := range []string{"ssh-rsa ", "ssh-dss ", "ssh-ed25519 ", "ecdsa-sha2-"} {
		if bytes.HasPrefix(b, []byte(t)) {
			return true
		}
	}
	return false
}

func (p *prober) sshPublicLines(text []byte) {
	for _, line := range bytes.Split(text, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !isSSHLine(line) {
			continue
		}
		pub, comment, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			p.skip("SSH key: %v", err)
			continue
		}
		cp, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			p.skip("SSH key type %s", pub.Type())
			continue
		}
		spki, err := marshalSPKI(cp.CryptoPublicKey())
		if err != nil {
			p.skip("SSH key: %v", err)
			continue
		}
		name, typ, bits := p.keyName(spki, true)
		p.add(Object{Type: xdb.TypeKey, Name: name, Comment: comment, DER: spki, KeyType: typ, KeyBits: bits})
	}
}

func (p *prober) template(b []byte) {
	t, err := ParseXCATemplate(b)
	if err != nil {
		p.skip("template: %v", err)
		return
	}
	name := t.IntName
	if name == "" {
		name = p.base
	}
	if name == "" {
		name = p.x509Name(t.Subject)
	}
	p.add(Object{Type: xdb.TypeTemplate, Name: name, Comment: t.Comment, Template: t})
}

func (p *prober) pvk(data []byte) {
	key, err := parsePVK(data, func() ([]byte, bool) { return p.password() })
	if errors.Is(err, errPVKPassword) {
		if len(p.opts.Password) > 0 {
			p.wrongPassword()
		}
		return
	}
	if err != nil {
		p.skip("PVK: %v", err)
		return
	}
	der, err := pki.MarshalPKCS8(key)
	if err != nil {
		p.skip("PVK: %v", err)
		return
	}
	p.privateKey(der, "")
}

// marshalSPKI encodes a public key, DSA included.
func marshalSPKI(pub crypto.PublicKey) ([]byte, error) {
	if k, ok := pub.(*dsa.PublicKey); ok {
		params, err := asn1.Marshal(struct{ P, Q, G any }{k.P, k.Q, k.G})
		if err != nil {
			return nil, err
		}
		y, err := asn1.Marshal(k.Y)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(struct {
			Algo pkix.AlgorithmIdentifier
			Key  asn1.BitString
		}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}, Parameters: asn1.RawValue{FullBytes: params}},
			asn1.BitString{Bytes: y, BitLength: 8 * len(y)}})
	}
	return x509.MarshalPKIXPublicKey(pub)
}

// pkcs8SPKI derives the SubjectPublicKeyInfo of a PKCS#8 key, also for EC
// curves Go cannot compute with (from the public key inside the SEC 1
// structure).
func pkcs8SPKI(der []byte) []byte {
	if k, err := pki.ParsePKCS8(der); err == nil {
		switch v := k.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			b, err := x509.MarshalPKIXPublicKey(v.Public())
			if err == nil {
				return b
			}
		case pki.DSAKey:
			b, err := marshalSPKI(v.Public())
			if err == nil {
				return b
			}
		}
		return nil
	}
	var info struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil || !info.Algo.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}) {
		return nil
	}
	var ec struct {
		Version    int
		PrivateKey []byte
		Params     asn1.RawValue  `asn1:"optional,explicit,tag:0"`
		PublicKey  asn1.BitString `asn1:"optional,explicit,tag:1"`
	}
	if _, err := asn1.Unmarshal(info.PrivateKey, &ec); err != nil || ec.PublicKey.BitLength == 0 {
		return nil
	}
	b, err := asn1.Marshal(struct {
		Algo pkix.AlgorithmIdentifier
		Key  asn1.BitString
	}{info.Algo, ec.PublicKey})
	if err != nil {
		return nil
	}
	return b
}

// PrivateSigner parses an Object's private key; nil for algorithms Go
// cannot use (they can still be stored and exported as PKCS#8).
func (o *Object) PrivateSigner() crypto.Signer {
	if o.Private == nil {
		return nil
	}
	k, err := pki.ParsePKCS8(o.Private)
	if err != nil {
		return nil
	}
	return k
}

// KeyTypeName names a public key's algorithm.
func KeyTypeName(pub crypto.PublicKey) string { return keyTypeName(pub) }

// sec1ToPKCS8 wraps an EC private key with named curve parameters in a
// PrivateKeyInfo without interpreting the curve.
func sec1ToPKCS8(der []byte) []byte {
	var ec struct {
		Version    int
		PrivateKey []byte
		Params     asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		PublicKey  asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}
	if _, err := asn1.Unmarshal(der, &ec); err != nil || ec.Params == nil {
		return nil
	}
	params, err := asn1.Marshal(ec.Params)
	if err != nil {
		return nil
	}
	b, err := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, Parameters: asn1.RawValue{FullBytes: params}}, der})
	if err != nil {
		return nil
	}
	return b
}

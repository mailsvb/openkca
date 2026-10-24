package codec

import (
	"bytes"
	"crypto" //nolint:staticcheck // DSA keys exist in old databases
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

	"github.com/mailsvb/go-ca/internal/pkcs12"
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
	// OpenPGP keys: the fingerprint, and on the primary key the public
	// certificate to store with it
	PGPFingerprint string
	PGP            []byte
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
// PKCS#8, PKCS#12, OpenSSH public and private keys, RFC 4716 public keys,
// PuTTY private keys, PVK and XCA templates) and OpenPGP keys, armored or
// binary.
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
	case isPPK(text):
		p.putty(text)
	case isPGPArmor(text) || isPGPBinary(data):
		p.pgp(data)
	case bytes.Contains(text, []byte("-----BEGIN ")):
		p.pemFile(data)
	case bytes.Contains(text, []byte(rfc4716Begin)):
		p.rfc4716(text)
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
	// SSH public keys next to PEM blocks
	for _, line := range bytes.Split(data, []byte("\n")) {
		if isSSHLine(bytes.TrimSpace(line)) {
			p.sshPublicLines(bytes.TrimSpace(line))
		}
	}
	if bytes.Contains(data, []byte(rfc4716Begin)) {
		p.rfc4716(data)
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
			if der, err := pki.MarshalPublicKey(k); err == nil {
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
			if der, err = x509.DecryptPEMBlock(b, pw); errors.Is(err, x509.IncorrectPasswordError) { //nolint:staticcheck
				p.wrongPassword()
				return
			} else if err != nil {
				if alg, _, _ := strings.Cut(b.Headers["DEK-Info"], ","); alg != "" && strings.Contains(err.Error(), "unknown encryption mode") {
					p.skip("%s: unsupported encryption %s", b.Type, alg)
				} else {
					p.skip("%s: %v", b.Type, err)
				}
				return
			}
		}
		p.traditional(b.Type, der)
	case PEMOpenSSHKey:
		p.opensshPrivate(b.Bytes)
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
	case parses(func() error { _, err := pki.ParseCertificate(der); return err }):
		p.cert(der)
	case parses(func() error { _, err := pki.ParseCertificateRequest(der); return err }):
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
	case parses(func() error { _, err := pki.ParsePublicKey(der); return err }):
		p.publicKey(der)
	case parses(func() error { _, err := x509.ParsePKCS1PrivateKey(der); return err }):
		p.traditional(pemRSAPrivate, der)
	case parses(func() error { _, err := pki.ParseECPrivateKey(der); return err }) || sec1ToPKCS8(der) != nil:
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

func (p *prober) cert(der []byte) { p.namedCert(der, "") }

func (p *prober) request(der []byte) {
	r, err := pki.ParseCertificateRequest(der)
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
	c, err := pkcs12.Decode(der, string(pw))
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
	for _, s := range c.Skipped {
		p.skip("PKCS#12: %s", s)
	}
	// Each key with its certificate, found by localKeyId or public key, is
	// named after the key's friendlyName, else the certificate's, else its
	// subject, as XCA names them; the other certificates after their own
	// friendlyName or as CA certificates of the first key.
	used := make([]bool, len(c.Certs))
	primary := ""
	for _, k := range c.Keys {
		ci := -1
		for i, cb := range c.Certs {
			if !used[i] && len(k.LocalKeyID) > 0 && bytes.Equal(k.LocalKeyID, cb.LocalKeyID) {
				ci = i
				break
			}
		}
		if spki := pkcs8SPKI(k.DER); ci < 0 && spki != nil {
			for i, cb := range c.Certs {
				if x, err := pki.ParseCertificate(cb.DER); !used[i] && err == nil && bytes.Equal(x.RawSubjectPublicKeyInfo, spki) {
					ci = i
					break
				}
			}
		}
		alias := k.FriendlyName
		if ci >= 0 {
			used[ci] = true
			if alias == "" {
				alias = c.Certs[ci].FriendlyName
			}
			if name := p.namedCert(c.Certs[ci].DER, alias); alias == "" {
				alias = name
			}
		}
		if primary == "" {
			primary = alias
		}
		p.privateKey(k.DER, alias+"_key", "")
	}
	n := 0
	for i, cb := range c.Certs {
		if used[i] {
			continue
		}
		name := cb.FriendlyName
		if name == "" && primary != "" {
			name = fmt.Sprintf("%s_ca_%d", primary, n)
		}
		p.namedCert(cb.DER, name)
		n++
	}
}

// namedCert adds a certificate under name, or its subject's name if name
// is empty, and returns the name; "" if it does not parse.
func (p *prober) namedCert(der []byte, name string) string {
	c, err := pki.ParseCertificate(der)
	if err != nil {
		p.skip("certificate: %v", err)
		return ""
	}
	if name == "" {
		name = p.x509Name(c.RawSubject)
	}
	p.add(Object{Type: xdb.TypeCert, Name: name, DER: der})
	return name
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

func (p *prober) privateKey(pkcs8 []byte, name, comment string) {
	spki := pkcs8SPKI(pkcs8)
	if spki == nil {
		p.skip("private key: unsupported algorithm")
		return
	}
	n, typ, bits := p.keyName(spki, false)
	if name == "" || name == "_key" {
		name = n
	}
	p.add(Object{Type: xdb.TypeKey, Name: name, Comment: comment, DER: spki, Private: pkcs8, KeyType: typ, KeyBits: bits})
}

func (p *prober) pkcs8(der []byte) { p.privateKey(der, "", "") }

func (p *prober) encryptedPKCS8(der []byte) {
	pw, ok := p.password()
	if !ok {
		return
	}
	plain, err := pkcs12.DecryptPKCS8(der, pw)
	if errors.Is(err, pki.ErrWrongPassword) {
		p.wrongPassword()
		return
	} else if err != nil {
		p.skip("encrypted private key: %v", err)
		return
	}
	p.privateKey(plain, "", "")
}

func (p *prober) traditional(typ string, der []byte) {
	var key crypto.Signer
	var err error
	switch typ {
	case pemRSAPrivate:
		key, err = x509.ParsePKCS1PrivateKey(der)
	case pemECPrivate:
		if key, err = pki.ParseECPrivateKey(der); err != nil {
			if pk8 := sec1ToPKCS8(der); pk8 != nil {
				p.privateKey(pk8, "", "") // a curve Go cannot compute with
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
	p.privateKey(pk8, "", "")
}

func (p *prober) opensshPrivate(data []byte) {
	key, comment, err := parseOpenSSHPrivate(data, p.password)
	p.sshPrivate("OpenSSH key", key, comment, err)
}

func (p *prober) putty(data []byte) {
	key, comment, err := parsePPK(data, p.password)
	p.sshPrivate("PuTTY key", key, comment, err)
}

// sshPrivate adds a private key read from an SSH format; its comment is
// the item's comment and suggested name.
func (p *prober) sshPrivate(what string, key crypto.Signer, comment string, err error) {
	if errors.Is(err, errSSHPassword) {
		if len(p.opts.Password) > 0 {
			p.wrongPassword()
		}
		return
	}
	if err != nil {
		p.skip("%s: %v", what, err)
		return
	}
	der, err := pki.MarshalPKCS8(key)
	if err != nil {
		p.skip("%s: %v", what, err)
		return
	}
	p.privateKey(der, SSHComment(comment), comment)
}

// pgp adds the keys of an OpenPGP file: each primary key and subkey Go can
// hold becomes a key named after the first user ID; the primary key
// carries the certificate.
func (p *prober) pgp(data []byte) {
	ents, skipped, _, wrong := ReadPGP(data, p.password)
	if wrong {
		p.wrongPassword()
	}
	for _, s := range skipped {
		p.skip("%s", s)
	}
	for _, e := range ents {
		uid := ""
		if len(e.Info.UIDs) > 0 {
			uid = e.Info.UIDs[0]
		}
		for i, k := range e.Info.Keys {
			if k.Public == nil {
				p.skip("OpenPGP subkey %s: %s keys cannot be stored", k.Fingerprint, k.Algorithm)
				continue
			}
			spki, err := marshalSPKI(k.Public)
			if err != nil {
				p.skip("OpenPGP key %s: %v", k.Fingerprint, err)
				continue
			}
			name, typ, bits := p.keyName(spki, e.Private[i] == nil)
			if uid != "" {
				name = uid
			}
			if i > 0 {
				name += " [" + k.Usage + "]"
			}
			o := Object{Type: xdb.TypeKey, Name: name, DER: spki, KeyType: typ, KeyBits: bits, PGPFingerprint: k.Fingerprint}
			if i == 0 {
				o.PGP = e.Cert
			}
			if e.Private[i] != nil {
				if o.Private, err = pki.MarshalPKCS8(e.Private[i]); err != nil {
					p.skip("OpenPGP key %s: %v", k.Fingerprint, err)
					continue
				}
			}
			p.add(o)
		}
	}
}

// sshPublic adds a public key read from an SSH format, named like
// sshPrivate does.
func (p *prober) sshPublic(pub crypto.PublicKey, comment string) {
	spki, err := marshalSPKI(pub)
	if err != nil {
		p.skip("SSH key: %v", err)
		return
	}
	name, typ, bits := p.keyName(spki, true)
	if c := SSHComment(comment); c != "" {
		name = c
	}
	p.add(Object{Type: xdb.TypeKey, Name: name, Comment: comment, DER: spki, KeyType: typ, KeyBits: bits})
}

func (p *prober) rfc4716(text []byte) {
	keys, errs := parseRFC4716(text)
	for _, k := range keys {
		p.sshPublic(k.pub, k.comment)
	}
	for _, err := range errs {
		p.skip("%v", err)
	}
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
		p.sshPublic(cp.CryptoPublicKey(), comment)
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
	p.privateKey(der, "", "")
}

// MarshalSPKI encodes a public key as SubjectPublicKeyInfo, for every
// algorithm pki knows, DSA included.
func MarshalSPKI(pub crypto.PublicKey) ([]byte, error) { return marshalSPKI(pub) }

func marshalSPKI(pub crypto.PublicKey) ([]byte, error) { return pki.MarshalPublicKey(pub) }

// pkcs8SPKI derives the SubjectPublicKeyInfo of a PKCS#8 key, also for EC
// curves Go cannot compute with (from the public key inside the SEC 1
// structure).
func pkcs8SPKI(der []byte) []byte {
	if k, err := pki.ParsePKCS8(der); err == nil {
		b, err := pki.MarshalPublicKey(k.Public())
		if err != nil {
			return nil
		}
		return b
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

package store

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/index"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/tmpl"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// Translator renders a message key for texts that end up in exported
// files (vCalendar reminders).
type Translator func(key string, args ...any) string

// ExportRequest selects items and a format.
type ExportRequest struct {
	Format     int
	IDs        []int64
	Password   []byte // export password for formats with codec.FCrypt
	PEMComment bool   // XCA's "Include internal name and comment" option
	DBPass     []byte
	Keys       KeyPasswords
	T          Translator
	Now        time.Time
}

// ExportResult is a file to download.
type ExportResult struct {
	Filename    string
	ContentType string
	Data        []byte
	Text        bool
}

// ErrNeedExportPassword means the format encrypts and no password was given.
var ErrNeedExportPassword = errors.New("an export password is required")

// ErrNoPrivateKey means the format needs a private key the item lacks.
var ErrNoPrivateKey = errors.New("there is no private key for this item")

type itemRef struct {
	typ     int
	item    *xdb.Item
	key     *xdb.Key
	cert    *xdb.Cert
	req     *xdb.Request
	crl     *xdb.CRL
	tmpl    *xdb.Template
	pub     crypto.PublicKey // keys and certificates
	pubSPKI []byte
}

func refOf(snap *xdb.Snapshot, id int64) *itemRef {
	for _, k := range snap.Keys {
		if k.ID == id {
			pub, _ := codec.ParsePublic(k.Public)
			return &itemRef{typ: xdb.TypeKey, item: &k.Item, key: k, pub: pub, pubSPKI: k.Public}
		}
	}
	for _, c := range snap.Certs {
		if c.ID == id {
			r := &itemRef{typ: xdb.TypeCert, item: &c.Item, cert: c}
			if x, err := pki.ParseCertificate(c.DER); err == nil {
				r.pub, r.pubSPKI = x.PublicKey, x.RawSubjectPublicKeyInfo
			}
			return r
		}
	}
	for _, q := range snap.Requests {
		if q.ID == id {
			return &itemRef{typ: xdb.TypeRequest, item: &q.Item, req: q}
		}
	}
	for _, l := range snap.CRLs {
		if l.ID == id {
			return &itemRef{typ: xdb.TypeCRL, item: &l.Item, crl: l}
		}
	}
	for _, t := range snap.Templates {
		if t.ID == id {
			return &itemRef{typ: xdb.TypeTemplate, item: &t.Item, tmpl: t}
		}
	}
	return nil
}

func itemRefs(snap *xdb.Snapshot, ids []int64) ([]*itemRef, error) {
	if len(ids) == 0 {
		return nil, errors.New("nothing selected")
	}
	var out []*itemRef
	for _, id := range ids {
		r := refOf(snap, id)
		if r == nil {
			return nil, fmt.Errorf("item %d not found", id)
		}
		if len(out) > 0 && r.typ != out[0].typ {
			return nil, errors.New("the selected items are of different types")
		}
		out = append(out, r)
	}
	return out, nil
}

// keyOf returns the key item belonging to a certificate.
func keyOf(snap *xdb.Snapshot, c *xdb.Cert) *xdb.Key {
	if c.KeyID == 0 {
		return nil
	}
	return findKey(snap, c.KeyID)
}

// disabledFlags mirrors the exportFlags functions of XCA's models.
func disabledFlags(snap *xdb.Snapshot, r *itemRef) codec.Flags {
	var d codec.Flags
	switch r.typ {
	case xdb.TypeCert:
		c := r.cert
		if c.IssuerID == 0 || c.IssuerID == c.ID {
			d |= codec.FChain
		}
		if k := keyOf(snap, c); k == nil || !k.HasPrivate || k.Token {
			d |= codec.FPrivate
		} else if _, err := codec.ParsePublic(k.Public); err != nil {
			d |= codec.FPrivate
		}
		if !c.CA {
			d |= codec.FCA
		}
		if r.pub == nil || !codec.JWKSupported(r.pub) {
			d |= codec.FJWK
		}
	case xdb.TypeKey:
		k := r.key
		if r.pub == nil {
			// a key Go cannot use: public PEM/DER and PKCS#8 only
			d |= codec.FSSH2 | codec.FJWK | codec.FPVK | codec.FTradition
		} else {
			switch codec.KeyTypeName(r.pub) {
			case "RSA", "DSA":
			default:
				d |= codec.FPVK
			}
			switch codec.KeyTypeName(r.pub) {
			case "Ed25519", "X25519":
				d |= codec.FTradition
			}
			if !codec.SSHCompatible(r.pub) {
				d |= codec.FSSH2
			}
			if !codec.JWKSupported(r.pub) {
				d |= codec.FJWK
			}
		}
		if !k.HasPrivate || k.Token {
			d |= codec.FPrivate
		}
		if PGPOf(snap, k.ID) == nil {
			d |= codec.FPGP
		}
	}
	return d
}

// ExportFormats lists the formats available for a selection.
func ExportFormats(snap *xdb.Snapshot, ids []int64) []codec.Format {
	var d codec.Flags
	typ := 0
	for _, id := range ids {
		r := refOf(snap, id)
		if r == nil {
			return nil
		}
		if typ != 0 && r.typ != typ {
			return nil
		}
		typ = r.typ
		d |= disabledFlags(snap, r)
	}
	if len(ids) > 1 {
		d |= codec.FSingle
	} else {
		d |= codec.FMulti
	}
	var out []codec.Format
	for _, f := range codec.Select(typ, d) {
		if typ == xdb.TypeKey && refOf(snap, ids[0]).pub == nil && f.Flags&codec.FDER != 0 && f.Flags&codec.FPrivate != 0 {
			continue // DER private is the traditional form
		}
		out = append(out, f)
	}
	return out
}

var reservedName = regexp.MustCompile(`^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$`)
var unsafeChars = regexp.MustCompile("[ $&;`/\\\\<>:\"|?*]+")

// FileName is pki_base::getUnderlinedName: the internal name made safe as
// a file name.
func FileName(name string) string {
	if reservedName.MatchString(name) {
		name += "_"
	}
	name = unsafeChars.ReplaceAllString(name, "_")
	if name == "" {
		name = "_"
	}
	return name
}

func contentType(f codec.Format) string {
	switch f.Ext {
	case "ics":
		return "text/calendar; charset=utf-8"
	case "jwk":
		return "application/json"
	case "p7b":
		return "application/pkcs7-mime"
	case "pfx":
		return "application/x-pkcs12"
	case "pvk", "der", "cer", "gpg":
		return "application/octet-stream"
	case "asc", "rev":
		return "application/pgp-keys"
	}
	return "text/plain; charset=utf-8"
}

// keyPassword returns the password a stored private key is encrypted with.
func keyPassword(keyID int64, own int, dbPass []byte, kp KeyPasswords) ([]byte, error) {
	switch own {
	case xdb.PassPrivate:
		if pw := kp[keyID]; len(pw) > 0 {
			return pw, nil
		}
		return nil, ErrNeedKeyPassword
	case xdb.PassBogus:
		return []byte("Bogus"), nil
	case xdb.PassPIN:
		return nil, errors.New("the key is on a security token, which go-ca does not access")
	}
	return dbPass, nil
}

// privateDER decrypts a stored key to an unencrypted PKCS#8 structure,
// also for algorithms Go cannot compute with.
func (h *Handle) privateDER(ctx context.Context, k *xdb.Key, dbPass []byte, kp KeyPasswords) ([]byte, error) {
	if !k.HasPrivate {
		return nil, ErrNoPrivateKey
	}
	if s, err := h.unlock(ctx, k.ID, k.KeyType, dbPass, kp); err == nil {
		return pki.MarshalPKCS8(s)
	} else if errors.Is(err, ErrNeedKeyPassword) {
		return nil, err
	}
	blob, own, err := h.DB.PrivateKey(ctx, k.ID)
	if err != nil {
		return nil, err
	}
	pw, err := keyPassword(k.ID, own, dbPass, kp)
	if err != nil {
		return nil, err
	}
	der, err := pki.DecryptPKCS8(blob, pw)
	if errors.Is(err, pki.ErrWrongPassword) && own == xdb.PassPrivate {
		return nil, ErrNeedKeyPassword
	}
	return der, err
}

func (h *Handle) signer(ctx context.Context, k *xdb.Key, dbPass []byte, kp KeyPasswords) (crypto.Signer, error) {
	if k == nil || !k.HasPrivate {
		return nil, ErrNoPrivateKey
	}
	return h.unlock(ctx, k.ID, k.KeyType, dbPass, kp)
}

// chain returns a certificate followed by its issuers up to the root.
func chain(snap *xdb.Snapshot, c *xdb.Cert) []*xdb.Cert {
	out := []*xdb.Cert{c}
	seen := map[int64]bool{c.ID: true}
	for c.IssuerID != 0 && !seen[c.IssuerID] {
		p := findCert(snap, c.IssuerID)
		if p == nil {
			break
		}
		seen[p.ID] = true
		out = append(out, p)
		c = p
	}
	return out
}

func revocationOf(snap *xdb.Snapshot, c *xdb.Cert) *xdb.Revocation {
	if c.IssuerID == 0 || c.IssuerID == c.ID {
		return nil
	}
	for _, r := range snap.Revocations {
		if r.CAID == c.IssuerID && r.Serial == c.Serial {
			return r
		}
	}
	return nil
}

// unusable is pki_x509::unusable: expired or revoked.
func unusable(snap *xdb.Snapshot, c *xdb.Cert, now time.Time) bool {
	info := pki.DescribeCert(c.DER)
	return (!info.NoExpiry && info.NotAfter.Before(now)) || revocationOf(snap, c) != nil
}

func (e *exporter) certPEM(c *xdb.Cert) []byte {
	var b []byte
	if e.req.PEMComment {
		subj, _ := pki.RawSubject(c.DER)
		b = codec.Comment(c.Name, c.Comment, codec.RFC2253(subj))
	}
	return append(b, codec.PEM(codec.PEMCert, c.DER)...)
}

func (e *exporter) keyComment(k *xdb.Key) []byte {
	if !e.req.PEMComment {
		return nil
	}
	return codec.Comment(k.Name, k.Comment, fmt.Sprintf("%d bit %s", k.Len, pki.KeyTypeText(k.KeyType)))
}

type exporter struct {
	h    *Handle
	ctx  context.Context
	snap *xdb.Snapshot
	req  ExportRequest
	refs []*itemRef
	f    codec.Format
	out  bytes.Buffer
}

func (e *exporter) password() ([]byte, error) {
	if len(e.req.Password) == 0 {
		return nil, ErrNeedExportPassword
	}
	return e.req.Password, nil
}

// Export writes the selected items in a format.
func (h *Handle) Export(ctx context.Context, req ExportRequest) (*ExportResult, error) {
	f, ok := codec.FormatByID(req.Format)
	if !ok {
		return nil, errors.New("unknown export format")
	}
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	refs, err := itemRefs(snap, req.IDs)
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, a := range ExportFormats(snap, req.IDs) {
		allowed = allowed || a.ID == f.ID
	}
	if !allowed {
		return nil, errors.New("this format is not available for the selection")
	}
	if req.Now.IsZero() {
		req.Now = time.Now()
	}
	if req.T == nil {
		req.T = func(k string, a ...any) string { return k }
	}
	e := &exporter{h: h, ctx: ctx, snap: snap, req: req, refs: refs, f: f}
	switch f.Type {
	case xdb.TypeCert:
		err = e.certs()
	case xdb.TypeKey:
		err = e.keys()
	case xdb.TypeRequest:
		err = e.requests()
	case xdb.TypeCRL:
		err = e.crls()
	case xdb.TypeTemplate:
		err = e.templates()
	}
	if err != nil {
		return nil, err
	}
	name := FileName(refs[0].item.Name)
	if f.Flags&codec.FUnusable != 0 {
		name = "unusable"
	}
	return &ExportResult{Filename: name + "." + f.Ext, ContentType: contentType(f), Data: e.out.Bytes(), Text: f.Text()}, nil
}

func (e *exporter) dbName() string { return e.h.Name + ".xdb" }

func (e *exporter) certVEvent(c *xdb.Cert) []string {
	info := pki.DescribeCert(c.DER)
	t := e.req.T
	return codec.VEvent(c.DER, info.NotAfter, t("vcal.cert.summary", c.Name),
		t("vcal.cert.description", c.Name, info.NotBefore.UTC().Format(time.DateTime), info.NotAfter.UTC().Format(time.DateTime), e.dbName()),
		c.Comment, e.alarm(), e.req.Now)
}

func (e *exporter) crlVEvent(l *xdb.CRL) []string {
	info := pki.DescribeCRL(l.DER)
	t := e.req.T
	if ca := findCert(e.snap, l.IssuerID); ca != nil {
		return codec.VEvent(l.DER, info.NextUpdate, t("vcal.crl.summary", ca.Name),
			t("vcal.crl.description", ca.Name, info.NextUpdate.UTC().Format(time.DateTime), e.dbName()), l.Comment, e.alarm(), e.req.Now)
	}
	return codec.VEvent(l.DER, info.NextUpdate, t("vcal.crl.summary_plain", l.Name),
		t("vcal.crl.description_plain", l.Name, info.ThisUpdate.UTC().Format(time.DateTime), info.NextUpdate.UTC().Format(time.DateTime), e.dbName()),
		l.Comment, e.alarm(), e.req.Now)
}

func (e *exporter) alarm() string {
	if a := e.snap.Settings["ical_expiry"]; a != "" {
		return a
	}
	return "1W"
}

func (e *exporter) vcal(events []string) {
	e.out.Write(codec.VCalendar(events, "go-ca//go-ca"))
}

func (e *exporter) certs() error {
	f := e.f.Flags
	first := e.refs[0].cert
	var certs []*xdb.Cert
	for _, r := range e.refs {
		certs = append(certs, r.cert)
	}
	unusableCerts := func() []*xdb.Cert {
		var out []*xdb.Cert
		for _, c := range e.snap.Certs {
			if unusable(e.snap, c, e.req.Now) {
				out = append(out, c)
			}
		}
		return out
	}
	ders := func(l []*xdb.Cert) [][]byte {
		var out [][]byte
		for _, c := range l {
			out = append(out, c.DER)
		}
		return out
	}
	switch {
	case f&codec.FPEM != 0:
		switch {
		case f&codec.FChain != 0:
			certs = chain(e.snap, first)
		case f&codec.FUnusable != 0:
			certs = unusableCerts()
		case f&codec.FPrivate != 0:
			k := keyOf(e.snap, first)
			if f&codec.FPKCS8 != 0 {
				pw, err := e.password()
				if err != nil {
					return err
				}
				der, err := e.h.privateDER(e.ctx, k, e.req.DBPass, e.req.Keys)
				if err != nil {
					return err
				}
				b, err := codec.PKCS8PEM(der, pw)
				clear(der)
				if err != nil {
					return err
				}
				e.out.Write(e.keyComment(k))
				e.out.Write(b)
			} else {
				s, err := e.h.signer(e.ctx, k, e.req.DBPass, e.req.Keys)
				if err != nil {
					return err
				}
				b, err := codec.PrivatePEM(s, nil)
				if err != nil {
					return err
				}
				e.out.Write(e.keyComment(k))
				e.out.Write(b)
			}
		}
		for _, c := range certs {
			e.out.Write(e.certPEM(c))
		}
	case f&codec.FOVPN != 0:
		var ca, extra, cert, key []byte
		if k := keyOf(e.snap, first); k != nil && k.HasPrivate {
			s, err := e.h.signer(e.ctx, k, e.req.DBPass, e.req.Keys)
			if err != nil {
				return err
			}
			if key, err = codec.PrivatePEM(s, nil); err != nil {
				return err
			}
		}
		for _, c := range chain(e.snap, first) {
			p := codec.PEM(codec.PEMCert, c.DER)
			switch {
			case c.IssuerID == c.ID:
				ca = append(ca, p...)
			case len(cert) == 0:
				cert = p
			default:
				extra = append(extra, p...)
			}
		}
		e.out.Write(codec.OpenVPN(ca, extra, cert, key))
	case f&codec.FPKCS7 != 0:
		switch {
		case f&codec.FChain != 0:
			certs = chain(e.snap, first)
		case f&codec.FUnusable != 0:
			certs = unusableCerts()
		}
		b, err := codec.PKCS7(ders(certs))
		if err != nil {
			return err
		}
		e.out.Write(b)
	case f&codec.FDER != 0:
		e.out.Write(first.DER)
	case f&codec.FPKCS12 != 0:
		pw, err := e.password()
		if err != nil {
			return err
		}
		s, err := e.h.signer(e.ctx, keyOf(e.snap, first), e.req.DBPass, e.req.Keys)
		if err != nil {
			return err
		}
		cert, err := pki.ParseCertificate(first.DER)
		if err != nil {
			return err
		}
		var extra []*x509.Certificate
		if f&codec.FChain != 0 {
			for _, c := range chain(e.snap, first)[1:] {
				if x, err := pki.ParseCertificate(c.DER); err == nil {
					extra = append(extra, x)
				}
			}
		}
		algo := e.snap.Settings["pkcs12_enc_algo"]
		if algo == "" {
			algo = codec.PKCS12Algorithms[0]
		}
		b, err := codec.PKCS12(s, cert, extra, string(pw), algo)
		if err != nil {
			return err
		}
		e.out.Write(b)
	case f&codec.FIndex != 0:
		// The issued certificates of the selected CAs, as in the index
		// file go-ca maintains for each CA.
		for _, ca := range certs {
			var issued []*xdb.Cert
			for _, c := range e.snap.Certs {
				if c.IssuerID == ca.ID && c.ID != ca.ID {
					issued = append(issued, c)
				}
			}
			sort.Slice(issued, func(i, j int) bool { return issued[i].Serial < issued[j].Serial })
			for _, c := range issued {
				e.out.WriteString(index.Entry(c, revocationOf(e.snap, c), e.req.Now))
			}
		}
	case f&codec.FCal != 0:
		var ev []string
		for _, c := range certs {
			ev = append(ev, e.certVEvent(c)...)
			if f&codec.FCA == 0 {
				continue
			}
			var latest *xdb.CRL
			for _, ch := range e.snap.Certs {
				if ch.IssuerID == c.ID && ch.ID != c.ID && !unusable(e.snap, ch, e.req.Now) {
					ev = append(ev, e.certVEvent(ch)...)
				}
			}
			for _, l := range e.snap.CRLs {
				if l.IssuerID == c.ID && (latest == nil || pki.DescribeCRL(l.DER).NextUpdate.After(pki.DescribeCRL(latest.DER).NextUpdate)) {
					latest = l
				}
			}
			if latest != nil {
				ev = append(ev, e.crlVEvent(latest)...)
			}
		}
		e.vcal(ev)
	case f&codec.FConfig != 0:
		x, err := pki.ParseCertificate(first.DER)
		if err != nil {
			return err
		}
		e.out.Write(codec.OpenSSLConf(x.RawSubject, x.Extensions, e.snap.Settings["string_opt"]))
	case f&codec.FJWK != 0:
		var keys []map[string]any
		for _, r := range e.refs {
			j, err := codec.JWK(r.cert.Name, r.pub, nil)
			if err != nil {
				return err
			}
			j["x5t"], j["x5t#256"] = codec.Thumbprints(r.cert.DER)
			if f&codec.FX5C != 0 {
				var x5c []string
				for _, c := range chain(e.snap, r.cert) {
					x5c = append(x5c, codec.Base64(c.DER))
				}
				j["x5c"] = x5c
			}
			keys = append(keys, j)
		}
		b, err := codec.JWKJSON(keys)
		if err != nil {
			return err
		}
		e.out.Write(b)
	default:
		return errors.New("unsupported export format")
	}
	return nil
}

func (e *exporter) keys() error {
	f := e.f.Flags
	if f&codec.FPGP != 0 {
		return e.pgp()
	}
	for _, r := range e.refs {
		k := r.key
		var s crypto.Signer
		var err error
		needSigner := f&codec.FPrivate != 0 && f&codec.FPKCS8 == 0
		if needSigner {
			if s, err = e.h.signer(e.ctx, k, e.req.DBPass, e.req.Keys); err != nil {
				return err
			}
		}
		var pw []byte
		if f&codec.FCrypt != 0 {
			if pw, err = e.password(); err != nil {
				return err
			}
		}
		switch {
		case f&codec.FPEM != 0 && f&codec.FPrivate != 0:
			b, err := codec.PrivatePEM(s, pw)
			if err != nil {
				return err
			}
			e.out.Write(e.keyComment(k))
			e.out.Write(b)
		case f&codec.FPEM != 0:
			e.out.Write(e.keyComment(k))
			e.out.Write(codec.PEM(codec.PEMPublicKey, k.Public))
		case f&codec.FDER != 0 && f&codec.FPrivate != 0:
			_, der, err := codec.Traditional(s)
			if err != nil {
				return err
			}
			e.out.Write(der)
		case f&codec.FDER != 0:
			e.out.Write(k.Public)
		case f&codec.FPKCS8 != 0:
			der, err := e.h.privateDER(e.ctx, k, e.req.DBPass, e.req.Keys)
			if err != nil {
				return err
			}
			b, err := codec.PKCS8PEM(der, pw)
			clear(der)
			if err != nil {
				return err
			}
			e.out.Write(e.keyComment(k))
			e.out.Write(b)
		case f&codec.FOpenSSH != 0:
			b, err := codec.OpenSSHPrivate(s, k.Comment, pw)
			if err != nil {
				return err
			}
			e.out.Write(b)
		case f&codec.FPuTTY != 0 && f&codec.FPrivate != 0:
			version := 3
			if f&codec.FPPK2 != 0 {
				version = 2
			}
			b, err := codec.PuTTYPrivate(s, k.Comment, version, pw)
			if err != nil {
				return err
			}
			e.out.Write(b)
		case f&codec.FPuTTY != 0:
			b, err := codec.RFC4716Public(r.pub, k.Comment)
			if err != nil {
				return err
			}
			e.out.Write(b)
		case f&codec.FSSH2 != 0 && f&codec.FPrivate != 0:
			b, err := codec.SSHPrivate(s)
			if err != nil {
				return err
			}
			e.out.Write(b)
		case f&codec.FSSH2 != 0:
			b, err := codec.SSHPublic(r.pub, k.Comment)
			if err != nil {
				return err
			}
			e.out.Write(b)
		case f&codec.FPVK != 0:
			b, err := codec.PVK(s)
			if err != nil {
				return err
			}
			e.out.Write(b)
		case f&codec.FJWK != 0:
			// collected below
		default:
			return errors.New("unsupported export format")
		}
	}
	if f&codec.FJWK != 0 {
		var keys []map[string]any
		for _, r := range e.refs {
			var s crypto.Signer
			if f&codec.FPrivate != 0 {
				var err error
				if s, err = e.h.signer(e.ctx, r.key, e.req.DBPass, e.req.Keys); err != nil {
					return err
				}
			}
			j, err := codec.JWK(r.key.Name, r.pub, s)
			if err != nil {
				return err
			}
			keys = append(keys, j)
		}
		b, err := codec.JWKJSON(keys)
		if err != nil {
			return err
		}
		e.out.Write(b)
	}
	return nil
}

func (e *exporter) requests() error {
	f := e.f.Flags
	for _, r := range e.refs {
		q := r.req
		switch {
		case f&codec.FPEM != 0:
			if e.req.PEMComment {
				if x, err := pki.ParseCertificateRequest(q.DER); err == nil {
					e.out.Write(codec.Comment(q.Name, q.Comment, codec.RFC2253(x.RawSubject)))
				}
			}
			e.out.Write(codec.PEM(codec.PEMRequest, q.DER))
		case f&codec.FDER != 0:
			e.out.Write(q.DER)
		case f&codec.FConfig != 0:
			x, err := pki.ParseCertificateRequest(q.DER)
			if err != nil {
				return err
			}
			e.out.Write(codec.OpenSSLConf(x.RawSubject, x.Extensions, e.snap.Settings["string_opt"]))
		}
	}
	return nil
}

func (e *exporter) crls() error {
	f := e.f.Flags
	var ev []string
	for _, r := range e.refs {
		l := r.crl
		switch {
		case f&codec.FPEM != 0:
			if e.req.PEMComment {
				if x, err := x509.ParseRevocationList(l.DER); err == nil {
					e.out.Write(codec.Comment(l.Name, l.Comment, codec.RFC2253(x.RawIssuer)))
				}
			}
			e.out.Write(codec.PEM(codec.PEMCRL, l.DER))
		case f&codec.FDER != 0:
			e.out.Write(l.DER)
		case f&codec.FCal != 0:
			ev = append(ev, e.crlVEvent(l)...)
		}
	}
	if f&codec.FCal != 0 {
		e.vcal(ev)
	}
	return nil
}

func (e *exporter) templates() error {
	for _, r := range e.refs {
		t, err := tmpl.Decode(r.tmpl.Blob, r.tmpl.Version)
		if err != nil {
			return err
		}
		if e.req.PEMComment {
			e.out.Write(codec.Comment(r.tmpl.Name, r.tmpl.Comment, codec.RFC2253(t.Subject)))
		}
		e.out.Write(codec.XCATemplate(r.tmpl.Name, r.tmpl.Comment, t))
	}
	return nil
}

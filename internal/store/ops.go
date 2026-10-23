package store

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/xdb"
	"github.com/mailsvb/go-ca/internal/xdbpass"
)

// ErrNeedKeyPassword means a key with its own password is involved and the
// password was missing or wrong.
var ErrNeedKeyPassword = errors.New("the key's own password is required")

// KeyPasswords supplies passwords for keys with their own password, by key
// item id. The database password covers all other keys.
type KeyPasswords map[int64][]byte

// unlock decrypts the private key of item keyID.
func (h *Handle) unlock(ctx context.Context, keyID int64, keyType string, dbPass []byte, kp KeyPasswords) (crypto.Signer, error) {
	blob, own, err := h.DB.PrivateKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("the key has no private part: %w", err)
	}
	pw := dbPass
	switch own {
	case xdb.PassPrivate:
		if pw = kp[keyID]; len(pw) == 0 {
			return nil, ErrNeedKeyPassword
		}
	case xdb.PassBogus:
		pw = []byte("Bogus")
	case xdb.PassPIN:
		return nil, errors.New("the key is on a security token, which go-ca does not access")
	}
	key, _, err := pki.DecryptPrivateKey(blob, keyType, pw)
	if errors.Is(err, pki.ErrWrongPassword) && own == xdb.PassPrivate {
		return nil, ErrNeedKeyPassword
	}
	return key, err
}

func findKey(snap *xdb.Snapshot, id int64) *xdb.Key {
	for _, k := range snap.Keys {
		if k.ID == id {
			return k
		}
	}
	return nil
}

func findCert(snap *xdb.Snapshot, id int64) *xdb.Cert {
	for _, c := range snap.Certs {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func findRequest(snap *xdb.Snapshot, id int64) *xdb.Request {
	for _, r := range snap.Requests {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// GenerateKey creates a key, encrypted with the database password.
func (h *Handle) GenerateKey(ctx context.Context, name string, spec pki.KeySpec, dbPass []byte) (int64, error) {
	key, err := pki.GenerateKey(spec)
	if err != nil {
		return 0, err
	}
	var id int64
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		id, err = insertGenerated(ctx, tx, name, key, dbPass)
		return err
	})
	h.changed(ctx)
	return id, err
}

func insertGenerated(ctx context.Context, tx *xdb.Tx, name string, key crypto.Signer, dbPass []byte) (int64, error) {
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return 0, err
	}
	blob, err := pki.EncryptPrivateKey(key, dbPass)
	if err != nil {
		return 0, err
	}
	typ, bits := pki.StoredKeyType(spki)
	return tx.InsertKey(ctx, xdb.NewKey{Name: name, Source: 2, KeyType: typ, Len: bits, SPKI: spki,
		Private: blob, OwnPass: xdb.PassCommon})
}

// IssueParams is the certificate editor's input.
type IssueParams struct {
	Request    bool // create a CSR instead of a certificate
	Name       string
	Comment    string
	Source     int // 2 generated, 3 transformed, 6 renewed
	Subject    []pki.DNAttr
	KeyID      int64        // existing key, or 0 with NewKey set
	NewKey     *pki.KeySpec // generate a key named like the item
	FromReqID  int64        // certificate from this CSR
	ReqSubject bool         // keep the CSR's subject (XCA default) instead of Subject
	CopyReqExt bool         // copy the CSR's extensions
	SignerID   int64        // CA certificate; 0 = self-signed
	NotBefore  time.Time
	NotAfter   time.Time
	NoExpiry   bool
	Hash       string
	Ext        pki.ExtSpec
	KeyPass    KeyPasswords
}

// Preview builds the extensions the editor would produce, without signing
// or storing anything (the editor's Validate button).
func (h *Handle) Preview(ctx context.Context, p IssueParams) ([]pkix.Extension, []byte, error) {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return nil, nil, err
	}
	subject, spki, _, err := subjectAndKey(snap, p, nil)
	if err != nil {
		return nil, nil, err
	}
	ectx, _, err := extContext(snap, p, subject, spki)
	if err != nil {
		return nil, nil, err
	}
	exts, err := pki.BuildExtensions(p.Ext, ectx)
	if err != nil {
		return nil, nil, err
	}
	if p.CopyReqExt && p.FromReqID != 0 && !p.Request {
		exts = mergeReqExt(snap, p.FromReqID, exts)
	}
	return exts, subject, nil
}

// subjectAndKey resolves the subject name and public key. With newKey
// non-nil and p.NewKey set, a placeholder is used for previews.
func subjectAndKey(snap *xdb.Snapshot, p IssueParams, generated crypto.Signer) (subject, spki []byte, req *x509.CertificateRequest, err error) {
	settings := snap.Settings
	if p.FromReqID != 0 && !p.Request {
		r := findRequest(snap, p.FromReqID)
		if r == nil {
			return nil, nil, nil, errors.New("the selected request does not exist")
		}
		if req, err = x509.ParseCertificateRequest(r.DER); err != nil {
			return nil, nil, nil, err
		}
		spki = req.RawSubjectPublicKeyInfo
		if p.ReqSubject {
			subject = req.RawSubject
		}
	}
	if subject == nil {
		if subject, err = pki.BuildName(p.Subject, settings["string_opt"]); err != nil {
			return nil, nil, nil, err
		}
	}
	if spki == nil {
		switch {
		case generated != nil:
			spki, err = x509.MarshalPKIXPublicKey(generated.Public())
		case p.KeyID != 0:
			k := findKey(snap, p.KeyID)
			if k == nil {
				return nil, nil, nil, errors.New("the selected key does not exist")
			}
			spki = k.Public
		case p.NewKey != nil:
			// Preview with a key to be generated: no key identifier yet.
			spki = nil
		default:
			return nil, nil, nil, errors.New("select or generate a key")
		}
	}
	return subject, spki, req, err
}

// extContext gathers what extension values refer to: the signer's key
// identifier, name and alternative names.
func extContext(snap *xdb.Snapshot, p IssueParams, subject, spki []byte) (pki.ExtContext, *xdb.Cert, error) {
	ectx := pki.ExtContext{SubjectSPKI: spki, Subject: subject, Request: p.Request,
		NoNetscape: snap.Settings["disable_netscape"] == "yes"}
	if spki == nil {
		// key not generated yet (preview): use a dummy so SKI can be shown
		dummy, _ := pki.GenerateKey(pki.KeySpec{Type: "Ed25519"})
		ectx.SubjectSPKI, _ = x509.MarshalPKIXPublicKey(dummy.Public())
	}
	if p.Request {
		return ectx, nil, nil
	}
	if p.SignerID == 0 {
		ectx.SelfSigned = true
		ectx.IssuerSPKI = ectx.SubjectSPKI
		return ectx, nil, nil
	}
	ca := findCert(snap, p.SignerID)
	if ca == nil || !ca.CA {
		return ectx, nil, errors.New("the selected signer is not a CA certificate")
	}
	cc, err := x509.ParseCertificate(ca.DER)
	if err != nil {
		return ectx, nil, err
	}
	ectx.IssuerSPKI, ectx.IssuerSKI = cc.RawSubjectPublicKeyInfo, cc.SubjectKeyId
	ectx.IssuerName, ectx.IssuerSerial = cc.RawIssuer, cc.SerialNumber
	for _, e := range cc.Extensions {
		if e.Id.Equal(asnOID(2, 5, 29, 17)) {
			ectx.IssuerSAN = e.Value
		}
	}
	return ectx, ca, nil
}

// mergeReqExt applies the CSR's extensions over the editor's, replacing
// those with the same OID (XCA: addV3ext(ext, override=true)).
func mergeReqExt(snap *xdb.Snapshot, reqID int64, exts []pkix.Extension) []pkix.Extension {
	r := findRequest(snap, reqID)
	if r == nil {
		return exts
	}
	req, err := x509.ParseCertificateRequest(r.DER)
	if err != nil {
		return exts
	}
	for _, re := range req.Extensions {
		replaced := false
		for i := range exts {
			if exts[i].Id.Equal(re.Id) {
				exts[i], replaced = re, true
			}
		}
		if !replaced {
			exts = append(exts, re)
		}
	}
	return exts
}

// usedSerials returns the serials a CA must not reuse: its own, those of
// certificates it issued and its revocations (getUniqueSerial).
func usedSerials(snap *xdb.Snapshot, ca *xdb.Cert) map[string]bool {
	used := map[string]bool{ca.Serial: true}
	for _, c := range snap.Certs {
		if c.IssuerID == ca.ID {
			used[c.Serial] = true
		}
	}
	for _, r := range snap.Revocations {
		if r.CAID == ca.ID {
			used[r.Serial] = true
		}
	}
	return used
}

// Issue creates a certificate or CSR as the editor describes and stores it
// (with a generated key, if requested) in one transaction.
func (h *Handle) Issue(ctx context.Context, p IssueParams, dbPass []byte) (int64, error) {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	if p.Name == "" {
		return 0, errors.New("the internal name must not be empty")
	}
	var generated crypto.Signer
	if p.NewKey != nil && p.KeyID == 0 && (p.FromReqID == 0 || p.Request) {
		if generated, err = pki.GenerateKey(*p.NewKey); err != nil {
			return 0, err
		}
	}
	subject, spki, csr, err := subjectAndKey(snap, p, generated)
	if err != nil {
		return 0, err
	}
	if err := checkMandatory(snap, subject); err != nil {
		return 0, err
	}
	ectx, ca, err := extContext(snap, p, subject, spki)
	if err != nil {
		return 0, err
	}
	exts, err := pki.BuildExtensions(p.Ext, ectx)
	if err != nil {
		return 0, err
	}
	// The subject's own private key (self-signed certificates and CSRs).
	var subjectKey crypto.Signer = generated
	if subjectKey == nil && (p.Request || p.SignerID == 0) {
		keyID := p.KeyID
		if csr != nil { // self-signed from a CSR: the CSR's key must be in the database
			r := findRequest(snap, p.FromReqID)
			keyID = r.KeyID
			if keyID == 0 {
				return 0, errors.New("the private key of the request is not in the database")
			}
		}
		k := findKey(snap, keyID)
		if k == nil || !k.HasPrivate {
			return 0, errors.New("the selected key has no private part")
		}
		if subjectKey, err = h.unlock(ctx, k.ID, k.KeyType, dbPass, p.KeyPass); err != nil {
			return 0, err
		}
	}
	var der []byte
	if p.Request {
		if der, err = pki.CreateRequest(subject, exts, subjectKey, p.Hash); err != nil {
			return 0, err
		}
	} else {
		if p.CopyReqExt && csr != nil {
			exts = mergeReqExt(snap, p.FromReqID, exts)
		}
		var pub crypto.PublicKey
		if csr != nil {
			pub = csr.PublicKey
		} else if generated != nil {
			pub = generated.Public()
		} else if pub, err = x509.ParsePKIXPublicKey(spki); err != nil {
			return 0, fmt.Errorf("go-ca cannot issue certificates for this key type: %w", err)
		}
		cr := pki.CertRequest{Subject: subject, PublicKey: pub, NotBefore: p.NotBefore, NotAfter: p.NotAfter,
			Extensions: exts, Hash: p.Hash, SignerKey: subjectKey}
		if p.NoExpiry {
			cr.NotAfter = pki.NoExpiry
		}
		serialLen, _ := strconv.Atoi(snap.Settings["serial_len"])
		used := map[string]bool{}
		if ca != nil {
			used = usedSerials(snap, ca)
			cak := findKey(snap, ca.KeyID)
			if ca.KeyID == 0 || cak == nil || !cak.HasPrivate {
				return 0, errors.New("the private key of the CA is not in the database")
			}
			if cr.SignerKey, err = h.unlock(ctx, cak.ID, cak.KeyType, dbPass, p.KeyPass); err != nil {
				return 0, err
			}
			if cr.Issuer, err = x509.ParseCertificate(ca.DER); err != nil {
				return 0, err
			}
		}
		for i := 0; ; i++ {
			if i > 100 {
				return 0, errors.New("failed to find an unused serial number")
			}
			if cr.Serial, err = pki.RandomSerial(serialLen); err != nil {
				return 0, err
			}
			if !used[pki.SerialHex(cr.Serial)] {
				break
			}
		}
		if der, err = pki.CreateCertificate(cr); err != nil {
			return 0, err
		}
	}
	source := p.Source
	if source == 0 {
		source = 2
	}
	var id int64
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		if generated != nil {
			if _, err := insertGenerated(ctx, tx, p.Name, generated, dbPass); err != nil {
				return err
			}
		}
		if p.Request {
			id, err = tx.InsertRequest(ctx, xdb.NewRequest{Name: p.Name, Comment: p.Comment, Source: source, DER: der})
			return err
		}
		if id, err = tx.InsertCert(ctx, xdb.NewCert{Name: p.Name, Comment: p.Comment, Source: source, DER: der}); err != nil {
			return err
		}
		if csr != nil {
			r := findRequest(snap, p.FromReqID)
			issuer := p.Name
			if ca != nil {
				issuer = ca.Name
			}
			msg := fmt.Sprintf("Signed on %s by '%s'", time.Now().UTC().Format("2006-01-02 15:04:05 GMT"), issuer)
			if err := tx.MarkSigned(ctx, r.ID, true); err != nil {
				return err
			}
			if err := tx.Rename(ctx, r.ID, r.Name, xdb.AppendComment(r.Comment, msg)); err != nil {
				return err
			}
		}
		return nil
	})
	h.changed(ctx)
	return id, err
}

// checkMandatory enforces settings.mandatory_dn (comma separated names).
func checkMandatory(snap *xdb.Snapshot, subject []byte) error {
	present := map[string]bool{}
	for _, e := range pki.NameAttrs(subject) {
		present[e.Name] = true
	}
	for _, m := range splitComma(snap.Settings["mandatory_dn"]) {
		oid, err := pki.AttrOID(m)
		if err != nil {
			continue
		}
		if !present[pki.AttrShortName(oid)] {
			return &MissingAttrError{Attr: pki.AttrShortName(oid)}
		}
	}
	return nil
}

// MissingAttrError reports a mandatory subject entry that is empty.
type MissingAttrError struct{ Attr string }

func (e *MissingAttrError) Error() string { return "mandatory subject entry missing: " + e.Attr }

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s + "," {
		if r == ',' {
			if t := trimSpace(cur); t != "" {
				out = append(out, t)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	return out
}

func trimSpace(s string) string { return string(bytes.TrimSpace([]byte(s))) }

// ExtractPublicKey stores the public key of a certificate or request as a
// key item (db_x509super::extractPubkey).
func (h *Handle) ExtractPublicKey(ctx context.Context, id int64) (int64, error) {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	var name, kind string
	var spki []byte
	if c := findCert(snap, id); c != nil {
		if cc, err := x509.ParseCertificate(c.DER); err == nil {
			name, kind, spki = c.Name, "Certificate", cc.RawSubjectPublicKeyInfo
		}
	} else if r := findRequest(snap, id); r != nil {
		if rr, err := x509.ParseCertificateRequest(r.DER); err == nil {
			name, kind, spki = r.Name, "Certificate request", rr.RawSubjectPublicKeyInfo
		}
	}
	if spki == nil {
		return 0, errors.New("no public key found")
	}
	for _, k := range snap.Keys {
		if bytes.Equal(k.Public, spki) {
			return 0, errors.New("this key is already in the database")
		}
	}
	typ, bits := pki.StoredKeyType(spki)
	var kid int64
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		kid, err = tx.InsertKey(ctx, xdb.NewKey{Name: name, Source: 3, KeyType: typ, Len: bits, SPKI: spki,
			Comment: xdb.AppendComment("", fmt.Sprintf("Extracted from %s '%s'", kind, name))})
		return err
	})
	h.changed(ctx)
	return kid, err
}

// CertToRequest creates a CSR from a certificate and its key
// (db_x509::toRequest): same subject, hash and extensions without AKI/IAN.
func (h *Handle) CertToRequest(ctx context.Context, id int64, dbPass []byte, kp KeyPasswords) (int64, error) {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	c := findCert(snap, id)
	if c == nil {
		return 0, errors.New("certificate not found")
	}
	k := findKey(snap, c.KeyID)
	if k == nil || !k.HasPrivate {
		return 0, errors.New("the private key of the certificate is not in the database")
	}
	key, err := h.unlock(ctx, k.ID, k.KeyType, dbPass, kp)
	if err != nil {
		return 0, err
	}
	cc, err := x509.ParseCertificate(c.DER)
	if err != nil {
		return 0, err
	}
	var exts []pkix.Extension
	for _, e := range cc.Extensions {
		if !e.Id.Equal(asnOID(2, 5, 29, 35)) && !e.Id.Equal(asnOID(2, 5, 29, 18)) {
			exts = append(exts, e)
		}
	}
	der, err := pki.CreateRequest(cc.RawSubject, exts, key, pki.HashName(cc.SignatureAlgorithm))
	if err != nil {
		return 0, err
	}
	var rid int64
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		rid, err = tx.InsertRequest(ctx, xdb.NewRequest{Name: c.Name, Source: 3, DER: der})
		return err
	})
	h.changed(ctx)
	return rid, err
}

// ChangeDatabasePassword re-encrypts every key protected by the database
// password and stores a new password hash, after a backup.
func (h *Handle) ChangeDatabasePassword(ctx context.Context, oldPass, newPass []byte) error {
	stored, err := h.DB.Setting(ctx, "pwhash")
	if err != nil {
		return err
	}
	if ok, _ := xdbpass.Verify(stored, oldPass); !ok {
		return pki.ErrWrongPassword
	}
	rows, err := h.DB.PrivateKeyRows(ctx)
	if err != nil {
		return err
	}
	type re struct {
		id   int64
		blob []byte
	}
	var updates []re
	for _, r := range rows {
		if r.OwnPass != xdb.PassCommon {
			continue
		}
		key, _, err := pki.DecryptPrivateKey(r.Blob, r.KeyType, oldPass)
		if err != nil {
			return fmt.Errorf("key %d: %w", r.ID, err)
		}
		blob, err := pki.EncryptPrivateKey(key, newPass)
		if err != nil {
			return err
		}
		updates = append(updates, re{r.ID, blob})
	}
	if _, err := h.Backup(ctx); err != nil {
		return err
	}
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		for _, u := range updates {
			if err := tx.UpdatePrivateKey(ctx, u.id, u.blob, xdb.PassCommon); err != nil {
				return err
			}
		}
		return tx.SetSetting(ctx, "pwhash", xdbpass.NewHash(newPass))
	})
	h.changed(ctx)
	return err
}

// SetKeyPassword gives a key its own password (ownPass = 1). current is
// the key's present password: the database password or its own.
func (h *Handle) SetKeyPassword(ctx context.Context, keyID int64, dbPass []byte, kp KeyPasswords, newPass []byte) error {
	return h.rekey(ctx, keyID, dbPass, kp, newPass, xdb.PassPrivate)
}

// ResetKeyPassword protects a key with the database password again.
func (h *Handle) ResetKeyPassword(ctx context.Context, keyID int64, dbPass []byte, kp KeyPasswords) error {
	return h.rekey(ctx, keyID, dbPass, kp, dbPass, xdb.PassCommon)
}

func (h *Handle) rekey(ctx context.Context, keyID int64, dbPass []byte, kp KeyPasswords, newPass []byte, own int) error {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return err
	}
	k := findKey(snap, keyID)
	if k == nil || !k.HasPrivate {
		return errors.New("the key has no private part")
	}
	key, err := h.unlock(ctx, k.ID, k.KeyType, dbPass, kp)
	if err != nil {
		return err
	}
	blob, err := pki.EncryptPrivateKey(key, newPass)
	if err != nil {
		return err
	}
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error { return tx.UpdatePrivateKey(ctx, keyID, blob, own) })
	h.changed(ctx)
	return err
}

// Rename, Delete and MarkSigned wrap the single-statement writes.
func (h *Handle) Rename(ctx context.Context, id int64, name, comment string) error {
	err := h.DB.Write(ctx, func(tx *xdb.Tx) error { return tx.Rename(ctx, id, name, comment) })
	h.changed(ctx)
	return err
}

func (h *Handle) Delete(ctx context.Context, id int64) error {
	err := h.DB.Write(ctx, func(tx *xdb.Tx) error { return tx.Delete(ctx, id) })
	h.changed(ctx)
	return err
}

func (h *Handle) MarkSigned(ctx context.Context, id int64, signed bool) error {
	err := h.DB.Write(ctx, func(tx *xdb.Tx) error { return tx.MarkSigned(ctx, id, signed) })
	h.changed(ctx)
	return err
}

// SetSettings writes options shared with XCA.
func (h *Handle) SetSettings(ctx context.Context, values map[string]string) error {
	err := h.DB.Write(ctx, func(tx *xdb.Tx) error {
		for k, v := range values {
			if err := tx.SetSetting(ctx, k, v); err != nil {
				return err
			}
		}
		return nil
	})
	h.changed(ctx)
	return err
}

func asnOID(parts ...int) asn1.ObjectIdentifier { return parts }

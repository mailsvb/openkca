package store

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys exist in old OpenPGP keyrings
	"errors"
	"path"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/vault"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// PGPView is a stored OpenPGP certificate with its keys mapped to the
// key items holding them.
type PGPView struct {
	Cert   *xdb.PGPCert
	Info   *codec.PGPInfo
	KeyIDs []int64 // per Info.Keys: the key item, 0 if the key is not stored
}

// Primary returns the key item of the primary key.
func (v *PGPView) Primary() int64 { return v.KeyIDs[0] }

// ErrNoPGP means a key has no OpenPGP certificate.
var ErrNoPGP = errors.New("the key has no OpenPGP certificate")

func samePublic(a, b crypto.PublicKey) bool {
	if da, ok := a.(*dsa.PublicKey); ok {
		db, ok := b.(*dsa.PublicKey)
		return ok && da.Y.Cmp(db.Y) == 0 && da.P.Cmp(db.P) == 0 && da.G.Cmp(db.G) == 0
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

// pgpViews describes every stored certificate. A certificate that does not
// parse is left out.
func pgpViews(snap *xdb.Snapshot) []*PGPView {
	pubs := make(map[int64]crypto.PublicKey, len(snap.Keys))
	for _, k := range snap.Keys {
		if p, err := codec.ParsePublic(k.Public); err == nil {
			pubs[k.ID] = p
		}
	}
	var out []*PGPView
	for _, c := range snap.PGP {
		info, err := codec.ParsePGPCert(c.Cert)
		if err != nil {
			continue
		}
		v := &PGPView{Cert: c, Info: info, KeyIDs: make([]int64, len(info.Keys))}
		v.KeyIDs[0] = c.KeyID
		for i, k := range info.Keys[1:] {
			if k.Public == nil {
				continue
			}
			for _, sk := range snap.Keys {
				if p := pubs[sk.ID]; p != nil && samePublic(p, k.Public) {
					v.KeyIDs[i+1] = sk.ID
					break
				}
			}
		}
		out = append(out, v)
	}
	return out
}

// PGPOf returns the certificate whose primary key is keyID, or nil.
func PGPOf(snap *xdb.Snapshot, keyID int64) *PGPView {
	for _, c := range snap.PGP {
		if c.KeyID == keyID {
			for _, v := range pgpViews(&xdb.Snapshot{Keys: snap.Keys, PGP: []*xdb.PGPCert{c}}) {
				return v
			}
		}
	}
	return nil
}

// PGPSubkeyOf returns the certificate in which keyID is a subkey, or nil.
func PGPSubkeyOf(snap *xdb.Snapshot, keyID int64) *PGPView {
	for _, v := range pgpViews(snap) {
		for _, id := range v.KeyIDs[1:] {
			if id == keyID {
				return v
			}
		}
	}
	return nil
}

// PGPSubkey names a stored key to bind to a certificate, or a key to
// generate for it (Spec set, named Name).
type PGPSubkey struct {
	KeyID int64
	Spec  *pki.KeySpec
	Name  string
	Usage string // codec.PGPEncrypt, codec.PGPSign or codec.PGPAuth
}

// GeneratePGPKey generates a primary key and its subkeys and certifies
// them as an OpenPGP key. It returns the primary key's item ID.
func (h *Handle) GeneratePGPKey(ctx context.Context, name, comment string, spec pki.KeySpec, subs []PGPSubkey, p codec.PGPParams, kr *vault.Keyring) (int64, error) {
	primary, err := pki.GenerateKey(spec)
	if err != nil {
		return 0, err
	}
	keys, err := h.pgpSubkeys(ctx, subs, kr, nil)
	if err != nil {
		return 0, err
	}
	if p.Created.IsZero() {
		p.Created = time.Now()
	}
	var id int64
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		if id, err = insertGenerated(ctx, tx, name, comment, primary, kr); err != nil {
			return err
		}
		return certifyPGP(ctx, tx, id, primary, subs, keys, p, kr)
	})
	h.changed(ctx)
	return id, err
}

// CreatePGP certifies a stored key as the primary key of a new OpenPGP
// key, with the given subkeys.
func (h *Handle) CreatePGP(ctx context.Context, keyID int64, subs []PGPSubkey, p codec.PGPParams, kr *vault.Keyring, kp KeyPasswords) error {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return err
	}
	k := findKey(snap, keyID)
	if k == nil {
		return errors.New("key not found")
	}
	if PGPOf(snap, keyID) != nil {
		return errors.New("the key has an OpenPGP certificate already")
	}
	primary, err := h.signer(ctx, k, kr, kp)
	if err != nil {
		return err
	}
	keys, err := h.pgpSubkeys(ctx, subs, kr, kp)
	if err != nil {
		return err
	}
	if p.Created.IsZero() {
		p.Created = time.Now()
	}
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		return certifyPGP(ctx, tx, keyID, primary, subs, keys, p, kr)
	})
	h.changed(ctx)
	return err
}

// pgpSubkeys unlocks the stored subkeys and generates the new ones, which
// certifyPGP stores.
func (h *Handle) pgpSubkeys(ctx context.Context, subs []PGPSubkey, kr *vault.Keyring, kp KeyPasswords) ([]crypto.Signer, error) {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]crypto.Signer, len(subs))
	for i, s := range subs {
		if s.Spec != nil {
			if keys[i], err = pki.GenerateKey(*s.Spec); err != nil {
				return nil, err
			}
			continue
		}
		k := findKey(snap, s.KeyID)
		if k == nil {
			return nil, errors.New("subkey not found")
		}
		if keys[i], err = h.signer(ctx, k, kr, kp); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// certifyPGP stores the generated subkeys, builds the certificate and
// stores it for primaryID.
func certifyPGP(ctx context.Context, tx *xdb.Tx, primaryID int64, primary crypto.Signer, subs []PGPSubkey, keys []crypto.Signer, p codec.PGPParams, kr *vault.Keyring) error {
	var bind []codec.PGPSubkey
	for i, s := range subs {
		if s.Spec != nil {
			if _, err := insertGenerated(ctx, tx, s.Name, "", keys[i], kr); err != nil {
				return err
			}
		}
		bind = append(bind, codec.PGPSubkey{Key: keys[i], Usage: s.Usage})
	}
	cert, err := codec.NewPGPCert(primary, bind, p)
	if err != nil {
		return err
	}
	return setPGPCert(ctx, tx, primaryID, cert)
}

func setPGPCert(ctx context.Context, tx *xdb.Tx, keyID int64, cert []byte) error {
	info, err := codec.ParsePGPCert(cert)
	if err != nil {
		return err
	}
	return tx.SetPGPCert(ctx, xdb.PGPCert{KeyID: keyID, Fingerprint: info.Keys[0].Fingerprint, Cert: cert})
}

// AddPGPSubkey binds a stored key, for example an SSH key as
// authentication subkey, or a new one to the OpenPGP key of primaryID. The
// subkey expires with the primary key.
func (h *Handle) AddPGPSubkey(ctx context.Context, primaryID int64, sub PGPSubkey, kr *vault.Keyring, kp KeyPasswords) error {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return err
	}
	v := PGPOf(snap, primaryID)
	if v == nil {
		return ErrNoPGP
	}
	if sub.Spec == nil && (sub.KeyID == primaryID || PGPOf(snap, sub.KeyID) != nil) {
		return errors.New("the key is the primary key of an OpenPGP key")
	}
	primary, err := h.signer(ctx, findKey(snap, primaryID), kr, kp)
	if err != nil {
		return err
	}
	keys, err := h.pgpSubkeys(ctx, []PGPSubkey{sub}, kr, kp)
	if err != nil {
		return err
	}
	now := time.Now().Truncate(time.Second)
	var lifetime time.Duration
	if exp := v.Info.Keys[0].Expires; !exp.IsZero() {
		if !exp.After(now) {
			return errors.New("the OpenPGP key has expired")
		}
		lifetime = exp.Sub(now)
	}
	cert, err := codec.AddPGPSubkey(v.Cert.Cert, primary, codec.PGPSubkey{Key: keys[0], Usage: sub.Usage}, now, lifetime)
	if err != nil {
		return err
	}
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		if sub.Spec != nil {
			if _, err := insertGenerated(ctx, tx, sub.Name, "", keys[0], kr); err != nil {
				return err
			}
		}
		return setPGPCert(ctx, tx, primaryID, cert)
	})
	h.changed(ctx)
	return err
}

// DeletePGP removes the OpenPGP certificate of a key; the keys stay.
func (h *Handle) DeletePGP(ctx context.Context, keyID int64) error {
	err := h.DB.Write(ctx, func(tx *xdb.Tx) error { return tx.DeletePGPCert(ctx, keyID) })
	h.changed(ctx)
	return err
}

// pgpSecrets unlocks the secret of every stored key of a certificate; a
// key not stored, without private part or on a token stays nil, except the
// primary key, which is required.
func (h *Handle) pgpSecrets(ctx context.Context, snap *xdb.Snapshot, v *PGPView, kr *vault.Keyring, kp KeyPasswords) ([]crypto.Signer, error) {
	keys := make([]crypto.Signer, len(v.KeyIDs))
	for i, id := range v.KeyIDs {
		k := findKey(snap, id)
		if id == 0 || k == nil || !k.HasPrivate || k.Token {
			if i == 0 {
				return nil, ErrNoPrivateKey
			}
			continue
		}
		s, err := h.signer(ctx, k, kr, kp)
		if err != nil {
			return nil, err
		}
		keys[i] = s
	}
	return keys, nil
}

// pgpExport writes the OpenPGP formats of keys.
func (e *exporter) pgp() error {
	f := e.f.Flags
	var out []byte
	version := 6
	for _, r := range e.refs {
		v := PGPOf(e.snap, r.key.ID)
		if v == nil {
			return ErrNoPGP
		}
		if v.Info.Version != 6 {
			version = 4
		}
		switch {
		case f&codec.FRevocation != 0:
			k, err := e.h.signer(e.ctx, r.key, e.req.Keyring, e.req.Keys)
			if err != nil {
				return err
			}
			rev, err := codec.PGPRevocation(v.Cert.Cert, k, false, e.req.Now)
			if err != nil {
				return err
			}
			out = append(out, rev...)
		case f&codec.FPrivate != 0:
			var pw []byte
			if f&codec.FCrypt != 0 {
				var err error
				if pw, err = e.password(); err != nil {
					return err
				}
			}
			keys, err := e.h.pgpSecrets(e.ctx, e.snap, v, e.req.Keyring, e.req.Keys)
			if err != nil {
				return err
			}
			sec, err := codec.PGPSecret(v.Cert.Cert, keys, pw)
			if err != nil {
				return err
			}
			out = append(out, sec...)
		default:
			out = append(out, v.Cert.Cert...)
		}
	}
	if f&codec.FBinary != 0 {
		e.out.Write(out)
		return nil
	}
	block := codec.PGPPublicBlock
	if f&codec.FPrivate != 0 && f&codec.FRevocation == 0 {
		block = codec.PGPPrivateBlock
	}
	b, err := codec.PGPArmor(block, out, version)
	if err != nil {
		return err
	}
	e.out.Write(b)
	return nil
}

// PGPBundle exports a key's OpenPGP key as a ZIP archive: the public key,
// the secret key (encrypted with req.Password when set) and a revocation
// certificate, all armored. req selects one key.
func (h *Handle) PGPBundle(ctx context.Context, req ExportRequest) (*ExportResult, error) {
	if len(req.IDs) != 1 {
		return nil, errors.New("select exactly one key")
	}
	type part struct {
		format int
		suffix string
	}
	parts := []part{{110, ".asc"}, {112, ".secret.asc"}, {114, ".rev.asc"}}
	if len(req.Password) > 0 {
		parts[1].format = 113
	}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	now := time.Now()
	var base string
	for _, p := range parts {
		req.Format = p.format
		res, err := h.Export(ctx, req)
		if err != nil {
			return nil, err
		}
		base = strings.TrimSuffix(res.Filename, path.Ext(res.Filename))
		w, err := z.CreateHeader(&zip.FileHeader{Name: base + p.suffix, Method: zip.Deflate, Modified: now})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(res.Data); err != nil {
			return nil, err
		}
		clear(res.Data)
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return &ExportResult{Filename: base + ".pgp.zip", ContentType: "application/zip", Data: buf.Bytes()}, nil
}

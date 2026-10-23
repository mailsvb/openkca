package codec

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys exist in old OpenPGP keyrings
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	gcecdh "github.com/ProtonMail/go-crypto/openpgp/ecdh"
	gcecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	gced25519 "github.com/ProtonMail/go-crypto/openpgp/ed25519"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/go-crypto/openpgp/x25519"

	"github.com/mailsvb/go-ca/internal/pki"
)

// Armor block types of OpenPGP keys.
const (
	PGPPublicBlock  = "PGP PUBLIC KEY BLOCK"
	PGPPrivateBlock = "PGP PRIVATE KEY BLOCK"
)

// Key usages of an OpenPGP key, as gpg shows them.
const (
	PGPCertify = "C"
	PGPSign    = "S"
	PGPEncrypt = "E"
	PGPAuth    = "A"
)

// Limits for OpenPGP data being read.
const (
	pgpMaxEntities     = 1 << 10
	pgpMaxSignatures   = 1 << 14 // verified per file
	pgpMaxOtherCerts   = 1 << 7  // third-party certifications kept per user ID
	pgpMaxArgon2Memory = 19      // exponent: 2^19 KiB (512 MiB)
	pgpMaxArgon2Work   = 1 << 24 // KiB times passes
)

// S2K parameters for exported secret keys: v4 keys use iterated and salted
// SHA-256 with AES-256 in CFB mode, which every implementation reads; v6
// keys use Argon2 with AES-256 in OCB mode (RFC 9580, second recommended
// Argon2 parameter set).
const (
	pgpS2KCount      = 65011712
	pgpArgon2Passes  = 3
	pgpArgon2Lanes   = 4
	pgpArgon2Memory  = 1 << 16 // KiB
	pgpDummyS2KBytes = "\xff\x00\x65\x00GNU\x01"
)

// ErrPGPArgon2Limit means an imported key asks for more Argon2 work than
// go-ca allows.
var ErrPGPArgon2Limit = errors.New("openpgp: the key's Argon2 parameters exceed go-ca's limits")

// PGPParams describe a new OpenPGP certificate.
type PGPParams struct {
	Version  int // 4 or 6
	UIDs     []string
	Created  time.Time
	Lifetime time.Duration // 0: does not expire
}

// PGPSubkey is a subkey to bind to a certificate, with its usage
// (PGPEncrypt, PGPSign or PGPAuth).
type PGPSubkey struct {
	Key   crypto.Signer
	Usage string
}

// PGPKeyInfo describes the primary key or a subkey of a certificate.
type PGPKeyInfo struct {
	Fingerprint string // upper case hex
	KeyID       string // upper case hex, 16 digits
	Algorithm   string
	Created     time.Time
	Expires     time.Time // zero: does not expire
	Usage       string    // e.g. "SC", "E"
	Revoked     bool
	Public      crypto.PublicKey // nil for algorithms go-ca cannot store
}

// Usages lists the key's usages, one letter each.
func (k PGPKeyInfo) Usages() []string { return strings.Split(k.Usage, "") }

// PGPInfo describes an OpenPGP certificate.
type PGPInfo struct {
	Version int
	UIDs    []string // primary user ID first
	Keys    []PGPKeyInfo
	Revoked bool
}

// Expired reports whether the primary key has expired at now.
func (i *PGPInfo) Expired(now time.Time) bool {
	return !i.Keys[0].Expires.IsZero() && !now.Before(i.Keys[0].Expires)
}

// PGPEntity is one key found in an imported OpenPGP file.
type PGPEntity struct {
	Cert    []byte // the public certificate, binary
	Info    *PGPInfo
	Private []crypto.Signer // per key of Info.Keys; nil where the file has no usable secret
}

// FormatPGPFingerprint groups a fingerprint in blocks of four as gpg shows
// v4 fingerprints.
func FormatPGPFingerprint(fpr string) string {
	var b strings.Builder
	for i := 0; i < len(fpr); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
			if i == len(fpr)/2 && len(fpr) == 40 {
				b.WriteByte(' ')
			}
		}
		b.WriteString(fpr[i:min(i+4, len(fpr))])
	}
	return b.String()
}

// ValidPGPUserID reports whether s can be an OpenPGP user ID: UTF-8 text
// of one line.
func ValidPGPUserID(s string) bool {
	if s == "" || len(s) > 1024 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// PGPCompatible reports whether a key can be an OpenPGP key of the
// version: a primary key or signing subkey (encrypt false) or an
// encryption subkey (encrypt true).
func PGPCompatible(pub crypto.PublicKey, version int, encrypt bool) bool {
	_, err := pgpPublicKey(pub, time.Unix(0, 0), version == 6, encrypt)
	return err == nil
}

func pgpConfig(created time.Time, v6 bool) *packet.Config {
	c := &packet.Config{
		Time:          func() time.Time { return created },
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
		V6Keys:        v6,
	}
	return c
}

// NewPGPCert certifies primary with the user IDs of p and binds the
// subkeys, signing with primary. It returns the binary certificate.
func NewPGPCert(primary crypto.Signer, subs []PGPSubkey, p PGPParams) ([]byte, error) {
	if p.Version != 4 && p.Version != 6 {
		return nil, fmt.Errorf("openpgp: unsupported key version %d", p.Version)
	}
	v6 := p.Version == 6
	if len(p.UIDs) == 0 && !v6 {
		return nil, errors.New("openpgp: a v4 key needs a user ID")
	}
	created := p.Created.UTC().Truncate(time.Second)
	if p.Lifetime < 0 || p.Lifetime/time.Second > 1<<32-1 {
		return nil, errors.New("openpgp: invalid key lifetime")
	}
	lifetime := uint32(p.Lifetime / time.Second)
	if !pki.CanSign(primary) {
		return nil, errors.New("openpgp: the primary key must be able to sign")
	}
	pub, err := pgpPublicKey(primary.Public(), created, v6, false)
	if err != nil {
		return nil, err
	}
	priv, err := pgpPrivateKey(pub, primary)
	if err != nil {
		return nil, err
	}
	config := pgpConfig(created, v6)
	e := &openpgp.Entity{PrimaryKey: &priv.PublicKey, PrivateKey: priv, Identities: map[string]*openpgp.Identity{}}
	if v6 {
		sig := pgpSignature(e.PrimaryKey, packet.SigTypeDirectSignature, created)
		pgpKeyProperties(sig, e.PrimaryKey, lifetime, v6)
		if err := sig.SignDirectKeyBinding(e.PrimaryKey, priv, config); err != nil {
			return nil, err
		}
		e.DirectSignatures = append(e.DirectSignatures, packet.NewVerifiableSig(sig))
	}
	var order []string
	for i, uid := range p.UIDs {
		if !ValidPGPUserID(uid) {
			return nil, fmt.Errorf("openpgp: invalid user ID %q", uid)
		}
		if _, dup := e.Identities[uid]; dup {
			return nil, fmt.Errorf("openpgp: duplicate user ID %q", uid)
		}
		sig := pgpSignature(e.PrimaryKey, packet.SigTypePositiveCert, created)
		if !v6 {
			pgpKeyProperties(sig, e.PrimaryKey, lifetime, v6)
		}
		isPrimary := i == 0
		sig.IsPrimaryId = &isPrimary
		if err := sig.SignUserId(uid, e.PrimaryKey, priv, config); err != nil {
			return nil, err
		}
		e.Identities[uid] = &openpgp.Identity{Primary: e, Name: uid, UserId: &packet.UserId{Id: uid},
			SelfCertifications: []*packet.VerifiableSignature{packet.NewVerifiableSig(sig)}}
		order = append(order, uid)
	}
	for _, sub := range subs {
		if err := addPGPSubkey(e, priv, sub, created, lifetime, config); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	if err := writePGPEntity(&buf, e, order, nil); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// AddPGPSubkey binds a further subkey to a certificate, signed with the
// primary key, created at created.
func AddPGPSubkey(cert []byte, primary crypto.Signer, sub PGPSubkey, created time.Time, lifetime time.Duration) ([]byte, error) {
	e, err := readPGPCert(cert)
	if err != nil {
		return nil, err
	}
	priv, err := pgpPrivateKey(e.PrimaryKey, primary)
	if err != nil {
		return nil, err
	}
	created = created.UTC().Truncate(time.Second)
	if lifetime < 0 || lifetime/time.Second > 1<<32-1 {
		return nil, errors.New("openpgp: invalid key lifetime")
	}
	if err := addPGPSubkey(e, priv, sub, created, uint32(lifetime/time.Second), pgpConfig(created, e.PrimaryKey.Version == 6)); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writePGPEntity(&buf, e, nil, nil); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func addPGPSubkey(e *openpgp.Entity, primary *packet.PrivateKey, sub PGPSubkey, created time.Time, lifetime uint32, config *packet.Config) error {
	encrypt := sub.Usage == PGPEncrypt
	if !encrypt && sub.Usage != PGPSign && sub.Usage != PGPAuth {
		return fmt.Errorf("openpgp: invalid subkey usage %q", sub.Usage)
	}
	if !encrypt && !pki.CanSign(sub.Key) {
		return errors.New("openpgp: a signing or authentication subkey must be able to sign")
	}
	pub, err := pgpPublicKey(sub.Key.Public(), created, e.PrimaryKey.Version == 6, encrypt)
	if err != nil {
		return err
	}
	pub.IsSubkey = true
	for _, s := range e.Subkeys {
		if bytes.Equal(s.PublicKey.Fingerprint, pub.Fingerprint) {
			return errors.New("openpgp: the key is a subkey already")
		}
	}
	if bytes.Equal(pub.Fingerprint, e.PrimaryKey.Fingerprint) {
		return errors.New("openpgp: the primary key cannot be its own subkey")
	}
	priv, err := pgpPrivateKey(pub, sub.Key)
	if err != nil {
		return err
	}
	sig := pgpSignature(e.PrimaryKey, packet.SigTypeSubkeyBinding, created)
	sig.KeyLifetimeSecs = &lifetime
	sig.FlagsValid = true
	switch sub.Usage {
	case PGPEncrypt:
		sig.FlagEncryptCommunications, sig.FlagEncryptStorage = true, true
	case PGPSign:
		sig.FlagSign = true
	case PGPAuth:
		sig.FlagAuthenticate = true
	}
	if !encrypt {
		sig.EmbeddedSignature = pgpSignature(pub, packet.SigTypePrimaryKeyBinding, created)
		if err := sig.EmbeddedSignature.CrossSignKey(pub, e.PrimaryKey, priv, config); err != nil {
			return err
		}
	}
	if err := sig.SignKey(pub, primary, config); err != nil {
		return err
	}
	e.Subkeys = append(e.Subkeys, openpgp.Subkey{Primary: e, PublicKey: pub,
		Bindings: []*packet.VerifiableSignature{packet.NewVerifiableSig(sig)}})
	return nil
}

func pgpSignature(signer *packet.PublicKey, typ packet.SignatureType, created time.Time) *packet.Signature {
	return &packet.Signature{
		Version:           signer.Version,
		SigType:           typ,
		PubKeyAlgo:        signer.PubKeyAlgo,
		Hash:              pgpHash(signer),
		CreationTime:      created,
		IssuerKeyId:       &signer.KeyId,
		IssuerKeyVersion:  uint8(signer.Version),
		IssuerFingerprint: signer.Fingerprint,
	}
}

// pgpHash is SHA-256, or SHA-384/SHA-512 for P-384 and P-521 keys.
func pgpHash(pub *packet.PublicKey) crypto.Hash {
	if c, err := pub.Curve(); err == nil {
		switch c {
		case packet.CurveNistP384:
			return crypto.SHA384
		case packet.CurveNistP521:
			return crypto.SHA512
		}
	}
	return crypto.SHA256
}

// pgpKeyProperties sets the primary key's flags and preferences on a self
// signature, as gpg and go-crypto write them.
func pgpKeyProperties(sig *packet.Signature, pub *packet.PublicKey, lifetime uint32, v6 bool) {
	sig.KeyLifetimeSecs = &lifetime
	sig.FlagsValid, sig.FlagCertify, sig.FlagSign = true, true, true
	sig.SEIPDv1, sig.SEIPDv2 = true, v6
	sig.PreferredSymmetric = []uint8{uint8(packet.CipherAES256), uint8(packet.CipherAES192), uint8(packet.CipherAES128)}
	sig.PreferredHash = []uint8{10, 9, 8} // SHA-512, SHA-384, SHA-256
	sig.PreferredCompression = []uint8{uint8(packet.CompressionNone)}
	if v6 {
		for _, c := range sig.PreferredSymmetric {
			sig.PreferredCipherSuites = append(sig.PreferredCipherSuites, [2]uint8{c, uint8(packet.AEADModeOCB)})
		}
	}
}

// OpenPGP encodings of the curves go-ca supports (the OID without tag and
// length) and the KDF parameters of ECDH keys on them.
var (
	oidP256       = []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	oidP384       = []byte{0x2b, 0x81, 0x04, 0x00, 0x22}
	oidP521       = []byte{0x2b, 0x81, 0x04, 0x00, 0x23}
	oidEd25519    = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}
	oidCurve25519 = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}
)

func curveOID(c elliptic.Curve) (oid, kdf []byte, err error) {
	switch c {
	case elliptic.P256():
		return oidP256, []byte{3, 1, 8, 7}, nil // SHA-256, AES-128
	case elliptic.P384():
		return oidP384, []byte{3, 1, 9, 9}, nil // SHA-384, AES-256
	case elliptic.P521():
		return oidP521, []byte{3, 1, 10, 9}, nil // SHA-512, AES-256
	}
	return nil, nil, ErrUnsupportedKey
}

func goCurve(c packet.Curve) elliptic.Curve {
	switch c {
	case packet.CurveNistP256:
		return elliptic.P256()
	case packet.CurveNistP384:
		return elliptic.P384()
	case packet.CurveNistP521:
		return elliptic.P521()
	}
	return nil
}

// pgpPublicKey turns a Go public key into an OpenPGP key packet. v4 keys
// use the algorithms GnuPG knows (EdDSA and ECDH on Curve25519); v6 keys
// use RFC 9580's Ed25519 and X25519.
func pgpPublicKey(pub crypto.PublicKey, created time.Time, v6, encrypt bool) (*packet.PublicKey, error) {
	var pk *packet.PublicKey
	var err error
	switch k := pub.(type) {
	case *rsa.PublicKey:
		pk = packet.NewRSAPublicKey(created, k)
	case *dsa.PublicKey:
		if v6 || encrypt {
			return nil, ErrUnsupportedKey
		}
		pk = packet.NewDSAPublicKey(created, k)
	case ed25519.PublicKey:
		switch {
		case encrypt:
			return nil, ErrUnsupportedKey
		case v6:
			pk = packet.NewEd25519PublicKey(created, &gced25519.PublicKey{Point: slices.Clone(k)})
		default:
			pk, err = pgpParsedPublic(packet.PubKeyAlgoEdDSA, created, pgpOIDField(oidEd25519), pgpMPI(append([]byte{0x40}, k...)))
		}
	case *ecdh.PublicKey:
		switch {
		case k.Curve() != ecdh.X25519() || !encrypt:
			return nil, ErrUnsupportedKey
		case v6:
			pk = packet.NewX25519PublicKey(created, &x25519.PublicKey{Point: k.Bytes()})
		default:
			pk, err = pgpParsedPublic(packet.PubKeyAlgoECDH, created, pgpOIDField(oidCurve25519),
				pgpMPI(append([]byte{0x40}, k.Bytes()...)), []byte{3, 1, 8, 7})
		}
	case *ecdsa.PublicKey:
		oid, kdf, cerr := curveOID(k.Curve)
		if cerr != nil {
			return nil, cerr
		}
		point, perr := k.Bytes()
		if perr != nil {
			return nil, perr
		}
		if encrypt {
			pk, err = pgpParsedPublic(packet.PubKeyAlgoECDH, created, pgpOIDField(oid), pgpMPI(point), kdf)
		} else {
			pk, err = pgpParsedPublic(packet.PubKeyAlgoECDSA, created, pgpOIDField(oid), pgpMPI(point))
		}
		if err == nil && v6 {
			err = pk.UpgradeToV6()
		}
	default:
		return nil, ErrUnsupportedKey
	}
	if err != nil {
		return nil, err
	}
	if v6 && pk.Version != 6 {
		if err := pk.UpgradeToV6(); err != nil {
			return nil, err
		}
	}
	return pk, nil
}

func pgpOIDField(oid []byte) []byte { return append([]byte{byte(len(oid))}, oid...) }

// pgpMPI encodes a big-endian number as an OpenPGP multiprecision integer.
func pgpMPI(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	bits := 0
	if len(b) > 0 {
		bits = (len(b)-1)*8 + big.NewInt(int64(b[0])).BitLen()
	}
	return append([]byte{byte(bits >> 8), byte(bits)}, b...)
}

// pgpParsedPublic builds a v4 public key packet from its fields and lets
// go-crypto parse it, which gives its key types their curve.
func pgpParsedPublic(algo packet.PublicKeyAlgorithm, created time.Time, fields ...[]byte) (*packet.PublicKey, error) {
	body := []byte{4, 0, 0, 0, 0, byte(algo)}
	binary.BigEndian.PutUint32(body[1:], uint32(created.Unix()))
	for _, f := range fields {
		body = append(body, f...)
	}
	p, err := packet.Read(bytes.NewReader(pgpPacket(6, body)))
	if err != nil {
		return nil, err
	}
	pk, ok := p.(*packet.PublicKey)
	if !ok {
		return nil, errors.New("openpgp: not a public key packet")
	}
	return pk, nil
}

// pgpPacket frames a packet body with a new format header.
func pgpPacket(tag byte, body []byte) []byte {
	out := []byte{0xc0 | tag}
	switch n := len(body); {
	case n < 192:
		out = append(out, byte(n))
	case n < 8384:
		n -= 192
		out = append(out, byte(n>>8)+192, byte(n))
	default:
		out = append(out, 0xff, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, body...)
}

// pgpPacketBody strips the header of one serialized packet.
func pgpPacketBody(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0]&0x80 == 0 {
		return nil, errors.New("openpgp: bad packet header")
	}
	if b[0]&0x40 == 0 { // old format
		switch b[0] & 3 {
		case 0:
			return b[2:], nil
		case 1:
			return b[3:], nil
		case 2:
			return b[5:], nil
		}
		return nil, errors.New("openpgp: indeterminate packet length")
	}
	switch l := b[1]; {
	case l < 192:
		return b[2:], nil
	case l < 224:
		return b[3:], nil
	case l == 255:
		return b[6:], nil
	}
	return nil, errors.New("openpgp: partial packet length")
}

// pgpPrivateKey attaches the secret of key to an OpenPGP public key
// packet, after checking that they belong together.
func pgpPrivateKey(pk *packet.PublicKey, key crypto.Signer) (*packet.PrivateKey, error) {
	want, err := PGPGoPublic(pk)
	if err != nil {
		return nil, err
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if dk, ok := key.(pki.DSAKey); ok {
		w, ok := want.(*dsa.PublicKey)
		if !ok || w.Y.Cmp(dk.Y) != 0 || w.P.Cmp(dk.P) != 0 {
			return nil, errors.New("openpgp: the private key does not belong to the OpenPGP key")
		}
	} else if e, ok := key.Public().(equaler); !ok || !e.Equal(want) {
		return nil, errors.New("openpgp: the private key does not belong to the OpenPGP key")
	}
	var secret any
	switch pub := pk.PublicKey.(type) {
	case *rsa.PublicKey:
		k, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrUnsupportedKey
		}
		secret = k
	case *dsa.PublicKey:
		k, ok := key.(pki.DSAKey)
		if !ok {
			return nil, ErrUnsupportedKey
		}
		secret = k.PrivateKey
	case *gcecdsa.PublicKey:
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrUnsupportedKey
		}
		p := gcecdsa.NewPrivateKey(*pub)
		p.D = new(big.Int).Set(k.D)
		secret = p
	case *eddsa.PublicKey:
		k, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, ErrUnsupportedKey
		}
		p := eddsa.NewPrivateKey(*pub)
		p.D = slices.Clone(k.Seed())
		secret = p
	case *gced25519.PublicKey:
		k, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, ErrUnsupportedKey
		}
		p := gced25519.NewPrivateKey(*pub)
		p.Key = slices.Clone(k)
		secret = p
	case *gcecdh.PublicKey:
		p := gcecdh.NewPrivateKey(*pub)
		switch k := key.(type) {
		case pki.X25519Key:
			p.D = k.Bytes()
		case *ecdsa.PrivateKey:
			p.D = k.D.FillBytes(make([]byte, (k.Curve.Params().BitSize+7)/8))
		default:
			return nil, ErrUnsupportedKey
		}
		secret = p
	case *x25519.PublicKey:
		k, ok := key.(pki.X25519Key)
		if !ok {
			return nil, ErrUnsupportedKey
		}
		p := x25519.NewPrivateKey(*pub)
		p.Secret = k.Bytes()
		secret = p
	default:
		return nil, ErrUnsupportedKey
	}
	return &packet.PrivateKey{PublicKey: *pk, PrivateKey: secret}, nil
}

// PGPGoPublic converts an OpenPGP key to a Go public key, for the
// algorithms go-ca can store.
func PGPGoPublic(pk *packet.PublicKey) (crypto.PublicKey, error) {
	switch pub := pk.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub, nil
	case *dsa.PublicKey:
		return pub, nil
	case *gcecdsa.PublicKey:
		c, err := pk.Curve()
		if err != nil || goCurve(c) == nil {
			return nil, ErrUnsupportedKey
		}
		return ecdsa.ParseUncompressedPublicKey(goCurve(c), pub.MarshalPoint())
	case *eddsa.PublicKey:
		if c, err := pk.Curve(); err != nil || c != packet.Curve25519 || len(pub.X) != ed25519.PublicKeySize {
			return nil, ErrUnsupportedKey
		}
		return ed25519.PublicKey(slices.Clone(pub.X)), nil
	case *gced25519.PublicKey:
		if len(pub.Point) != ed25519.PublicKeySize {
			return nil, ErrUnsupportedKey
		}
		return ed25519.PublicKey(slices.Clone(pub.Point)), nil
	case *gcecdh.PublicKey:
		c, err := pk.Curve()
		if err != nil {
			return nil, ErrUnsupportedKey
		}
		if c == packet.Curve25519 {
			return ecdh.X25519().NewPublicKey(pub.Point)
		}
		if goCurve(c) == nil {
			return nil, ErrUnsupportedKey
		}
		return ecdsa.ParseUncompressedPublicKey(goCurve(c), pub.Point)
	case *x25519.PublicKey:
		return ecdh.X25519().NewPublicKey(pub.Point)
	}
	return nil, ErrUnsupportedKey
}

// pgpGoPrivate converts a decrypted OpenPGP secret key to a Go key.
func pgpGoPrivate(sk *packet.PrivateKey) (crypto.Signer, error) {
	var key crypto.Signer
	var err error
	switch k := sk.PrivateKey.(type) {
	case *rsa.PrivateKey:
		key = k
	case *dsa.PrivateKey:
		key = pki.DSAKey{PrivateKey: k}
	case *gcecdsa.PrivateKey:
		c, cerr := sk.Curve()
		if cerr != nil || goCurve(c) == nil {
			return nil, ErrUnsupportedKey
		}
		key, err = ecdsa.ParseRawPrivateKey(goCurve(c), k.D.FillBytes(make([]byte, (goCurve(c).Params().BitSize+7)/8)))
	case *eddsa.PrivateKey:
		if len(k.D) != ed25519.SeedSize {
			return nil, ErrUnsupportedKey
		}
		key = ed25519.NewKeyFromSeed(k.D)
	case *gced25519.PrivateKey:
		if len(k.Key) < ed25519.SeedSize {
			return nil, ErrUnsupportedKey
		}
		key = ed25519.NewKeyFromSeed(k.Key[:ed25519.SeedSize])
	case *gcecdh.PrivateKey:
		c, cerr := sk.Curve()
		if cerr != nil {
			return nil, ErrUnsupportedKey
		}
		if c == packet.Curve25519 {
			x, xerr := ecdh.X25519().NewPrivateKey(k.D)
			key, err = pki.X25519Key{PrivateKey: x}, xerr
		} else if gc := goCurve(c); gc != nil && len(k.D) <= (gc.Params().BitSize+7)/8 {
			d := make([]byte, (gc.Params().BitSize+7)/8)
			copy(d[len(d)-len(k.D):], k.D)
			key, err = ecdsa.ParseRawPrivateKey(gc, d)
		} else {
			return nil, ErrUnsupportedKey
		}
	case *x25519.PrivateKey:
		x, xerr := ecdh.X25519().NewPrivateKey(k.Secret)
		key, err = pki.X25519Key{PrivateKey: x}, xerr
	default:
		return nil, ErrUnsupportedKey
	}
	if err != nil {
		return nil, err
	}
	// the secret must belong to the public key it came with
	if _, err := pgpPrivateKey(&sk.PublicKey, key); err != nil {
		return nil, err
	}
	return key, nil
}

func readPGPCert(cert []byte) (*openpgp.Entity, error) {
	el, err := openpgp.ReadKeyRing(bytes.NewReader(cert))
	if err != nil {
		return nil, err
	}
	if len(el) != 1 {
		return nil, fmt.Errorf("openpgp: %d keys in a certificate", len(el))
	}
	return el[0], nil
}

// pgpIdentities lists user IDs with the primary one first.
func pgpIdentities(e *openpgp.Entity) []string {
	var names []string
	for n := range e.Identities {
		names = append(names, n)
	}
	sort.Strings(names)
	if _, primary := e.PrimaryIdentity(time.Time{}, nil); primary != nil {
		i := slices.Index(names, primary.Name)
		if i > 0 {
			names = slices.Insert(slices.Delete(names, i, i+1), 0, primary.Name)
		}
	}
	return names
}

// writePGPEntity writes a certificate, or with secrets (one per key,
// primary first) a transferable secret key, in a stable order: user IDs in
// order, else the primary first and the rest sorted.
func writePGPEntity(w io.Writer, e *openpgp.Entity, order []string, secrets []*packet.PrivateKey) error {
	if order == nil {
		order = pgpIdentities(e)
	}
	writeKey := func(pub *packet.PublicKey, i int) error {
		if secrets == nil {
			return pub.Serialize(w)
		}
		if s := secrets[i]; s != nil {
			return s.Serialize(w)
		}
		if i == 0 {
			return errors.New("openpgp: the primary secret key is missing")
		}
		if pub.Version == 6 {
			return pub.Serialize(w) // no GNU dummy for v6: the public subkey
		}
		var b bytes.Buffer
		if err := pub.Serialize(&b); err != nil {
			return err
		}
		body, err := pgpPacketBody(b.Bytes())
		if err != nil {
			return err
		}
		_, err = w.Write(pgpPacket(7, append(slices.Clone(body), pgpDummyS2KBytes...)))
		return err
	}
	sigs := func(list []*packet.VerifiableSignature) error {
		for _, s := range list {
			if err := s.Packet.Serialize(w); err != nil {
				return err
			}
		}
		return nil
	}
	if err := writeKey(e.PrimaryKey, 0); err != nil {
		return err
	}
	if err := sigs(e.Revocations); err != nil {
		return err
	}
	if err := sigs(e.DirectSignatures); err != nil {
		return err
	}
	for _, name := range order {
		id := e.Identities[name]
		if err := id.UserId.Serialize(w); err != nil {
			return err
		}
		for _, l := range [][]*packet.VerifiableSignature{id.Revocations, id.SelfCertifications, id.OtherCertifications} {
			if err := sigs(l); err != nil {
				return err
			}
		}
	}
	for i, s := range e.Subkeys {
		if err := writeKey(s.PublicKey, i+1); err != nil {
			return err
		}
		if err := sigs(s.Revocations); err != nil {
			return err
		}
		if err := sigs(s.Bindings); err != nil {
			return err
		}
	}
	return nil
}

// ParsePGPCert describes a stored certificate.
func ParsePGPCert(cert []byte) (*PGPInfo, error) {
	e, err := readPGPCert(cert)
	if err != nil {
		return nil, err
	}
	return describePGP(e, time.Now()), nil
}

func pgpAlgorithm(pk *packet.PublicKey) string {
	bits, _ := pk.BitLength()
	curve, _ := pk.Curve()
	switch pk.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly, packet.PubKeyAlgoRSAEncryptOnly:
		return "RSA " + strconv.Itoa(int(bits))
	case packet.PubKeyAlgoDSA:
		return "DSA " + strconv.Itoa(int(bits))
	case packet.PubKeyAlgoElGamal:
		return "ElGamal " + strconv.Itoa(int(bits))
	case packet.PubKeyAlgoECDSA:
		return "ECDSA " + string(curve)
	case packet.PubKeyAlgoECDH:
		if curve == packet.Curve25519 {
			return "ECDH Curve25519"
		}
		return "ECDH " + string(curve)
	case packet.PubKeyAlgoEdDSA:
		return "EdDSA Ed25519"
	case packet.PubKeyAlgoEd25519:
		return "Ed25519"
	case packet.PubKeyAlgoX25519:
		return "X25519"
	case packet.PubKeyAlgoEd448:
		return "Ed448"
	case packet.PubKeyAlgoX448:
		return "X448"
	}
	return "algorithm " + strconv.Itoa(int(pk.PubKeyAlgo))
}

func pgpUsage(sig *packet.Signature, pk *packet.PublicKey) string {
	if sig == nil || !sig.FlagsValid {
		// no key flags: what the algorithm can do
		u := ""
		if pk.PubKeyAlgo.CanSign() {
			u += PGPSign
		}
		if pk.PubKeyAlgo.CanEncrypt() {
			u += PGPEncrypt
		}
		return u
	}
	var u string
	if sig.FlagSign {
		u += PGPSign
	}
	if sig.FlagCertify {
		u += PGPCertify
	}
	if sig.FlagEncryptCommunications || sig.FlagEncryptStorage {
		u += PGPEncrypt
	}
	if sig.FlagAuthenticate {
		u += PGPAuth
	}
	return u
}

func pgpKeyInfo(pk *packet.PublicKey, sig *packet.Signature) PGPKeyInfo {
	k := PGPKeyInfo{Fingerprint: strings.ToUpper(hex.EncodeToString(pk.Fingerprint)), KeyID: pk.KeyIdString(),
		Algorithm: pgpAlgorithm(pk), Created: pk.CreationTime, Usage: pgpUsage(sig, pk)}
	if sig != nil && sig.KeyLifetimeSecs != nil && *sig.KeyLifetimeSecs > 0 {
		k.Expires = pk.CreationTime.Add(time.Duration(*sig.KeyLifetimeSecs) * time.Second)
	}
	k.Public, _ = PGPGoPublic(pk)
	return k
}

func describePGP(e *openpgp.Entity, now time.Time) *PGPInfo {
	info := &PGPInfo{Version: e.PrimaryKey.Version, UIDs: pgpIdentities(e), Revoked: e.Revoked(now)}
	primarySig, _ := e.PrimarySelfSignature(time.Time{}, nil)
	info.Keys = append(info.Keys, pgpKeyInfo(e.PrimaryKey, primarySig))
	info.Keys[0].Revoked = info.Revoked
	for i := range e.Subkeys {
		s := &e.Subkeys[i]
		sig, _ := s.LatestValidBindingSignature(time.Time{}, nil)
		k := pgpKeyInfo(s.PublicKey, sig)
		if sig != nil {
			k.Revoked = s.Revoked(sig, now)
		}
		info.Keys = append(info.Keys, k)
	}
	return info
}

// PGPArmor wraps binary OpenPGP data in ASCII armor; v4 data gets the
// CRC-24 line older readers expect, v6 data none (RFC 9580).
func PGPArmor(blockType string, data []byte, version int) ([]byte, error) {
	var buf bytes.Buffer
	w, err := armor.EncodeWithChecksumOption(&buf, blockType, nil, version != 6)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// PGPSecret writes a transferable secret key: the certificate with the
// secret of each key (keys[i] for PGPInfo.Keys[i], primary first). A
// missing subkey secret is written as a GNU dummy (v4) or as the public
// subkey (v6). With a password the secrets are encrypted.
func PGPSecret(cert []byte, keys []crypto.Signer, password []byte) ([]byte, error) {
	e, err := readPGPCert(cert)
	if err != nil {
		return nil, err
	}
	if len(keys) != 1+len(e.Subkeys) || keys[0] == nil {
		return nil, errors.New("openpgp: the primary secret key is missing")
	}
	pubs := []*packet.PublicKey{e.PrimaryKey}
	for _, s := range e.Subkeys {
		pubs = append(pubs, s.PublicKey)
	}
	v6 := e.PrimaryKey.Version == 6
	config := &packet.Config{DefaultCipher: packet.CipherAES256,
		S2KConfig: &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA256, S2KCount: pgpS2KCount}}
	if v6 {
		config.S2KConfig = &s2k.Config{S2KMode: s2k.Argon2S2K, Argon2Config: &s2k.Argon2Config{
			NumberOfPasses: pgpArgon2Passes, DegreeOfParallelism: pgpArgon2Lanes, Memory: pgpArgon2Memory}}
		config.AEADConfig = &packet.AEADConfig{DefaultMode: packet.AEADModeOCB}
	}
	secrets := make([]*packet.PrivateKey, len(keys))
	for i, k := range keys {
		if k == nil {
			continue
		}
		if secrets[i], err = pgpPrivateKey(pubs[i], k); err != nil {
			return nil, err
		}
	}
	if len(password) > 0 {
		if err := packet.EncryptPrivateKeys(secrets, password, config); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	if err := writePGPEntity(&buf, e, nil, secrets); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// PGPRevocation creates a key revocation signature ("key is superseded"
// when superseded, else "no reason") signed with the primary key, as gpg
// keeps it for a new key.
func PGPRevocation(cert []byte, primary crypto.Signer, superseded bool, now time.Time) ([]byte, error) {
	e, err := readPGPCert(cert)
	if err != nil {
		return nil, err
	}
	priv, err := pgpPrivateKey(e.PrimaryKey, primary)
	if err != nil {
		return nil, err
	}
	now = now.UTC().Truncate(time.Second)
	sig := pgpSignature(e.PrimaryKey, packet.SigTypeKeyRevocation, now)
	reason := packet.NoReason
	if superseded {
		reason = packet.KeySuperseded
	}
	sig.RevocationReason = &reason
	sig.RevocationReasonText = ""
	if err := sig.RevokeKey(e.PrimaryKey, priv, pgpConfig(now, e.PrimaryKey.Version == 6)); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := sig.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// isPGPArmor reports whether text holds an armored OpenPGP key.
func isPGPArmor(text []byte) bool {
	return bytes.Contains(text, []byte("-----BEGIN "+PGPPublicBlock+"-----")) ||
		bytes.Contains(text, []byte("-----BEGIN "+PGPPrivateBlock+"-----"))
}

// isPGPBinary reports whether data starts with an OpenPGP key packet.
func isPGPBinary(data []byte) bool {
	if len(data) < 2 || data[0]&0x80 == 0 {
		return false
	}
	tag := data[0] & 0x3f
	if data[0]&0x40 == 0 {
		tag = (data[0] >> 2) & 0x0f
	}
	return tag == 5 || tag == 6
}

// pgpBinaryBlocks returns the binary contents of all armored key blocks
// of text, or data itself when it is binary.
func pgpBinaryBlocks(data []byte) ([][]byte, error) {
	if isPGPBinary(data) {
		return [][]byte{data}, nil
	}
	var out [][]byte
	rest := data
	for {
		i := bytes.Index(rest, []byte("-----BEGIN PGP "))
		if i < 0 {
			break
		}
		rest = rest[i:]
		blk, err := armor.Decode(bytes.NewReader(rest))
		if err != nil {
			return out, err
		}
		b, err := io.ReadAll(blk.Body)
		if err != nil {
			return out, err
		}
		if blk.Type == PGPPublicBlock || blk.Type == PGPPrivateBlock {
			out = append(out, b)
		}
		end := bytes.Index(rest, []byte("-----END PGP "))
		if end < 0 {
			break
		}
		rest = rest[end+len("-----END PGP "):]
	}
	return out, nil
}

// pgpReader reads OpenPGP keys of a file. Its budget limits signature
// checks across the file.
type pgpReader struct {
	password func() ([]byte, bool)
	budget   int
	skipped  []string
	// needPassword and wrongPassword report secrets left encrypted
	needPassword, wrongPassword bool
}

// ReadPGP reads every key of an armored or binary OpenPGP file. password
// is asked for when a secret key is encrypted; without one, or with a wrong
// one, the key is skipped and NeedPassword or WrongPassword set.
func ReadPGP(data []byte, password func() ([]byte, bool)) (ents []PGPEntity, skipped []string, needPassword, wrongPassword bool) {
	r := &pgpReader{password: password, budget: pgpMaxSignatures}
	blocks, err := pgpBinaryBlocks(data)
	if err != nil {
		r.skipped = append(r.skipped, "OpenPGP armor: "+err.Error())
	}
	for _, b := range blocks {
		el, err := openpgp.ReadKeyRing(bytes.NewReader(b))
		if err != nil && len(el) == 0 {
			r.skipped = append(r.skipped, "OpenPGP: "+err.Error())
			continue
		}
		for _, e := range el {
			if len(ents) >= pgpMaxEntities {
				r.skipped = append(r.skipped, "OpenPGP: too many keys")
				break
			}
			if ent, ok := r.entity(e); ok {
				ents = append(ents, ent)
			}
		}
	}
	return ents, r.skipped, r.needPassword, r.wrongPassword
}

func (r *pgpReader) verify(f func() error) bool {
	if r.budget <= 0 {
		return false
	}
	r.budget--
	return f() == nil
}

func (r *pgpReader) entity(e *openpgp.Entity) (PGPEntity, bool) {
	name := strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
	if _, err := PGPGoPublic(e.PrimaryKey); err != nil {
		r.skipped = append(r.skipped, fmt.Sprintf("OpenPGP key %s: %s is not supported", name, pgpAlgorithm(e.PrimaryKey)))
		return PGPEntity{}, false
	}
	if r.budget <= 0 {
		r.skipped = append(r.skipped, fmt.Sprintf("OpenPGP key %s: too many signatures in the file", name))
		return PGPEntity{}, false
	}
	pk := e.PrimaryKey
	keep := func(list []*packet.VerifiableSignature, check func(*packet.Signature) error) []*packet.VerifiableSignature {
		var out []*packet.VerifiableSignature
		for _, s := range list {
			if r.verify(func() error { return check(s.Packet) }) {
				out = append(out, s)
			}
		}
		return out
	}
	e.Revocations = keep(e.Revocations, pk.VerifyRevocationSignature)
	e.DirectSignatures = keep(e.DirectSignatures, pk.VerifyDirectKeySignature)
	for uid, id := range e.Identities {
		check := func(s *packet.Signature) error { return pk.VerifyUserIdSignature(uid, pk, s) }
		id.SelfCertifications = keep(id.SelfCertifications, check)
		id.Revocations = keep(id.Revocations, check)
		if len(id.OtherCertifications) > pgpMaxOtherCerts {
			id.OtherCertifications = id.OtherCertifications[:pgpMaxOtherCerts]
		}
		if len(id.SelfCertifications) == 0 {
			delete(e.Identities, uid)
		}
	}
	var subs []openpgp.Subkey
	for _, s := range e.Subkeys {
		sub := s.PublicKey
		s.Bindings = keep(s.Bindings, func(sig *packet.Signature) error { return pk.VerifyKeySignature(sub, sig) })
		s.Revocations = keep(s.Revocations, func(sig *packet.Signature) error { return pk.VerifySubkeyRevocationSignature(sig, sub) })
		if len(s.Bindings) > 0 {
			subs = append(subs, s)
		}
	}
	e.Subkeys = subs
	if (pk.Version < 6 && len(e.Identities) == 0) || (pk.Version == 6 && len(e.DirectSignatures) == 0) {
		r.skipped = append(r.skipped, fmt.Sprintf("OpenPGP key %s: no valid self-signature", name))
		return PGPEntity{}, false
	}
	var cert bytes.Buffer
	if err := writePGPEntity(&cert, e, nil, nil); err != nil {
		r.skipped = append(r.skipped, fmt.Sprintf("OpenPGP key %s: %v", name, err))
		return PGPEntity{}, false
	}
	ent := PGPEntity{Cert: cert.Bytes(), Info: describePGP(e, time.Now())}
	privs := []*packet.PrivateKey{e.PrivateKey}
	for _, s := range e.Subkeys {
		privs = append(privs, s.PrivateKey)
	}
	ent.Private = make([]crypto.Signer, len(privs))
	for i, sk := range privs {
		if sk == nil || sk.Dummy() {
			continue
		}
		if sk.Encrypted {
			if err := pgpCheckS2K(sk); err != nil {
				r.skipped = append(r.skipped, fmt.Sprintf("OpenPGP key %s: %v", ent.Info.Keys[i].Fingerprint, err))
				continue
			}
			pw, ok := r.password()
			if !ok {
				r.needPassword = true
				return PGPEntity{}, false
			}
			if err := sk.Decrypt(pw); err != nil {
				r.wrongPassword = true
				return PGPEntity{}, false
			}
		}
		k, err := pgpGoPrivate(sk)
		if err != nil {
			if ent.Info.Keys[i].Public != nil {
				r.skipped = append(r.skipped, fmt.Sprintf("OpenPGP key %s: secret key: %v", ent.Info.Keys[i].Fingerprint, err))
			}
			continue
		}
		ent.Private[i] = k
	}
	return ent, true
}

// pgpCheckS2K refuses encrypted secret keys whose Argon2 parameters would
// cost more than go-ca allows. go-crypto keeps the parameters private, so
// they are read from the packet as it serializes.
func pgpCheckS2K(sk *packet.PrivateKey) error {
	var full, pub bytes.Buffer
	if err := sk.Serialize(&full); err != nil {
		return err
	}
	if err := sk.PublicKey.Serialize(&pub); err != nil {
		return err
	}
	fb, err := pgpPacketBody(full.Bytes())
	if err != nil {
		return err
	}
	pb, err := pgpPacketBody(pub.Bytes())
	if err != nil {
		return err
	}
	if len(fb) <= len(pb) {
		return nil
	}
	p := fb[len(pb):]
	next := func(n int) []byte {
		if len(p) < n {
			p = nil
			return nil
		}
		b := p[:n]
		p = p[n:]
		return b
	}
	usage := next(1)
	if usage == nil || usage[0] == 0 || (usage[0] != 253 && usage[0] != 254 && usage[0] != 255) {
		return nil // no S2K specifier
	}
	if sk.Version == 6 {
		next(1) // length of the following fields
	}
	next(1) // cipher
	if usage[0] == 253 {
		next(1) // AEAD mode
	}
	if sk.Version == 6 {
		next(1) // S2K specifier length
	}
	spec := next(1)
	if spec == nil || spec[0] != 4 { // only Argon2 costs more than a fixed bound
		return nil
	}
	params := next(16 + 3)
	if params == nil {
		return errors.New("openpgp: truncated Argon2 parameters")
	}
	passes, mem := int(params[16]), params[18]
	if mem > pgpMaxArgon2Memory || passes*(1<<mem) > pgpMaxArgon2Work {
		return ErrPGPArgon2Limit
	}
	return nil
}

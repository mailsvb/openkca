package codec

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys exist in old databases
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/mailsvb/openkca/internal/pki"
)

// errSSHPassword means an SSH private key file needs a passphrase that is
// missing or wrong.
var errSSHPassword = errors.New("ssh: passphrase required or wrong")

var errSSHTruncated = errors.New("ssh: truncated key data")

// sshReader reads the SSH wire encoding (RFC 4251 section 5).
type sshReader struct {
	b   []byte
	err error
}

func (r *sshReader) uint32() uint32 {
	if r.err != nil || len(r.b) < 4 {
		r.err = errSSHTruncated
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

func (r *sshReader) bytes() []byte {
	n := r.uint32()
	if r.err != nil || uint64(n) > uint64(len(r.b)) {
		r.err = errSSHTruncated
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *sshReader) string() string { return string(r.bytes()) }

func (r *sshReader) mpint() *big.Int {
	b := r.bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		r.err = errors.New("ssh: negative integer")
	}
	return new(big.Int).SetBytes(b)
}

func appendSSHUint32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

func appendSSHString(b, s []byte) []byte {
	return append(appendSSHUint32(b, uint32(len(s))), s...)
}

func appendSSHMPInt(b []byte, n *big.Int) []byte {
	v := n.Bytes()
	if len(v) > 0 && v[0]&0x80 != 0 {
		v = append([]byte{0}, v...)
	}
	return appendSSHString(b, v)
}

// sshPublicBlob returns the SSH algorithm name and public key blob.
func sshPublicBlob(pub crypto.PublicKey) (string, []byte, error) {
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", nil, ErrUnsupportedKey
	}
	switch k.Type() {
	case ssh.KeyAlgoRSA, ssh.KeyAlgoDSA, ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return k.Type(), k.Marshal(), nil
	}
	return "", nil, ErrUnsupportedKey
}

// parseSSHPublicBlob parses an SSH public key blob into a Go public key.
// DSA keys are read here, as x/crypto refuses those over 1024 bits, which
// PuTTYgen makes.
func parseSSHPublicBlob(blob []byte) (crypto.PublicKey, error) {
	r := &sshReader{b: blob}
	if r.string() == ssh.KeyAlgoDSA {
		p, q, g, y := r.mpint(), r.mpint(), r.mpint(), r.mpint()
		if r.err != nil || len(r.b) != 0 || p.Sign() <= 0 || q.Sign() <= 0 || g.Sign() <= 0 || y.Sign() <= 0 {
			return nil, errors.New("ssh: invalid DSA public key")
		}
		return &dsa.PublicKey{Parameters: dsa.Parameters{P: p, Q: q, G: g}, Y: y}, nil
	}
	k, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, err
	}
	cp, ok := k.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("ssh: unsupported key type %s", k.Type())
	}
	return cp.CryptoPublicKey(), nil
}

func sshCurve(algo string) (elliptic.Curve, string) {
	switch algo {
	case ssh.KeyAlgoECDSA256:
		return elliptic.P256(), "nistp256"
	case ssh.KeyAlgoECDSA384:
		return elliptic.P384(), "nistp384"
	case ssh.KeyAlgoECDSA521:
		return elliptic.P521(), "nistp521"
	}
	return nil, ""
}

// sshSigner unwraps the key types an SSH format can hold.
func sshSigner(key crypto.Signer) (crypto.Signer, error) {
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		return *k, nil
	case *rsa.PrivateKey:
		if len(k.Primes) != 2 {
			return nil, ErrUnsupportedKey
		}
		k.Precompute()
		return k, nil
	case *ecdsa.PrivateKey, ed25519.PrivateKey, pki.DSAKey:
		return key, nil
	}
	return nil, ErrUnsupportedKey
}

// ecdsaPrivate builds an ECDSA key from its scalar and checks it against
// the public point.
func ecdsaPrivate(curve elliptic.Curve, d *big.Int, point []byte) (*ecdsa.PrivateKey, error) {
	size := (curve.Params().BitSize + 7) / 8
	if d.BitLen() > 8*size {
		return nil, errors.New("ssh: invalid ECDSA private key")
	}
	k, err := ecdsa.ParseRawPrivateKey(curve, d.FillBytes(make([]byte, size)))
	if err != nil {
		return nil, err
	}
	if point != nil {
		own, err := k.PublicKey.Bytes()
		if err != nil || subtle.ConstantTimeCompare(own, point) != 1 {
			return nil, errors.New("ssh: ECDSA private key does not match its public key")
		}
	}
	return k, nil
}

// rsaPrivate builds and checks an RSA key from its parts.
func rsaPrivate(n, e, d, p, q *big.Int) (*rsa.PrivateKey, error) {
	if !e.IsInt64() || e.Int64() > 1<<31-1 {
		return nil, errors.New("ssh: invalid RSA exponent")
	}
	k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())}, D: d, Primes: []*big.Int{p, q}}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	k.Precompute()
	return k, nil
}

// dsaPrivateKey builds a DSA key from its parts and checks y.
func dsaPrivateKey(p, q, g, y, x *big.Int) (pki.DSAKey, error) {
	if p.Sign() <= 0 || q.Sign() <= 0 || g.Sign() <= 0 || x.Sign() <= 0 || x.Cmp(q) >= 0 {
		return pki.DSAKey{}, errors.New("ssh: invalid DSA key")
	}
	k := dsaFromParts(p, q, g, x)
	if y != nil && k.Y.Cmp(y) != 0 {
		return pki.DSAKey{}, errors.New("ssh: DSA private key does not match its public key")
	}
	return k, nil
}

// sameSSHPublic reports whether a key belongs to an SSH public key blob.
func sameSSHPublic(key crypto.Signer, blob []byte) bool {
	_, own, err := sshPublicBlob(key.Public())
	return err == nil && subtle.ConstantTimeCompare(own, blob) == 1
}

// SSHComment is the SSH key comment for an item comment: its first line
// with white space collapsed (pki_key::SSH2publicQByteArray).
func SSHComment(comment string) string {
	first, _, _ := strings.Cut(comment, "\n")
	return strings.Join(strings.Fields(first), " ")
}

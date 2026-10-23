package codec

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys exist in old databases
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/mailsvb/go-ca/internal/pki"
)

// ErrUnsupportedKey is returned for a key type a format cannot hold.
var ErrUnsupportedKey = errors.New("codec: the key type is not supported by this format")

type dsaPrivate struct {
	Version       int
	P, Q, G, Y, X *big.Int
}

// ParsePublic parses a SubjectPublicKeyInfo; Go's parser handles RSA, NIST
// EC, Ed25519 and DSA.
func ParsePublic(spki []byte) (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(spki)
}

// Traditional returns OpenSSL's "traditional" encoding of a private key
// (i2d_PrivateKey): PKCS#1, SEC 1 or the DSA sequence; Ed25519 has none and
// gets PKCS#8, as OpenSSL writes it.
func Traditional(key crypto.Signer) (typ string, der []byte, err error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return pemRSAPrivate, x509.MarshalPKCS1PrivateKey(k), nil
	case *ecdsa.PrivateKey:
		der, err = x509.MarshalECPrivateKey(k)
		return pemECPrivate, der, err
	case pki.DSAKey:
		der, err = asn1.Marshal(dsaPrivate{P: k.P, Q: k.Q, G: k.G, Y: k.Y, X: k.X})
		return pemDSAPrivate, der, err
	case ed25519.PrivateKey:
		der, err = x509.MarshalPKCS8PrivateKey(k)
		return PEMPrivateKey, der, err
	}
	return "", nil, ErrUnsupportedKey
}

// PrivatePEM writes a private key in traditional PEM form, encrypted with
// AES-256-CBC (OpenSSL's Proc-Type/DEK-Info headers) when password is set.
func PrivatePEM(key crypto.Signer, password []byte) ([]byte, error) {
	typ, der, err := Traditional(key)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	if password == nil {
		return PEM(typ, der), nil
	}
	//lint:ignore SA1019 OpenSSL's traditional encrypted PEM is what this export is for
	b, err := x509.EncryptPEMBlock(rand.Reader, typ, der, password, x509.PEMCipherAES256) //nolint:staticcheck
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(b), nil
}

// PKCS8PEM writes a DER PrivateKeyInfo as PEM, encrypted (PBES2, AES-256-CBC)
// when password is set.
func PKCS8PEM(der, password []byte) ([]byte, error) {
	if password == nil {
		return PEM(PEMPrivateKey, der), nil
	}
	enc, err := pki.EncryptPKCS8(der, password)
	if err != nil {
		return nil, err
	}
	return PEM(PEMEncrypted, enc), nil
}

// SSHCompatible reports whether a public key has an OpenSSH encoding.
func SSHCompatible(pub crypto.PublicKey) bool {
	_, err := ssh.NewPublicKey(pub)
	return err == nil
}

// SSHPublic writes an authorized_keys line: type, base64 key and the first
// line of the comment (pki_key::SSH2publicQByteArray).
func SSHPublic(pub crypto.PublicKey, comment string) ([]byte, error) {
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, ErrUnsupportedKey
	}
	line := k.Type() + " " + base64.StdEncoding.EncodeToString(k.Marshal())
	first, _, _ := strings.Cut(comment, "\n")
	if c := strings.Join(strings.Fields(first), " "); c != "" {
		line += " " + c
	}
	return []byte(line + "\n"), nil
}

// SSHPrivate writes a private key for OpenSSH: openssh-key-v1 for Ed25519,
// traditional PEM for the others, as XCA does.
func SSHPrivate(key crypto.Signer) ([]byte, error) {
	if k, ok := key.(ed25519.PrivateKey); ok {
		b, err := ssh.MarshalPrivateKey(k, "")
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(b), nil
	}
	if !SSHCompatible(key.Public()) {
		return nil, ErrUnsupportedKey
	}
	return PrivatePEM(key, nil)
}

// JWKCurve returns the JWK curve name of a public key, "" if JWK cannot
// express it.
func JWKCurve(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "P-256"
		case elliptic.P384():
			return "P-384"
		case elliptic.P521():
			return "P-521"
		}
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return ""
}

// JWKSupported reports whether a public key can be written as a JWK.
func JWKSupported(pub crypto.PublicKey) bool {
	_, rsaKey := pub.(*rsa.PublicKey)
	return rsaKey || JWKCurve(pub) != ""
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func padded(n *big.Int, size int) string { return b64u(n.FillBytes(make([]byte, size))) }

// JWK fills a JSON Web Key (pki_key::fillJWK, pki_evp::fillJWK). priv adds
// the private members. Ed25519 keys are written as OKP keys (RFC 8037),
// which XCA does not offer.
func JWK(kid string, pub crypto.PublicKey, priv crypto.Signer) (map[string]any, error) {
	j := map[string]any{"kid": kid}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		j["kty"], j["n"], j["e"] = "RSA", b64u(k.N.Bytes()), b64u(big.NewInt(int64(k.E)).Bytes())
		if p, ok := priv.(*rsa.PrivateKey); ok {
			p.Precompute()
			j["d"], j["p"], j["q"] = b64u(p.D.Bytes()), b64u(p.Primes[0].Bytes()), b64u(p.Primes[1].Bytes())
			j["dp"], j["dq"], j["qi"] = b64u(p.Precomputed.Dp.Bytes()), b64u(p.Precomputed.Dq.Bytes()), b64u(p.Precomputed.Qinv.Bytes())
		}
	case *ecdsa.PublicKey:
		crv := JWKCurve(k)
		if crv == "" {
			return nil, ErrUnsupportedKey
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		raw, err := k.Bytes() // uncompressed point 04 || X || Y
		if err != nil {
			return nil, err
		}
		j["kty"], j["crv"], j["x"], j["y"] = "EC", crv, b64u(raw[1:1+size]), b64u(raw[1+size:])
		if p, ok := priv.(*ecdsa.PrivateKey); ok {
			d, err := p.Bytes()
			if err != nil {
				return nil, err
			}
			j["d"] = b64u(d)
		}
	case ed25519.PublicKey:
		j["kty"], j["crv"], j["x"] = "OKP", "Ed25519", b64u(k)
		if p, ok := priv.(ed25519.PrivateKey); ok {
			j["d"] = b64u(p.Seed())
		}
	default:
		return nil, ErrUnsupportedKey
	}
	return j, nil
}

// Microsoft PVK (OpenSSL crypto/pem/pvkfmt.c).
const (
	pvkMagic       = 0xb0b5f11e
	pvkKeyX        = 1
	pvkSign        = 2
	blobPrivate    = 0x07
	blobPublic     = 0x06
	calgRSAKeyX    = 0xa400
	calgDSSSign    = 0x2200
	magicRSA2      = 0x32415352
	magicDSS2      = 0x32535344
	pvkSaltLen     = 16
	pvkHeaderLen   = 24
	blobHeaderSize = 8
)

func le(n *big.Int, size int) []byte {
	b := n.FillBytes(make([]byte, size))
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// PVK writes an unencrypted Microsoft PVK private key (RSA or DSA), like
// i2b_PVK_bio without encryption.
func PVK(key crypto.Signer) ([]byte, error) {
	var blob []byte
	keyType := uint32(pvkSign)
	switch k := key.(type) {
	case *rsa.PrivateKey:
		k.Precompute()
		bits := k.N.BitLen()
		n, hn := (bits+7)/8, (bits+15)/16
		if len(k.Primes) != 2 {
			return nil, ErrUnsupportedKey
		}
		keyType = pvkKeyX
		blob = append(blob, blobPrivate, 2, 0, 0)
		blob = binary.LittleEndian.AppendUint32(blob, calgRSAKeyX)
		blob = binary.LittleEndian.AppendUint32(blob, magicRSA2)
		blob = binary.LittleEndian.AppendUint32(blob, uint32(bits))
		blob = binary.LittleEndian.AppendUint32(blob, uint32(k.E))
		blob = append(blob, le(k.N, n)...)
		for _, v := range []*big.Int{k.Primes[0], k.Primes[1], k.Precomputed.Dp, k.Precomputed.Dq, k.Precomputed.Qinv} {
			blob = append(blob, le(v, hn)...)
		}
		blob = append(blob, le(k.D, n)...)
	case pki.DSAKey:
		bits := k.P.BitLen()
		n := (bits + 7) / 8
		if k.Q.BitLen() > 160 {
			return nil, ErrUnsupportedKey
		}
		blob = append(blob, blobPrivate, 2, 0, 0)
		blob = binary.LittleEndian.AppendUint32(blob, calgDSSSign)
		blob = binary.LittleEndian.AppendUint32(blob, magicDSS2)
		blob = binary.LittleEndian.AppendUint32(blob, uint32(bits))
		blob = append(blob, le(k.P, n)...)
		blob = append(blob, le(k.Q, 20)...)
		blob = append(blob, le(k.G, n)...)
		blob = append(blob, le(k.X, 20)...)
		for range 24 { // DSSSEED: counter and seed unset
			blob = append(blob, 0xff)
		}
	default:
		return nil, ErrUnsupportedKey
	}
	out := make([]byte, 0, pvkHeaderLen+len(blob))
	for _, v := range []uint32{pvkMagic, 0, keyType, 0, 0, uint32(len(blob))} {
		out = binary.LittleEndian.AppendUint32(out, v)
	}
	return append(out, blob...), nil
}

// dsaFromPublic builds a pki.DSAKey from parameters and x.
func dsaFromParts(p, q, g, x *big.Int) pki.DSAKey {
	y := new(big.Int).Exp(g, x, p)
	return pki.DSAKey{PrivateKey: &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: dsa.Parameters{P: p, Q: q, G: g}, Y: y}, X: x}}
}

func keyTypeName(pub crypto.PublicKey) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "EC"
	case ed25519.PublicKey:
		return "Ed25519"
	case *dsa.PublicKey:
		return "DSA"
	}
	return fmt.Sprintf("%T", pub)
}

var errPVKPassword = errors.New("pvk: password required or wrong")

func fromLE(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

// parsePVK reads a Microsoft PVK private key, decrypting it (RC4 with a
// SHA-1 key, 128 or 40 bit) when needed.
func parsePVK(data []byte, password func() ([]byte, bool)) (crypto.Signer, error) {
	if len(data) < pvkHeaderLen {
		return nil, errors.New("pvk: too short")
	}
	h := make([]uint32, 6)
	for i := range h {
		h[i] = binary.LittleEndian.Uint32(data[4*i:])
	}
	encrypted, saltLen, keyLen := h[3] != 0, int(h[4]), int(h[5])
	if pvkHeaderLen+saltLen+keyLen > len(data) || keyLen < blobHeaderSize+12 {
		return nil, errors.New("pvk: truncated")
	}
	salt := data[pvkHeaderLen : pvkHeaderLen+saltLen]
	blob := append([]byte(nil), data[pvkHeaderLen+saltLen:pvkHeaderLen+saltLen+keyLen]...)
	if encrypted {
		pw, ok := password()
		if !ok {
			return nil, errPVKPassword
		}
		sum := sha1.Sum(append(append([]byte(nil), salt...), pw...))
		var plain []byte
		for _, n := range []int{16, 5} {
			k := make([]byte, 16)
			copy(k, sum[:n])
			c, err := rc4.NewCipher(k)
			if err != nil {
				return nil, err
			}
			try := append([]byte(nil), blob...)
			c.XORKeyStream(try[blobHeaderSize:], try[blobHeaderSize:])
			if m := binary.LittleEndian.Uint32(try[blobHeaderSize:]); m == magicRSA2 || m == magicDSS2 {
				plain = try
				break
			}
		}
		if plain == nil {
			return nil, errPVKPassword
		}
		blob = plain
	}
	if blob[0] != blobPrivate {
		return nil, errors.New("pvk: not a private key blob")
	}
	b := blob[blobHeaderSize:]
	magic, bits := binary.LittleEndian.Uint32(b), int(binary.LittleEndian.Uint32(b[4:]))
	b = b[8:]
	take := func(n int) (*big.Int, error) {
		if len(b) < n {
			return nil, errors.New("pvk: truncated key")
		}
		v := fromLE(b[:n])
		b = b[n:]
		return v, nil
	}
	n := (bits + 7) / 8
	switch magic {
	case magicRSA2:
		if len(b) < 4 {
			return nil, errors.New("pvk: truncated key")
		}
		e := int(binary.LittleEndian.Uint32(b))
		b = b[4:]
		hn := (bits + 15) / 16
		var vals [7]*big.Int
		for i, size := range []int{n, hn, hn, hn, hn, hn, n} {
			v, err := take(size)
			if err != nil {
				return nil, err
			}
			vals[i] = v
		}
		k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: vals[0], E: e}, D: vals[6], Primes: []*big.Int{vals[1], vals[2]}}
		if err := k.Validate(); err != nil {
			return nil, err
		}
		k.Precompute()
		return k, nil
	case magicDSS2:
		var vals [4]*big.Int
		for i, size := range []int{n, 20, n, 20} {
			v, err := take(size)
			if err != nil {
				return nil, err
			}
			vals[i] = v
		}
		return dsaFromParts(vals[0], vals[1], vals[2], vals[3]), nil
	}
	return nil, fmt.Errorf("pvk: unsupported key magic %08x", magic)
}

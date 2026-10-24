// Package pkcs12 reads and writes PKCS#12 files (RFC 7292). It moves keys
// as PKCS#8 PrivateKeyInfo and certificates as DER and leaves parsing them
// to the caller, so it takes every key type go-ca knows, including those
// crypto/x509 cannot read.
package pkcs12

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"unicode/utf16"

	"github.com/mailsvb/go-ca/internal/pki"
)

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	oidKeyBag          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidShroudedKeyBag  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidCertBag         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidCRLBag          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 4}
	oidSecretBag       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 5}
	oidSafeContentsBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
	oidX509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	oidFriendlyName    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidLocalKeyID      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
)

// ErrPassword is returned when the password does not open a file.
var ErrPassword = errors.New("pkcs12: wrong password")

type pfxPDU struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

type safeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue `asn1:"tag:0,explicit"`
	Attributes []attribute   `asn1:"set,optional"`
}

type attribute struct {
	ID     asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type certBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

type encryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

// Bag is a key or a certificate with its attributes.
type Bag struct {
	DER          []byte // a PKCS#8 PrivateKeyInfo or an X.509 certificate
	FriendlyName string
	LocalKeyID   []byte
}

// Contents is what a PKCS#12 file holds, in file order.
type Contents struct {
	Keys    []Bag
	Certs   []Bag
	Skipped []string // what was not read: CRL bags, secrets, ...
}

// Decode opens a PKCS#12 file in password integrity mode: it verifies the
// MAC, if there is one, and decrypts every part. A wrong password, by MAC
// or by decryption, is ErrPassword. An empty password is tried in both of
// its encodings.
func Decode(der []byte, pass string) (*Contents, error) {
	var pfx pfxPDU
	if rest, err := asn1.Unmarshal(der, &pfx); err != nil {
		return nil, fmt.Errorf("pkcs12: %w", err)
	} else if len(rest) > 0 {
		return nil, errors.New("pkcs12: trailing data")
	}
	if pfx.Version != 3 {
		return nil, fmt.Errorf("pkcs12: version %d", pfx.Version)
	}
	switch {
	case pfx.AuthSafe.ContentType.Equal(oidSignedData):
		return nil, errors.New("pkcs12: public-key integrity mode is not supported")
	case !pfx.AuthSafe.ContentType.Equal(oidData):
		return nil, fmt.Errorf("pkcs12: unsupported content %v", pfx.AuthSafe.ContentType)
	}
	var authSafe []byte
	if _, err := asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authSafe); err != nil {
		return nil, fmt.Errorf("pkcs12: authenticated safe: %w", err)
	}
	pws := []password{newPassword(pass)}
	if pass == "" {
		pws = emptyPasswords()
	}
	defer func() {
		for _, pw := range pws {
			pw.clear()
		}
	}()
	hasMAC := len(pfx.MacData.Mac.Algorithm.Algorithm) > 0
	for _, pw := range pws {
		if hasMAC {
			if err := pfx.MacData.verify(authSafe, pw); errors.Is(err, errMAC) {
				continue
			} else if err != nil {
				return nil, err
			}
		}
		c, err := decodeAuthSafe(authSafe, pw)
		if errors.Is(err, errDecrypt) {
			continue
		}
		return c, err
	}
	return nil, ErrPassword
}

func decodeAuthSafe(authSafe []byte, pw password) (*Contents, error) {
	var cis []contentInfo
	if rest, err := asn1.Unmarshal(authSafe, &cis); err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("pkcs12: authenticated safe: %v", err)
	}
	c := &Contents{}
	for _, ci := range cis {
		switch {
		case ci.ContentType.Equal(oidData):
			var data []byte
			if _, err := asn1.Unmarshal(ci.Content.Bytes, &data); err != nil {
				return nil, fmt.Errorf("pkcs12: data: %w", err)
			}
			if err := c.safeContents(data, pw, 0); err != nil {
				return nil, err
			}
		case ci.ContentType.Equal(oidEncryptedData):
			var ed encryptedData
			if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
				return nil, fmt.Errorf("pkcs12: encrypted data: %w", err)
			}
			eci := ed.EncryptedContentInfo
			data, err := decrypt(eci.ContentEncryptionAlgorithm, eci.EncryptedContent, pw)
			if err != nil {
				return nil, err
			}
			if err := c.safeContents(data, pw, 0); err != nil {
				return nil, err
			}
		case ci.ContentType.Equal(oidEnvelopedData):
			c.Skipped = append(c.Skipped, "content encrypted to a public key")
		default:
			c.Skipped = append(c.Skipped, fmt.Sprintf("content %v", ci.ContentType))
		}
	}
	return c, nil
}

func (c *Contents) safeContents(data []byte, pw password, depth int) error {
	var bags []safeBag
	if rest, err := asn1.Unmarshal(data, &bags); err != nil || len(rest) > 0 {
		// Garbage that passed the padding check: the wrong password in a
		// file without MAC, or a damaged file.
		return errDecrypt
	}
	for _, b := range bags {
		name, id := b.attributes()
		switch {
		case b.ID.Equal(oidKeyBag):
			if !isDER(b.Value.Bytes) {
				return errors.New("pkcs12: key bag is not DER")
			}
			c.Keys = append(c.Keys, Bag{DER: b.Value.Bytes, FriendlyName: name, LocalKeyID: id})
		case b.ID.Equal(oidShroudedKeyBag):
			var epki encryptedPrivateKeyInfo
			if _, err := asn1.Unmarshal(b.Value.Bytes, &epki); err != nil {
				return fmt.Errorf("pkcs12: shrouded key bag: %w", err)
			}
			key, err := decrypt(epki.Algorithm, epki.Data, pw)
			if err != nil {
				return err
			}
			if !isDER(key) {
				clear(key)
				return errDecrypt
			}
			c.Keys = append(c.Keys, Bag{DER: key, FriendlyName: name, LocalKeyID: id})
		case b.ID.Equal(oidCertBag):
			var cb certBag
			if _, err := asn1.Unmarshal(b.Value.Bytes, &cb); err != nil {
				return fmt.Errorf("pkcs12: certificate bag: %w", err)
			}
			if !cb.ID.Equal(oidX509Certificate) {
				c.Skipped = append(c.Skipped, fmt.Sprintf("certificate of type %v", cb.ID))
				continue
			}
			c.Certs = append(c.Certs, Bag{DER: cb.Data, FriendlyName: name, LocalKeyID: id})
		case b.ID.Equal(oidCRLBag):
			c.Skipped = append(c.Skipped, "CRL bag")
		case b.ID.Equal(oidSecretBag):
			c.Skipped = append(c.Skipped, "secret bag")
		case b.ID.Equal(oidSafeContentsBag):
			if depth >= 4 {
				return errors.New("pkcs12: safe contents nested too deeply")
			}
			if err := c.safeContents(b.Value.Bytes, pw, depth+1); err != nil {
				return err
			}
		default:
			c.Skipped = append(c.Skipped, fmt.Sprintf("bag %v", b.ID))
		}
	}
	return nil
}

func isDER(b []byte) bool {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	return err == nil && len(rest) == 0
}

func (b *safeBag) attributes() (name string, id []byte) {
	for _, a := range b.Attributes {
		var v asn1.RawValue
		if _, err := asn1.Unmarshal(a.Values.Bytes, &v); err != nil {
			continue
		}
		switch {
		case a.ID.Equal(oidFriendlyName) && v.Tag == asn1.TagBMPString && len(v.Bytes)%2 == 0:
			u := make([]uint16, len(v.Bytes)/2)
			for i := range u {
				u[i] = uint16(v.Bytes[2*i])<<8 | uint16(v.Bytes[2*i+1])
			}
			name = string(utf16.Decode(u))
		case a.ID.Equal(oidLocalKeyID) && v.Tag == asn1.TagOctetString:
			id = v.Bytes
		}
	}
	return name, id
}

// Profile is the protection of a new file.
type Profile struct {
	certs, key, mac     asn1.ObjectIdentifier
	iterations, macIter int
	saltLen, macSaltLen int
}

// The profiles of the pkcs12_enc_algo setting. Their parameters are those
// of OpenSSL 3 and go-pkcs12's Modern2023, LegacyDES and LegacyRC2.
var (
	// AES256 is PBES2 with AES-256-CBC and PBKDF2-HMAC-SHA256 for keys
	// and certificates, and a SHA-256 MAC: OpenSSL 3's default.
	AES256 = Profile{certs: pki.OIDPBES2, key: pki.OIDPBES2, mac: oidSHA256, iterations: 2048, macIter: 2048, saltLen: 16, macSaltLen: 16}
	// DES3 is PBE-SHA1-3DES for keys and certificates and a SHA-1 MAC,
	// for Windows before 10 1709 and old Java.
	DES3 = Profile{certs: oidPBEWithSHAAnd3KeyTripleDESCBC, key: oidPBEWithSHAAnd3KeyTripleDESCBC, mac: oidSHA1, iterations: 2048, macIter: 1, saltLen: 8, macSaltLen: 8}
	// RC2 is PBE-SHA1-RC2-40 for the certificates, 3DES for the key, as
	// OpenSSL before 3.0 and XCA write it.
	RC2 = Profile{certs: oidPBEWithSHAAnd40BitRC2CBC, key: oidPBEWithSHAAnd3KeyTripleDESCBC, mac: oidSHA1, iterations: 2048, macIter: 1, saltLen: 8, macSaltLen: 8}
)

// WithIterations returns p with n iterations for the MAC and both
// encryptions. Each is a way to test a guessed password, so they rise
// together.
func (p Profile) WithIterations(n int) Profile {
	p.iterations, p.macIter = n, n
	return p
}

// Encode writes a PKCS#12 file as OpenSSL's PKCS12_create does: the
// certificates in an encrypted SafeContents, the shrouded key in a plain
// one, and a MAC over both. key.DER is a PKCS#8 PrivateKeyInfo, or nil for
// a file without key; certs[0] is the key's certificate. Every bag carries
// its FriendlyName, if any; the key and its certificate also the SHA-1 of
// that certificate as localKeyId. LocalKeyID fields are ignored.
func Encode(key Bag, certs []Bag, pass string, prof Profile) ([]byte, error) {
	if key.DER == nil && len(certs) == 0 {
		return nil, errors.New("pkcs12: nothing to write")
	}
	pw := newPassword(pass)
	defer pw.clear()

	var localKeyID *attribute
	if key.DER != nil && len(certs) > 0 {
		sum := sha1.Sum(certs[0].DER)
		v, err := asn1.Marshal(sum[:])
		if err != nil {
			return nil, err
		}
		localKeyID = &attribute{ID: oidLocalKeyID, Values: set(v)}
	}
	attrs := func(name string, withID bool) ([]attribute, error) {
		var a []attribute
		if name != "" {
			u := utf16.Encode([]rune(name))
			bmp := make([]byte, 0, 2*len(u))
			for _, c := range u {
				bmp = append(bmp, byte(c>>8), byte(c))
			}
			v, err := asn1.Marshal(asn1.RawValue{Tag: asn1.TagBMPString, Bytes: bmp})
			if err != nil {
				return nil, err
			}
			a = append(a, attribute{ID: oidFriendlyName, Values: set(v)})
		}
		if withID && localKeyID != nil {
			a = append(a, *localKeyID)
		}
		return a, nil
	}

	var safes []contentInfo
	if len(certs) > 0 {
		var bags []safeBag
		for i, c := range certs {
			cb, err := asn1.Marshal(certBag{ID: oidX509Certificate, Data: c.DER})
			if err != nil {
				return nil, err
			}
			a, err := attrs(c.FriendlyName, i == 0)
			if err != nil {
				return nil, err
			}
			bags = append(bags, safeBag{ID: oidCertBag, Value: explicit0(cb), Attributes: a})
		}
		plain, err := asn1.Marshal(bags)
		if err != nil {
			return nil, err
		}
		algo, enc, err := encrypt(prof.certs, plain, pw, prof.iterations, prof.saltLen)
		if err != nil {
			return nil, err
		}
		ed, err := asn1.Marshal(encryptedData{EncryptedContentInfo: encryptedContentInfo{
			ContentType: oidData, ContentEncryptionAlgorithm: algo, EncryptedContent: enc}})
		if err != nil {
			return nil, err
		}
		safes = append(safes, contentInfo{ContentType: oidEncryptedData, Content: explicit0(ed)})
	}
	if key.DER != nil {
		algo, enc, err := encrypt(prof.key, key.DER, pw, prof.iterations, prof.saltLen)
		if err != nil {
			return nil, err
		}
		epki, err := asn1.Marshal(encryptedPrivateKeyInfo{Algorithm: algo, Data: enc})
		if err != nil {
			return nil, err
		}
		a, err := attrs(key.FriendlyName, true)
		if err != nil {
			return nil, err
		}
		bags, err := asn1.Marshal([]safeBag{{ID: oidShroudedKeyBag, Value: explicit0(epki), Attributes: a}})
		if err != nil {
			return nil, err
		}
		data, err := asn1.Marshal(bags)
		if err != nil {
			return nil, err
		}
		safes = append(safes, contentInfo{ContentType: oidData, Content: explicit0(data)})
	}
	authSafe, err := asn1.Marshal(safes)
	if err != nil {
		return nil, err
	}
	md := macData{Mac: digestInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: prof.mac, Parameters: asn1.NullRawValue}},
		MacSalt: make([]byte, prof.macSaltLen), Iterations: prof.macIter}
	if _, err := rand.Read(md.MacSalt); err != nil {
		return nil, err
	}
	if md.Mac.Digest, err = md.mac(authSafe, pw); err != nil {
		return nil, err
	}
	content, err := asn1.Marshal(authSafe)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(pfxPDU{Version: 3, AuthSafe: contentInfo{ContentType: oidData, Content: explicit0(content)}, MacData: md})
}

// explicit0 wraps DER in an explicit [0] tag.
func explicit0(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}
}

// set wraps the DER of one value in a SET.
func set(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: der}
}

package codec

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// TestProbeNewKeyTypes reads certificates, requests and keys of the new
// algorithms in PEM and DER, including the forms crypto/x509 refuses.
func TestProbeNewKeyTypes(t *testing.T) {
	for _, spec := range []pki.KeySpec{
		{Type: "EC", Curve: "brainpoolP256r1"}, {Type: "Ed448"}, {Type: "RSA-PSS", Bits: 2048},
		{Type: "ML-DSA", Param: "ML-DSA-44"}, {Type: "Composite", Param: "MLDSA44-Ed25519-SHA512"},
		{Type: "ML-KEM", Param: "ML-KEM-512"}, {Type: "X448"},
	} {
		key, err := pki.GenerateKey(spec)
		if err != nil {
			t.Fatal(err)
		}
		spki, _ := pki.MarshalPublicKey(key.Public())
		pk8, _ := pki.MarshalPKCS8(key)
		wantType, wantBits := pki.StoredKeyType(spki)
		check := func(what string, data []byte, typ int) {
			t.Helper()
			r := Probe("x", data, ProbeOptions{})
			if len(r.Objects) != 1 || r.Objects[0].Type != typ {
				t.Fatalf("%s %s: %d objects, skipped %v", spec.Type, what, len(r.Objects), r.Unrecognized)
			}
			o := r.Objects[0]
			if typ == xdb.TypeKey && (!bytes.Equal(o.DER, spki) || o.KeyType != wantType || o.KeyBits != wantBits) {
				t.Errorf("%s %s: key %q %d", spec.Type, what, o.KeyType, o.KeyBits)
			}
		}
		check("SPKI PEM", PEM(PEMPublicKey, spki), xdb.TypeKey)
		check("SPKI DER", spki, xdb.TypeKey)
		check("PKCS#8 PEM", PEM(PEMPrivateKey, pk8), xdb.TypeKey)
		check("PKCS#8 DER", pk8, xdb.TypeKey)

		if !pki.CanSign(key) {
			continue
		}
		subject, _ := pki.BuildName([]pki.DNAttr{{Name: "CN", Value: spec.Type}}, "")
		der, err := pki.CreateCertificate(pki.CertRequest{Subject: subject, PublicKey: key.Public(), Serial: big.NewInt(1),
			NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Hash: "sha256", SignerKey: key})
		if err != nil {
			t.Fatal(err)
		}
		check("certificate PEM", PEM(PEMCert, der), xdb.TypeCert)
		check("certificate DER", der, xdb.TypeCert)
		csr, err := pki.CreateRequest(subject, nil, key, "sha256")
		if err != nil {
			t.Fatal(err)
		}
		check("request PEM", PEM(PEMRequest, csr), xdb.TypeRequest)
		check("request DER", csr, xdb.TypeRequest)
	}
}

// TestBrainpoolTraditional reads and writes Brainpool keys in OpenSSL's
// traditional SEC 1 form.
func TestBrainpoolTraditional(t *testing.T) {
	key, _ := pki.GenerateKey(pki.KeySpec{Type: "EC", Curve: "brainpoolP384r1"})
	typ, der, err := Traditional(key)
	if err != nil || typ != pemECPrivate {
		t.Fatalf("%s %v", typ, err)
	}
	spki, _ := pki.MarshalPublicKey(key.Public())
	for what, data := range map[string][]byte{"PEM": PEM(typ, der), "DER": der} {
		r := Probe("bp", data, ProbeOptions{})
		if len(r.Objects) != 1 || !bytes.Equal(r.Objects[0].DER, spki) || r.Objects[0].Private == nil {
			t.Fatalf("%s: %d objects, skipped %v", what, len(r.Objects), r.Unrecognized)
		}
	}
}

// TestExportGating checks which formats take the new key types.
func TestExportGating(t *testing.T) {
	for _, c := range []struct {
		spec              pki.KeySpec
		trad, pkcs12, ssh bool
	}{
		{pki.KeySpec{Type: "RSA", Bits: 2048}, true, true, true},
		{pki.KeySpec{Type: "RSA-PSS", Bits: 2048}, false, false, false},
		{pki.KeySpec{Type: "EC", Curve: "P-256"}, true, true, true},
		{pki.KeySpec{Type: "EC", Curve: "brainpoolP384r1"}, true, false, false},
		{pki.KeySpec{Type: "Ed25519"}, false, true, true},
		{pki.KeySpec{Type: "Ed448"}, false, false, false},
		{pki.KeySpec{Type: "X448"}, false, false, false},
		{pki.KeySpec{Type: "ML-DSA", Param: "ML-DSA-65"}, false, true, false},
		{pki.KeySpec{Type: "ML-KEM", Param: "ML-KEM-768"}, false, false, false},
		{pki.KeySpec{Type: "Composite", Param: "MLDSA44-Ed25519-SHA512"}, false, false, false},
	} {
		key, _ := pki.GenerateKey(c.spec)
		pub := key.Public()
		if TraditionalSupported(pub) != c.trad || PKCS12Supported(pub) != c.pkcs12 || SSHCompatible(pub) != c.ssh {
			t.Errorf("%v: traditional %v PKCS#12 %v SSH %v", c.spec, TraditionalSupported(pub), PKCS12Supported(pub), SSHCompatible(pub))
		}
		if JWKSupported(pub) && c.spec.Type != "RSA" && c.spec.Curve != "P-256" && c.spec.Type != "Ed25519" {
			t.Errorf("%v: JWK offered", c.spec)
		}
		if _, err := PVK(key); (err == nil) != (c.spec.Type == "RSA") {
			t.Errorf("%v: PVK %v", c.spec, err)
		}
		// every key has a PEM form: its own or PKCS#8
		typ, der, err := Traditional(key)
		if err != nil {
			t.Fatalf("%v: %v", c.spec, err)
		}
		if (typ == PEMPrivateKey) == c.trad {
			t.Errorf("%v: traditional form %s", c.spec, typ)
		}
		r := Probe("k", PEM(typ, der), ProbeOptions{})
		if len(r.Objects) != 1 || r.Objects[0].Private == nil {
			t.Errorf("%v: %s does not read back: %v", c.spec, typ, r.Unrecognized)
		}
		if !c.pkcs12 {
			if _, err := PKCS12(key, nil, nil, "pw", ""); err != ErrUnsupportedKey {
				t.Errorf("%v: PKCS#12 %v", c.spec, err)
			}
		}
	}
}

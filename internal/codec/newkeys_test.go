package codec

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/go-ca/internal/pkcs12"
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
		spec      pki.KeySpec
		trad, ssh bool
	}{
		{pki.KeySpec{Type: "RSA", Bits: 2048}, true, true},
		{pki.KeySpec{Type: "RSA-PSS", Bits: 2048}, false, false},
		{pki.KeySpec{Type: "EC", Curve: "P-256"}, true, true},
		{pki.KeySpec{Type: "EC", Curve: "brainpoolP384r1"}, true, false},
		{pki.KeySpec{Type: "Ed25519"}, false, true},
		{pki.KeySpec{Type: "Ed448"}, false, false},
		{pki.KeySpec{Type: "X448"}, false, false},
		{pki.KeySpec{Type: "ML-DSA", Param: "ML-DSA-65"}, false, false},
		{pki.KeySpec{Type: "ML-KEM", Param: "ML-KEM-768"}, false, false},
		{pki.KeySpec{Type: "Composite", Param: "MLDSA44-Ed25519-SHA512"}, false, false},
	} {
		key, _ := pki.GenerateKey(c.spec)
		pub := key.Public()
		if TraditionalSupported(pub) != c.trad || SSHCompatible(pub) != c.ssh {
			t.Errorf("%v: traditional %v SSH %v", c.spec, TraditionalSupported(pub), SSHCompatible(pub))
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
	}
}

// TestPKCS12AllKeyTypes writes every key type with a certificate and a CA
// certificate as PKCS#12 in each algorithm and reads it back.
func TestPKCS12AllKeyTypes(t *testing.T) {
	caKey, _ := pki.GenerateKey(pki.KeySpec{Type: "Ed25519"})
	caName, _ := pki.BuildName([]pki.DNAttr{{Name: "CN", Value: "CA"}}, "")
	caDER, err := pki.CreateCertificate(pki.CertRequest{Subject: caName, PublicKey: caKey.Public(), Serial: big.NewInt(1),
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Hash: "sha256", SignerKey: caKey})
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := pki.ParseCertificate(caDER)
	specs := []pki.KeySpec{{Type: "RSA", Bits: 2048}, {Type: "RSA-PSS", Bits: 2048}, {Type: "Ed25519"}, {Type: "Ed448"},
		{Type: "X25519"}, {Type: "X448"}, {Type: "SLH-DSA", Param: "SLH-DSA-SHA2-128f"}}
	for _, c := range pki.ECCurves {
		specs = append(specs, pki.KeySpec{Type: "EC", Curve: c.Name})
	}
	for _, p := range pki.MLDSAParamSets {
		specs = append(specs, pki.KeySpec{Type: "ML-DSA", Param: p.Name})
	}
	for _, p := range pki.MLKEMParamSets {
		specs = append(specs, pki.KeySpec{Type: "ML-KEM", Param: p.Name})
	}
	specs = append(specs, pki.KeySpec{Type: "Composite", Param: pki.CompositeAlgs[0].Name},
		pki.KeySpec{Type: "CompositeKEM", Param: pki.CompositeKEMAlgs[0].Name})
	// OpenSSL reads the files of every key type it knows
	_, err = exec.LookPath("openssl")
	haveOpenSSL := err == nil
	dir := t.TempDir()
	openssl := func(args ...string) (string, error) {
		cmd := exec.Command("openssl", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, spec := range specs {
		key, err := pki.GenerateKey(spec)
		if err != nil {
			t.Fatal(err)
		}
		spki, _ := pki.MarshalPublicKey(key.Public())
		pk8, _ := pki.MarshalPKCS8(key)
		subject, _ := pki.BuildName([]pki.DNAttr{{Name: "CN", Value: "leaf"}}, "")
		leaf, err := pki.CreateCertificate(pki.CertRequest{Subject: subject, SPKI: spki, Serial: big.NewInt(2),
			NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), Hash: "sha256", Issuer: ca, SignerKey: caKey})
		if err != nil {
			t.Fatalf("%v: %v", spec, err)
		}
		for _, algo := range PKCS12Algorithms {
			p12, err := PKCS12(pk8, []pkcs12.Bag{{DER: leaf, FriendlyName: "the alias"}, {DER: caDER}}, "pw", algo, 0)
			if err != nil {
				t.Fatalf("%v %s: %v", spec, algo, err)
			}
			r := Probe("x.p12", p12, ProbeOptions{Password: []byte("pw")})
			if len(r.Objects) != 3 || len(r.Unrecognized) > 0 {
				t.Fatalf("%v %s: %d objects, skipped %v", spec, algo, len(r.Objects), r.Unrecognized)
			}
			cert, k, caObj := r.Objects[0], r.Objects[1], r.Objects[2]
			if cert.Name != "the alias" || !bytes.Equal(cert.DER, leaf) ||
				k.Name != "the alias_key" || !bytes.Equal(k.DER, spki) || !bytes.Equal(k.Private, pk8) ||
				caObj.Name != "the alias_ca_0" || !bytes.Equal(caObj.DER, caDER) {
				t.Errorf("%v %s: %s %s %s", spec, algo, cert.Name, k.Name, caObj.Name)
			}
			if !haveOpenSSL {
				continue
			}
			os.WriteFile(filepath.Join(dir, "k.pem"), PEM(PEMPrivateKey, pk8), 0o600)
			if _, err := openssl("pkey", "-in", "k.pem", "-noout"); err != nil {
				continue // a key type this OpenSSL does not know
			}
			os.WriteFile(filepath.Join(dir, "x.p12"), p12, 0o600)
			args := []string{"pkcs12", "-in", "x.p12", "-passin", "pass:pw", "-nodes"}
			if algo == "PBE-SHA1-RC2-40" {
				args = append(args, "-legacy")
			}
			if out, err := openssl(args...); err != nil || !strings.Contains(out, "friendlyName: the alias") ||
				!strings.Contains(out, "BEGIN PRIVATE KEY") || strings.Count(out, "BEGIN CERTIFICATE") != 2 {
				t.Errorf("%v %s: openssl: %v\n%s", spec, algo, err, out)
			}
		}
	}
}

// TestPKCS12UnknownKey: a key go-ca cannot read is reported, not dropped
// silently, and its certificate is still imported.
func TestPKCS12UnknownKey(t *testing.T) {
	unknown, _ := asn1.Marshal(struct {
		Version int
		Algo    pkix.AlgorithmIdentifier
		Key     []byte
	}{Algo: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}}, Key: []byte{1, 2, 3}})
	leaf := selfSigned(t, "leaf")
	p12, err := PKCS12(unknown, []pkcs12.Bag{{DER: leaf}}, "pw", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	r := Probe("x.p12", p12, ProbeOptions{Password: []byte("pw")})
	if len(r.Objects) != 1 || r.Objects[0].Name != "leaf" || len(r.Unrecognized) != 1 || !strings.Contains(r.Unrecognized[0], "unsupported algorithm") {
		t.Fatalf("%+v", r)
	}
}

// macIterations reads the MAC iteration count of a PKCS#12 file.
func macIterations(t *testing.T, p12 []byte) int {
	t.Helper()
	var p struct {
		Version  int
		AuthSafe asn1.RawValue
		MacData  struct {
			Mac        asn1.RawValue
			Salt       []byte
			Iterations int `asn1:"optional,default:1"`
		}
	}
	if _, err := asn1.Unmarshal(p12, &p); err != nil {
		t.Fatal(err)
	}
	return p.MacData.Iterations
}

// TestPKCS12Iterations: the count applies to AES-256-CBC only.
func TestPKCS12Iterations(t *testing.T) {
	key, _ := pki.GenerateKey(pki.KeySpec{Type: "Ed25519"})
	pk8, _ := pki.MarshalPKCS8(key)
	certs := []pkcs12.Bag{{DER: selfSigned(t, "leaf")}}
	for algo, want := range map[string]int{"AES-256-CBC": 4096, "": 4096, "PBE-SHA1-3DES": 1, "PBE-SHA1-RC2-40": 1} {
		p12, err := PKCS12(pk8, certs, "pw", algo, 4096)
		if err != nil {
			t.Fatal(err)
		}
		if n := macIterations(t, p12); n != want {
			t.Errorf("%q: MAC iterations %d, want %d", algo, n, want)
		}
	}
	p12, _ := PKCS12(pk8, certs, "pw", "", 0)
	if n := macIterations(t, p12); n != PKCS12Iterations {
		t.Errorf("default: %d", n)
	}
	for v, ok := range map[string]bool{"": true, "2048": true, "200000": true, "10000000": true, "2047": false, "10000001": false, "x": false, "-1": false} {
		if _, got := ParsePKCS12Iterations(v); got != ok {
			t.Errorf("ParsePKCS12Iterations(%q) = %v", v, got)
		}
	}
}

// TestProbeEncryptedKeys: legacy PKCS#8 encryptions import, and schemes
// go-ca cannot decrypt are reported as such, not as a wrong password.
func TestProbeEncryptedKeys(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("openssl", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
	}
	run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ec.pem")
	run("pkcs8", "-topk8", "-in", "ec.pem", "-v1", "PBE-SHA1-3DES", "-passout", "pass:pw", "-out", "v1.pem")
	run("pkcs8", "-topk8", "-in", "ec.pem", "-scrypt", "-passout", "pass:pw", "-out", "scrypt.pem")
	run("pkcs8", "-topk8", "-in", "ec.pem", "-v2", "camellia-256-cbc", "-passout", "pass:pw", "-out", "camellia.pem")
	run("ec", "-in", "ec.pem", "-camellia256", "-passout", "pass:pw", "-out", "camellia-trad.pem")
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, n := range []string{"v1.pem", "scrypt.pem"} {
		if r := Probe(n, read(n), ProbeOptions{Password: []byte("pw")}); len(r.Objects) != 1 || r.Objects[0].Private == nil {
			t.Errorf("%s: %+v", n, r)
		}
		if r := Probe(n, read(n), ProbeOptions{Password: []byte("nope")}); !r.PasswordWrong {
			t.Errorf("%s: wrong password not reported", n)
		}
	}
	for n, want := range map[string]string{"camellia.pem": "unsupported cipher Camellia-256-CBC", "camellia-trad.pem": "unsupported encryption CAMELLIA-256-CBC"} {
		r := Probe(n, read(n), ProbeOptions{Password: []byte("pw")})
		if r.PasswordWrong || len(r.Objects) != 0 || len(r.Unrecognized) != 1 || !strings.Contains(r.Unrecognized[0], want) {
			t.Errorf("%s: %+v", n, r)
		}
	}
}

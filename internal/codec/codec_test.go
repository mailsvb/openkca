package codec

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/pki"
)

func selfSigned(t *testing.T, cn string) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestPKCS7RoundTrip(t *testing.T) {
	a, b := selfSigned(t, "a"), selfSigned(t, "b")
	p7, err := PKCS7([][]byte{a, b})
	if err != nil {
		t.Fatal(err)
	}
	certs, crls, err := ParsePKCS7(p7)
	if err != nil || len(certs) != 2 || len(crls) != 0 {
		t.Fatalf("%v %d %d", err, len(certs), len(crls))
	}
	r := Probe("x.p7b", p7, ProbeOptions{})
	if len(r.Objects) != 2 || r.Objects[0].Name != "a" {
		t.Fatalf("%+v", r)
	}
}

func TestProbeOpenSSLFiles(t *testing.T) {
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
	run("genrsa", "-out", "rsa.pem", "2048")
	run("req", "-new", "-x509", "-key", "rsa.pem", "-subj", "/O=Org/CN=Foreign", "-days", "30", "-out", "cert.pem")
	run("pkcs12", "-export", "-in", "cert.pem", "-inkey", "rsa.pem", "-name", "my alias", "-passout", "pass:secret", "-out", "both.p12")
	run("rsa", "-in", "rsa.pem", "-aes256", "-passout", "pass:secret", "-traditional", "-out", "rsa-enc.pem")
	run("rsa", "-in", "rsa.pem", "-outform", "PVK", "-passout", "pass:secret", "-provider", "legacy", "-provider", "default", "-out", "rsa.pvk")
	run("pkcs8", "-topk8", "-in", "rsa.pem", "-v2", "aes-128-cbc", "-passout", "pass:secret", "-out", "rsa.pk8")
	run("ecparam", "-name", "prime256v1", "-genkey", "-out", "ec.pem")
	run("ecparam", "-name", "brainpoolP256r1", "-genkey", "-noout", "-out", "bp.pem")
	run("dsaparam", "-genkey", "-noout", "-out", "dsa.pem", "1024")
	run("x509", "-in", "cert.pem", "-outform", "DER", "-out", "cert.der")
	run("crl2pkcs7", "-nocrl", "-certfile", "cert.pem", "-out", "cert.p7b")
	// PKCS#12 with keys crypto/x509 refuses, with certificates only and
	// with a key only
	run("genpkey", "-algorithm", "ED448", "-out", "ed448.pem")
	run("req", "-new", "-x509", "-key", "ed448.pem", "-subj", "/CN=Ed448 leaf", "-days", "30", "-out", "ed448.crt")
	run("pkcs12", "-export", "-in", "ed448.crt", "-inkey", "ed448.pem", "-certfile", "cert.pem", "-passout", "pass:secret", "-out", "ed448.p12")
	run("req", "-new", "-x509", "-key", "bp.pem", "-subj", "/CN=Brainpool", "-days", "30", "-out", "bp.crt")
	run("pkcs12", "-export", "-in", "bp.crt", "-inkey", "bp.pem", "-name", "bp", "-passout", "pass:secret", "-out", "bp.p12")
	run("pkcs12", "-export", "-nokeys", "-in", "cert.pem", "-passout", "pass:secret", "-out", "certonly.p12")
	run("pkcs12", "-export", "-nocerts", "-inkey", "ed448.pem", "-name", "lonely", "-passout", "pass:secret", "-out", "keyonly.p12")
	run("pkcs12", "-export", "-legacy", "-in", "cert.pem", "-inkey", "rsa.pem", "-passout", "pass:secret", "-out", "legacy.p12")

	cases := []struct {
		file, password string
		want           []string // type:name
	}{
		{"both.p12", "secret", []string{"3:my alias", "1:my alias_key"}},
		{"ed448.p12", "secret", []string{"3:Ed448 leaf", "1:Ed448 leaf_key", "3:Ed448 leaf_ca_0"}},
		{"bp.p12", "secret", []string{"3:bp", "1:bp_key"}},
		{"certonly.p12", "secret", []string{"3:Foreign"}},
		{"keyonly.p12", "secret", []string{"1:lonely_key"}},
		{"legacy.p12", "secret", []string{"3:Foreign", "1:Foreign_key"}},
		{"rsa-enc.pem", "secret", []string{"1:rsa-enc"}},
		{"rsa.pvk", "secret", []string{"1:rsa"}},
		{"rsa.pk8", "secret", []string{"1:rsa"}},
		{"ec.pem", "", []string{"1:ec"}},
		{"bp.pem", "", []string{"1:bp"}},
		{"dsa.pem", "", []string{"1:dsa"}},
		{"cert.der", "", []string{"3:Foreign"}},
		{"cert.p7b", "", []string{"3:Foreign"}},
	}
	for _, c := range cases {
		data, err := os.ReadFile(filepath.Join(dir, c.file))
		if err != nil {
			t.Fatal(err)
		}
		if c.password != "" {
			if r := Probe(c.file, data, ProbeOptions{}); !r.NeedPassword {
				t.Errorf("%s: password not requested", c.file)
			}
		}
		r := Probe(c.file, data, ProbeOptions{Password: []byte(c.password)})
		var got []string
		for _, o := range r.Objects {
			got = append(got, fmt.Sprintf("%d:%s", o.Type, o.Name))
			if o.Type == 1 && o.Private == nil {
				t.Errorf("%s: no private key", c.file)
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) || len(r.Unrecognized) > 0 {
			t.Errorf("%s: got %v (unrecognized %v), want %v", c.file, got, r.Unrecognized, c.want)
		}
	}
}

func TestExportKeysReadable(t *testing.T) {
	// every exported key form parses back to the same public key
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	for _, k := range []crypto.Signer{rsaKey, ecKey, edKey} {
		spki, _ := x509.MarshalPKIXPublicKey(k.Public())
		pk8, _ := pki.MarshalPKCS8(k)
		var outs [][]byte
		b, err := PrivatePEM(k, nil)
		outs = append(outs, b)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := k.(ed25519.PrivateKey); !ok {
			b, _ = PrivatePEM(k, []byte("pw"))
			outs = append(outs, b)
		}
		b, _ = PKCS8PEM(pk8, []byte("pw"))
		outs = append(outs, b)
		b, _ = SSHPrivate(k)
		outs = append(outs, b)
		if _, ok := k.(*rsa.PrivateKey); ok {
			b, _ = PVK(k)
			outs = append(outs, b)
		}
		for i, o := range outs {
			r := Probe("", o, ProbeOptions{Password: []byte("pw")})
			if len(r.Objects) != 1 || !bytes.Equal(r.Objects[0].DER, spki) || r.Objects[0].Private == nil {
				t.Fatalf("%T form %d: %+v", k, i, r)
			}
		}
		j, err := JWK("k", k.Public(), k)
		if err != nil || j["d"] == nil {
			t.Fatalf("%T jwk: %v", k, err)
		}
	}
}

func TestICSFolding(t *testing.T) {
	v := icsValue(strings.Repeat("a,", 50) + "\nend")
	for i, l := range strings.Split(v, "\r\n") {
		if len(l) > 75 || (i > 0 && !strings.HasPrefix(l, " ")) {
			t.Fatalf("line %d: %q", i, l)
		}
	}
	if strings.ReplaceAll(v, "\r\n ", "") != strings.Repeat(`a\,`, 50)+`\nend` {
		t.Fatalf("content changed: %q", v)
	}
}

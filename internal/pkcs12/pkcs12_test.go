package pkcs12

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestDeriveKey(t *testing.T) {
	// the vectors of go-pkcs12's pbkdf_test.go
	key := deriveKey(sha1.New, idKey, newPassword("sesame").bmp, []byte("\xff\xff\xff\xff\xff\xff\xff\xff"), 2048, 24)
	if want := []byte("\x7c\xd9\xfd\x3e\x2b\x3b\xe7\x69\x1a\x44\xe3\xbe\xf0\xf9\xea\x0f\xb9\xb8\x97\xd4\xe3\x25\xd9\xd1"); !bytes.Equal(key, want) {
		t.Errorf("long key %x", key)
	}
	key = deriveKey(sha1.New, idKey, []byte("\x00\x00"), []byte("\xf3\x7e\x05\xb5\x18\x32\x4b\x4b"), 2048, 24)
	if want := []byte("\x00\xf7\x59\xff\x47\xd1\x4d\xd0\x36\x65\xd5\x94\x3c\xb3\xc4\xa3\x9a\x25\x55\xc0\x2a\xed\x66\xe1"); !bytes.Equal(key, want) {
		t.Errorf("leading zeros %x", key)
	}
}

func testCert(t *testing.T, cn string) (*ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	pk8, _ := x509.MarshalPKCS8PrivateKey(k)
	return k, der, pk8
}

var profiles = map[string]Profile{"AES256": AES256, "DES3": DES3, "RC2": RC2}

func TestRoundTrip(t *testing.T) {
	_, leaf, key := testCert(t, "leaf")
	_, ca, _ := testCert(t, "ca")
	for name, prof := range profiles {
		for _, pass := range []string{"secret", "", "pässwörd 🔑"} {
			p12, err := Encode(Bag{DER: key, FriendlyName: "my alias 🔑"}, []Bag{{DER: leaf, FriendlyName: "my alias 🔑"}, {DER: ca}}, pass, prof)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			c, err := Decode(p12, pass)
			if err != nil {
				t.Fatalf("%s %q: %v", name, pass, err)
			}
			if len(c.Keys) != 1 || len(c.Certs) != 2 || !bytes.Equal(c.Keys[0].DER, key) ||
				!bytes.Equal(c.Certs[0].DER, leaf) || !bytes.Equal(c.Certs[1].DER, ca) {
				t.Fatalf("%s: %+v", name, c)
			}
			id := sha1.Sum(leaf)
			if c.Keys[0].FriendlyName != "my alias 🔑" || c.Certs[0].FriendlyName != "my alias 🔑" ||
				!bytes.Equal(c.Keys[0].LocalKeyID, id[:]) || !bytes.Equal(c.Certs[0].LocalKeyID, id[:]) ||
				c.Certs[1].FriendlyName != "" || c.Certs[1].LocalKeyID != nil {
				t.Errorf("%s: attributes %+v", name, c)
			}
			if _, err := Decode(p12, pass+"x"); !errors.Is(err, ErrPassword) {
				t.Errorf("%s: wrong password: %v", name, err)
			}
		}
	}
	// certificates only, key only
	p12, _ := Encode(Bag{}, []Bag{{DER: ca, FriendlyName: "the ca"}}, "pw", AES256)
	if c, err := Decode(p12, "pw"); err != nil || len(c.Keys) != 0 || len(c.Certs) != 1 || c.Certs[0].FriendlyName != "the ca" || c.Certs[0].LocalKeyID != nil {
		t.Errorf("certificates only: %v %+v", err, c)
	}
	p12, _ = Encode(Bag{DER: key, FriendlyName: "k"}, nil, "pw", AES256)
	if c, err := Decode(p12, "pw"); err != nil || len(c.Keys) != 1 || len(c.Certs) != 0 || c.Keys[0].FriendlyName != "k" {
		t.Errorf("key only: %v %+v", err, c)
	}
}

// TestGoPKCS12 checks against go-pkcs12 in both directions.
func TestGoPKCS12(t *testing.T) {
	k, leaf, key := testCert(t, "leaf")
	_, caDER, _ := testCert(t, "ca")
	leafCert, _ := x509.ParseCertificate(leaf)
	ca, _ := x509.ParseCertificate(caDER)
	for name, prof := range profiles {
		ours, err := Encode(Bag{DER: key, FriendlyName: "a"}, []Bag{{DER: leaf, FriendlyName: "a"}, {DER: caDER}}, "pw", prof)
		if err != nil {
			t.Fatal(err)
		}
		gk, gc, gchain, err := gopkcs12.DecodeChain(ours, "pw")
		if err != nil || !gc.Equal(leafCert) || len(gchain) != 1 || !gchain[0].Equal(ca) || !k.Equal(gk) {
			t.Errorf("%s: go-pkcs12 reads ours: %v", name, err)
		}
	}
	for name, enc := range map[string]*gopkcs12.Encoder{"Modern2023": gopkcs12.Modern2023, "Modern2026": gopkcs12.Modern2026,
		"LegacyDES": gopkcs12.LegacyDES, "LegacyRC2": gopkcs12.LegacyRC2, "Passwordless": gopkcs12.Passwordless} {
		pass := "pw"
		if name == "Passwordless" {
			pass = ""
		}
		theirs, err := enc.Encode(k, leafCert, []*x509.Certificate{ca}, pass)
		if err != nil {
			t.Fatal(err)
		}
		c, err := Decode(theirs, pass)
		if err != nil || len(c.Keys) != 1 || !bytes.Equal(c.Keys[0].DER, key) || len(c.Certs) != 2 {
			t.Errorf("%s: we read go-pkcs12's: %v %+v", name, err, c)
		}
	}
	ts, _ := gopkcs12.Modern2023.EncodeTrustStore([]*x509.Certificate{leafCert, ca}, "pw")
	if c, err := Decode(ts, "pw"); err != nil || len(c.Certs) != 2 || len(c.Keys) != 0 {
		t.Errorf("trust store: %v %+v", err, c)
	}
}

// TestRFC9579 reads the PBMAC1 examples of RFC 9579 Appendix A and
// go-pkcs12's short key forgery.
func TestRFC9579(t *testing.T) {
	load := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		der, err := base64.StdEncoding.DecodeString(string(bytes.Join(bytes.Fields(b), nil)))
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	for _, n := range []string{"a1", "a2", "a3"} {
		c, err := Decode(load("rfc9579-"+n+".txt"), "1234")
		if err != nil || len(c.Keys) != 1 || len(c.Certs) != 1 {
			t.Errorf("%s: %v %+v", n, err, c)
		}
	}
	for _, n := range []string{"a4", "a5"} { // bad iteration count, salt
		if _, err := Decode(load("rfc9579-"+n+".txt"), "1234"); !errors.Is(err, ErrPassword) {
			t.Errorf("%s: %v", n, err)
		}
	}
	if _, err := Decode(load("rfc9579-a6.txt"), "1234"); err == nil || !strings.Contains(err.Error(), "key length") {
		t.Errorf("a6 (no key length): %v", err)
	}
	if c, err := Decode(load("pbmac1-short-key-bypass.txt"), "anything"); err == nil {
		t.Errorf("short PBMAC1 key accepted: %+v", c)
	}
}

// TestOpenSSL reads what OpenSSL writes and lets OpenSSL read ours.
func TestOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("openssl", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "k.pem", "-subj", "/CN=x", "-days", "1", "-out", "c.pem")
	run("pkcs8", "-topk8", "-nocrypt", "-in", "k.pem", "-outform", "DER", "-out", "k.der")
	keyDER, _ := os.ReadFile(filepath.Join(dir, "k.der"))
	for _, c := range []struct {
		file string
		args []string
		keys int
	}{
		{"default.p12", nil, 1},
		{"named.p12", []string{"-name", "my name", "-caname", "the ca", "-certfile", "c.pem"}, 1},
		{"des.p12", []string{"-descert", "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1"}, 1},
		{"nomac.p12", []string{"-nomac"}, 1},
		{"nocerts.p12", []string{"-nocerts"}, 1},
		{"nokeys.p12", []string{"-nokeys"}, 0},
		{"plain.p12", []string{"-keypbe", "NONE", "-certpbe", "NONE"}, 1},
	} {
		args := append([]string{"pkcs12", "-export", "-in", "c.pem", "-inkey", "k.pem", "-passout", "pass:pw", "-out", c.file}, c.args...)
		run(args...)
		der, _ := os.ReadFile(filepath.Join(dir, c.file))
		got, err := Decode(der, "pw")
		if err != nil {
			t.Errorf("%s: %v", c.file, err)
			continue
		}
		if len(got.Keys) != c.keys || c.keys == 1 && !bytes.Equal(got.Keys[0].DER, keyDER) {
			t.Errorf("%s: %d keys", c.file, len(got.Keys))
		}
		if c.file == "named.p12" && (got.Keys[0].FriendlyName != "my name" || len(got.Certs) != 2 || got.Certs[1].FriendlyName != "the ca") {
			t.Errorf("%s: names %+v", c.file, got)
		}
		if _, err := Decode(der, "nope"); c.file != "plain.p12" && !errors.Is(err, ErrPassword) {
			t.Errorf("%s: wrong password %v", c.file, err)
		}
	}
	// ours, read by OpenSSL
	certDER := pemToDER(t, filepath.Join(dir, "c.pem"))
	for name, prof := range profiles {
		p12, err := Encode(Bag{DER: keyDER, FriendlyName: "go-ca name"}, []Bag{{DER: certDER, FriendlyName: "go-ca name"}}, "pw", prof)
		if err != nil {
			t.Fatal(err)
		}
		fn := name + ".p12"
		os.WriteFile(filepath.Join(dir, fn), p12, 0o600)
		args := []string{"pkcs12", "-in", fn, "-passin", "pass:pw", "-nodes"}
		if prof.certs.Equal(oidPBEWithSHAAnd40BitRC2CBC) {
			args = append(args, "-legacy")
		}
		out := run(args...)
		if !strings.Contains(out, "friendlyName: go-ca name") || !strings.Contains(out, "localKeyID:") ||
			!strings.Contains(out, "BEGIN PRIVATE KEY") || !strings.Contains(out, "BEGIN CERTIFICATE") {
			t.Errorf("%s: openssl reads\n%s", name, out)
		}
	}
}

func pemToDER(t *testing.T, fn string) []byte {
	b, err := os.ReadFile(fn)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	s = s[strings.Index(s, "\n")+1 : strings.Index(s, "-----END")]
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return der
}

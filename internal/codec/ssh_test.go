package codec

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys exist in old databases
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/mailsvb/openkca/internal/pki"
)

func sshTestKeys(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	var d dsa.PrivateKey
	if err := dsa.GenerateParameters(&d.Parameters, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	if err := dsa.GenerateKey(&d, rand.Reader); err != nil {
		t.Fatal(err)
	}
	return map[string]crypto.Signer{"rsa": rsaKey, "p256": p256, "p384": p384, "p521": p521, "ed25519": edKey, "dsa": pki.DSAKey{PrivateKey: &d}}
}

// probeOne reads a single key and checks its public key, private key,
// comment and name.
func probeOne(t *testing.T, label string, data []byte, pw string, want crypto.Signer, comment string, private bool) {
	t.Helper()
	r := Probe("file.ext", data, ProbeOptions{Password: []byte(pw)})
	if len(r.Objects) != 1 {
		t.Fatalf("%s: %+v", label, r)
	}
	o := r.Objects[0]
	spki, _ := marshalSPKI(want.Public())
	if !bytes.Equal(o.DER, spki) {
		t.Fatalf("%s: public key differs", label)
	}
	if private != (o.Private != nil) {
		t.Fatalf("%s: private part %v, want %v", label, o.Private != nil, private)
	}
	if private {
		wantDER, _ := pki.MarshalPKCS8(want)
		if !bytes.Equal(o.Private, wantDER) {
			t.Fatalf("%s: private key differs", label)
		}
	}
	wantName := comment
	if wantName == "" {
		wantName = "file"
	}
	if o.Comment != comment || o.Name != wantName {
		t.Fatalf("%s: comment %q name %q, want %q %q", label, o.Comment, o.Name, comment, wantName)
	}
}

// fastBcrypt lowers the bcrypt rounds of new OpenSSH files, which take
// seconds each with the race detector.
func fastBcrypt(t *testing.T) {
	old := opensshRounds
	opensshRounds = 2
	t.Cleanup(func() { opensshRounds = old })
}

func TestSSHFormatsRoundTrip(t *testing.T) {
	fastBcrypt(t)
	for name, k := range sshTestKeys(t) {
		comment := "me@" + name
		forms := map[string]func(pw []byte) ([]byte, error){
			"openssh": func(pw []byte) ([]byte, error) { return OpenSSHPrivate(k, comment, pw) },
			"ppk2":    func(pw []byte) ([]byte, error) { return PuTTYPrivate(k, comment, 2, pw) },
			"ppk3":    func(pw []byte) ([]byte, error) { return PuTTYPrivate(k, comment, 3, pw) },
		}
		for form, write := range forms {
			plain, err := write(nil)
			if err != nil {
				t.Fatalf("%s %s: %v", name, form, err)
			}
			probeOne(t, name+" "+form, plain, "", k, comment, true)
			enc, err := write([]byte("secret"))
			if err != nil {
				t.Fatalf("%s %s encrypted: %v", name, form, err)
			}
			if bytes.Equal(enc, plain) || bytes.Contains(enc, []byte("Encryption: none")) {
				t.Fatalf("%s %s: not encrypted", name, form)
			}
			probeOne(t, name+" "+form+" encrypted", enc, "secret", k, comment, true)
			if r := Probe("", enc, ProbeOptions{}); !r.NeedPassword || r.PasswordWrong || len(r.Objects) != 0 {
				t.Fatalf("%s %s without password: %+v", name, form, r)
			}
			if r := Probe("", enc, ProbeOptions{Password: []byte("wrong")}); !r.PasswordWrong || len(r.Objects) != 0 {
				t.Fatalf("%s %s wrong password: %+v", name, form, r)
			}
		}
		pub, err := RFC4716Public(k.Public(), comment)
		if err != nil {
			t.Fatal(err)
		}
		probeOne(t, name+" rfc4716", pub, "", k, comment, false)
		line, _ := SSHPublic(k.Public(), comment)
		probeOne(t, name+" authorized_keys", line, "", k, comment, false)
		// x/crypto's own reader takes go-ca's OpenSSH files
		if _, ok := k.(pki.DSAKey); !ok {
			enc, _ := OpenSSHPrivate(k, comment, []byte("secret"))
			if _, err := ssh.ParseRawPrivateKeyWithPassphrase(enc, []byte("secret")); err != nil {
				t.Fatalf("%s: x/crypto: %v", name, err)
			}
		}
	}
}

func TestSSHCommentsAndNames(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	long := strings.Repeat("ä", 50) + " end"
	pub, _ := RFC4716Public(k.Public(), long+"\nsecond line")
	for _, l := range strings.Split(string(pub), "\n") {
		if len(l) > rfc4716Line {
			t.Fatalf("line of %d bytes: %q", len(l), l)
		}
	}
	probeOne(t, "folded comment", pub, "", k, long, false)
	// no comment: the file name names the key
	plain, _ := OpenSSHPrivate(k, "", nil)
	probeOne(t, "no comment", plain, "", k, "", true)
	// several public keys in one file
	_, k2, _ := ed25519.GenerateKey(rand.Reader)
	a, _ := RFC4716Public(k.Public(), "a")
	b, _ := RFC4716Public(k2.Public(), "b")
	r := Probe("", append(a, b...), ProbeOptions{})
	if len(r.Objects) != 2 || r.Objects[0].Name != "a" || r.Objects[1].Name != "b" {
		t.Fatalf("%+v", r)
	}
	// Argon2 parameters beyond the limit are refused before any work
	enc, _ := PuTTYPrivate(k, "x", 3, []byte("pw"))
	huge := bytes.Replace(enc, []byte("Argon2-Passes: 13\n"), []byte("Argon2-Passes: 100000\n"), 1)
	if r := Probe("", huge, ProbeOptions{Password: []byte("pw")}); len(r.Objects) != 0 || len(r.Unrecognized) != 1 {
		t.Fatalf("huge Argon2 work: %+v", r)
	}
	// a damaged PuTTY file is reported, not imported
	ppk, _ := PuTTYPrivate(k, "x", 3, nil)
	bad := bytes.Replace(ppk, []byte("Comment: x"), []byte("Comment: y"), 1)
	if r := Probe("", bad, ProbeOptions{}); len(r.Objects) != 0 || len(r.Unrecognized) != 1 || r.NeedPassword {
		t.Fatalf("damaged PPK: %+v", r)
	}
}

func run(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func TestSSHKeygenFiles(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not installed")
	}
	dir := t.TempDir()
	// files written by ssh-keygen
	for _, c := range []struct{ typ, bits, cipher string }{
		{"ed25519", "", ""}, {"ecdsa", "384", ""}, {"rsa", "2048", ""},
		{"ed25519", "", "aes256-gcm@openssh.com"}, {"ecdsa", "256", "aes128-cbc"}, {"rsa", "2048", "aes256-ctr"},
	} {
		f := filepath.Join(dir, c.typ+c.bits+c.cipher)
		args := []string{"-q", "-t", c.typ, "-C", "user@" + c.typ, "-f", f}
		if c.bits != "" {
			args = append(args, "-b", c.bits)
		}
		pw := ""
		if c.cipher != "" {
			pw = "secret"
			args = append(args, "-Z", c.cipher)
			if c.cipher != "aes256-ctr" { // ssh-keygen's default cipher keeps its default rounds
				args = append(args, "-a", "2")
			}
		}
		args = append(args, "-N", pw)
		run(t, dir, "ssh-keygen", args...)
		data, _ := os.ReadFile(f)
		r := Probe(f, data, ProbeOptions{Password: []byte(pw)})
		if len(r.Objects) != 1 || r.Objects[0].Private == nil || r.Objects[0].Comment != "user@"+c.typ || r.Objects[0].Name != "user@"+c.typ {
			t.Fatalf("%s: %+v", f, r)
		}
		pubLine, _ := os.ReadFile(f + ".pub")
		rfc := run(t, dir, "ssh-keygen", "-e", "-m", "RFC4716", "-f", f+".pub")
		pr := Probe("", []byte(rfc), ProbeOptions{})
		if len(pr.Objects) != 1 || !bytes.Equal(pr.Objects[0].DER, r.Objects[0].DER) {
			t.Fatalf("%s RFC 4716: %+v", f, pr)
		}
		if pr := Probe("", pubLine, ProbeOptions{}); len(pr.Objects) != 1 || pr.Objects[0].Name != "user@"+c.typ {
			t.Fatalf("%s.pub: %+v", f, pr)
		}
	}
	// go-ca's files read by ssh-keygen; one with the default bcrypt rounds
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	b, _ := OpenSSHPrivate(edKey, "c", []byte("secret"))
	os.WriteFile(filepath.Join(dir, "goca-default"), b, 0o600)
	run(t, dir, "ssh-keygen", "-y", "-P", "secret", "-f", "goca-default")
	fastBcrypt(t)
	// OpenSSH 10 removed DSA; older builds may also leave it out
	noDSA := exec.Command("ssh-keygen", "-q", "-t", "dsa", "-N", "", "-f", filepath.Join(dir, "dsa-probe")).Run() != nil
	for name, k := range sshTestKeys(t) {
		if name == "dsa" && noDSA {
			continue
		}
		want, _ := SSHPublic(k.Public(), "")
		for _, pw := range []string{"", "secret"} {
			b, _ := OpenSSHPrivate(k, "c", []byte(pw))
			f := filepath.Join(dir, "goca-"+name+pw)
			os.WriteFile(f, b, 0o600)
			got := run(t, dir, "ssh-keygen", "-y", "-P", pw, "-f", f)
			if strings.Fields(got)[1] != strings.Fields(string(want))[1] {
				t.Fatalf("%s %q: ssh-keygen read\n%s", name, pw, got)
			}
		}
		rfc, _ := RFC4716Public(k.Public(), "a comment")
		f := filepath.Join(dir, "goca-"+name+".rfc")
		os.WriteFile(f, rfc, 0o600)
		if got := run(t, dir, "ssh-keygen", "-i", "-m", "RFC4716", "-f", f); strings.Fields(got)[1] != strings.Fields(string(want))[1] {
			t.Fatalf("%s: ssh-keygen -i\n%s", name, got)
		}
	}
}

func TestPuTTYgenFiles(t *testing.T) {
	fastBcrypt(t)
	if _, err := exec.LookPath("puttygen"); err != nil {
		t.Skip("puttygen not installed")
	}
	dir := t.TempDir()
	pwFile, emptyFile := filepath.Join(dir, "pw"), filepath.Join(dir, "empty")
	os.WriteFile(pwFile, []byte("secret\n"), 0o600)
	os.WriteFile(emptyFile, nil, 0o600)
	// files written by puttygen
	for _, typ := range []string{"ed25519", "ecdsa", "rsa", "dsa"} {
		for _, v := range []string{"2", "3"} {
			for _, pw := range []string{"", "secret"} {
				f := filepath.Join(dir, typ+v+pw+".ppk")
				pass := emptyFile
				if pw != "" {
					pass = pwFile
				}
				args := []string{"-t", typ, "-C", "putty " + typ, "-o", f, "--new-passphrase", pass, "--ppk-param", "version=" + v}
				if typ == "rsa" || typ == "dsa" {
					args = append(args, "-b", "2048")
				}
				run(t, dir, "puttygen", args...)
				data, _ := os.ReadFile(f)
				r := Probe(f, data, ProbeOptions{Password: []byte(pw)})
				if len(r.Objects) != 1 || r.Objects[0].Private == nil || r.Objects[0].Name != "putty "+typ {
					t.Fatalf("%s: %+v", f, r)
				}
				pub := run(t, dir, "puttygen", f, "-O", "public", "--old-passphrase", pass)
				if pr := Probe("", []byte(pub), ProbeOptions{}); len(pr.Objects) != 1 || !bytes.Equal(pr.Objects[0].DER, r.Objects[0].DER) || pr.Objects[0].Name != "putty "+typ {
					t.Fatalf("%s public: %+v\n%s", f, pr, pub)
				}
			}
		}
	}
	// go-ca's files read by puttygen
	for name, k := range sshTestKeys(t) {
		want, _ := SSHPublic(k.Public(), "")
		for _, v := range []int{2, 3} {
			for _, pw := range []string{"", "secret"} {
				b, _ := PuTTYPrivate(k, "c", v, []byte(pw))
				f := filepath.Join(dir, "goca-"+name+pw+".ppk")
				os.WriteFile(f, b, 0o600)
				pass := emptyFile
				if pw != "" {
					pass = pwFile
				}
				got := run(t, dir, "puttygen", f, "-O", "public-openssh", "--old-passphrase", pass)
				if strings.Fields(got)[1] != strings.Fields(string(want))[1] {
					t.Fatalf("%s v%d %q: puttygen read\n%s", name, v, pw, got)
				}
			}
		}
		rfc, _ := RFC4716Public(k.Public(), "c")
		f := filepath.Join(dir, "goca-"+name+".pub")
		os.WriteFile(f, rfc, 0o600)
		if got := run(t, dir, "puttygen", f, "-O", "public-openssh"); strings.Fields(got)[1] != strings.Fields(string(want))[1] {
			t.Fatalf("%s: puttygen public\n%s", name, got)
		}
	}
}

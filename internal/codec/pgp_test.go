package codec

import (
	"bytes"
	"crypto"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/pki"
)

type pgpCase struct {
	name     string
	primary  pki.KeySpec
	sub      pki.KeySpec
	versions []int
	gnupg    bool // GnuPG 2.4 knows the algorithms
}

var pgpCases = []pgpCase{
	{"ed25519", pki.KeySpec{Type: "Ed25519"}, pki.KeySpec{Type: "X25519"}, []int{4, 6}, true},
	{"p256", pki.KeySpec{Type: "EC", Curve: "P-256"}, pki.KeySpec{Type: "EC", Curve: "P-256"}, []int{4, 6}, true},
	{"p384", pki.KeySpec{Type: "EC", Curve: "P-384"}, pki.KeySpec{Type: "EC", Curve: "P-384"}, []int{4}, true},
	{"p521", pki.KeySpec{Type: "EC", Curve: "P-521"}, pki.KeySpec{Type: "EC", Curve: "P-521"}, []int{4}, true},
	{"rsa", pki.KeySpec{Type: "RSA", Bits: 2048}, pki.KeySpec{Type: "RSA", Bits: 2048}, []int{4, 6}, true},
	{"brainpool256", pki.KeySpec{Type: "EC", Curve: "brainpoolP256r1"}, pki.KeySpec{Type: "EC", Curve: "brainpoolP256r1"}, []int{4, 6}, true},
	{"brainpool384", pki.KeySpec{Type: "EC", Curve: "brainpoolP384r1"}, pki.KeySpec{Type: "EC", Curve: "brainpoolP384r1"}, []int{4}, true},
	{"brainpool512", pki.KeySpec{Type: "EC", Curve: "brainpoolP512r1"}, pki.KeySpec{Type: "EC", Curve: "brainpoolP512r1"}, []int{4}, true},
	{"secp256k1", pki.KeySpec{Type: "EC", Curve: "secp256k1"}, pki.KeySpec{Type: "EC", Curve: "secp256k1"}, []int{4}, true},
	{"ed448", pki.KeySpec{Type: "Ed448"}, pki.KeySpec{Type: "X448"}, []int{4, 6}, false},
	{"ed25519-mlkem", pki.KeySpec{Type: "Ed25519"}, pki.KeySpec{Type: "CompositeKEM", Param: "MLKEM768-X25519-SHA3-256"}, []int{4, 6}, false},
	{"mldsa65", pki.KeySpec{Type: "Composite", Param: "MLDSA65-Ed25519-SHA512"},
		pki.KeySpec{Type: "CompositeKEM", Param: "MLKEM768-X25519-SHA3-256"}, []int{6}, false},
	{"mldsa87", pki.KeySpec{Type: "Composite", Param: "MLDSA87-Ed448-SHAKE256"},
		pki.KeySpec{Type: "CompositeKEM", Param: "MLKEM1024-X448-SHA3-256"}, []int{6}, false},
}

func genKey(t *testing.T, s pki.KeySpec) crypto.Signer {
	t.Helper()
	k, err := pki.GenerateKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sameKey(a, b crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.Public().(equaler)
	return ok && e.Equal(b.Public())
}

func TestPGPCertRoundTrip(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, c := range pgpCases {
		primary, sub := genKey(t, c.primary), genKey(t, c.sub)
		for _, v := range c.versions {
			p := PGPParams{Version: v, UIDs: []string{"Alice <alice@example.org>", "Alice (work) <a@example.com>"},
				Created: created, Lifetime: 365 * 24 * time.Hour}
			cert, err := NewPGPCert(primary, []PGPSubkey{{Key: sub, Usage: PGPEncrypt}}, p)
			if err != nil {
				t.Fatalf("%s v%d: %v", c.name, v, err)
			}
			info, err := ParsePGPCert(cert)
			if err != nil {
				t.Fatalf("%s v%d: parse: %v", c.name, v, err)
			}
			fprLen := map[int]int{4: 40, 6: 64}[v]
			if info.Version != v || len(info.Keys) != 2 || len(info.Keys[0].Fingerprint) != fprLen {
				t.Fatalf("%s v%d: info %+v", c.name, v, info)
			}
			if strings.Join(info.UIDs, "|") != strings.Join(p.UIDs, "|") {
				t.Errorf("%s v%d: UIDs %q", c.name, v, info.UIDs)
			}
			if info.Keys[0].Usage != "SC" || info.Keys[1].Usage != "E" {
				t.Errorf("%s v%d: usage %s %s", c.name, v, info.Keys[0].Usage, info.Keys[1].Usage)
			}
			if !info.Keys[0].Created.Equal(created) || !info.Keys[0].Expires.Equal(created.AddDate(1, 0, 0)) {
				t.Errorf("%s v%d: created %v expires %v", c.name, v, info.Keys[0].Created, info.Keys[0].Expires)
			}
			// the same keys and time give the same fingerprints
			again, _ := NewPGPCert(primary, []PGPSubkey{{Key: sub, Usage: PGPEncrypt}}, p)
			if info2, _ := ParsePGPCert(again); info2.Keys[0].Fingerprint != info.Keys[0].Fingerprint ||
				info2.Keys[1].Fingerprint != info.Keys[1].Fingerprint {
				t.Errorf("%s v%d: fingerprints not stable", c.name, v)
			}
			pws := []string{""}
			if c.name == "ed25519" || c.name == "rsa" { // encryption is slow; the algorithm does not matter to it
				pws = append(pws, "pässword")
			}
			for _, pw := range pws {
				sec, err := PGPSecret(cert, []crypto.Signer{primary, sub}, []byte(pw))
				if err != nil {
					t.Fatalf("%s v%d: secret: %v", c.name, v, err)
				}
				ents, skipped, need, wrong := ReadPGP(sec, func() ([]byte, bool) { return []byte(pw), pw != "" })
				if len(ents) != 1 || need || wrong || len(skipped) > 0 {
					t.Fatalf("%s v%d pw %q: read %d %v %v %v", c.name, v, pw, len(ents), skipped, need, wrong)
				}
				e := ents[0]
				if !bytes.Equal(e.Cert, cert) {
					t.Errorf("%s v%d: certificate changed on the way back", c.name, v)
				}
				if e.Private[0] == nil || e.Private[1] == nil || !sameKey(e.Private[0], primary) || !sameKey(e.Private[1], sub) {
					t.Errorf("%s v%d: secrets differ", c.name, v)
				}
				if pw != "" {
					if ents, _, _, wrong := ReadPGP(sec, func() ([]byte, bool) { return []byte("wrong"), true }); len(ents) != 0 || !wrong {
						t.Errorf("%s v%d: wrong password accepted", c.name, v)
					}
				}
			}
			// a subkey without its secret
			sec, err := PGPSecret(cert, []crypto.Signer{primary, nil}, nil)
			if err != nil {
				t.Fatalf("%s v%d: secret without subkey: %v", c.name, v, err)
			}
			ents, _, _, _ := ReadPGP(sec, nil)
			if len(ents) != 1 || ents[0].Private[0] == nil || ents[0].Private[1] != nil {
				t.Errorf("%s v%d: stub subkey not read back", c.name, v)
			}
		}
	}
}

func TestPGPRejects(t *testing.T) {
	ed := genKey(t, pki.KeySpec{Type: "Ed25519"})
	x := genKey(t, pki.KeySpec{Type: "X25519"})
	now := time.Now()
	if _, err := NewPGPCert(x, nil, PGPParams{Version: 4, UIDs: []string{"x"}, Created: now}); err == nil {
		t.Error("X25519 primary key accepted")
	}
	if _, err := NewPGPCert(ed, []PGPSubkey{{Key: ed, Usage: PGPEncrypt}}, PGPParams{Version: 4, UIDs: []string{"x"}, Created: now}); err == nil {
		t.Error("Ed25519 encryption subkey accepted")
	}
	if _, err := NewPGPCert(ed, nil, PGPParams{Version: 4, Created: now}); err == nil {
		t.Error("v4 key without user ID accepted")
	}
	if _, err := NewPGPCert(ed, nil, PGPParams{Version: 4, UIDs: []string{"a\nb"}, Created: now}); err == nil {
		t.Error("user ID with a line break accepted")
	}
	if !PGPCompatible(ed.Public(), 4, false) || PGPCompatible(ed.Public(), 4, true) || !PGPCompatible(x.Public(), 6, true) || PGPCompatible(x.Public(), 6, false) {
		t.Error("PGPCompatible")
	}
	if _, err := NewPGPCert(ed, nil, PGPParams{Version: 6, Created: now}); err != nil {
		t.Errorf("v6 key without user ID: %v", err)
	}
	cert, _ := NewPGPCert(ed, nil, PGPParams{Version: 4, UIDs: []string{"x"}, Created: now})
	other := genKey(t, pki.KeySpec{Type: "Ed25519"})
	if _, err := PGPSecret(cert, []crypto.Signer{other}, nil); err == nil {
		t.Error("secret export with a foreign key")
	}
	// tampered self-signature: the user ID is dropped, and with it the key
	bad := bytes.Clone(cert)
	bad[len(bad)-5] ^= 0xff
	if ents, skipped, _, _ := ReadPGP(bad, nil); len(ents) != 0 || len(skipped) != 1 {
		t.Errorf("tampered certificate: %d keys, skipped %v", len(ents), skipped)
	}
}

func TestPGPArgon2Limit(t *testing.T) {
	ed := genKey(t, pki.KeySpec{Type: "Ed25519"})
	cert, _ := NewPGPCert(ed, nil, PGPParams{Version: 6, Created: time.Now()})
	sec, err := PGPSecret(cert, []crypto.Signer{ed}, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	// raise the memory exponent of the Argon2 specifier (4, salt, 3 passes, 4 lanes, 2^16 KiB)
	i := bytes.Index(sec, []byte{pgpArgon2Passes, pgpArgon2Lanes, 16})
	if i < 17 || sec[i-17] != 4 {
		t.Fatal("Argon2 specifier not found")
	}
	sec[i+2] = 30
	asked := false
	ents, skipped, _, _ := ReadPGP(sec, func() ([]byte, bool) { asked = true; return []byte("pw"), true })
	if asked || len(ents) != 1 || ents[0].Private[0] != nil || len(skipped) != 1 || !strings.Contains(skipped[0], "Argon2") {
		t.Fatalf("asked %v, %d keys, skipped %v", asked, len(ents), skipped)
	}
}

func TestPGPFormatFingerprint(t *testing.T) {
	got := FormatPGPFingerprint("0123456789ABCDEF0123456789ABCDEF01234567")
	if got != "0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567" {
		t.Fatal(got)
	}
}

// gnupg runs gpg in its own home directory.
type gnupg struct {
	t    *testing.T
	home string
}

func newGnuPG(t *testing.T) *gnupg {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed")
	}
	home, err := os.MkdirTemp("", "gpg")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(home, 0o700)
	g := &gnupg{t: t, home: home}
	t.Cleanup(func() {
		c := exec.Command("gpgconf", "--kill", "gpg-agent")
		c.Env = append(os.Environ(), "GNUPGHOME="+home)
		c.Run()
		os.RemoveAll(home)
	})
	return g
}

func (g *gnupg) run(stdin []byte, args ...string) ([]byte, error) {
	c := exec.Command("gpg", append([]string{"--batch", "--no-tty", "--pinentry-mode", "loopback"}, args...)...)
	c.Env = append(os.Environ(), "GNUPGHOME="+g.home)
	c.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return out.Bytes(), &gpgError{err, errb.String()}
	}
	return out.Bytes(), nil
}

type gpgError struct {
	err    error
	stderr string
}

func (e *gpgError) Error() string { return e.err.Error() + ": " + e.stderr }

func (g *gnupg) must(stdin []byte, args ...string) []byte {
	g.t.Helper()
	out, err := g.run(stdin, args...)
	if err != nil {
		g.t.Fatalf("gpg %s: %v", strings.Join(args, " "), err)
	}
	return out
}

// fingerprints lists the fpr records of --with-colons output.
func colonFingerprints(out []byte) []string {
	var fprs []string
	for _, l := range strings.Split(string(out), "\n") {
		if f := strings.Split(l, ":"); len(f) > 9 && f[0] == "fpr" {
			fprs = append(fprs, f[9])
		}
	}
	return fprs
}

// TestPGPWithGnuPG has gpg import go-ca's v4 keys and use them: verify
// fingerprints, sign and verify, encrypt and decrypt, import the
// revocation certificate.
func TestPGPWithGnuPG(t *testing.T) {
	for _, c := range pgpCases {
		if !c.gnupg {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			g := newGnuPG(t)
			primary, sub := genKey(t, c.primary), genKey(t, c.sub)
			cert, err := NewPGPCert(primary, []PGPSubkey{{Key: sub, Usage: PGPEncrypt}},
				PGPParams{Version: 4, UIDs: []string{"Test Key <test@example.org>"}, Created: time.Now().Add(-time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			info, _ := ParsePGPCert(cert)
			pub, _ := PGPArmor(PGPPublicBlock, cert, 4)
			g.must(pub, "--import")
			got := colonFingerprints(g.must(nil, "--with-colons", "--list-keys"))
			if len(got) != 2 || got[0] != info.Keys[0].Fingerprint || got[1] != info.Keys[1].Fingerprint {
				t.Fatalf("gpg fingerprints %v, go-ca %s %s", got, info.Keys[0].Fingerprint, info.Keys[1].Fingerprint)
			}
			// gpg encrypts to the public key; go-ca's secret, imported, decrypts
			msg := []byte("hello from go-ca")
			enc := g.must(msg, "--trust-model", "always", "--armor", "--recipient", info.Keys[0].Fingerprint, "--encrypt")
			sec, err := PGPSecret(cert, []crypto.Signer{primary, sub}, []byte("pw"))
			if err != nil {
				t.Fatal(err)
			}
			armored, _ := PGPArmor(PGPPrivateBlock, sec, 4)
			g.must(armored, "--passphrase", "pw", "--import")
			if out := g.must(enc, "--passphrase", "pw", "--decrypt"); !bytes.Equal(out, msg) {
				t.Fatalf("decrypted %q", out)
			}
			sig := g.must(msg, "--passphrase", "pw", "--local-user", info.Keys[0].Fingerprint, "--detach-sign")
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "msg"), msg, 0o600)
			os.WriteFile(filepath.Join(dir, "msg.sig"), sig, 0o600)
			g.must(nil, "--verify", filepath.Join(dir, "msg.sig"), filepath.Join(dir, "msg"))
			// the revocation certificate
			rev, err := PGPRevocation(cert, primary, false, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			ra, _ := PGPArmor(PGPPublicBlock, rev, 4)
			g.must(ra, "--import")
			if out := g.must(nil, "--with-colons", "--list-keys"); !strings.HasPrefix(strings.Split(string(out), "\npub:")[1], "r:") {
				t.Fatalf("not revoked:\n%s", out)
			}
		})
	}
}

// TestPGPFromGnuPG imports keys gpg generated, in each export form.
func TestPGPFromGnuPG(t *testing.T) {
	for _, algo := range [][2]string{{"ed25519", "cv25519"}, {"nistp256", "nistp256"}, {"rsa3072", "rsa3072"},
		{"brainpoolP384r1", "brainpoolP384r1"}, {"secp256k1", "secp256k1"}} {
		t.Run(algo[0], func(t *testing.T) {
			t.Parallel()
			g := newGnuPG(t)
			g.must(nil, "--passphrase", "pw", "--quick-gen-key", "Gpg Key <gpg@example.org>", algo[0], "sign", "2y")
			fpr := colonFingerprints(g.must(nil, "--with-colons", "--list-keys"))[0]
			g.must(nil, "--passphrase", "pw", "--quick-add-key", fpr, algo[1], "encr", "2y")
			want := colonFingerprints(g.must(nil, "--with-colons", "--list-keys"))
			if len(want) != 2 {
				t.Fatalf("gpg made %d keys", len(want))
			}
			for _, exp := range []struct {
				args             []string
				primary, subkeys bool
			}{
				{[]string{"--export"}, false, false},
				{[]string{"--armor", "--export"}, false, false},
				{[]string{"--passphrase", "pw", "--export-secret-keys"}, true, true},
				{[]string{"--passphrase", "pw", "--armor", "--export-secret-keys"}, true, true},
				{[]string{"--passphrase", "pw", "--armor", "--export-secret-subkeys"}, false, true},
			} {
				data := g.must(nil, exp.args...)
				ents, skipped, need, wrong := ReadPGP(data, func() ([]byte, bool) { return []byte("pw"), true })
				if len(ents) != 1 || len(skipped) > 0 || need || wrong {
					t.Fatalf("%v: %d keys, skipped %v, need %v wrong %v", exp.args, len(ents), skipped, need, wrong)
				}
				e := ents[0]
				if e.Info.Keys[0].Fingerprint != want[0] || e.Info.Keys[1].Fingerprint != want[1] {
					t.Fatalf("%v: fingerprints %s %s, gpg %v", exp.args, e.Info.Keys[0].Fingerprint, e.Info.Keys[1].Fingerprint, want)
				}
				if (e.Private[0] != nil) != exp.primary || (e.Private[1] != nil) != exp.subkeys {
					t.Fatalf("%v: secrets %v %v", exp.args, e.Private[0] != nil, e.Private[1] != nil)
				}
				if e.Info.Keys[0].Expires.IsZero() || e.Info.UIDs[0] != "Gpg Key <gpg@example.org>" {
					t.Fatalf("%v: info %+v", exp.args, e.Info)
				}
				if exp.primary {
					// go-ca writes the secret back; gpg accepts it as the same key
					sec, err := PGPSecret(e.Cert, e.Private, []byte("again"))
					if err != nil {
						t.Fatal(err)
					}
					h := newGnuPG(t)
					h.must(sec, "--passphrase", "again", "--import")
					if got := colonFingerprints(h.must(nil, "--with-colons", "--list-secret-keys")); len(got) != 2 || got[0] != want[0] {
						t.Fatalf("re-imported %v", got)
					}
				}
			}
			if _, _, need, _ := ReadPGP(g.must(nil, "--passphrase", "pw", "--export-secret-keys"), func() ([]byte, bool) { return nil, false }); !need {
				t.Error("encrypted secret key read without a password")
			}
		})
	}
}

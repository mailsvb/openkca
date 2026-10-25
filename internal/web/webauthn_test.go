package web

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"

	"github.com/mailsvb/openkca/internal/session"
)

const (
	testRPID   = "ca.example.org"
	testOrigin = "https://ca.example.org"
)

// softKey is a software WebAuthn authenticator with the PRF extension:
// ES256 signatures, attestation "none", PRF = HMAC-SHA256 over the salt.
type softKey struct {
	priv       *ecdsa.PrivateKey
	id         []byte
	secret     []byte
	count      uint32
	flags      byte   // backup flags: 0 for a security key, BE|BS for a passkey
	userHandle []byte // set for a passkey (discoverable)
	lazyPRF    bool   // evaluates the PRF only on assertions
	noPRF      bool   // has no PRF at all
}

func newSoftKey(passkey, lazy bool) *softKey {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k := &softKey{priv: priv, id: make([]byte, 16), secret: make([]byte, 32), lazyPRF: lazy}
	rand.Read(k.id)
	rand.Read(k.secret)
	if passkey {
		k.flags = 0x18
	}
	return k
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (k *softKey) prf(salt []byte) string {
	m := hmac.New(sha256.New, k.secret)
	m.Write(salt)
	return b64u(m.Sum(nil))
}

func (k *softKey) authData(attested []byte) []byte {
	rp := sha256.Sum256([]byte(testRPID))
	flags := byte(0x01|0x04) | k.flags // UP, UV
	if attested != nil {
		flags |= 0x40
	}
	k.count++
	out := append(rp[:], flags)
	out = binary.BigEndian.AppendUint32(out, k.count)
	return append(out, attested...)
}

func clientData(typ string, challenge protocol.URLEncodedBase64) []byte {
	b, _ := json.Marshal(map[string]string{"type": typ, "challenge": b64u(challenge), "origin": testOrigin})
	return b
}

// create answers a registration.
func (k *softKey) create(t *testing.T, raw []byte) []byte {
	t.Helper()
	var opts protocol.CredentialCreation
	if err := json.Unmarshal(raw, &opts); err != nil {
		t.Fatalf("creation options %s: %v", raw, err)
	}
	if opts.Response.RelyingParty.ID != testRPID {
		t.Fatalf("rp id %q", opts.Response.RelyingParty.ID)
	}
	if k.flags != 0 {
		id, _ := opts.Response.User.ID.(string)
		k.userHandle, _ = base64.RawURLEncoding.DecodeString(id)
		if len(k.userHandle) != 16 {
			t.Fatalf("user handle %q", id)
		}
	}
	cose, err := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1,
		-2: k.priv.PublicKey.X.FillBytes(make([]byte, 32)), -3: k.priv.PublicKey.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	attested := append(make([]byte, 16), byte(len(k.id)>>8), byte(len(k.id)))
	attested = append(append(attested, k.id...), cose...)
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(attested)})
	if err != nil {
		t.Fatal(err)
	}
	ext := map[string]any{"enabled": !k.noPRF}
	if p := opts.Response.Extensions.PRF; p != nil && len(p.Eval.First) > 0 && !k.lazyPRF && !k.noPRF {
		ext["results"] = map[string]string{"first": k.prf(p.Eval.First)}
	}
	out, _ := json.Marshal(map[string]any{
		"id": b64u(k.id), "rawId": b64u(k.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64u(clientData("webauthn.create", opts.Response.Challenge)),
			"attestationObject": b64u(att), "transports": []string{"usb"}},
		"clientExtensionResults": map[string]any{"prf": ext},
	})
	return out
}

// get answers an assertion; it fails the test when the key is not allowed.
func (k *softKey) get(t *testing.T, raw []byte) []byte {
	t.Helper()
	var opts protocol.CredentialAssertion
	if err := json.Unmarshal(raw, &opts); err != nil {
		t.Fatalf("assertion options %s: %v", raw, err)
	}
	allowed := false
	for _, c := range opts.Response.AllowedCredentials {
		allowed = allowed || bytes.Equal(c.CredentialID, k.id)
	}
	if !allowed {
		t.Fatal("the key is not among the allowed credentials")
	}
	cd := clientData("webauthn.get", opts.Response.Challenge)
	ad := k.authData(nil)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte(nil), ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	resp := map[string]any{"clientDataJSON": b64u(cd), "authenticatorData": b64u(ad), "signature": b64u(sig)}
	if k.userHandle != nil {
		resp["userHandle"] = b64u(k.userHandle)
	}
	ext := map[string]any{}
	if p := opts.Response.Extensions.PRF; p != nil {
		if v, ok := p.EvalByCredential[b64u(k.id)]; ok {
			ext["prf"] = map[string]any{"results": map[string]string{"first": k.prf(v.First)}}
		}
	}
	out, _ := json.Marshal(map[string]any{"id": b64u(k.id), "rawId": b64u(k.id), "type": "public-key",
		"response": resp, "clientExtensionResults": ext})
	return out
}

func newWebAuthnServer(t *testing.T) (*httptest.Server, *Server) {
	return newTestServer(t, func(c *Config) {
		c.WebAuthn = WebAuthnConfig{RPID: testRPID, Origins: []string{testOrigin}}
	})
}

// postJSON posts a body (form or JSON) with the CSRF header and decodes the
// JSON answer.
func postJSON(t *testing.T, c *http.Client, u, csrf, ctype string, payload []byte) (int, map[string]any, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(payload))
	req.Header.Set("X-CSRF-Token", csrf)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	raw, _ := io.ReadAll(r.Body)
	var out map[string]any
	json.Unmarshal(raw, &out)
	return r.StatusCode, out, raw
}

var codeRE = regexp.MustCompile(`id="backup-code" class="backupcode">([0-9A-Z-]+)<`)

func TestWebAuthnAndBackupCode(t *testing.T) {
	ts, _ := newWebAuthnServer(t)
	c := client(t, ts)
	csrf := login(t, ts, c)
	form := func(path string, v url.Values) *http.Response {
		t.Helper()
		v.Set("csrf", csrf)
		r, err := c.PostForm(ts.URL+path, v)
		if err != nil {
			t.Fatal(err)
		}
		body(t, r)
		return r
	}
	form("/", url.Values{"name": {"wa"}, "password": {"password1"}, "password2": {"password1"}})
	if loc := form("/db/wa/login", url.Values{"password": {"password1"}}).Header.Get("Location"); loc != "/db/wa/" {
		t.Fatalf("login: %s", loc)
	}
	r, _ := c.Get(ts.URL + "/db/wa/certs")
	if !strings.Contains(body(t, r), "/db/wa/methods") {
		t.Fatal("no notice about the missing backup code")
	}

	register := func(k *softKey, typ, label string) {
		t.Helper()
		st, _, raw := postJSON(t, c, ts.URL+"/db/wa/webauthn/register/begin", csrf, "application/x-www-form-urlencoded",
			[]byte(url.Values{"type": {typ}, "label": {label}}.Encode()))
		if st != http.StatusOK {
			t.Fatalf("register begin: %d %s", st, raw)
		}
		st, out, raw := postJSON(t, c, ts.URL+"/db/wa/webauthn/register/finish", csrf, "application/json", k.create(t, raw))
		if st != http.StatusOK {
			t.Fatalf("register finish: %d %s", st, raw)
		}
		if a, ok := out["assert"]; ok {
			if !k.lazyPRF {
				t.Fatal("second touch for a key that evaluated the PRF")
			}
			opts, _ := json.Marshal(a)
			st, out, raw = postJSON(t, c, ts.URL+"/db/wa/webauthn/register/prf", csrf, "application/json", k.get(t, opts))
			if st != http.StatusOK {
				t.Fatalf("register prf: %d %s", st, raw)
			}
		} else if k.lazyPRF {
			t.Fatal("no second touch for a key without PRF output")
		}
		if !strings.Contains(out["redirect"].(string), "notice=added") {
			t.Fatalf("register: %v", out)
		}
	}
	yubi := newSoftKey(false, false)
	register(yubi, "security_key", "Desk key")
	phone := newSoftKey(true, true)
	register(phone, "passkey", "Phone")
	// A key without PRF support is refused.
	old := newSoftKey(false, false)
	old.noPRF = true
	_, _, raw := postJSON(t, c, ts.URL+"/db/wa/webauthn/register/begin", csrf, "application/x-www-form-urlencoded",
		[]byte(url.Values{"type": {"security_key"}, "label": {"Old key"}}.Encode()))
	if st, out, _ := postJSON(t, c, ts.URL+"/db/wa/webauthn/register/finish", csrf, "application/json", old.create(t, raw)); st != http.StatusUnprocessableEntity ||
		!strings.Contains(out["error"].(string), "PRF") {
		t.Fatalf("key without PRF: %d %v", st, out)
	}
	r, _ = c.Get(ts.URL + "/db/wa/methods")
	page := body(t, r)
	if !strings.Contains(page, "Desk key") || !strings.Contains(page, "Phone") || !strings.Contains(page, "Passkey") || strings.Contains(page, "Old key") {
		t.Fatal("keys not listed")
	}

	logout := func() {
		t.Helper()
		form("/db/wa/logout", url.Values{})
	}
	keyLogin := func(k *softKey) (int, map[string]any) {
		t.Helper()
		st, _, raw := postJSON(t, c, ts.URL+"/db/wa/webauthn/login/begin", csrf, "", nil)
		if st != http.StatusOK {
			t.Fatalf("login begin: %d %s", st, raw)
		}
		st, out, _ := postJSON(t, c, ts.URL+"/db/wa/webauthn/login/finish", csrf, "application/json", k.get(t, raw))
		return st, out
	}
	for _, k := range []*softKey{yubi, phone} {
		logout()
		if st, out := keyLogin(k); st != http.StatusOK || out["redirect"] != "/db/wa/" {
			t.Fatalf("login with a key: %d %v", st, out)
		}
		if r, _ := c.Get(ts.URL + "/db/wa/certs"); r.StatusCode != http.StatusOK {
			t.Fatalf("after key login: %d", r.StatusCode)
		}
	}
	// A key whose PRF output differs does not open the database.
	logout()
	evil := *yubi
	evil.secret = bytes.Repeat([]byte{1}, 32)
	if st, out := keyLogin(&evil); st != http.StatusUnauthorized || out["error"] == nil {
		t.Fatalf("wrong PRF output: %d %v", st, out)
	}
	// A finish without a begin is refused.
	if st, _, _ := postJSON(t, c, ts.URL+"/db/wa/webauthn/login/finish", csrf, "application/json", []byte("{}")); st != http.StatusBadRequest {
		t.Fatalf("finish without begin: %d", st)
	}

	// The login page offers keys and passkeys for this database.
	r, _ = c.Get(ts.URL + "/")
	if !strings.Contains(body(t, r), `data-webauthn="login" data-db="wa"`) {
		t.Fatal("no key login on the database list")
	}

	// Backup code: shown once, works once.
	if st, out := keyLogin(yubi); st != http.StatusOK {
		t.Fatalf("login: %d %v", st, out)
	}
	r, _ = c.PostForm(ts.URL+"/db/wa/methods/backup-code", url.Values{"csrf": {csrf}})
	m := codeRE.FindStringSubmatch(body(t, r))
	if m == nil {
		t.Fatal("no backup code shown")
	}
	r, _ = c.Get(ts.URL + "/db/wa/certs")
	if strings.Contains(body(t, r), `class="warn small nobackup"`) {
		t.Fatal("the notice stays with a backup code")
	}
	logout()
	if loc := form("/db/wa/login", url.Values{"method": {"backup_code"}, "code": {"AAAAA-AAAAA-AAAAA-AAAAA-AAAAAA"}}).Header.Get("Location"); !strings.Contains(loc, "dblogin.error.code") {
		t.Fatalf("wrong code: %s", loc)
	}
	if loc := form("/db/wa/login", url.Values{"method": {"backup_code"}, "code": {strings.ToLower(m[1])}}).Header.Get("Location"); !strings.Contains(loc, "notice=codeused") {
		t.Fatalf("backup code: %s", loc)
	}
	logout()
	if loc := form("/db/wa/login", url.Values{"method": {"backup_code"}, "code": {m[1]}}).Header.Get("Location"); !strings.Contains(loc, "dblogin.error.code") {
		t.Fatalf("code used twice: %s", loc)
	}

	// Without a fresh confirmation nothing changes; a password or a key
	// confirms.
	session.ConfirmFor = 0
	t.Cleanup(func() { session.ConfirmFor = 5 * time.Minute })
	form("/db/wa/login", url.Values{"password": {"password1"}})
	if loc := form("/db/wa/methods/password", url.Values{"label": {"x"}, "password": {"password2"}, "password2": {"password2"}}).Header.Get("Location"); !strings.Contains(loc, "error=confirm") {
		t.Fatalf("change without confirmation: %s", loc)
	}
	r, _ = c.Get(ts.URL + "/db/wa/methods")
	if p := body(t, r); !strings.Contains(p, "/db/wa/methods/confirm") || strings.Contains(p, "/remove") {
		t.Fatal("methods page without confirmation")
	}
	session.ConfirmFor = 5 * time.Minute
	if loc := form("/db/wa/methods/confirm", url.Values{"password": {"wrong password"}}).Header.Get("Location"); !strings.Contains(loc, "error=confirm_password") {
		t.Fatalf("confirm with a wrong password: %s", loc)
	}
	st, _, raw := postJSON(t, c, ts.URL+"/db/wa/webauthn/confirm/begin", csrf, "", nil)
	if st != http.StatusOK {
		t.Fatalf("confirm begin: %d %s", st, raw)
	}
	if st, out, _ := postJSON(t, c, ts.URL+"/db/wa/webauthn/confirm/finish", csrf, "application/json", phone.get(t, raw)); st != http.StatusOK || !strings.Contains(out["redirect"].(string), "/methods") {
		t.Fatalf("confirm with a passkey: %d %v", st, out)
	}
	if loc := form("/db/wa/methods/password", url.Values{"label": {"x"}, "password": {"password2"}, "password2": {"password2"}}).Header.Get("Location"); !strings.Contains(loc, "notice=added") {
		t.Fatalf("change after confirmation: %s", loc)
	}

	// Replacing the data key keeps only the password typed with it.
	if loc := form("/db/wa/methods/rekey", url.Values{"password": {"password2"}}).Header.Get("Location"); !strings.Contains(loc, "notice=rekeyed") {
		t.Fatalf("rekey: %s", loc)
	}
	r, _ = c.Get(ts.URL + "/db/wa/methods")
	if p := body(t, r); strings.Contains(p, "Desk key") || strings.Contains(p, "Phone") || len(methodIDRE.FindAllString(p, -1)) != 1 {
		t.Fatal("other methods kept after replacing the data key")
	}
	logout()
	if st, _, _ := postJSON(t, c, ts.URL+"/db/wa/webauthn/login/begin", csrf, "", nil); st != http.StatusNotFound {
		t.Fatalf("key login offered without keys: %d", st)
	}
	if loc := form("/db/wa/login", url.Values{"password": {"password2"}}).Header.Get("Location"); loc != "/db/wa/" {
		t.Fatalf("login with the kept password: %s", loc)
	}
}

// Without rp_id, keys and passkeys are neither offered nor accepted.
func TestWebAuthnOff(t *testing.T) {
	ts, _ := newTestServer(t)
	c := client(t, ts)
	csrf := login(t, ts, c)
	c.PostForm(ts.URL+"/", url.Values{"name": {"plain"}, "password": {"password1"}, "password2": {"password1"}, "csrf": {csrf}})
	c.PostForm(ts.URL+"/db/plain/login", url.Values{"password": {"password1"}, "csrf": {csrf}})
	r, _ := c.Get(ts.URL + "/db/plain/methods")
	if p := body(t, r); strings.Contains(p, `data-webauthn="register"`) || !strings.Contains(p, "general.webauthn.rp_id") {
		t.Fatal("keys offered without rp_id")
	}
	if st, _, _ := postJSON(t, c, ts.URL+"/db/plain/webauthn/register/begin", csrf, "application/x-www-form-urlencoded",
		[]byte("type=passkey&label=x")); st != http.StatusNotFound {
		t.Fatalf("register without rp_id: %d", st)
	}
}

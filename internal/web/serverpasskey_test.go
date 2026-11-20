package web

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

// browser is a client with its own cookie jar (client shares
// ts.Client(), so a second one would replace the first one's cookies).
func browser(ts *httptest.Server) *http.Client {
	c := *ts.Client()
	c.Jar, _ = cookiejar.New(nil)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// addServerPasskey registers k under label with the server password pw.
func addServerPasskey(t *testing.T, ts string, c *http.Client, csrf string, k *softKey, label, pw string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"label": {label}, "password": {pw}}.Encode()
	st, out, raw := postJSON(t, c, ts+"/passkeys/register/begin", csrf, "application/x-www-form-urlencoded", []byte(form))
	if st != http.StatusOK {
		return st, out
	}
	st, out, _ = postJSON(t, c, ts+"/passkeys/register/finish", csrf, "application/json", k.create(t, raw))
	return st, out
}

// passkeySignIn logs a fresh browser in with k.
func passkeySignIn(t *testing.T, ts string, c *http.Client, k *softKey) (int, map[string]any) {
	t.Helper()
	st, out, raw := postJSON(t, c, ts+"/login/passkey/begin", "", "", nil)
	if st != http.StatusOK {
		return st, out
	}
	st, out, _ = postJSON(t, c, ts+"/login/passkey/finish", "", "application/json", k.get(t, raw))
	return st, out
}

func signedIn(t *testing.T, ts string, c *http.Client) bool {
	t.Helper()
	r, err := c.Get(ts + "/")
	if err != nil {
		t.Fatal(err)
	}
	body(t, r)
	return r.StatusCode == http.StatusOK
}

func TestServerPasskeys(t *testing.T) {
	ts, srv := newWebAuthnServer(t)
	c := browser(ts)
	csrf := login(t, ts, c)

	r, _ := browser(ts).Get(ts.URL + "/login")
	if strings.Contains(body(t, r), "data-passkey-login") {
		t.Fatal("passkey button without a passkey")
	}
	if st, _ := passkeySignIn(t, ts.URL, browser(ts), newSoftKey(true, false)); st != http.StatusNotFound {
		t.Fatalf("passkey login without passkeys: %d", st)
	}

	mac, phone := newSoftKey(true, false), newSoftKey(true, false)
	// The server password is needed for every registration.
	if st, _ := addServerPasskey(t, ts.URL, c, csrf, mac, "Mac", ""); st != http.StatusUnauthorized {
		t.Fatalf("register without password: %d", st)
	}
	if st, _ := addServerPasskey(t, ts.URL, c, csrf, mac, "Mac", "wrong"); st != http.StatusUnauthorized {
		t.Fatalf("register with a wrong password: %d", st)
	}
	if st, out := addServerPasskey(t, ts.URL, c, csrf, mac, "Mac", serverPassword); st != http.StatusOK || out["redirect"] != "/passkeys?notice=added" {
		t.Fatalf("register Mac: %d %v", st, out)
	}
	if st, _ := addServerPasskey(t, ts.URL, c, csrf, phone, "mac", serverPassword); st != http.StatusConflict {
		t.Fatalf("duplicate name: %d", st)
	}
	if st, _ := addServerPasskey(t, ts.URL, c, csrf, mac, "Again", serverPassword); st != http.StatusUnprocessableEntity {
		t.Fatalf("same authenticator twice: %d", st)
	}
	if st, _ := addServerPasskey(t, ts.URL, c, csrf, phone, "Phone", serverPassword); st != http.StatusOK {
		t.Fatalf("register Phone: %d", st)
	}
	if st, _ := addServerPasskey(t, ts.URL, browser(ts), "", newSoftKey(true, false), "X", serverPassword); st != http.StatusUnauthorized {
		t.Fatalf("register without a session: %d", st)
	}
	if n := srv.passkeys.Count(); n != 2 {
		t.Fatalf("%d passkeys", n)
	}

	r, _ = c.Get(ts.URL + "/passkeys")
	page := body(t, r)
	if !strings.Contains(page, "Mac") || !strings.Contains(page, "Phone") {
		t.Fatal("passkeys page does not list both")
	}
	r, _ = browser(ts).Get(ts.URL + "/login")
	loginPage := body(t, r)
	if !strings.Contains(loginPage, "data-passkey-login") {
		t.Fatal("no passkey button on the login page")
	}
	if pw, pk := strings.Index(loginPage, `action="/login"`), strings.Index(loginPage, "data-passkey-section"); pw < 0 || pk < pw {
		t.Fatal("the passkey section is not below the password form")
	}

	// Both devices sign in.
	for name, k := range map[string]*softKey{"Mac": mac, "Phone": phone} {
		b := browser(ts)
		if st, out := passkeySignIn(t, ts.URL, b, k); st != http.StatusOK || out["redirect"] != "/" {
			t.Fatalf("%s sign-in: %d %v", name, st, out)
		}
		if !signedIn(t, ts.URL, b) {
			t.Fatalf("%s: no session after sign-in", name)
		}
	}
	if k, _ := srv.passkeys.ByCredential(mac.id); k.LastUsed.IsZero() {
		t.Fatal("last use not recorded")
	}

	// Finish without the pre-login cookie.
	b := browser(ts)
	_, _, raw := postJSON(t, b, ts.URL+"/login/passkey/begin", "", "", nil)
	if st, _, _ := postJSON(t, browser(ts), ts.URL+"/login/passkey/finish", "", "application/json", mac.get(t, raw)); st != http.StatusBadRequest {
		t.Fatalf("finish without ceremony: %d", st)
	}
	// A passkey for another user handle.
	stranger := newSoftKey(true, false)
	stranger.userHandle = make([]byte, 16)
	rand.Read(stranger.userHandle)
	if st, _ := passkeySignIn(t, ts.URL, browser(ts), stranger); st != http.StatusUnauthorized {
		t.Fatalf("stranger: %d", st)
	}

	// Removing one leaves the other and the password.
	var macID string
	for _, k := range srv.passkeys.List() {
		if k.Label == "Mac" {
			macID = k.ID
		}
	}
	resp, err := c.PostForm(ts.URL+"/passkeys/"+macID+"/delete", url.Values{"csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	body(t, resp)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if st, _ := passkeySignIn(t, ts.URL, browser(ts), mac); st != http.StatusUnauthorized {
		t.Fatalf("removed passkey: %d", st)
	}
	if st, _ := passkeySignIn(t, ts.URL, browser(ts), phone); st != http.StatusOK {
		t.Fatalf("remaining passkey: %d", st)
	}
	login(t, ts, browser(ts))

	// Failed passkey logins count toward the login rate limit.
	for range 5 {
		passkeySignIn(t, ts.URL, browser(ts), stranger)
	}
	if st, _ := passkeySignIn(t, ts.URL, browser(ts), phone); st != http.StatusTooManyRequests {
		t.Fatalf("rate limit: %d", st)
	}
}

// logBuffer collects log output from the server's goroutines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLog(srv *Server) *logBuffer {
	b := &logBuffer{}
	srv.log = slog.New(slog.NewTextHandler(b, nil))
	return b
}

func TestWebAuthnErrAttrs(t *testing.T) {
	err := protocol.ErrVerification.WithDetails("Error validating origin").WithInfo("Expected Values: [https://a], Received: https://b")
	attrs := webauthnErrAttrs(fmt.Errorf("wrapped: %w", err))
	got := fmt.Sprint(attrs...)
	for _, want := range []string{"err_type", "verification_error", "err_info", "Received: https://b"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q missing in %v", want, attrs)
		}
	}
	if a := webauthnErrAttrs(errors.New("plain")); len(a) != 2 {
		t.Fatalf("plain error: %v", a)
	}
}

func TestServerPasskeyLogging(t *testing.T) {
	ts, srv := newWebAuthnServer(t)
	logs := captureLog(srv)
	c := browser(ts)
	csrf := login(t, ts, c)
	mac := newSoftKey(true, false)
	if st, _ := addServerPasskey(t, ts.URL, c, csrf, mac, "Mac", serverPassword); st != http.StatusOK {
		t.Fatalf("register: %d", st)
	}
	for _, want := range []string{"server passkey registration started", "server passkey added", "label=Mac"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log lacks %q:\n%s", want, logs)
		}
	}

	// A browser on a host outside rp_id: the begin step warns about it.
	form := url.Values{"label": {"Phone"}, "password": {serverPassword}}.Encode()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/passkeys/register/begin", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Origin", "https://elsewhere.example")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body(t, resp)
	if !strings.Contains(logs.String(), "not general.webauthn.rp_id") {
		t.Fatalf("no origin warning:\n%s", logs)
	}

	// The browser failed: registration abort needs the session and CSRF.
	failure := []byte(`{"name":"NotAllowedError","message":"timed out\nor cancelled"}`)
	if st, _, _ := postJSON(t, browser(ts), ts.URL+"/passkeys/register/abort", "", "application/json", failure); st != http.StatusUnauthorized {
		t.Fatalf("register abort without a session: %d", st)
	}
	if st, _, _ := postJSON(t, c, ts.URL+"/passkeys/register/abort", "wrong", "application/json", failure); st != http.StatusForbidden {
		t.Fatalf("register abort without CSRF: %d", st)
	}
	if st, _, _ := postJSON(t, c, ts.URL+"/passkeys/register/abort", csrf, "application/json", failure); st != http.StatusNoContent {
		t.Fatalf("register abort: %d", st)
	}
	out := logs.String()
	if !strings.Contains(out, "server passkey registration failed in the browser") || !strings.Contains(out, "name=NotAllowedError") ||
		!strings.Contains(out, "label=Phone") || strings.Contains(out, "timed out\nor") {
		t.Fatalf("register abort log:\n%s", out)
	}

	// Login abort: only with a started ceremony, which it ends.
	if st, _, _ := postJSON(t, browser(ts), ts.URL+"/login/passkey/abort", "", "application/json", failure); st != http.StatusBadRequest {
		t.Fatalf("login abort without a ceremony: %d", st)
	}
	b := browser(ts)
	_, _, raw := postJSON(t, b, ts.URL+"/login/passkey/begin", "", "", nil)
	if st, _, _ := postJSON(t, b, ts.URL+"/login/passkey/abort", "", "application/json", failure); st != http.StatusNoContent {
		t.Fatalf("login abort: %d", st)
	}
	if !strings.Contains(logs.String(), "server passkey login failed in the browser") {
		t.Fatalf("login abort log:\n%s", logs)
	}
	if st, _, _ := postJSON(t, b, ts.URL+"/login/passkey/finish", "", "application/json", mac.get(t, raw)); st != http.StatusBadRequest {
		t.Fatalf("finish after abort: %d", st)
	}
	if st, _, _ := postJSON(t, b, ts.URL+"/login/passkey/abort", "", "application/json", failure); st != http.StatusBadRequest {
		t.Fatalf("second login abort: %d", st)
	}
}

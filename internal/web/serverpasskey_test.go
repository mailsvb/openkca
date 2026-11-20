package web

import (
	"crypto/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
	if !strings.Contains(body(t, r), "data-passkey-login") {
		t.Fatal("no passkey button on the login page")
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

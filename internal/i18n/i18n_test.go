package i18n

import "testing"

func TestCatalog(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	p := c.Match("de-DE,de;q=0.9,en;q=0.5")
	if p.Tag.String() != "en" {
		t.Fatalf("fallback language %s", p.Tag)
	}
	if got := p.T("app.name"); got != "go-ca" {
		t.Fatalf("app.name = %q", got)
	}
	if got := p.T("databases.schema", 7); got != "schema 7" {
		t.Fatalf("format = %q", got)
	}
	for n, want := range map[int]string{0: "No revoked certificates", 1: "1 revoked certificate", 3: "3 revoked certificates"} {
		if got := p.T("crl.entries", n); got != want {
			t.Errorf("plural %d = %q, want %q", n, got, want)
		}
	}
	if got := p.T("no.such.key"); got != "[no.such.key]" {
		t.Fatalf("missing key = %q", got)
	}
}

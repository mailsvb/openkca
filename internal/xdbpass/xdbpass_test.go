package xdbpass

import "testing"

// Values taken from databases written by XCA 2.6 and the fixture generator.
const (
	xcaT   = "T6d83239f1218a94f8E0EB67F4EF2B94BACE4A0A92102C9516A6D863856A546FC427A93FE0A32DB70D4B7C9BB61160024DB77B4CA1D2EDA9464B360FD90D91EC574144E8F06662E83"
	fixS   = "S1a2b1C1D4AB2916C1526FCB452181F028BF67BBC0B52B1027E526088F8FBF0BCDA0A60E4C45B5A0EB382AC671E993F8EF2B5CD35808446FA854EA9E86C58206949C8"
	fixMD5 = "5E:BE:22:94:EC:D0:E0:F0:8E:AB:76:90:D2:A6:EE:69"
)

func TestVerify(t *testing.T) {
	for _, tc := range []struct {
		stored, pw  string
		ok, upgrade bool
	}{
		{xcaT, "secret", true, false},
		{xcaT, "Secret", false, false},
		{fixS, "secret", true, true},
		{fixS, "wrong", false, false},
		{fixMD5, "secret", true, true},
		{fixMD5, "", false, false},
		{"garbage", "secret", false, false},
	} {
		ok, up := Verify(tc.stored, []byte(tc.pw))
		if ok != tc.ok || up != tc.upgrade {
			t.Errorf("Verify(%.10s…, %q) = %v,%v; want %v,%v", tc.stored, tc.pw, ok, up, tc.ok, tc.upgrade)
		}
	}
}

func TestNewHash(t *testing.T) {
	for _, pw := range []string{"", "secret", "ünïcödé"} {
		h := NewHash([]byte(pw))
		if FormOf(h) != FormT {
			t.Fatalf("NewHash form = %v", FormOf(h))
		}
		if ok, up := Verify(h, []byte(pw)); !ok || up {
			t.Fatalf("NewHash(%q) does not verify", pw)
		}
	}
}

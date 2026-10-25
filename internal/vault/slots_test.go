package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestSlotRoundTrip(t *testing.T) {
	k := NewKeyring(cheap)
	secret := bytes.Repeat([]byte{7}, 32)
	for _, typ := range SlotTypes {
		pw := secret
		if typ == SlotPassword {
			pw = []byte("correct horse")
		}
		kdf, wrapped, err := k.WrapSlot("slot-"+typ, typ, pw, cheap)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if typ == SlotPassword != strings.HasPrefix(kdf, "argon2id$") {
			t.Fatalf("%s: kdf %q", typ, kdf)
		}
		got, err := UnwrapSlot("slot-"+typ, typ, kdf, wrapped, pw, Default)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if !bytes.Equal(got.dek, k.dek) || got.Params() != Default {
			t.Fatalf("%s: unwrapped keyring differs", typ)
		}
		if _, err := UnwrapSlot("slot-"+typ, typ, kdf, wrapped, append([]byte("x"), pw...), cheap); !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("%s: wrong secret: %v", typ, err)
		}
	}
}

func TestSlotBinding(t *testing.T) {
	k := NewKeyring(cheap)
	secret := bytes.Repeat([]byte{1}, 32)
	kdf, wrapped, err := k.WrapSlot("a", SlotSecurityKey, secret, cheap)
	if err != nil {
		t.Fatal(err)
	}
	// Moved to another slot, retyped, or with another recipe: no longer opens.
	for _, c := range []struct{ id, typ, kdf string }{
		{"b", SlotSecurityKey, kdf},
		{"a", SlotPasskey, kdf},
		{"a", SlotSecurityKey, FormatHKDF([]byte("othersaltothersa"))},
	} {
		if _, err := UnwrapSlot(c.id, c.typ, c.kdf, wrapped, secret, cheap); !errors.Is(err, ErrWrongPassword) {
			t.Errorf("%+v opened: %v", c, err)
		}
	}
	// A password recipe on a key slot, or the reverse, is refused.
	if _, err := UnwrapSlot("a", SlotPassword, kdf, wrapped, secret, cheap); err == nil {
		t.Error("hkdf recipe accepted for a password")
	}
	pkdf, pw, _ := k.WrapSlot("p", SlotPassword, []byte("pw"), cheap)
	if _, err := UnwrapSlot("p", SlotPasskey, pkdf, pw, secret, cheap); err == nil {
		t.Error("argon2id recipe accepted for a passkey")
	}
	if _, err := UnwrapSlot("a", "token", kdf, wrapped, secret, cheap); err == nil {
		t.Error("unknown type accepted")
	}
	if _, err := UnwrapSlot("a", SlotSecurityKey, kdf, wrapped[1:], secret, cheap); err == nil || errors.Is(err, ErrWrongPassword) {
		t.Errorf("short wrap: %v", err)
	}
}

func TestSlotShortSecret(t *testing.T) {
	k := NewKeyring(cheap)
	if _, _, err := k.WrapSlot("a", SlotPasskey, []byte("short"), cheap); err == nil {
		t.Fatal("short secret wrapped")
	}
	if _, _, err := k.WrapSlot("a", SlotPassword, []byte("pw"), Params{}); err == nil {
		t.Fatal("invalid cost accepted")
	}
	k.Wipe()
	if _, _, err := k.WrapSlot("a", SlotPasskey, make([]byte, 32), cheap); !errors.Is(err, ErrLocked) {
		t.Fatalf("wiped: %v", err)
	}
}

func TestBackupCode(t *testing.T) {
	secret, code := NewBackupCode()
	if len(secret) != 16 || len(code) != 30 || strings.Count(code, "-") != 4 {
		t.Fatalf("%d %q", len(secret), code)
	}
	for _, typed := range []string{code, strings.ToLower(code), strings.ReplaceAll(code, "-", " "), strings.ReplaceAll(code, "-", "")} {
		got, err := ParseBackupCode(typed)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("%q: %v", typed, err)
		}
	}
	// Look-alike letters read as digits.
	plain := strings.ReplaceAll(code, "-", "")
	alike := strings.NewReplacer("1", "l", "0", "O").Replace(plain)
	if got, err := ParseBackupCode(alike); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("look-alikes %q: %v", alike, err)
	}
	for _, bad := range []string{"", "ABC", plain[:20], plain + "AAAA", "UUUUU-UUUUU-UUUUU-UUUUU-UUUUUU"} {
		if _, err := ParseBackupCode(bad); !errors.Is(err, ErrWrongPassword) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestParseHKDF(t *testing.T) {
	salt := []byte("0123456789abcdef")
	got, err := ParseHKDF(FormatHKDF(salt))
	if err != nil || !bytes.Equal(got, salt) {
		t.Fatal(got, err)
	}
	for _, s := range []string{"", "hkdf-sha256$", "hkdf-sha256$!!", "hkdf-sha1$AAAAAAAAAAA", FormatHKDF([]byte("short"))} {
		if _, err := ParseHKDF(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestCost(t *testing.T) {
	p, err := ParseCost(FormatCost(Default))
	if err != nil || p != Default {
		t.Fatal(p, err)
	}
	if _, err := ParseCost("argon2id$v=19$m=1,t=1,p=1"); err == nil {
		t.Fatal("invalid cost accepted")
	}
	if _, err := ParseCost(""); err == nil {
		t.Fatal("empty cost accepted")
	}
}

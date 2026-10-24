package vault

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
)

var cheap = Params{MemoryKiB: 64, Time: 1, Threads: 1}

func TestWrapUnwrap(t *testing.T) {
	k := NewKeyring(cheap)
	kdf, dek, err := k.Wrap([]byte("pw"), cheap)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kdf, "argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("kdf %q", kdf)
	}
	k2, err := Unwrap(kdf, dek, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.dek, k2.dek) || k2.Params() != cheap {
		t.Fatal("unwrapped keyring differs")
	}
	if _, err := Unwrap(kdf, dek, []byte("wrong")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	// The parameters are bound to the wrapped DEK.
	tampered := strings.Replace(kdf, "t=1", "t=2", 1)
	if _, err := Unwrap(tampered, dek, []byte("pw")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("tampered kdf: %v", err)
	}
}

func TestParseKDFLimits(t *testing.T) {
	for _, s := range []string{
		"argon2id$v=19$m=2097152,t=3,p=4$c2FsdHNhbHRzYWx0", // 2 GiB
		"argon2id$v=19$m=65536,t=0,p=4$c2FsdHNhbHRzYWx0",
		"argon2id$v=19$m=65536,t=3,p=0$c2FsdHNhbHRzYWx0",
		"argon2id$v=19$m=65536,t=99,p=4$c2FsdHNhbHRzYWx0",
		"argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0",
		"argon2id$v=19$m=65536,t=3,p=4$",
		"",
	} {
		if _, _, err := ParseKDF(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	p, salt, err := ParseKDF("argon2id$v=19$m=262144,t=3,p=4$c2FsdHNhbHRzYWx0")
	if err != nil || p != Default || string(salt) != "saltsaltsalt" {
		t.Fatalf("%+v %q %v", p, salt, err)
	}
}

func TestSealOpen(t *testing.T) {
	k := NewKeyring(cheap)
	priv, spki := []byte("pkcs8 der"), []byte("spki der")
	blob, err := k.Seal(priv, spki)
	if err != nil {
		t.Fatal(err)
	}
	if !IsSealed(blob) || Mode(blob) != ModeDEK {
		t.Fatal("not recognised")
	}
	got, err := k.Open(blob, spki)
	if err != nil || !bytes.Equal(got, priv) {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := k.Open(blob, []byte("other key")); err == nil {
		t.Fatal("opened under another public key")
	}
	blob[len(blob)-1] ^= 1
	if _, err := k.Open(blob, spki); err == nil {
		t.Fatal("opened a modified blob")
	}
	if _, err := NewKeyring(cheap).Open(blob, spki); err == nil {
		t.Fatal("opened with another DEK")
	}
	k.Wipe()
	if _, err := k.Seal(priv, spki); !errors.Is(err, ErrLocked) {
		t.Fatalf("after wipe: %v", err)
	}
}

func TestClone(t *testing.T) {
	k := NewKeyring(cheap)
	c := k.Clone()
	k.Wipe()
	if _, err := c.Seal([]byte("x"), nil); err != nil {
		t.Fatal("clone wiped with the original")
	}
}

func TestPasswordSeal(t *testing.T) {
	priv, spki := []byte("pkcs8 der"), []byte("spki der")
	blob, err := SealWithPassword(priv, spki, []byte("own"), cheap)
	if err != nil {
		t.Fatal(err)
	}
	if Mode(blob) != ModePassword {
		t.Fatal("mode")
	}
	got, err := OpenWithPassword(blob, spki, []byte("own"))
	if err != nil || !bytes.Equal(got, priv) {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := OpenWithPassword(blob, spki, []byte("bad")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := NewKeyring(cheap).Open(blob, spki); err == nil {
		t.Fatal("DEK opened a password blob")
	}
	// Parameters inside the blob are limited like those of the kdf setting.
	huge := append([]byte(nil), blob...)
	huge[5+16] = 0xff
	if _, err := OpenWithPassword(huge, spki, []byte("own")); err == nil || errors.Is(err, ErrWrongPassword) {
		t.Fatalf("huge memory parameter: %v", err)
	}
}

func TestNotSealed(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("GCK"), []byte("GCK\x01\x09xx"), {0x30, 0x82, 0x01, 0x00}} {
		if IsSealed(b) {
			t.Errorf("%q recognised", b)
		}
	}
}

func TestConcurrentDerive(t *testing.T) {
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := derive([]byte("pw"), []byte("saltsaltsaltsalt"), cheap); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

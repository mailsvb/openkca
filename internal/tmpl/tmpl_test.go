package tmpl

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// qs encodes s as a QDataStream QString.
func qs(s string) []byte {
	var b bytes.Buffer
	u := []rune(s)
	enc := make([]byte, 0, 2*len(u))
	for _, r := range u {
		enc = append(enc, byte(r>>8), byte(r))
	}
	n := uint32(len(enc))
	b.Write([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	b.Write(enc)
	return b.Bytes()
}

func TestDecodeV10(t *testing.T) {
	blob := []byte{0x30, 0x00, 0, 0, 0, 2}
	blob = append(blob, qs("validN")...)
	blob = append(blob, qs("365")...)
	blob = append(blob, qs("keyUseCritical")...)
	blob = append(blob, qs("1")...)
	tp, err := Decode(blob, 10)
	if err != nil {
		t.Fatal(err)
	}
	if tp.Settings["validN"] != "365" || tp.Settings["kuCritical"] != "1" || len(tp.Settings) != 2 {
		t.Fatalf("settings %v", tp.Settings)
	}
}

func TestDecodeFixtureBlob(t *testing.T) {
	// templates.template of the CA template in testdata/xdb/sample.xdb
	data, err := os.ReadFile("testdata/ca-template.b64")
	if err != nil {
		t.Skip(err)
	}
	blob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	tp, err := Decode(blob, 10)
	if err != nil {
		t.Fatal(err)
	}
	if tp.Settings["ca"] != "1" || tp.Settings["validN"] == "" {
		t.Fatalf("settings %v", tp.Settings)
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	data, _ := os.ReadFile("testdata/ca-template.b64")
	blob, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	tp, err := Decode(blob, 10)
	if err != nil {
		t.Fatal(err)
	}
	// XCA's own blob is reproduced byte for byte
	if !bytes.Equal(Encode(tp), blob) {
		t.Fatal("Encode differs from XCA's encoding")
	}
	spec := tp.Spec()
	if spec.CA != 1 || !spec.BCCritical || spec.KeyUse != 96 || spec.NSCertType != 112 || !spec.SubKey || spec.AuthKey {
		t.Fatalf("spec %+v", spec)
	}
	n := New(tp.Subject, spec, tp.Validity())
	back, err := Decode(Encode(n), 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ca", "bcCritical", "keyUse", "nsCertType", "validN", "validM", "subKey", "nsComment"} {
		if back.Settings[k] != tp.Settings[k] {
			t.Errorf("%s: %q, XCA %q", k, back.Settings[k], tp.Settings[k])
		}
	}
	if n, u := ValidityFromDates(3650); n != 10 || u != 2 {
		t.Fatalf("validity %d %d", n, u)
	}
}

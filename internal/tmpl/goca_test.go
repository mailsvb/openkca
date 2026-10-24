package tmpl

import (
	"testing"

	"github.com/mailsvb/openkca/internal/pki"
)

// TestGoCAKeys: the CDP/AIA flags round-trip through go-ca's settings but
// are left out of XCA's export form.
func TestGoCAKeys(t *testing.T) {
	tp := New(nil, pki.ExtSpec{PubCDP: true}, Validity{N: 1, Unit: 2})
	if spec := tp.Spec(); !spec.PubCDP || spec.PubAIA {
		t.Fatalf("flags %v %v", spec.PubCDP, spec.PubAIA)
	}
	back, err := Decode(Encode(tp), Version)
	if err != nil {
		t.Fatal(err)
	}
	for k := range back.Settings {
		if IsGoCAKey(k) {
			t.Fatalf("XCA form carries %s", k)
		}
	}
	if back.Spec().PubCDP {
		t.Fatal("flag survived the XCA form")
	}
}

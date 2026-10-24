package web

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/mailsvb/go-ca/internal/pki"
)

type keyChoice struct{ Value, Label string }

// keyGroup is a family of key types in the selection for new keys.
type keyGroup struct {
	Label   string // message key
	Choices []keyChoice
}

// keyGroups are the key types offered when generating a key, as
// "type:argument" values parseKeyChoice reads.
var keyGroups = func() []keyGroup {
	var rsa, pss, ec, mldsa, slhdsa, comp, mlkem, compKEM []keyChoice
	for _, b := range pki.RSASizes {
		rsa = append(rsa, keyChoice{fmt.Sprintf("RSA:%d", b), fmt.Sprintf("RSA %d", b)})
		pss = append(pss, keyChoice{fmt.Sprintf("RSA-PSS:%d", b), fmt.Sprintf("RSA-PSS %d", b)})
	}
	for _, c := range pki.ECCurves {
		ec = append(ec, keyChoice{"EC:" + c.Name, "ECDSA " + c.Name})
	}
	for _, p := range pki.MLDSAParamSets {
		mldsa = append(mldsa, keyChoice{"ML-DSA:" + p.Name, p.Name})
	}
	for _, p := range pki.SLHDSAParamSets {
		slhdsa = append(slhdsa, keyChoice{"SLH-DSA:" + p.Name, p.Name})
	}
	for _, a := range pki.CompositeAlgs {
		comp = append(comp, keyChoice{"Composite:" + a.Name, a.Name})
	}
	for _, p := range pki.MLKEMParamSets {
		mlkem = append(mlkem, keyChoice{"ML-KEM:" + p.Name, p.Name})
	}
	for _, a := range pki.CompositeKEMAlgs {
		compKEM = append(compKEM, keyChoice{"CompositeKEM:" + a.Name, a.Name})
	}
	return []keyGroup{
		{"newkey.group.rsa", rsa},
		{"newkey.group.rsapss", pss},
		{"newkey.group.ec", ec},
		{"newkey.group.edwards", []keyChoice{{"Ed25519", "Ed25519"}, {"Ed448", "Ed448"}}},
		{"newkey.group.mldsa", mldsa},
		{"newkey.group.slhdsa", slhdsa},
		{"newkey.group.composite", comp},
		{"newkey.group.ecdh", []keyChoice{{"X25519", "X25519"}, {"X448", "X448"}}},
		{"newkey.group.mlkem", mlkem},
		{"newkey.group.compositekem", compKEM},
	}
}()

// offeredKey reports whether a value is one of keyGroups.
func offeredKey(v string) bool {
	for _, g := range keyGroups {
		if slices.ContainsFunc(g.Choices, func(c keyChoice) bool { return c.Value == v }) {
			return true
		}
	}
	return false
}

// parseKeyChoice reads a key choice ("RSA:2048", "EC:P-256", "Ed25519",
// "ML-DSA:ML-DSA-65", "Composite:MLDSA65-Ed25519-SHA512", ...).
func parseKeyChoice(s string) (*pki.KeySpec, error) {
	typ, arg, _ := strings.Cut(s, ":")
	switch typ {
	case "RSA", "RSA-PSS":
		bits, err := strconv.Atoi(arg)
		if err != nil {
			return nil, err
		}
		return &pki.KeySpec{Type: typ, Bits: bits}, nil
	case "EC":
		return &pki.KeySpec{Type: "EC", Curve: arg}, nil
	case "Ed25519", "Ed448", "X25519", "X448":
		if arg == "" {
			return &pki.KeySpec{Type: typ}, nil
		}
	case "ML-DSA", "SLH-DSA", "ML-KEM", "Composite", "CompositeKEM":
		if arg != "" {
			return &pki.KeySpec{Type: typ, Param: arg}, nil
		}
	}
	return nil, fmt.Errorf("unknown key type %q", s)
}

// recommendedKey is one of the key types the picker offers first.
type recommendedKey struct {
	Value, Label string
	Note, Works  string // message keys
}

var recommendedKeys = []recommendedKey{
	{"EC:P-256", "ECDSA P-256", "keypick.note.p256", "keypick.works.p256"},
	{"Ed25519", "Ed25519", "keypick.note.ed25519", "keypick.works.ed25519"},
	{"RSA:3072", "RSA 3072", "keypick.note.rsa3072", "keypick.works.rsa3072"},
}

// pickerGroup is a folded family of further key types.
type pickerGroup struct {
	Label   string // message key
	Expert  bool   // shown with expert fields only
	Draft   bool   // encoding from an Internet-Draft, may change
	Open    bool   // holds the selected type
	Summary string
	Choices []keyChoice
}

// keyPicker is the data of the "keypicker" template: the recommended key
// types, then the other families. Families for experts (post-quantum,
// RSA-PSS, key agreement only) are left out unless expert fields are on
// or they hold the selected type.
type keyPicker struct {
	Name, Value string // form field and selected value
	DB          string // database name, for the options link
	Expert      bool
	Recommended []recommendedKey
	Groups      []pickerGroup
	Hidden      int // key types left out
}

var expertGroups = map[string]bool{"newkey.group.rsapss": true, "newkey.group.mldsa": true, "newkey.group.slhdsa": true,
	"newkey.group.composite": true, "newkey.group.ecdh": true, "newkey.group.mlkem": true, "newkey.group.compositekem": true}

var draftGroups = map[string]bool{"newkey.group.composite": true, "newkey.group.compositekem": true}

func newKeyPicker(name, value, db string, expert bool) keyPicker {
	kp := keyPicker{Name: name, Value: value, DB: db, Expert: expert, Recommended: recommendedKeys}
	recommended := func(v string) bool {
		return slices.ContainsFunc(recommendedKeys, func(r recommendedKey) bool { return r.Value == v })
	}
	for _, g := range keyGroups {
		pg := pickerGroup{Label: g.Label, Expert: expertGroups[g.Label], Draft: draftGroups[g.Label]}
		var labels []string
		for _, c := range g.Choices {
			if recommended(c.Value) {
				continue
			}
			pg.Choices = append(pg.Choices, c)
			labels = append(labels, c.Label)
			pg.Open = pg.Open || c.Value == value
		}
		if len(pg.Choices) == 0 {
			continue
		}
		if pg.Expert && !expert && !pg.Open {
			kp.Hidden += len(pg.Choices)
			continue
		}
		labels = trimCommonWord(labels)
		if len(labels) > 6 {
			labels = append(labels[:5], "…")
		}
		pg.Summary = strings.Join(labels, " · ")
		kp.Groups = append(kp.Groups, pg)
	}
	return kp
}

// trimCommonWord drops a first word all labels share ("ECDSA P-384",
// "ECDSA P-521" → "P-384", "P-521").
func trimCommonWord(labels []string) []string {
	if len(labels) < 2 {
		return labels
	}
	first, _, ok := strings.Cut(labels[0], " ")
	if !ok {
		return labels
	}
	out := make([]string, len(labels))
	for i, l := range labels {
		rest, found := strings.CutPrefix(l, first+" ")
		if !found {
			return labels
		}
		out[i] = rest
	}
	return out
}

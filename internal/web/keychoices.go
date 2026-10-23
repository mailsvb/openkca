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

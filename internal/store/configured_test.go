package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// moveDB creates a database and moves it into a subfolder of the data
// folder, returning its new path.
func moveDB(t *testing.T, s *Store, name, sub string) string {
	t.Helper()
	if err := s.Create(context.Background(), name, testPassword, testKDF); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.Dir, sub)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name+ExtOKCA)
	if err := os.Rename(filepath.Join(s.Dir, name+ExtOKCA), p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfigure(t *testing.T) {
	ctx := context.Background()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"zeta", "alpha"} {
		if err := s.Create(ctx, n, testPassword, testKDF); err != nil {
			t.Fatal(err)
		}
	}
	sub := moveDB(t, s, "lab", "cas")
	names, err := s.Configure(ctx, []Configured{
		{Label: "Home Lab CA", Path: sub, Background: true},
		{Label: "Zeta", Path: filepath.Join(s.Dir, "zeta.okca")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "lab,zeta" {
		t.Fatalf("names = %v", names)
	}
	infos, err := s.Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, i := range infos {
		got = append(got, i.Name+"="+i.Label)
	}
	// configured first in their order, then the rest of the folder
	if strings.Join(got, ",") != "lab=Home Lab CA,zeta=Zeta,alpha=alpha" {
		t.Fatalf("scan = %v", got)
	}
	if !infos[0].Configured || !infos[0].Background || !infos[1].Configured || infos[1].Background || infos[2].Configured {
		t.Fatalf("flags = %+v", infos)
	}
	// the database in the subfolder opens by its name
	h, err := s.Acquire(ctx, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Unlock(ctx, testPassword); err != nil {
		t.Fatal(err)
	}
	h.Release()
	// its name is taken for new databases
	if err := s.Create(ctx, "LAB", testPassword, testKDF); !errors.Is(err, ErrExists) {
		t.Fatalf("create lab: %v", err)
	}
	c, ok := s.ConfiguredDB("lab")
	if !ok || c.Label != "Home Lab CA" || !c.Background {
		t.Fatalf("ConfiguredDB = %+v %v", c, ok)
	}
}

func TestConfigureUploadAvoidsConfiguredName(t *testing.T) {
	ctx := context.Background()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sub := moveDB(t, s, "lab", "cas")
	src, err := os.ReadFile(sub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Configure(ctx, []Configured{{Label: "Lab", Path: sub}}); err != nil {
		t.Fatal(err)
	}
	name, err := s.Upload(ctx, "lab.okca", strings.NewReader(string(src)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if name != "lab-1" {
		t.Fatalf("upload name = %q", name)
	}
}

func TestConfigureErrors(t *testing.T) {
	ctx := context.Background()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, "top", testPassword, testKDF); err != nil {
		t.Fatal(err)
	}
	sub := moveDB(t, s, "lab", "cas")
	os.WriteFile(filepath.Join(s.Dir, "junk.okca"), []byte("not a database"), 0o600)
	clash := moveDB(t, s, "dup", "x")
	if err := s.Create(ctx, "dup", testPassword, testKDF); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		c    []Configured
		want string
	}{
		{[]Configured{{Label: "A", Path: filepath.Join(filepath.Dir(s.Dir), "out.okca")}}, "not inside"},
		{[]Configured{{Label: "A", Path: filepath.Join(s.Dir, "bad name.okca")}}, "not a valid"},
		{[]Configured{{Label: "A", Path: sub}, {Label: "B", Path: filepath.Join(s.Dir, "LAB.okca")}}, "used twice"},
		{[]Configured{{Label: "A", Path: clash}}, "same name"},
		{[]Configured{{Label: "A", Path: filepath.Join(s.Dir, "missing.okca")}}, "no such file"},
		{[]Configured{{Label: "A", Path: filepath.Join(s.Dir, "junk.okca")}}, "cannot be opened"},
	} {
		_, err := s.Configure(ctx, tc.c)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: err = %v, want %q", tc.c, err, tc.want)
		}
	}
	// a failed Configure leaves nothing configured
	if s.isConfigured("lab") || s.isConfigured("top") {
		t.Fatal("configuration kept after error")
	}
}

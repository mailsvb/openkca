package store

import (
	"archive/zip"
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mailsvb/openkca/internal/codec"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/vault"
)

func pgpParams(version int) codec.PGPParams {
	return codec.PGPParams{Version: version, UIDs: []string{"Alice <alice@example.org>"}, Lifetime: 2 * 365 * 24 * time.Hour}
}

func formatIDs(fs []codec.Format) []int {
	var ids []int
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	return ids
}

func TestPGPGenerateExportImport(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	pw := testPassword
	for _, name := range []string{"pgpa", "pgpb"} {
		if err := s.Create(ctx, name, pw, vault.Default); err != nil {
			t.Fatal(err)
		}
	}
	h, _ := load(t, s, "pgpa")
	for _, version := range []int{4, 6} {
		id, err := h.GeneratePGPKey(ctx, "alice", "", pki.KeySpec{Type: "Ed25519"},
			[]PGPSubkey{{Spec: &pki.KeySpec{Type: "X25519"}, Name: "alice encryption", Usage: codec.PGPEncrypt}}, pgpParams(version), krOf(t, h))
		if err != nil {
			t.Fatal(err)
		}
		snap, _ := h.Snapshot(ctx)
		v := PGPOf(snap, id)
		if v == nil || len(v.KeyIDs) != 2 || v.KeyIDs[1] == 0 || v.Info.Version != version {
			t.Fatalf("v%d: view %+v", version, v)
		}
		sub := findKey(snap, v.KeyIDs[1])
		if sub.Name != "alice encryption" || sub.KeyType != "X25519" || !sub.HasPrivate {
			t.Fatalf("v%d: subkey %+v", version, sub)
		}
		if w := PGPSubkeyOf(snap, sub.ID); w == nil || w.Primary() != id {
			t.Fatalf("v%d: subkey's certificate not found", version)
		}
		// the subkey has no OpenPGP formats of its own; the primary key all
		if got := formatIDs(ExportFormats(snap, []int64{sub.ID})); slices.Contains(got, 110) {
			t.Errorf("v%d: subkey formats %v", version, got)
		}
		got := formatIDs(ExportFormats(snap, []int64{id}))
		for _, f := range []int{110, 111, 112, 113, 114} {
			if !slices.Contains(got, f) {
				t.Errorf("v%d: format %d missing in %v", version, f, got)
			}
		}
		pub, err := h.Export(ctx, ExportRequest{Format: 110, IDs: []int64{id}, Keyring: krOf(t, h)})
		if err != nil || !pub.Text || !bytes.Contains(pub.Data, []byte("BEGIN PGP PUBLIC KEY BLOCK")) {
			t.Fatalf("v%d: public export %v %+v", version, err, pub)
		}
		if ents, _, _, _ := codec.ReadPGP(pub.Data, nil); len(ents) != 1 || !bytes.Equal(ents[0].Cert, v.Cert.Cert) {
			t.Fatalf("v%d: public export does not read back", version)
		}
		if _, err := h.Export(ctx, ExportRequest{Format: 113, IDs: []int64{id}, Keyring: krOf(t, h)}); err != ErrNeedExportPassword {
			t.Fatalf("v%d: encrypted export without password: %v", version, err)
		}
		sec, err := h.Export(ctx, ExportRequest{Format: 113, IDs: []int64{id}, Keyring: krOf(t, h), Password: []byte("export")})
		if err != nil {
			t.Fatal(err)
		}

		// import into the second database
		res := codec.Probe(sec.Filename, sec.Data, codec.ProbeOptions{Password: []byte("export")})
		if len(res.Objects) != 2 || res.Objects[0].PGP == nil || res.Objects[1].Private == nil {
			t.Fatalf("v%d: probe %+v", version, res)
		}
		h2, _ := load(t, s, "pgpb")
		plans, err := h2.PlanImport(ctx, res.Objects)
		if err != nil {
			t.Fatal(err)
		}
		results, err := h2.Import(ctx, plans, []int{0, 1}, krOf(t, h2), nil)
		if err != nil {
			t.Fatal(err)
		}
		snap2, _ := h2.Snapshot(ctx)
		v2 := PGPOf(snap2, results[0].ID)
		if v2 == nil || v2.KeyIDs[1] == 0 || v2.Info.Keys[0].Fingerprint != v.Info.Keys[0].Fingerprint {
			t.Fatalf("v%d: imported view %+v", version, v2)
		}
		if res.Objects[0].Name != "Alice <alice@example.org>" || res.Objects[1].Name != "Alice <alice@example.org> [E]" {
			t.Errorf("v%d: names %q %q", version, res.Objects[0].Name, res.Objects[1].Name)
		}
		// a second import changes nothing
		plans, _ = h2.PlanImport(ctx, res.Objects)
		if plans[0].Action != ImportExists || plans[1].Action != ImportExists {
			t.Fatalf("v%d: re-import actions %s %s", version, plans[0].Action, plans[1].Action)
		}
		// the bundle
		zr, err := h.PGPBundle(ctx, ExportRequest{IDs: []int64{id}, Keyring: krOf(t, h), Password: []byte("export")})
		if err != nil {
			t.Fatal(err)
		}
		r, err := zip.NewReader(bytes.NewReader(zr.Data), int64(len(zr.Data)))
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, f := range r.File {
			names = append(names, f.Name)
		}
		if strings.Join(names, " ") != "alice.asc alice.secret.asc alice.rev.asc" || zr.Filename != "alice.pgp.zip" {
			t.Fatalf("v%d: bundle %s %v", version, zr.Filename, names)
		}
		// deleting the primary key removes its certificate, not the subkey
		if err := h.Delete(ctx, id); err != nil {
			t.Fatal(err)
		}
		snap, _ = h.Snapshot(ctx)
		if PGPOf(snap, id) != nil || len(snap.PGP) != 0 || findKey(snap, sub.ID) == nil {
			t.Fatalf("v%d: after delete %d certificates", version, len(snap.PGP))
		}
		if err := h2.DeletePGP(ctx, results[0].ID); err != nil {
			t.Fatal(err)
		}
	}
}

// An SSH key becomes an OpenPGP key; another SSH key is added as its
// authentication subkey; importing the certificate later attaches it to
// the stored keys.
func TestPGPFromExistingKeys(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	pw := testPassword
	if err := s.Create(ctx, "pgpc", pw, vault.Default); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "pgpc")
	id, err := h.GenerateKey(ctx, "laptop", "user@laptop", pki.KeySpec{Type: "EC", Curve: "P-256"}, krOf(t, h))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := h.GenerateKey(ctx, "ssh", "", pki.KeySpec{Type: "Ed25519"}, krOf(t, h))
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := h.Snapshot(ctx)
	if got := formatIDs(ExportFormats(snap, []int64{id})); slices.Contains(got, 110) {
		t.Fatalf("PGP formats without a certificate: %v", got)
	}
	err = h.CreatePGP(ctx, id, []PGPSubkey{{Spec: &pki.KeySpec{Type: "EC", Curve: "P-256"}, Name: "laptop encryption", Usage: codec.PGPEncrypt}},
		pgpParams(4), krOf(t, h), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.CreatePGP(ctx, id, nil, pgpParams(4), krOf(t, h), nil); err == nil {
		t.Fatal("second certificate for the same key")
	}
	if err := h.AddPGPSubkey(ctx, id, PGPSubkey{KeyID: auth, Usage: codec.PGPAuth}, krOf(t, h), nil); err != nil {
		t.Fatal(err)
	}
	if err := h.AddPGPSubkey(ctx, id, PGPSubkey{KeyID: id, Usage: codec.PGPAuth}, krOf(t, h), nil); err == nil {
		t.Fatal("primary key added as its own subkey")
	}
	snap, _ = h.Snapshot(ctx)
	v := PGPOf(snap, id)
	if v == nil || len(v.KeyIDs) != 3 || v.KeyIDs[2] != auth || v.Info.Keys[2].Usage != "A" || v.Info.Keys[1].Usage != "E" {
		t.Fatalf("view %+v", v)
	}
	if !v.Info.Keys[2].Expires.Equal(v.Info.Keys[0].Expires) {
		t.Errorf("subkey expires %v, primary %v", v.Info.Keys[2].Expires, v.Info.Keys[0].Expires)
	}
	pub, err := h.Export(ctx, ExportRequest{Format: 111, IDs: []int64{id}, Keyring: krOf(t, h)})
	if err != nil || pub.Text || pub.ContentType != "application/octet-stream" {
		t.Fatalf("binary export %v %+v", err, pub)
	}
	// without the certificate, importing it again restores it
	if err := h.DeletePGP(ctx, id); err != nil {
		t.Fatal(err)
	}
	res := codec.Probe("laptop.gpg", pub.Data, codec.ProbeOptions{})
	plans, err := h.PlanImport(ctx, res.Objects)
	if err != nil || len(plans) != 3 || plans[0].Action != ImportPGP || plans[2].Action != ImportExists {
		t.Fatalf("plans %v %+v", err, plans)
	}
	if _, err := h.Import(ctx, plans, []int{0}, krOf(t, h), nil); err != nil {
		t.Fatal(err)
	}
	snap, _ = h.Snapshot(ctx)
	if w := PGPOf(snap, id); w == nil || !bytes.Equal(w.Cert.Cert, v.Cert.Cert) {
		t.Fatal("certificate not restored")
	}
	// a revocation certificate signed by the primary key
	rev, err := h.Export(ctx, ExportRequest{Format: 114, IDs: []int64{id}, Keyring: krOf(t, h)})
	if err != nil || !bytes.Contains(rev.Data, []byte("BEGIN PGP PUBLIC KEY BLOCK")) {
		t.Fatalf("revocation %v", err)
	}
	// the dump holds the armored certificate
	var dump bytes.Buffer
	if err := h.Dump(ctx, &dump, krOf(t, h), []byte("export")); err != nil {
		t.Fatal(err)
	}
	zr, _ := zip.NewReader(bytes.NewReader(dump.Bytes()), int64(dump.Len()))
	found := false
	for _, f := range zr.File {
		found = found || f.Name == "pgpc/keys/laptop.asc"
	}
	if !found {
		t.Fatal("certificate missing in the dump")
	}
}

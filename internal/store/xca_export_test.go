package store

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestExportForXCA writes every export format of a small hierarchy to
// $GOCA_XCA_DIR/export for XCA to import (testdata/gen/check-export-with-xca.sh).
func TestExportForXCA(t *testing.T) {
	dir := os.Getenv("GOCA_XCA_DIR")
	if dir == "" {
		t.Skip("GOCA_XCA_DIR not set")
	}
	s := copyFixtures(t)
	ctx := context.Background()
	pw := []byte("pw")
	p := buildSet(t, s, "xport", pw)
	snap, _ := p.h.Snapshot(ctx)
	out := dir + "/export"
	os.MkdirAll(out, 0o755)
	for _, id := range []int64{p.root, p.sub, p.leaf, p.edLeaf, p.req, p.crl, p.leafKey, p.edKey, p.tmpl, p.pubK} {
		for _, f := range ExportFormats(snap, []int64{id}) {
			res, err := p.h.Export(ctx, ExportRequest{Format: f.ID, IDs: []int64{id}, Password: []byte("export"), PEMComment: true, DBPass: pw})
			if err != nil {
				t.Fatal(err)
			}
			name := strings.TrimSuffix(res.Filename, "."+f.Ext) + "-" + strconv.Itoa(f.ID) + "." + f.Ext
			if err := os.WriteFile(out+"/"+name, res.Data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, algo := range []string{"AES-256-CBC", "PBE-SHA1-RC2-40"} {
		p.h.SetSettings(ctx, map[string]string{"pkcs12_enc_algo": algo})
		res, err := p.h.Export(ctx, ExportRequest{Format: 14, IDs: []int64{p.leaf}, Password: []byte("export"), DBPass: pw})
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(out+"/p12-"+algo+".pfx", res.Data, 0o644)
	}
}

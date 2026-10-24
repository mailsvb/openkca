package xcaimport

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/vault"
)

const fixtures = "../../testdata/xdb"

var cheap = vault.Params{MemoryKiB: 64, Time: 1, Threads: 1}

func openDst(t *testing.T) *sql.DB {
	t.Helper()
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "dst.gca")+"?"+q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestInspect(t *testing.T) {
	ctx := context.Background()
	for name, want := range map[string]Kind{"sample": KindXCA, "schema8": KindXCA, "md5": KindXCA, "variants": KindXCA,
		"legacy": KindLegacy, "newer": KindNewer} {
		info, err := Inspect(ctx, filepath.Join(fixtures, name+".xdb"), true)
		if err != nil || info.Kind != want {
			t.Errorf("%s: %+v %v", name, info, err)
		}
	}
	if _, err := Inspect(ctx, filepath.Join(fixtures, "garbage.xdb"), true); err == nil {
		t.Error("garbage accepted")
	}
}

func TestImportFixtures(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"sample", "schema8", "md5", "variants"} {
		src, err := Open(ctx, filepath.Join(fixtures, name+".xdb"))
		if err != nil {
			t.Fatal(err)
		}
		if ok, _, _ := src.Unlock(ctx, []byte("wrong")); ok {
			t.Fatalf("%s: wrong password accepted", name)
		}
		ok, kr, err := src.Unlock(ctx, []byte("secret"))
		if !ok || err != nil || kr != nil {
			t.Fatalf("%s: unlock %v %v", name, ok, err)
		}
		dst := openDst(t)
		kr, rep, err := src.Import(ctx, dst, []byte("secret"), nil, cheap, nil, nil)
		src.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(rep.Skipped) > 0 || rep.Items == 0 {
			t.Fatalf("%s: report %+v", name, rep)
		}
		db, err := gcadb.Open(ctx, dst)
		if err != nil {
			t.Fatal(err)
		}
		snap, err := db.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(snap.Keys) + len(snap.Certs) + len(snap.Requests) + len(snap.CRLs) + len(snap.Templates); n != rep.Items {
			t.Errorf("%s: %d items loaded, %d written", name, n, rep.Items)
		}
		if _, ok := snap.Settings["pwhash"]; ok || snap.Settings["kdf"] == "" {
			t.Errorf("%s: settings %v", name, snap.Settings)
		}
		var fk int
		dst.QueryRow("SELECT COUNT(*) FROM pragma_foreign_key_check").Scan(&fk)
		if fk != 0 {
			t.Errorf("%s: %d foreign key violations", name, fk)
		}
		// links survive
		for _, c := range snap.Certs {
			if c.KeyID == 0 || c.IssuerID == 0 {
				t.Errorf("%s/%s: key %d, issuer %d", name, c.Name, c.KeyID, c.IssuerID)
			}
		}
		for _, k := range snap.Keys {
			if !k.HasPrivate {
				continue
			}
			if k.Protection == gcadb.ProtPassword {
				if !k.Legacy {
					t.Errorf("%s/%s: own-password key not marked legacy", name, k.Name)
				}
				continue
			}
			sk, err := db.StoredPrivateKey(ctx, k.ID)
			if err != nil {
				t.Fatal(err)
			}
			der, err := kr.Open(sk.Blob, sk.Public)
			if err != nil {
				t.Errorf("%s/%s: %v", name, k.Name, err)
				continue
			}
			priv, err := pki.ParsePKCS8(der)
			if err != nil {
				t.Errorf("%s/%s: %v", name, k.Name, err)
				continue
			}
			if ok, _ := pki.MatchesPublic(priv, k.Public); !ok {
				t.Errorf("%s/%s: mismatch", name, k.Name)
			}
		}
		if len(snap.Templates) == 0 || snap.Templates[0].Data == nil {
			t.Errorf("%s: templates %v", name, snap.Templates)
		}
		log, _ := db.AuditLog(ctx, 0, 0, 10)
		if len(log) != 1 || log[0].Action != "database.import" {
			t.Errorf("%s: audit %+v", name, log)
		}
		if _, err := dst.Exec("DELETE FROM audit"); err == nil {
			t.Error("audit entries can be deleted")
		}
	}
}

func TestImportRefusesOld(t *testing.T) {
	if _, err := Open(context.Background(), filepath.Join(fixtures, "legacy.xdb")); err == nil {
		t.Fatal("legacy opened")
	}
	if _, err := Open(context.Background(), filepath.Join(fixtures, "nonexistent.xdb")); err == nil {
		t.Fatal("missing file opened")
	}
}

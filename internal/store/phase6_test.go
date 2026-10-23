package store

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/xdb"
)

type pkiSet struct {
	h                                   *Handle
	root, sub, leaf, edLeaf, req, crl   int64
	leafKey, edKey, rootKey, tmpl, pubK int64
}

func buildSet(t *testing.T, s *Store, name string, pw []byte) pkiSet {
	t.Helper()
	ctx := context.Background()
	if err := s.Create(ctx, name, pw); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, name)
	var p pkiSet
	p.h = h
	var err error
	must := func(id int64, err error) int64 {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	p.root = must(h.Issue(ctx, params("Root CA", 0), pw))
	p.sub = must(h.Issue(ctx, params("Sub CA", p.root), pw))
	lp := params("www.example.org", p.sub)
	lp.NewKey = &pki.KeySpec{Type: "RSA", Bits: 2048}
	lp.Ext = pki.ExtSpec{CA: 2, SubKey: true, AuthKey: true, KeyUse: 5, EKU: []string{"serverAuth"}, SubAltName: "DNS:copycn, IP:192.0.2.1"}
	p.leaf = must(h.Issue(ctx, lp, pw))
	ep := params("ed", p.sub)
	ep.NewKey = &pki.KeySpec{Type: "Ed25519"}
	ep.Ext = pki.ExtSpec{CA: 2}
	p.edLeaf = must(h.Issue(ctx, ep, pw))
	rp := params("request", 0)
	rp.Request = true
	p.req = must(h.Issue(ctx, rp, pw))
	if err = h.Revoke(ctx, p.edLeaf, Revocation{Reason: 1}); err != nil {
		t.Fatal(err)
	}
	snap, _ := h.Snapshot(ctx)
	p.crl = must(h.GenerateCRL(ctx, p.sub, DefaultCRLOptions(snap, findCert(snap, p.sub)), pw, nil))
	p.tmpl = must(h.TemplateFromItem(ctx, p.leaf))
	p.pubK = must(h.GenerateKey(ctx, "spare", pki.KeySpec{Type: "EC", Curve: "P-384"}, pw))
	snap, _ = h.Snapshot(ctx)
	p.leafKey = findCert(snap, p.leaf).KeyID
	p.edKey = findCert(snap, p.edLeaf).KeyID
	p.rootKey = findCert(snap, p.root).KeyID
	return p
}

func TestExportAllFormats(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	pw := []byte("pw")
	p := buildSet(t, s, "ex", pw)
	snap, _ := p.h.Snapshot(ctx)
	dir := t.TempDir()
	files := map[string][]byte{}
	for _, id := range []int64{p.root, p.sub, p.leaf, p.edLeaf, p.req, p.crl, p.leafKey, p.edKey, p.tmpl, p.pubK} {
		formats := ExportFormats(snap, []int64{id})
		if len(formats) == 0 {
			t.Fatalf("no formats for item %d", id)
		}
		for _, f := range formats {
			res, err := p.h.Export(ctx, ExportRequest{Format: f.ID, IDs: []int64{id}, Password: []byte("export"), PEMComment: true, DBPass: pw})
			if err != nil {
				t.Fatalf("item %d format %d (%s): %v", id, f.ID, f.Label, err)
			}
			if len(res.Data) == 0 && f.ID != 16 {
				t.Fatalf("item %d format %d: empty", id, f.ID)
			}
			key := strings.TrimSuffix(res.Filename, "."+f.Ext) + "-" + itoa(f.ID) + "." + f.Ext
			files[key] = res.Data
			os.WriteFile(filepath.Join(dir, key), res.Data, 0o600)
		}
	}
	// Multi selections
	for _, f := range ExportFormats(snap, []int64{p.leaf, p.edLeaf, p.sub}) {
		if f.Flags&codec.FSingle != 0 {
			t.Fatalf("single format %d offered for a selection", f.ID)
		}
		if _, err := p.h.Export(ctx, ExportRequest{Format: f.ID, IDs: []int64{p.leaf, p.edLeaf, p.sub}, DBPass: pw}); err != nil {
			t.Fatalf("multi format %d: %v", f.ID, err)
		}
	}
	// Formats that are not offered are refused
	if _, err := p.h.Export(ctx, ExportRequest{Format: 26, IDs: []int64{p.edKey}, DBPass: pw}); err == nil {
		t.Fatal("PVK of an Ed25519 key")
	}
	if _, err := p.h.Export(ctx, ExportRequest{Format: 15, IDs: []int64{p.leaf}, DBPass: pw}); err != ErrNeedExportPassword {
		t.Fatalf("PKCS#12 without password: %v", err)
	}

	// JWK
	var jwk map[string]any
	if err := json.Unmarshal(files["www.example.org-43.jwk"], &jwk); err != nil || jwk["kty"] != "RSA" || len(jwk["x5c"].([]any)) != 3 {
		t.Fatalf("jwk chain: %v %v", err, jwk)
	}
	// SSH
	if _, _, _, _, err := ssh.ParseAuthorizedKey(files["www.example.org-23.pub"]); err != nil {
		t.Fatalf("ssh public: %v", err)
	}
	if _, err := ssh.ParseRawPrivateKey(files["ed-22.priv"]); err != nil {
		t.Fatalf("ssh ed25519 private: %v", err)
	}
	if !bytes.Contains(files["www.example.org-17.ics"], []byte("BEGIN:VEVENT")) ||
		bytes.Count(files["Sub_CA-18.ics"], []byte("BEGIN:VEVENT")) != 3 { // CA, valid leaf, CRL
		t.Fatalf("vcalendar:\n%s", files["Sub_CA-18.ics"])
	}
	if n := strings.Count(string(files["Sub_CA-16.txt"]), "\n"); n != 2 {
		t.Fatalf("index: %d lines\n%s", n, files["Sub_CA-16.txt"])
	}
	if !bytes.Contains(files["www.example.org-4.ovpn"], []byte("<ca>")) || !bytes.Contains(files["www.example.org-4.ovpn"], []byte("<extra-certs>")) {
		t.Fatalf("ovpn:\n%s", files["www.example.org-4.ovpn"])
	}
	if !bytes.HasPrefix(files["www.example.org-1.crt"], []byte("XCA internal name: www.example.org\n")) {
		t.Fatalf("PEM comment:\n%s", files["www.example.org-1.crt"])
	}

	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("openssl", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	f := func(n string) string { return filepath.Join(dir, n) }
	if out := run("pkcs7", "-inform", "DER", "-in", f("www.example.org-12.p7b"), "-print_certs", "-noout"); strings.Count(out, "subject=") != 3 {
		t.Fatalf("pkcs7 chain:\n%s", out)
	}
	for _, algo := range codec.PKCS12Algorithms {
		p.h.SetSettings(ctx, map[string]string{"pkcs12_enc_algo": algo})
		res, err := p.h.Export(ctx, ExportRequest{Format: 14, IDs: []int64{p.leaf}, Password: []byte("export"), DBPass: pw})
		if err != nil {
			t.Fatal(err)
		}
		fn := f("p12-" + algo + ".pfx")
		os.WriteFile(fn, res.Data, 0o600)
		args := []string{"pkcs12", "-in", fn, "-passin", "pass:export", "-nodes"}
		if algo == "PBE-SHA1-RC2-40" {
			args = append(args, "-legacy")
		}
		if out := run(args...); strings.Count(out, "BEGIN CERTIFICATE") != 3 || !strings.Contains(out, "PRIVATE KEY") {
			t.Fatalf("pkcs12 %s:\n%s", algo, out)
		}
	}
	run("rsa", "-inform", "PVK", "-pvk-none", "-in", f("www.example.org-26.pvk"), "-check", "-noout")
	run("pkey", "-in", f("www.example.org-21.pem"), "-passin", "pass:export", "-noout")
	run("pkey", "-in", f("www.example.org-28.pk8"), "-passin", "pass:export", "-noout")
	run("pkey", "-inform", "DER", "-in", f("www.example.org-25.der"), "-noout")
	run("pkey", "-pubin", "-inform", "DER", "-in", f("www.example.org-24.der"), "-noout")
	run("crl", "-in", f("Sub_CA-32.crl"), "-noout")
	run("req", "-in", f("request-30.csr"), "-noout", "-verify")
	run("x509", "-inform", "DER", "-in", f("www.example.org-13.cer"), "-noout")
	// The OpenSSL config recreates the certificate's subject and extensions;
	// the result is compared parsed, as openssl's text output varies by version.
	run("req", "-new", "-x509", "-config", f("www.example.org-38.conf"), "-key", f("www.example.org-20.pem"), "-out", f("from-conf.pem"))
	pemData, _ := os.ReadFile(f("from-conf.pem"))
	blk, _ := pem.Decode(pemData)
	if blk == nil {
		t.Fatal("openssl req wrote no certificate")
	}
	got, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := x509.ParseCertificate(findCert(snap, p.leaf).DER)
	if !bytes.Equal(got.RawSubject, orig.RawSubject) {
		t.Fatalf("conf export: subject %q, want %q\n%s", got.Subject, orig.Subject, files["www.example.org-38.conf"])
	}
	if fmt.Sprint(got.DNSNames, got.IPAddresses, got.ExtKeyUsage, got.KeyUsage, got.BasicConstraintsValid, got.IsCA) !=
		fmt.Sprint(orig.DNSNames, orig.IPAddresses, orig.ExtKeyUsage, orig.KeyUsage, orig.BasicConstraintsValid, orig.IsCA) {
		t.Fatalf("conf export: extensions differ\n%s", files["www.example.org-38.conf"])
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestImportRoundTrip(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	pw := []byte("pw")
	p := buildSet(t, s, "src", pw)
	export := func(format int, ids ...int64) []byte {
		t.Helper()
		res, err := p.h.Export(ctx, ExportRequest{Format: format, IDs: ids, Password: []byte("export"), DBPass: pw, PEMComment: true})
		if err != nil {
			t.Fatalf("export %d: %v", format, err)
		}
		return res.Data
	}
	if err := s.Create(ctx, "dst", pw); err != nil {
		t.Fatal(err)
	}
	h, _ := load(t, s, "dst")
	importFile := func(name string, data []byte, password string) []ImportResult {
		t.Helper()
		r := codec.Probe(name, data, codec.ProbeOptions{Password: []byte(password)})
		if r.NeedPassword || len(r.Unrecognized) > 0 {
			t.Fatalf("%s: need password %v, unrecognized %v", name, r.NeedPassword, r.Unrecognized)
		}
		plans, err := h.PlanImport(ctx, r.Objects)
		if err != nil {
			t.Fatal(err)
		}
		sel := make([]int, len(plans))
		for i := range sel {
			sel[i] = i
		}
		res, err := h.Import(ctx, plans, sel, pw, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	// public key first, then the private part completes it
	importFile("spare.pem", export(19, p.leafKey), "")
	res := importFile("key.pk8", export(28, p.leafKey), "export")
	if len(res) != 1 || res[0].Action != ImportComplete {
		t.Fatalf("key completion: %+v", res)
	}
	// PKCS#12 with chain: certificate, key (exists now) and CA certificates
	res = importFile("leaf.pfx", export(14, p.leaf), "export")
	if len(res) != 4 {
		t.Fatalf("pkcs12: %+v", res)
	}
	importFile("edleaf.p7b", export(8, p.edLeaf), "")
	importFile("ed.priv", export(22, p.edKey), "")
	importFile("crl.der", export(33, p.crl), "")
	importFile("req.csr", export(30, p.req), "")
	importFile("tmpl.xca", export(35, p.tmpl), "")
	importFile("rsa.pvk", export(26, p.leafKey), "")
	importFile("root-key.pem", export(21, p.rootKey), "export")
	importFile("spare.pub", export(23, p.pubK), "")
	snap, _ := h.Snapshot(ctx)
	if len(snap.Certs) != 4 || len(snap.Keys) != 4 || len(snap.CRLs) != 1 || len(snap.Requests) != 1 || len(snap.Templates) != 1 {
		t.Fatalf("certs %d keys %d crls %d reqs %d templates %d", len(snap.Certs), len(snap.Keys), len(snap.CRLs), len(snap.Requests), len(snap.Templates))
	}
	var leaf, sub *xdb.Cert
	for _, c := range snap.Certs {
		switch c.Name {
		case "www.example.org":
			leaf = c
		case "Sub CA":
			sub = c
		}
	}
	if leaf == nil || sub == nil || leaf.IssuerID != sub.ID || leaf.KeyID == 0 {
		t.Fatalf("links: leaf %+v sub %+v", leaf, sub)
	}
	if snap.CRLs[0].IssuerID != sub.ID || len(snap.Revocations) != 1 {
		t.Fatalf("CRL import: issuer %d revocations %d", snap.CRLs[0].IssuerID, len(snap.Revocations))
	}
	if snap.Templates[0].Name != "www.example.org" {
		t.Fatalf("template name %q", snap.Templates[0].Name)
	}
	// keys are re-encrypted with the database password
	for _, k := range snap.Keys {
		if k.HasPrivate {
			if _, err := h.unlock(ctx, k.ID, k.KeyType, pw, nil); err != nil {
				t.Fatalf("key %s: %v", k.Name, err)
			}
		}
	}
	// importing the same files again changes nothing
	res = importFile("leaf.pfx", export(14, p.leaf), "export")
	for _, r := range res {
		if r.Action != ImportExists {
			t.Fatalf("duplicate import: %+v", res)
		}
	}
	// wrong password
	if r := codec.Probe("leaf.pfx", export(14, p.leaf), codec.ProbeOptions{Password: []byte("nope")}); !r.PasswordWrong {
		t.Fatal("wrong PKCS#12 password not reported")
	}
}

func TestDump(t *testing.T) {
	s := copyFixtures(t)
	ctx := context.Background()
	pw := []byte("pw")
	p := buildSet(t, s, "dump", pw)
	var buf bytes.Buffer
	if err := p.h.Dump(ctx, &buf, pw); err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, f := range z.File {
		names[f.Name] = true
	}
	for _, want := range []string{"dump/certificates/Root_CA.crt", "dump/certificates/www.example.org.crt", "dump/keys/www.example.org.pem",
		"dump/requests/request.csr", "dump/crls/Sub_CA.crl", "dump/templates/www.example.org.xca", "dump/keys/spare.pem"} {
		if !names[want] {
			t.Fatalf("%s missing in %v", want, names)
		}
	}
	// a key file decrypts with the database password
	for _, f := range z.File {
		if f.Name == "dump/keys/www.example.org.pem" {
			r, _ := f.Open()
			var b bytes.Buffer
			b.ReadFrom(r)
			res := codec.Probe(f.Name, b.Bytes(), codec.ProbeOptions{Password: pw})
			if len(res.Objects) != 1 || res.Objects[0].Private == nil {
				t.Fatalf("dumped key: %+v", res)
			}
		}
	}
}

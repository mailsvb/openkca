package web

import (
	"bytes"
	"errors"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/mailsvb/openkca/internal/codec"
	"github.com/mailsvb/openkca/internal/gcadb"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/store"
)

// sshKeyChoices are the key types offered for new SSH keys, the usual one
// first.
var sshKeyChoices = []keyChoice{
	{"Ed25519", "Ed25519"},
	{"EC:P-256", "ECDSA P-256"}, {"EC:P-384", "ECDSA P-384"}, {"EC:P-521", "ECDSA P-521"},
	{"RSA:3072", "RSA 3072"}, {"RSA:4096", "RSA 4096"},
}

// sshFlavors are the key pair downloads of store.SSHPair.
var sshFlavors = []string{"openssh", "putty", "putty2"}

func (s *Server) newSSHKeyPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "newsshkey", &page{Title: "newsshkey.title", Tab: "keys",
		Data: map[string]any{"KeyChoices": sshKeyChoices, "Type": sshKeyChoices[0].Value}})
}

func (s *Server) newSSHKey(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	name := strings.TrimSpace(r.PostFormValue("name"))
	comment := codec.SSHComment(r.PostFormValue("comment"))
	typ := r.PostFormValue("type")
	data := map[string]any{"KeyChoices": sshKeyChoices, "Type": typ, "Name": name, "Comment": comment}
	spec, err := parseKeyChoice(typ)
	offered := slices.ContainsFunc(sshKeyChoices, func(c keyChoice) bool { return c.Value == typ })
	if err != nil || !offered || name == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "newsshkey", &page{Title: "newsshkey.title", Tab: "keys",
			Error: "newkey.error.input", Data: data})
		return
	}
	kr := ds.Keyring()
	id, err := ds.Handle.GenerateKey(r.Context(), name, comment, *spec, kr)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("SSH key generated", "db", ds.DBName, "id", id, "type", typ)
	http.Redirect(w, r, dbPath(ds.DBName)+"item/"+strconv.FormatInt(id, 10)+"/ssh?notice=created", http.StatusSeeOther)
}

// sshKeyForm is the SSH page of a key.
type sshKeyForm struct {
	Key         *gcadb.Key
	Algorithm   string
	Fingerprint string // as ssh-keygen -l shows it
	Comment     string
	Line        string // authorized_keys line
	Private     bool   // the private key can be downloaded
	OwnPass     bool
	Flavors     []string
	Flavor      string
}

// sshKeyForm describes a key for its SSH page; false if the item is not a
// key SSH can use.
func (s *Server) sshKeyForm(r *http.Request, snap *gcadb.Snapshot) (*sshKeyForm, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil, false
	}
	for _, k := range snap.Keys {
		if k.ID != id {
			continue
		}
		pub, err := codec.ParsePublic(k.Public)
		if err != nil {
			return nil, false
		}
		sp, err := ssh.NewPublicKey(pub)
		if err != nil {
			return nil, false
		}
		line, err := codec.SSHPublic(pub, k.Comment)
		if err != nil {
			return nil, false
		}
		return &sshKeyForm{Key: k, Algorithm: sp.Type() + ", " + strconv.Itoa(pki.DescribePublicKey(k.Public).Bits) + " bit",
			Fingerprint: ssh.FingerprintSHA256(sp), Comment: codec.SSHComment(k.Comment), Line: strings.TrimSpace(string(line)),
			Private: k.HasPrivate && !k.Token, OwnPass: k.Protection == gcadb.ProtPassword,
			Flavors: sshFlavors, Flavor: sshFlavors[0]}, true
	}
	return nil, false
}

func (s *Server) sshKeyPage(w http.ResponseWriter, r *http.Request) {
	snap, err := dbSession(r).Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, ok := s.sshKeyForm(r, snap)
	if !ok {
		s.render(w, r, http.StatusNotFound, "error", &page{Title: "sshkey.title", Error: "sshkey.error.notssh"})
		return
	}
	p := &page{Title: "sshkey.title", Tab: "keys", Data: map[string]any{"F": f}}
	if r.URL.Query().Get("notice") == "created" {
		p.Notice = "item.notice.created"
	}
	s.render(w, r, http.StatusOK, "sshkey", p)
}

// sshKeyDownload sends a key pair as a ZIP archive.
func (s *Server) sshKeyDownload(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, ok := s.sshKeyForm(r, snap)
	if !ok || !f.Private {
		s.render(w, r, http.StatusNotFound, "error", &page{Title: "sshkey.title", Error: "sshkey.error.notssh"})
		return
	}
	if v := r.PostFormValue("format"); slices.Contains(sshFlavors, v) {
		f.Flavor = v
	}
	p := &page{Title: "sshkey.title", Tab: "keys", Data: map[string]any{"F": f}}
	fail := func(key string) {
		p.Error = key
		s.render(w, r, http.StatusUnprocessableEntity, "sshkey", p)
	}
	pw, pw2 := []byte(r.PostFormValue("password")), []byte(r.PostFormValue("password2"))
	defer clear(pw)
	defer clear(pw2)
	if !bytes.Equal(pw, pw2) {
		fail("export.error.mismatch")
		return
	}
	if f.OwnPass && s.keyLimit.Blocked(ds.ID) {
		fail("export.error.ratelimit")
		return
	}
	kr := ds.Keyring()
	res, err := ds.Handle.SSHPair(r.Context(), f.Flavor, store.ExportRequest{IDs: []int64{f.Key.ID}, Password: pw,
		Keyring: kr, Keys: keyPasswords(r, snap), T: s.printer(r).T})
	switch {
	case errors.Is(err, store.ErrNeedKeyPassword):
		if r.PostFormValue("keypass") != "" {
			s.keyLimit.Fail(ds.ID)
		}
		fail("export.error.keypass")
		return
	case err != nil:
		s.log.Warn("SSH key export failed", "db", ds.DBName, "id", f.Key.ID, "err", err)
		p.Error, p.ErrorArg = "export.error.failed", err.Error()
		s.render(w, r, http.StatusUnprocessableEntity, "sshkey", p)
		return
	}
	s.log.Info("private key exported", "db", ds.DBName, "items", []int64{f.Key.ID}, "format", f.Flavor, "ip", clientIP(r))
	w.Header().Set("Content-Type", res.ContentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": res.Filename}))
	w.Header().Set("Content-Length", strconv.Itoa(len(res.Data)))
	w.Write(res.Data)
}

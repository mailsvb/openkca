package web

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/store"
	"github.com/mailsvb/go-ca/internal/xdb"
)

var typeTabs = map[int]string{xdb.TypeKey: "keys", xdb.TypeRequest: "requests", xdb.TypeCert: "certs", xdb.TypeCRL: "crls", xdb.TypeTemplate: "templates"}
var typeKinds = map[int]string{xdb.TypeKey: "key", xdb.TypeRequest: "request", xdb.TypeCert: "cert", xdb.TypeCRL: "crl", xdb.TypeTemplate: "template"}

func formIDs(vals []string) []int64 {
	var ids []int64
	seen := map[int64]bool{}
	for _, v := range vals {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

type exportForm struct {
	IDs      []int64
	Items    []link
	Formats  []codec.Format
	Format   int
	Comment  bool
	Type     string
	OwnPass  bool // a key with its own password is involved
	Crypt    bool // an offered format asks for an export password
	Text     string
	Filename string
}

func (s *Server) exportForm(r *http.Request, snap *xdb.Snapshot, ids []int64) (*exportForm, bool) {
	f := &exportForm{IDs: ids, Formats: store.ExportFormats(snap, ids)}
	if len(ids) == 0 || len(f.Formats) == 0 {
		return f, false
	}
	ix := newIndex(snap)
	for _, id := range ids {
		f.Items = append(f.Items, link{id, ix.names[id]})
		if k := ix.keys[id]; k != nil && k.OwnPass == xdb.PassPrivate {
			f.OwnPass = true
		}
		if c := ix.certs[id]; c != nil {
			if k := ix.keys[c.KeyID]; k != nil && k.OwnPass == xdb.PassPrivate {
				f.OwnPass = true
			}
		}
	}
	for _, x := range f.Formats {
		f.Crypt = f.Crypt || x.Flags&codec.FCrypt != 0
	}
	f.Type = typeKinds[f.Formats[0].Type]
	f.Format = f.Formats[0].ID
	return f, true
}

func (s *Server) exportPage(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, ok := s.exportForm(r, snap, formIDs(r.URL.Query()["id"]))
	if !ok {
		s.render(w, r, http.StatusBadRequest, "error", &page{Title: "export.title", Error: "export.error.selection"})
		return
	}
	s.render(w, r, http.StatusOK, "export", &page{Title: "export.title", Tab: typeTabs[f.Formats[0].Type], Data: map[string]any{"F": f}})
}

func (s *Server) exportSubmit(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	r.ParseForm()
	f, ok := s.exportForm(r, snap, formIDs(r.PostForm["id"]))
	if !ok {
		s.render(w, r, http.StatusBadRequest, "error", &page{Title: "export.title", Error: "export.error.selection"})
		return
	}
	f.Format, _ = strconv.Atoi(r.PostFormValue("format"))
	f.Comment = r.PostFormValue("comment") != ""
	p := &page{Title: "export.title", Tab: typeTabs[f.Formats[0].Type], Data: map[string]any{"F": f}}
	fail := func(key string) {
		p.Error = key
		s.render(w, r, http.StatusUnprocessableEntity, "export", p)
	}
	format, ok := codec.FormatByID(f.Format)
	if !ok {
		fail("export.error.format")
		return
	}
	pw, pw2 := []byte(r.PostFormValue("password")), []byte(r.PostFormValue("password2"))
	defer clear(pw)
	defer clear(pw2)
	if format.Flags&codec.FCrypt != 0 {
		if len(pw) == 0 {
			fail("export.error.nopassword")
			return
		}
		if !bytes.Equal(pw, pw2) {
			fail("export.error.mismatch")
			return
		}
	}
	if f.OwnPass && s.keyLimit.Blocked(ds.ID) {
		fail("export.error.ratelimit")
		return
	}
	dbPass := ds.Password()
	defer clear(dbPass)
	res, err := ds.Handle.Export(r.Context(), store.ExportRequest{Format: f.Format, IDs: f.IDs, Password: pw, PEMComment: f.Comment,
		DBPass: dbPass, Keys: keyPasswords(r, snap), T: s.printer(r).T})
	switch {
	case errors.Is(err, store.ErrNeedKeyPassword):
		if r.PostFormValue("keypass") != "" {
			s.keyLimit.Fail(ds.ID)
		}
		fail("export.error.keypass")
		return
	case errors.Is(err, store.ErrNeedExportPassword):
		fail("export.error.nopassword")
		return
	case err != nil:
		s.log.Warn("export failed", "db", ds.DBName, "format", f.Format, "err", err)
		p.Error, p.ErrorArg = "export.error.failed", err.Error()
		s.render(w, r, http.StatusUnprocessableEntity, "export", p)
		return
	}
	if format.Flags&codec.FPrivate != 0 {
		s.log.Info("private key exported", "db", ds.DBName, "items", f.IDs, "format", f.Format, "ip", clientIP(r))
	}
	if r.PostFormValue("action") == "show" && res.Text {
		f.Text, f.Filename = string(res.Data), res.Filename
		s.render(w, r, http.StatusOK, "export", p)
		return
	}
	w.Header().Set("Content-Type", res.ContentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": res.Filename}))
	w.Header().Set("Content-Length", strconv.Itoa(len(res.Data)))
	w.Write(res.Data)
}

// pendingImport is an import in review, kept in the database session.
type pendingImport struct {
	mu    sync.Mutex
	files []*pendingFile
	plans []store.ImportPlan
}

type pendingFile struct {
	Name   string
	data   []byte
	Result codec.ProbeResult
}

func (p *pendingImport) Wipe() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, f := range p.files {
		clear(f.data)
		for _, o := range f.Result.Objects {
			clear(o.Private)
		}
	}
	p.files, p.plans = nil, nil
}

func (s *Server) probeOptions(r *http.Request, pw []byte) codec.ProbeOptions {
	pr := s.printer(r)
	return codec.ProbeOptions{Password: pw, Pasted: pr.T("import.pasted"),
		KeyName: func(bits int, typ string, public bool) string {
			if typ == "ED25" {
				typ = "Ed25519"
			}
			if public {
				return pr.T("import.keyname.public", strconv.Itoa(bits), typ)
			}
			return pr.T("import.keyname", strconv.Itoa(bits), typ)
		}}
}

// replan collects the objects of all files and checks them against the
// database.
func replan(r *http.Request, h *store.Handle, p *pendingImport) error {
	var objs []codec.Object
	for _, f := range p.files {
		objs = append(objs, f.Result.Objects...)
	}
	plans, err := h.PlanImport(r.Context(), objs)
	if err != nil {
		return err
	}
	p.plans = plans
	return nil
}

func (s *Server) importPage(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	p := &page{Title: "importitems.title", Tab: r.URL.Query().Get("tab"), Data: map[string]any{"MaxUploadMB": s.cfg.MaxUpload >> 20}}
	if pi, ok := ds.Pending().(*pendingImport); ok {
		pi.mu.Lock()
		p.Data["Files"], p.Data["Plans"] = pi.files, pi.plans
		needPW := false
		for _, f := range pi.files {
			needPW = needPW || f.Result.NeedPassword
		}
		p.Data["NeedPassword"] = needPW
		pi.mu.Unlock()
	}
	switch q := r.URL.Query(); {
	case q.Get("error") != "" && strings.HasPrefix(q.Get("error"), "importitems.error."):
		p.Error = q.Get("error")
	}
	s.render(w, r, http.StatusOK, "import", p)
}

func (s *Server) importRedirect(w http.ResponseWriter, r *http.Request, query string) {
	target := dbPath(dbSession(r).DBName) + "import"
	if query != "" {
		target += "?" + query
	}
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// importUpload reads uploaded files and pasted text into a new review.
func (s *Server) importUpload(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUpload+1<<20)
	mr, err := r.MultipartReader()
	if err != nil {
		s.importRedirect(w, r, "error=importitems.error.nofile")
		return
	}
	pi := &pendingImport{}
	var pw []byte
	defer clear(pw)
	total := int64(0)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			pi.Wipe()
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				s.importRedirect(w, r, "error=importitems.error.toolarge")
			} else {
				s.importRedirect(w, r, "error=importitems.error.nofile")
			}
			return
		}
		data, err := io.ReadAll(io.LimitReader(part, s.cfg.MaxUpload-total+1))
		total += int64(len(data))
		if err != nil || total > s.cfg.MaxUpload {
			pi.Wipe()
			s.importRedirect(w, r, "error=importitems.error.toolarge")
			return
		}
		switch part.FormName() {
		case "file":
			if part.FileName() != "" && len(data) > 0 {
				pi.files = append(pi.files, &pendingFile{Name: part.FileName(), data: data})
			}
		case "pem":
			if len(bytes.TrimSpace(data)) > 0 {
				pi.files = append(pi.files, &pendingFile{Name: "", data: data})
			}
		case "password":
			pw = data
		}
	}
	if len(pi.files) == 0 {
		s.importRedirect(w, r, "error=importitems.error.nofile")
		return
	}
	opts := s.probeOptions(r, pw)
	for _, f := range pi.files {
		f.Result = codec.Probe(f.Name, f.data, opts)
	}
	if err := replan(r, ds.Handle, pi); err != nil {
		pi.Wipe()
		s.fail(w, r, err)
		return
	}
	ds.SetPending(pi)
	s.importRedirect(w, r, "")
}

// importPassword probes the files that need a password again.
func (s *Server) importPassword(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	pi, ok := ds.Pending().(*pendingImport)
	if !ok {
		s.importRedirect(w, r, "")
		return
	}
	pw := []byte(r.PostFormValue("password"))
	defer clear(pw)
	opts := s.probeOptions(r, pw)
	pi.mu.Lock()
	for _, f := range pi.files {
		if f.Result.NeedPassword {
			f.Result = codec.Probe(f.Name, f.data, opts)
		}
	}
	err := replan(r, ds.Handle, pi)
	pi.mu.Unlock()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.importRedirect(w, r, "")
}

func (s *Server) importCancel(w http.ResponseWriter, r *http.Request) {
	dbSession(r).SetPending(nil)
	s.importRedirect(w, r, "")
}

// importCommit stores the selected objects under the names entered.
func (s *Server) importCommit(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	pi, ok := ds.Pending().(*pendingImport)
	if !ok {
		s.importRedirect(w, r, "")
		return
	}
	r.ParseForm()
	pi.mu.Lock()
	plans := append([]store.ImportPlan(nil), pi.plans...)
	pi.mu.Unlock()
	var sel []int
	for _, v := range r.PostForm["sel"] {
		i, err := strconv.Atoi(v)
		if err != nil || i < 0 || i >= len(plans) || plans[i].Action == store.ImportExists {
			continue
		}
		if name := strings.TrimSpace(r.PostFormValue("name." + v)); name != "" {
			plans[i].Name = name
		}
		sel = append(sel, i)
	}
	if len(sel) == 0 {
		s.importRedirect(w, r, "error=importitems.error.noselection")
		return
	}
	dbPass := ds.Password()
	defer clear(dbPass)
	res, err := ds.Handle.Import(r.Context(), plans, sel, dbPass, s.printer(r).T)
	if err != nil {
		s.log.Error("import failed", "db", ds.DBName, "err", err)
		s.importRedirect(w, r, "error=importitems.error.failed")
		return
	}
	ds.SetPending(nil)
	s.log.Info("items imported", "db", ds.DBName, "count", len(res), "ip", clientIP(r))
	tab := typeTabs[plans[sel[0]].Type]
	http.Redirect(w, r, dbPath(ds.DBName)+tab+"?notice=imported&n="+strconv.Itoa(len(res)), http.StatusSeeOther)
}

// dump downloads the whole database as a ZIP archive of PEM files.
func (s *Server) dump(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	dbPass := ds.Password()
	defer clear(dbPass)
	var buf bytes.Buffer
	if err := ds.Handle.Dump(r.Context(), &buf, dbPass); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("database dumped", "db", ds.DBName, "ip", clientIP(r))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": store.FileName(ds.DBName) + ".zip"}))
	w.Write(buf.Bytes())
}

package web

import (
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"

	"github.com/mailsvb/go-ca/internal/store"
	"github.com/mailsvb/go-ca/internal/vault"
)

func backTo(w http.ResponseWriter, r *http.Request, query string) {
	target := "/?" + query
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// createDB creates a new, empty database in the data folder.
func (s *Server) createDB(w http.ResponseWriter, r *http.Request) {
	name := r.PostFormValue("name")
	pw := []byte(r.PostFormValue("password"))
	again := []byte(r.PostFormValue("password2"))
	defer clear(pw)
	defer clear(again)
	if string(pw) != string(again) {
		backTo(w, r, "error=create.error.mismatch")
		return
	}
	err := s.store.Create(r.Context(), name, pw, vault.Default)
	switch {
	case errors.Is(err, store.ErrShortPassword):
		backTo(w, r, "error=create.error.short")
	case errors.Is(err, store.ErrBadName):
		backTo(w, r, "error=create.error.name")
	case errors.Is(err, store.ErrExists):
		backTo(w, r, "error=create.error.exists")
	case err != nil:
		s.log.Error("create database failed", "name", name, "err", err)
		backTo(w, r, "error=create.error.failed")
	default:
		s.log.Info("database created", "db", name, "ip", clientIP(r))
		backTo(w, r, "notice=created&name="+url.QueryEscape(name)+"&db="+url.QueryEscape(name))
	}
}

// importDB stores an uploaded .xdb file. The body is streamed part by part
// straight into a temporary file in the data folder.
func (s *Server) importDB(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUpload+1<<20) // room for the multipart framing
	mr, err := r.MultipartReader()
	if err != nil {
		backTo(w, r, "error=import.error.nofile")
		return
	}
	var part *multipart.Part
	for {
		part, err = mr.NextPart()
		if err != nil {
			backTo(w, r, "error=import.error.nofile")
			return
		}
		if part.FormName() == "file" && part.FileName() != "" {
			break
		}
		io.Copy(io.Discard, part)
	}
	name, err := s.store.Upload(r.Context(), part.FileName(), part, s.cfg.MaxUpload)
	var rej *store.RejectedError
	var tooBig *http.MaxBytesError
	switch {
	case errors.Is(err, store.ErrTooLarge), errors.As(err, &tooBig):
		backTo(w, r, "error=import.error.toolarge")
	case errors.As(err, &rej):
		s.log.Warn("import refused", "file", part.FileName(), "status", rej.Status, "detail", rej.Detail)
		backTo(w, r, "error=import.error."+string(rej.Status))
	case err != nil:
		s.log.Error("import failed", "file", part.FileName(), "err", err)
		backTo(w, r, "error=import.error.failed")
	default:
		s.log.Info("database imported", "db", name, "file", part.FileName(), "ip", clientIP(r))
		backTo(w, r, "notice=imported&name="+url.QueryEscape(name)+"&db="+url.QueryEscape(name))
	}
}

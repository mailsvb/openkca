package web

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/codec"
	"github.com/mailsvb/go-ca/internal/i18n"
	"github.com/mailsvb/go-ca/internal/session"
)

// page is the data every template receives.
type page struct {
	Title     string // message key
	Error     string // message key
	ErrorArg  string // its argument, if any
	Notice    string // message key
	NoticeArg string // its argument, if any
	CSRF      string
	DB        *dbHeader
	Tab       string
	Data      map[string]any
	Lang      string
}

type dbHeader struct {
	Name   string
	Schema int
}

var tabs = []string{"keys", "requests", "certs", "templates", "crls"}

func (s *Server) parseTemplates() error {
	s.templates = map[string]*template.Template{}
	files, err := templateFS.ReadDir("templates")
	if err != nil {
		return err
	}
	for _, tag := range s.cfg.Catalog.Languages() {
		pr := s.cfg.Catalog.Match(tag.String())
		t := template.New("").Funcs(funcs(pr))
		for _, f := range files {
			b, err := templateFS.ReadFile(path.Join("templates", f.Name()))
			if err != nil {
				return err
			}
			if _, err := t.New(strings.TrimSuffix(f.Name(), ".html")).Parse(string(b)); err != nil {
				return fmt.Errorf("template %s: %w", f.Name(), err)
			}
		}
		s.templates[tag.String()] = t
	}
	return nil
}

func funcs(pr *i18n.Printer) template.FuncMap {
	return template.FuncMap{
		"T": pr.T,
		"time": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.UTC().Format("2006-01-02 15:04")
		},
		"date": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.UTC().Format("2006-01-02")
		},
		"size": func(n int64) string {
			switch {
			case n >= 1<<20:
				return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
			case n >= 1<<10:
				return fmt.Sprintf("%.1f kB", float64(n)/(1<<10))
			}
			return fmt.Sprintf("%d B", n)
		},
		"tabs": func() []string { return tabs },
		"join": strings.Join,
		"depth": func(depth int) string {
			return fmt.Sprintf("d%d", min(depth, 8))
		},
		"bit": func(v, i int) bool { return v&(1<<i) != 0 },
		"has": func(list []string, v string) bool {
			for _, x := range list {
				if x == v {
					return true
				}
			}
			return false
		},
		"otherEKU": func(list, known []string) string {
			var out []string
			for _, x := range list {
				k := false
				for _, y := range known {
					k = k || x == y
				}
				if !k {
					out = append(out, x)
				}
			}
			return strings.Join(out, ", ")
		},
		"flag": func(f codec.Flags, name string) bool {
			return f&map[string]codec.Flags{"private": codec.FPrivate, "crypt": codec.FCrypt}[name] != 0
		},
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
	}
}

// printer chooses the language for a request.
func (s *Server) printer(r *http.Request) *i18n.Printer {
	lang := ""
	if ss := serverSession(r); ss != nil {
		lang = ss.Lang
	}
	return s.cfg.Catalog.Match(lang, r.Header.Get("Accept-Language"))
}

// render executes a page template (or, for htmx requests, a named fragment
// when frag is set in p.Data["fragment"]).
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p *page) {
	pr := s.printer(r)
	t := s.templates[pr.Tag.String()]
	if t == nil {
		t = s.templates["en"]
	}
	p.Lang = pr.Tag.String()
	if ss := serverSession(r); ss != nil {
		p.CSRF = ss.CSRF
	}
	if ds := dbSession(r); ds != nil && p.DB == nil {
		p.DB = header(ds)
	}
	exec := name
	if frag, ok := p.Data["fragment"].(string); ok && isHTMX(r) {
		exec = frag
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, exec, p); err != nil {
		s.log.Error("template failed", "template", exec, "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func header(ds *session.Session) *dbHeader {
	return &dbHeader{Name: ds.DBName, Schema: ds.Handle.DB.Schema}
}

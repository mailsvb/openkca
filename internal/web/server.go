// Package web serves the HTML user interface (server-rendered templates with
// htmx) and wires the server login, database sessions and the data folder.
package web

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/auth"
	"github.com/mailsvb/go-ca/internal/i18n"
	"github.com/mailsvb/go-ca/internal/session"
	"github.com/mailsvb/go-ca/internal/store"
	"github.com/mailsvb/go-ca/internal/xdbpass"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	authCookie = "xca_auth"
	dbCookie   = "xca_sess"
)

// Config configures a Server.
type Config struct {
	Store        *store.Store
	PasswordHash string // argon2id hash of the server password
	Catalog      *i18n.Catalog
	IdleTimeout  time.Duration
	MaxUpload    int64 // import size limit in bytes
	Logger       *slog.Logger
}

// Server is the HTTP handler.
type Server struct {
	cfg       Config
	store     *store.Store
	auth      *auth.Sessions
	dbs       *session.Manager
	srvLimit  *auth.Limiter                 // server password, per client IP
	dbLimit   *auth.Limiter                 // database passwords, per database
	keyLimit  *auth.Limiter                 // own key passwords, per database session
	templates map[string]*template.Template // by language tag
	log       *slog.Logger
	mux       *http.ServeMux
}

// New builds the server.
func New(cfg Config) (*Server, error) {
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 30 * time.Minute
	}
	if cfg.MaxUpload == 0 {
		cfg.MaxUpload = 256 << 20
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{
		cfg:      cfg,
		store:    cfg.Store,
		auth:     auth.NewSessions(cfg.IdleTimeout),
		dbs:      session.NewManager(cfg.IdleTimeout),
		srvLimit: auth.NewLimiter(5, time.Minute),
		dbLimit:  auth.NewLimiter(5, time.Minute),
		keyLimit: auth.NewLimiter(5, time.Minute),
		log:      cfg.Logger,
	}
	s.auth.OnEnd = s.dbs.EndServer
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

// Run sweeps idle sessions until ctx ends, then closes all databases. It
// returns once every database is closed.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	poll := time.NewTicker(30 * time.Second)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			s.dbs.CloseAll()
			return
		case <-t.C:
			s.auth.Sweep()
			s.dbs.Sweep()
		case <-poll.C:
			// Changes desktop XCA makes reach the index files.
			s.store.PollOpen(ctx)
		}
	}
}

func (s *Server) routes() {
	m := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	m.Handle("GET /static/", http.StripPrefix("/static/", staticHandler(http.FileServerFS(static))))
	m.HandleFunc("GET /login", s.loginPage)
	m.HandleFunc("POST /login", s.login)
	m.HandleFunc("POST /logout", s.requireServer(s.logout))
	m.HandleFunc("GET /{$}", s.requireServer(s.databases))
	m.HandleFunc("POST /{$}", s.requireServer(s.createDB))
	m.HandleFunc("POST /import", s.requireServer(s.importDB))
	m.HandleFunc("POST /db/{name}/login", s.requireServer(s.dbLogin))
	m.HandleFunc("POST /db/{name}/logout", s.requireServer(s.requireDB(s.dbLogout)))
	m.HandleFunc("GET /db/{name}/{$}", s.requireServer(s.requireDB(s.dbHome)))
	m.HandleFunc("GET /db/{name}/options", s.requireServer(s.requireDB(s.options)))
	m.HandleFunc("GET /db/{name}/item/{id}", s.requireServer(s.requireDB(s.item)))
	m.HandleFunc("POST /db/{name}/item/{id}/check-key", s.requireServer(s.requireDB(s.checkKey)))
	m.HandleFunc("GET /db/{name}/{tab}", s.requireServer(s.requireDB(s.list)))
	m.HandleFunc("POST /db/{name}/options", s.requireServer(s.requireDB(s.saveOptions)))
	m.HandleFunc("GET /db/{name}/password", s.requireServer(s.requireDB(s.dbPasswordPage)))
	m.HandleFunc("POST /db/{name}/password", s.requireServer(s.requireDB(s.dbPassword)))
	m.HandleFunc("GET /db/{name}/new/key", s.requireServer(s.requireDB(s.newKeyPage)))
	m.HandleFunc("POST /db/{name}/new/key", s.requireServer(s.requireDB(s.newKey)))
	m.HandleFunc("GET /db/{name}/new/{kind}", s.requireServer(s.requireDB(s.editorPage)))
	m.HandleFunc("POST /db/{name}/new/{kind}", s.requireServer(s.requireDB(s.editorSubmit)))
	m.HandleFunc("POST /db/{name}/item/{id}/rename", s.requireServer(s.requireDB(s.renameItem)))
	m.HandleFunc("POST /db/{name}/item/{id}/delete", s.requireServer(s.requireDB(s.deleteItem)))
	m.HandleFunc("POST /db/{name}/item/{id}/signed", s.requireServer(s.requireDB(s.markSigned)))
	m.HandleFunc("POST /db/{name}/item/{id}/extract-key", s.requireServer(s.requireDB(s.extractKey)))
	m.HandleFunc("POST /db/{name}/item/{id}/to-request", s.requireServer(s.requireDB(s.toRequest)))
	m.HandleFunc("POST /db/{name}/item/{id}/key-password", s.requireServer(s.requireDB(s.keyPassword)))
	m.HandleFunc("POST /db/{name}/item/{id}/revoke", s.requireServer(s.requireDB(s.revokeCert)))
	m.HandleFunc("POST /db/{name}/item/{id}/unrevoke", s.requireServer(s.requireDB(s.unrevokeCert)))
	m.HandleFunc("POST /db/{name}/item/{id}/ca-properties", s.requireServer(s.requireDB(s.caProperties)))
	m.HandleFunc("GET /db/{name}/item/{id}/revocations", s.requireServer(s.requireDB(s.revocationsPage)))
	m.HandleFunc("POST /db/{name}/item/{id}/revocations", s.requireServer(s.requireDB(s.revocationsSubmit)))
	m.HandleFunc("GET /db/{name}/item/{id}/crl", s.requireServer(s.requireDB(s.crlPage)))
	m.HandleFunc("POST /db/{name}/item/{id}/crl", s.requireServer(s.requireDB(s.crlSubmit)))
	m.HandleFunc("GET /db/{name}/item/{id}/renew", s.requireServer(s.requireDB(s.renewPage)))
	m.HandleFunc("POST /db/{name}/item/{id}/renew", s.requireServer(s.requireDB(s.renewSubmit)))
	s.mux = m
}

func staticHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

// ServeHTTP applies the security headers to every response.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Strict-Transport-Security", "max-age=31536000")
	if !strings.HasPrefix(r.URL.Path, "/static/") {
		h.Set("Cache-Control", "no-store")
	}
	s.mux.ServeHTTP(w, r)
}

type ctxKey int

const (
	ctxServer ctxKey = iota
	ctxDB
)

func serverSession(r *http.Request) *auth.ServerSession {
	ss, _ := r.Context().Value(ctxServer).(*auth.ServerSession)
	return ss
}

func dbSession(r *http.Request) *session.Session {
	ds, _ := r.Context().Value(ctxDB).(*session.Session)
	return ds
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isHTMX(r *http.Request) bool { return r.Header.Get("HX-Request") == "true" }

// requireServer enforces the server login and, for state-changing requests,
// the CSRF token.
func (s *Server) requireServer(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ss *auth.ServerSession
		if c, err := r.Cookie(authCookie); err == nil {
			ss = s.auth.Get(c.Value)
		}
		if ss == nil {
			if r.Method == http.MethodGet && !isHTMX(r) {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			if isHTMX(r) {
				w.Header().Set("HX-Redirect", "/login")
			}
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			token := r.Header.Get("X-CSRF-Token")
			// Uploads must send the header (htmx does): parsing a multipart
			// body here would spool it to the system temp folder.
			if token == "" && !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
				token = r.PostFormValue("csrf")
			}
			if !ss.CSRFOK(token) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxServer, ss)))
	}
}

// requireDB resolves the database session from the cookie scoped to /db/{name}/.
func (s *Server) requireDB(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		var ds *session.Session
		if c, err := r.Cookie(dbCookie); err == nil {
			ds = s.dbs.Get(c.Value, serverSession(r).ID, name)
		}
		if ds == nil {
			if isHTMX(r) {
				w.Header().Set("HX-Redirect", "/")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/?db="+url.QueryEscape(name), http.StatusSeeOther)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxDB, ds)))
	}
}

func (s *Server) setCookie(w http.ResponseWriter, name, value, path string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: path, MaxAge: maxAge,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func dbPath(name string) string { return "/db/" + name + "/" }

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(authCookie); err == nil && s.auth.Get(c.Value) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login", &page{Title: "login.title"})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	p := &page{Title: "login.title"}
	if s.srvLimit.Blocked(ip) {
		p.Error = "login.error.ratelimit"
		s.render(w, r, http.StatusTooManyRequests, "login", p)
		return
	}
	pw := []byte(r.PostFormValue("password"))
	defer clear(pw)
	if !auth.CheckPassword(s.cfg.PasswordHash, pw) {
		s.srvLimit.Fail(ip)
		s.log.Warn("server login failed", "ip", ip)
		p.Error = "login.error.password"
		s.render(w, r, http.StatusUnauthorized, "login", p)
		return
	}
	s.srvLimit.Reset(ip)
	// A fresh ID on every login (session fixation).
	if c, err := r.Cookie(authCookie); err == nil {
		s.auth.End(c.Value)
	}
	ss := s.auth.Create()
	s.setCookie(w, authCookie, ss.ID, "/", 0)
	s.log.Info("server login", "ip", ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.auth.End(serverSession(r).ID)
	s.setCookie(w, authCookie, "", "/", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) databases(w http.ResponseWriter, r *http.Request) {
	infos, err := s.store.Scan(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	open := s.dbs.OpenDatabases(serverSession(r).ID)
	p := &page{Title: "databases.title", Data: map[string]any{
		"Databases": infos, "Open": open, "Selected": r.URL.Query().Get("db"),
		"MaxUploadMB": s.cfg.MaxUpload >> 20,
	}}
	q := r.URL.Query()
	if e := q.Get("error"); strings.HasPrefix(e, "dblogin.error.") || strings.HasPrefix(e, "create.error.") || strings.HasPrefix(e, "import.error.") {
		p.Error = e
	}
	if n := q.Get("notice"); n == "created" || n == "imported" {
		p.Notice, p.NoticeArg = "databases.notice."+n, q.Get("name")
	}
	s.render(w, r, http.StatusOK, "databases", p)
}

func (s *Server) dbLogin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	back := func(key string) {
		http.Redirect(w, r, "/?db="+url.QueryEscape(name)+"&error="+key, http.StatusSeeOther)
	}
	if s.dbLimit.Blocked(name) {
		back("dblogin.error.ratelimit")
		return
	}
	h, err := s.store.Acquire(r.Context(), name)
	if err != nil {
		s.log.Warn("database open failed", "db", name, "err", err)
		if errors.Is(err, store.ErrLocked) {
			back("dblogin.error.locked")
		} else if errors.Is(err, os.ErrNotExist) {
			back("dblogin.error.missing")
		} else {
			back("dblogin.error.unsupported")
		}
		return
	}
	pw := []byte(r.PostFormValue("password"))
	defer clear(pw)
	stored, err := h.DB.Setting(r.Context(), "pwhash")
	if err != nil {
		h.Release()
		s.fail(w, r, err)
		return
	}
	ok, upgrade := xdbpass.Verify(stored, pw)
	if !ok {
		h.Release()
		s.dbLimit.Fail(name)
		s.log.Warn("database login failed", "db", name, "ip", clientIP(r))
		back("dblogin.error.password")
		return
	}
	s.dbLimit.Reset(name)
	if upgrade {
		// XCA replaces S and MD5 hashes with the T form after a correct login.
		if err := h.DB.SetSetting(r.Context(), "pwhash", xdbpass.NewHash(pw)); err != nil {
			s.log.Error("password hash upgrade failed", "db", name, "err", err)
		} else {
			s.log.Info("password hash upgraded to T form", "db", name)
		}
	}
	rep, err := h.PrepareAfterLogin(r.Context(), pw)
	if err != nil {
		h.Release()
		s.log.Error("database preparation failed", "db", name, "err", err)
		back("dblogin.error.upgrade")
		return
	}
	if rep.Backup != "" {
		s.log.Info("database prepared", "db", name, "backup", rep.Backup, "upgraded_from", rep.UpgradedFrom,
			"converted_keys", rep.ConvertedKeys)
	}
	if rep.OwnPassLegacy > 0 {
		s.log.Warn("legacy keys with their own password left unconverted", "db", name, "count", rep.OwnPassLegacy)
	}
	if c, err := r.Cookie(dbCookie); err == nil {
		s.dbs.End(c.Value)
	}
	ds := s.dbs.Create(serverSession(r).ID, name, h, pw)
	s.setCookie(w, dbCookie, ds.ID, dbPath(name), 0)
	s.log.Info("database opened", "db", name, "ip", clientIP(r))
	http.Redirect(w, r, dbPath(name), http.StatusSeeOther)
}

func (s *Server) dbLogout(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	s.dbs.End(ds.ID)
	s.setCookie(w, dbCookie, "", dbPath(ds.DBName), -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) dbHome(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, dbPath(r.PathValue("name"))+"certs", http.StatusSeeOther)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "path", r.URL.Path, "err", err)
	s.render(w, r, http.StatusInternalServerError, "error", &page{Title: "error.title", Error: "error.internal"})
}

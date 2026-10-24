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
	"strconv"
	"strings"
	"time"

	"github.com/mailsvb/openkca/internal/auth"
	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/i18n"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/pubserve"
	"github.com/mailsvb/openkca/internal/session"
	"github.com/mailsvb/openkca/internal/store"
	"github.com/mailsvb/openkca/internal/vault"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	authCookie = "gca_auth"
	dbCookie   = "gca_sess"
)

// Config configures a Server.
type Config struct {
	Store        *store.Store
	PasswordHash string // argon2id hash of the server password
	Catalog      *i18n.Catalog
	IdleTimeout  time.Duration
	MaxUpload    int64 // import size limit in bytes
	Logger       *slog.Logger
	// CRLAlerts returns the published CRLs that expire soon or expired.
	CRLAlerts func() []pubserve.Alert
}

// Server is the HTTP handler.
type Server struct {
	cfg        Config
	store      *store.Store
	auth       *auth.Sessions
	dbs        *session.Manager
	srvLimit   *auth.Limiter // server password, per client IP
	dbLimit    *auth.Limiter // database passwords, per database
	keyLimit   *auth.Limiter // own key passwords, per database session
	loginSlots chan struct{} // concurrent server password checks
	dh         dhJobs
	templates  map[string]*template.Template // by language tag
	log        *slog.Logger
	mux        *http.ServeMux
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
		cfg:        cfg,
		store:      cfg.Store,
		auth:       auth.NewSessions(cfg.IdleTimeout),
		dbs:        session.NewManager(cfg.IdleTimeout),
		srvLimit:   auth.NewLimiter(5, time.Minute),
		dbLimit:    auth.NewLimiter(5, time.Minute),
		keyLimit:   auth.NewLimiter(5, time.Minute),
		loginSlots: make(chan struct{}, 2),
		log:        cfg.Logger,
	}
	s.dh.m = map[string]*dhJob{}
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
	for {
		select {
		case <-ctx.Done():
			s.dbs.CloseAll()
			return
		case <-t.C:
			s.auth.Sweep()
			s.dbs.Sweep()
			s.srvLimit.Sweep()
			s.dbLimit.Sweep()
			s.keyLimit.Sweep()
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
	m.HandleFunc("GET /oid", s.requireServer(s.oidPage))
	m.HandleFunc("POST /{$}", s.requireServer(s.createDB))
	m.HandleFunc("POST /import", s.requireServer(s.importDB))
	m.HandleFunc("GET /dh", s.requireServer(s.dhPage))
	m.HandleFunc("POST /dh", s.requireServer(s.dhStart))
	m.HandleFunc("POST /dh/cancel", s.requireServer(s.dhCancel))
	m.HandleFunc("GET /dh/download", s.requireServer(s.dhDownload))
	m.HandleFunc("POST /db/{name}/login", s.requireServer(s.dbLogin))
	m.HandleFunc("POST /db/{name}/logout", s.requireServer(s.requireDBSession(s.dbLogout)))
	m.HandleFunc("GET /db/{name}/converting", s.requireServer(s.requireDBSession(s.convertingPage)))
	m.HandleFunc("GET /db/{name}/{$}", s.requireServer(s.requireDB(s.dbHome)))
	m.HandleFunc("GET /db/{name}/options", s.requireServer(s.requireDB(s.options)))
	m.HandleFunc("GET /db/{name}/trash", s.requireServer(s.requireDB(s.trashPage)))
	m.HandleFunc("POST /db/{name}/trash/empty", s.requireServer(s.requireDB(s.purgeItems)))
	m.HandleFunc("POST /db/{name}/trash/{id}/restore", s.requireServer(s.requireDB(s.restoreItem)))
	m.HandleFunc("POST /db/{name}/trash/{id}/purge", s.requireServer(s.requireDB(s.purgeItems)))
	m.HandleFunc("GET /db/{name}/audit", s.requireServer(s.requireDB(s.auditPage)))
	m.HandleFunc("GET /db/{name}/item/{id}", s.requireServer(s.requireDB(s.item)))
	m.HandleFunc("POST /db/{name}/item/{id}/check-key", s.requireServer(s.requireDB(s.checkKey)))
	m.HandleFunc("GET /db/{name}/{tab}", s.requireServer(s.requireDB(s.list)))
	m.HandleFunc("GET /db/{name}/export", s.requireServer(s.requireDB(s.exportPage)))
	m.HandleFunc("POST /db/{name}/export", s.requireServer(s.requireDB(s.exportSubmit)))
	m.HandleFunc("GET /db/{name}/import", s.requireServer(s.requireDB(s.importPage)))
	m.HandleFunc("POST /db/{name}/import", s.requireServer(s.requireDB(s.importUpload)))
	m.HandleFunc("POST /db/{name}/import/password", s.requireServer(s.requireDB(s.importPassword)))
	m.HandleFunc("POST /db/{name}/import/commit", s.requireServer(s.requireDB(s.importCommit)))
	m.HandleFunc("POST /db/{name}/import/cancel", s.requireServer(s.requireDB(s.importCancel)))
	m.HandleFunc("POST /db/{name}/dump", s.requireServer(s.requireDB(s.dump)))
	m.HandleFunc("POST /db/{name}/options", s.requireServer(s.requireDB(s.saveOptions)))
	m.HandleFunc("POST /db/{name}/expert", s.requireServer(s.requireDB(s.setExpert)))
	m.HandleFunc("GET /db/{name}/password", s.requireServer(s.requireDB(s.dbPasswordPage)))
	m.HandleFunc("POST /db/{name}/password", s.requireServer(s.requireDB(s.dbPassword)))
	m.HandleFunc("GET /db/{name}/new/key", s.requireServer(s.requireDB(s.newKeyPage)))
	m.HandleFunc("POST /db/{name}/new/key", s.requireServer(s.requireDB(s.newKey)))
	m.HandleFunc("GET /db/{name}/new/sshkey", s.requireServer(s.requireDB(s.newSSHKeyPage)))
	m.HandleFunc("POST /db/{name}/new/sshkey", s.requireServer(s.requireDB(s.newSSHKey)))
	m.HandleFunc("GET /db/{name}/item/{id}/ssh", s.requireServer(s.requireDB(s.sshKeyPage)))
	m.HandleFunc("POST /db/{name}/item/{id}/ssh", s.requireServer(s.requireDB(s.sshKeyDownload)))
	m.HandleFunc("GET /db/{name}/new/pgpkey", s.requireServer(s.requireDB(s.newPGPKeyPage)))
	m.HandleFunc("POST /db/{name}/new/pgpkey", s.requireServer(s.requireDB(s.newPGPKey)))
	m.HandleFunc("GET /db/{name}/item/{id}/pgp", s.requireServer(s.requireDB(s.pgpKeyPage)))
	m.HandleFunc("POST /db/{name}/item/{id}/pgp", s.requireServer(s.requireDB(s.pgpKeyDownload)))
	m.HandleFunc("POST /db/{name}/item/{id}/pgp/create", s.requireServer(s.requireDB(s.pgpCreate)))
	m.HandleFunc("POST /db/{name}/item/{id}/pgp/subkey", s.requireServer(s.requireDB(s.pgpAddSubkey)))
	m.HandleFunc("POST /db/{name}/item/{id}/pgp/remove", s.requireServer(s.requireDB(s.pgpRemove)))
	m.HandleFunc("GET /db/{name}/new", s.requireServer(s.requireDB(s.purposePage)))
	m.HandleFunc("GET /db/{name}/create/{profile}", s.requireServer(s.requireDB(s.profilePage)))
	m.HandleFunc("POST /db/{name}/create/{profile}", s.requireServer(s.requireDB(s.profileSubmit)))
	m.HandleFunc("GET /db/{name}/new/{kind}", s.requireServer(s.requireDB(s.editorPage)))
	m.HandleFunc("POST /db/{name}/new/{kind}", s.requireServer(s.requireDB(s.editorSubmit)))
	m.HandleFunc("POST /db/{name}/item/{id}/rename", s.requireServer(s.requireDB(s.renameItem)))
	m.HandleFunc("POST /db/{name}/item/{id}/delete", s.requireServer(s.requireDB(s.deleteItem)))
	m.HandleFunc("POST /db/{name}/item/{id}/signed", s.requireServer(s.requireDB(s.markSigned)))
	m.HandleFunc("POST /db/{name}/item/{id}/extract-key", s.requireServer(s.requireDB(s.extractKey)))
	m.HandleFunc("POST /db/{name}/item/{id}/to-request", s.requireServer(s.requireDB(s.toRequest)))
	m.HandleFunc("POST /db/{name}/item/{id}/key-password", s.requireServer(s.requireDB(s.keyPassword)))
	m.HandleFunc("POST /db/{name}/item/{id}/revoke", s.requireServer(s.requireDB(s.revokeCert)))
	m.HandleFunc("GET /db/{name}/item/{id}/edit", s.requireServer(s.requireDB(s.templateEditPage)))
	m.HandleFunc("POST /db/{name}/item/{id}/duplicate", s.requireServer(s.requireDB(s.duplicateTemplate)))
	m.HandleFunc("POST /db/{name}/item/{id}/to-template", s.requireServer(s.requireDB(s.toTemplate)))
	m.HandleFunc("POST /db/{name}/item/{id}/unrevoke", s.requireServer(s.requireDB(s.unrevokeCert)))
	m.HandleFunc("POST /db/{name}/item/{id}/ca-properties", s.requireServer(s.requireDB(s.caProperties)))
	m.HandleFunc("GET /db/{name}/item/{id}/revocations", s.requireServer(s.requireDB(s.revocationsPage)))
	m.HandleFunc("POST /db/{name}/item/{id}/revocations", s.requireServer(s.requireDB(s.revocationsSubmit)))
	m.HandleFunc("GET /db/{name}/item/{id}/crl", s.requireServer(s.requireDB(s.crlPage)))
	m.HandleFunc("POST /db/{name}/item/{id}/crl", s.requireServer(s.requireDB(s.crlSubmit)))
	m.HandleFunc("POST /db/{name}/item/{id}/crl/now", s.requireServer(s.requireDB(s.crlNow)))
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
		ctx := db.WithClient(context.WithValue(r.Context(), ctxServer, ss), clientIP(r))
		next(w, r.WithContext(ctx))
	}
}

// requireDBSession resolves the database session from the cookie scoped
// to /db/{name}/, also while the database is still being converted.
func (s *Server) requireDBSession(next http.HandlerFunc) http.HandlerFunc {
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

// requireDB is requireDBSession for sessions that have their keyring: a
// session whose database is still being converted is sent to the progress
// page.
func (s *Server) requireDB(next http.HandlerFunc) http.HandlerFunc {
	return s.requireDBSession(func(w http.ResponseWriter, r *http.Request) {
		ds := dbSession(r)
		if !ds.Ready() {
			target := dbPath(ds.DBName) + "converting"
			if isHTMX(r) {
				w.Header().Set("HX-Redirect", target)
				w.WriteHeader(http.StatusConflict)
				return
			}
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}
		next(w, r)
	})
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
	// Argon2id takes 64 MiB per run: limit the runs in parallel, and count
	// the attempt before hashing so that parallel requests cannot pass the
	// rate limit together.
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		p.Error = "login.error.busy"
		s.render(w, r, http.StatusTooManyRequests, "login", p)
		return
	}
	s.srvLimit.Fail(ip)
	pw := []byte(r.PostFormValue("password"))
	defer clear(pw)
	if !auth.CheckPassword(s.cfg.PasswordHash, pw) {
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
		"MaxUploadMB": s.cfg.MaxUpload >> 20, "MinLen": store.MinPasswordLen,
		"CRLAlerts": s.crlAlerts(),
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

// crlAlert is a published CRL that expires soon or expired, for display.
type crlAlert struct {
	pubserve.Alert
	DBLabel string
}

func (s *Server) crlAlerts() []crlAlert {
	if s.cfg.CRLAlerts == nil {
		return nil
	}
	var out []crlAlert
	for _, a := range s.cfg.CRLAlerts() {
		label := a.DB
		if c, ok := s.store.ConfiguredDB(a.DB); ok {
			label = c.Label
		}
		out = append(out, crlAlert{a, label})
	}
	return out
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
	openErr := func(err error) {
		s.log.Warn("database open failed", "db", name, "err", err)
		switch {
		case errors.Is(err, pki.ErrWrongPassword):
			s.log.Warn("database login failed", "db", name, "ip", clientIP(r))
			back("dblogin.error.password")
		case errors.Is(err, store.ErrLocked):
			back("dblogin.error.locked")
		case errors.Is(err, os.ErrNotExist):
			back("dblogin.error.missing")
		default:
			back("dblogin.error.unsupported")
		}
	}
	// Count the attempt before the (slow) check, as for the server login.
	s.dbLimit.Fail(name)
	pw := []byte(r.PostFormValue("password"))
	defer clear(pw)
	if store.IsXCAName(name) {
		// An XCA file is imported into a new go-ca
		// database in the background; the session waits for it on the
		// progress page.
		conv, err := s.store.StartImport(r.Context(), name, pw, vault.Default)
		if err != nil {
			openErr(err)
			return
		}
		s.dbLimit.Reset(name)
		s.log.Info("database import started", "file", name, "ip", clientIP(r))
		ds := s.dbs.Create(serverSession(r).ID, name, nil, nil, conv)
		s.setCookie(w, dbCookie, ds.ID, dbPath(name), 0)
		http.Redirect(w, r, dbPath(name)+"converting", http.StatusSeeOther)
		return
	}
	h, err := s.store.Acquire(r.Context(), name)
	if err != nil {
		openErr(err)
		return
	}
	kr, err := h.Unlock(r.Context(), pw)
	if err != nil {
		if errors.Is(err, pki.ErrWrongPassword) {
			h.Audit(r.Context(), "database.unlock_failed", 0, "")
		}
		h.Release()
		openErr(err)
		return
	}
	s.dbLimit.Reset(name)
	h.Audit(r.Context(), "database.unlock", 0, "")
	if c, err := r.Cookie(dbCookie); err == nil {
		s.dbs.End(c.Value)
	}
	ds := s.dbs.Create(serverSession(r).ID, name, h, kr, nil)
	s.setCookie(w, dbCookie, ds.ID, dbPath(name), 0)
	s.log.Info("database opened", "db", name, "ip", clientIP(r))
	http.Redirect(w, r, dbPath(name), http.StatusSeeOther)
}

// convertingPage shows the progress of an import; htmx polls it. When
// the import has finished, the browser gets a session on the new go-ca
// database and continues there; when it failed, the session ends.
func (s *Server) convertingPage(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	if ds.Ready() {
		s.redirect(w, r, dbPath(ds.DBName))
		return
	}
	conv := ds.Conversion()
	failed := func() {
		s.dbs.End(ds.ID)
		s.setCookie(w, dbCookie, "", dbPath(ds.DBName), -1)
		s.redirect(w, r, "/?db="+url.QueryEscape(ds.DBName)+"&error=dblogin.error.upgrade")
	}
	if conv == nil {
		failed()
		return
	}
	// Small databases import in well under a second: wait a moment
	// instead of showing the progress page at once.
	wait := time.NewTimer(time.Second)
	defer wait.Stop()
	select {
	case <-conv.Finished():
	case <-wait.C:
	}
	select {
	case <-conv.Finished():
		kr, rep, err := conv.Result()
		if err != nil {
			failed()
			return
		}
		h, err := s.store.Acquire(r.Context(), rep.Target)
		if err != nil {
			kr.Wipe()
			s.log.Error("opening the imported database failed", "db", rep.Target, "err", err)
			failed()
			return
		}
		s.dbs.End(ds.ID)
		s.setCookie(w, dbCookie, "", dbPath(ds.DBName), -1)
		nds := s.dbs.Create(serverSession(r).ID, rep.Target, h, kr, nil)
		s.setCookie(w, dbCookie, nds.ID, dbPath(rep.Target), 0)
		q := "?notice=converted&name=" + url.QueryEscape(ds.DBName)
		if n := rep.OwnPassLegacy + rep.Unopened; n > 0 {
			q = "?notice=converted.ownpass&n=" + strconv.Itoa(n)
		}
		s.redirect(w, r, dbPath(rep.Target)+"keys"+q)
		return
	default:
	}
	done, total := conv.Progress()
	s.render(w, r, http.StatusOK, "converting", &page{Title: "converting.title",
		Data: map[string]any{"Name": ds.DBName, "Done": done, "Total": total, "fragment": "convstatus"}})
}

// redirect sends the browser on, with HX-Redirect for htmx requests.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, target string) {
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
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

package web

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/store"
	"github.com/mailsvb/openkca/internal/vault"
)

// methodRow is one unlock method on the methods page.
type methodRow struct {
	db.UnlockMethod
	Configured bool // the configuration file opens the database with it
	Current    bool // this session was opened with it
}

func (s *Server) methodsData(r *http.Request) (map[string]any, error) {
	ds := dbSession(r)
	ms, err := ds.Handle.Methods(r.Context())
	if err != nil {
		return nil, err
	}
	cfg, cur := ds.Handle.ConfiguredMethod(), ds.Method()
	var rows []methodRow
	var backup *methodRow
	passwords, keys := 0, 0
	// Passwords first, then keys and passkeys, each in the order used.
	for _, t := range vault.SlotTypes {
		for _, m := range ms {
			if m.Type != t {
				continue
			}
			row := methodRow{UnlockMethod: m, Configured: m.UUID == cfg, Current: m.UUID == cur}
			switch m.Type {
			case vault.SlotBackupCode:
				backup = &row
				continue
			case vault.SlotPassword:
				passwords++
			default:
				keys++
			}
			rows = append(rows, row)
		}
	}
	p, _ := ds.Handle.KDFParams(r.Context())
	left := int(ds.ConfirmedUntil().Sub(time.Now()).Minutes()) + 1
	return map[string]any{
		"Methods": rows, "Backup": backup, "Passwords": passwords, "Keys": keys,
		"MaxPasswords": store.MaxPasswords, "MaxKeys": store.MaxWebAuthn, "MaxLabel": store.MaxLabelLength,
		"WebAuthn": s.webauthn != nil, "Confirmed": ds.Confirmed(), "ConfirmLeft": left,
		"MinLen": store.MinPasswordLen, "Memory": p.MemoryMiB(), "Time": int(p.Time), "Default": vault.Default,
		"MemoryChoices": vault.MemoryChoicesMiB, "TimeChoices": vault.TimeChoices,
		"Background": ds.Handle.ConfiguredMethod() != "",
	}, nil
}

var methodNotices = map[string]bool{"added": true, "removed": true, "renamed": true, "password": true,
	"confirmed": true, "kdf": true, "rekeyed": true, "codeused": true}

func (s *Server) methodsPage(w http.ResponseWriter, r *http.Request) {
	p := &page{Title: "methods.title", Tab: "options"}
	q := r.URL.Query()
	if n := q.Get("notice"); methodNotices[n] {
		p.Notice = "methods.notice." + n
	}
	if e := q.Get("error"); methodErrors[e] {
		p.Error = "methods.error." + e
	}
	s.renderMethods(w, r, http.StatusOK, p)
}

func (s *Server) renderMethods(w http.ResponseWriter, r *http.Request, status int, p *page) {
	data, err := s.methodsData(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p.Data != nil {
		for k, v := range p.Data {
			data[k] = v
		}
	}
	p.Title, p.Tab, p.Data = "methods.title", "options", data
	s.render(w, r, status, "methods", p)
}

var methodErrors = map[string]bool{"confirm": true, "confirm_password": true, "mismatch": true, "short": true,
	"label": true, "toomany": true, "last": true, "configured": true, "notpassword": true, "kdf": true,
	"background": true, "rekey_password": true, "ratelimit": true}

// methodsBack redirects to the methods page with a notice or an error.
func (s *Server) methodsBack(w http.ResponseWriter, r *http.Request, query string) {
	http.Redirect(w, r, dbPath(dbSession(r).DBName)+"methods?"+query, http.StatusSeeOther)
}

// confirmed checks the confirmation window of a change to the unlock
// methods; outside of it the user is sent to confirm first.
func (s *Server) confirmed(w http.ResponseWriter, r *http.Request) bool {
	if dbSession(r).Confirmed() {
		return true
	}
	s.methodsBack(w, r, "error=confirm")
	return false
}

// methodError maps a store error to a page error, or fails the request.
func (s *Server) methodError(w http.ResponseWriter, r *http.Request, err error) {
	key := ""
	switch {
	case errors.Is(err, store.ErrShortPassword):
		key = "short"
	case errors.Is(err, store.ErrBadLabel):
		key = "label"
	case errors.Is(err, store.ErrTooManyMethods):
		key = "toomany"
	case errors.Is(err, store.ErrLastPassword):
		key = "last"
	case errors.Is(err, store.ErrConfiguredMethod):
		key = "configured"
	case errors.Is(err, store.ErrNotPassword):
		key = "notpassword"
	case errors.Is(err, store.ErrBackground):
		key = "background"
	case errors.Is(err, db.ErrNoMethod):
		http.NotFound(w, r)
		return
	default:
		s.fail(w, r, err)
		return
	}
	s.methodsBack(w, r, "error="+key)
}

// confirmPassword re-confirms the session with a password.
func (s *Server) confirmPassword(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	if s.keyLimit.Blocked(ds.ID) {
		s.methodsBack(w, r, "error=ratelimit")
		return
	}
	pw := []byte(r.PostFormValue("password"))
	defer clear(pw)
	kr, err := ds.Handle.Unlock(r.Context(), pw)
	if err != nil {
		if isWrongSecret(err) {
			s.keyLimit.Fail(ds.ID)
			s.methodsBack(w, r, "error=confirm_password")
			return
		}
		s.fail(w, r, err)
		return
	}
	kr.Wipe()
	s.keyLimit.Reset(ds.ID)
	ds.Confirm()
	s.methodsBack(w, r, "notice=confirmed")
}

// newPassword reads and checks the two new-password fields.
func newPassword(r *http.Request) ([]byte, string) {
	n1, n2 := []byte(r.PostFormValue("password")), []byte(r.PostFormValue("password2"))
	defer clear(n2)
	if string(n1) != string(n2) {
		clear(n1)
		return nil, "mismatch"
	}
	if len(n1) < store.MinPasswordLen {
		clear(n1)
		return nil, "short"
	}
	return n1, ""
}

func (s *Server) addPassword(w http.ResponseWriter, r *http.Request) {
	if !s.confirmed(w, r) {
		return
	}
	ds := dbSession(r)
	pw, bad := newPassword(r)
	if bad != "" {
		s.methodsBack(w, r, "error="+bad)
		return
	}
	defer clear(pw)
	if _, err := ds.Handle.AddPassword(r.Context(), ds.Keyring(), r.PostFormValue("label"), pw); err != nil {
		s.methodError(w, r, err)
		return
	}
	s.log.Info("unlock method added", "db", ds.DBName, "type", vault.SlotPassword, "ip", clientIP(r))
	s.methodsBack(w, r, "notice=added")
}

func (s *Server) changeMethodPassword(w http.ResponseWriter, r *http.Request) {
	if !s.confirmed(w, r) {
		return
	}
	ds := dbSession(r)
	pw, bad := newPassword(r)
	if bad != "" {
		s.methodsBack(w, r, "error="+bad)
		return
	}
	defer clear(pw)
	if err := ds.Handle.ChangePassword(r.Context(), ds.Keyring(), r.PathValue("id"), pw); err != nil {
		s.methodError(w, r, err)
		return
	}
	s.log.Info("database password changed", "db", ds.DBName, "ip", clientIP(r))
	s.methodsBack(w, r, "notice=password")
}

func (s *Server) renameMethod(w http.ResponseWriter, r *http.Request) {
	if !s.confirmed(w, r) {
		return
	}
	ds := dbSession(r)
	if err := ds.Handle.RenameMethod(r.Context(), r.PathValue("id"), r.PostFormValue("label")); err != nil {
		s.methodError(w, r, err)
		return
	}
	s.methodsBack(w, r, "notice=renamed")
}

func (s *Server) removeMethod(w http.ResponseWriter, r *http.Request) {
	if !s.confirmed(w, r) {
		return
	}
	ds := dbSession(r)
	if err := ds.Handle.RemoveMethod(r.Context(), r.PathValue("id")); err != nil {
		s.methodError(w, r, err)
		return
	}
	s.log.Info("unlock method removed", "db", ds.DBName, "ip", clientIP(r))
	s.methodsBack(w, r, "notice=removed")
}

// backupCode generates (or replaces) the backup code and shows it once.
func (s *Server) backupCode(w http.ResponseWriter, r *http.Request) {
	if !s.confirmed(w, r) {
		return
	}
	ds := dbSession(r)
	code, err := ds.Handle.GenerateBackupCode(r.Context(), ds.Keyring())
	if err != nil {
		s.methodError(w, r, err)
		return
	}
	s.log.Info("backup code generated", "db", ds.DBName, "ip", clientIP(r))
	s.renderMethods(w, r, http.StatusOK, &page{Notice: "methods.notice.backup", Data: map[string]any{"NewCode": code}})
}

// setKDF sets the Argon2id cost for passwords set from now on.
func (s *Server) setKDF(w http.ResponseWriter, r *http.Request) {
	if !s.confirmed(w, r) {
		return
	}
	ds := dbSession(r)
	m, err1 := strconv.Atoi(r.PostFormValue("kdf_memory"))
	t, err2 := strconv.Atoi(r.PostFormValue("kdf_time"))
	if err1 != nil || err2 != nil || !slices.Contains(vault.MemoryChoicesMiB, m) || !slices.Contains(vault.TimeChoices, t) {
		s.methodsBack(w, r, "error=kdf")
		return
	}
	p := vault.Params{MemoryKiB: uint32(m) * 1024, Time: uint32(t), Threads: vault.Default.Threads}
	if err := ds.Handle.SetKDFParams(r.Context(), p); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("key derivation cost changed", "db", ds.DBName, "argon2_mib", m, "argon2_t", t)
	s.methodsBack(w, r, "notice=kdf")
}

// rekey replaces the data key; the password typed with it is the only
// unlock method kept.
func (s *Server) rekey(w http.ResponseWriter, r *http.Request) {
	if !s.confirmed(w, r) {
		return
	}
	ds := dbSession(r)
	if s.keyLimit.Blocked(ds.ID) {
		s.methodsBack(w, r, "error=ratelimit")
		return
	}
	pw := []byte(r.PostFormValue("password"))
	defer clear(pw)
	kr, err := ds.Handle.ReplaceDataKey(r.Context(), pw)
	if err != nil {
		if isWrongSecret(err) {
			s.keyLimit.Fail(ds.ID)
			s.methodsBack(w, r, "error=rekey_password")
			return
		}
		s.methodError(w, r, err)
		return
	}
	// Other sessions on this database hold the old data key.
	s.dbs.EndDatabase(ds.DBName, ds.ID)
	ds.SetKeyring(kr)
	if ms, err := ds.Handle.Methods(r.Context()); err == nil && len(ms) == 1 {
		ds.SetMethod(ms[0].UUID)
	}
	s.log.Info("data key replaced", "db", ds.DBName, "ip", clientIP(r))
	s.methodsBack(w, r, "notice=rekeyed")
}

// passwordRedirect keeps the old password page's address working.
func (s *Server) passwordRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, dbPath(dbSession(r).DBName)+"methods", http.StatusMovedPermanently)
}

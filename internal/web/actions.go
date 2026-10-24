package web

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/store"
	"github.com/mailsvb/go-ca/internal/vault"
)

func itemID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil
}

func (s *Server) toItem(w http.ResponseWriter, r *http.Request, id int64, query string) {
	target := dbPath(dbSession(r).DBName) + "item/" + strconv.FormatInt(id, 10)
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

func (s *Server) toList(w http.ResponseWriter, r *http.Request, tab, query string) {
	target := dbPath(dbSession(r).DBName) + tab
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

func (s *Server) renameItem(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ds := dbSession(r)
	name := strings.TrimSpace(r.PostFormValue("name"))
	comment := strings.ReplaceAll(r.PostFormValue("comment"), "\r\n", "\n")
	if name == "" {
		s.toItem(w, r, id, "error=item.error.noname")
		return
	}
	if err := ds.Handle.Rename(r.Context(), id, name, comment); err != nil {
		s.fail(w, r, err)
		return
	}
	s.toItem(w, r, id, "notice=saved")
}

func (s *Server) deleteItem(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ds := dbSession(r)
	snap, err := ds.Handle.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	tab := tabOf(snap, id)
	if err := ds.Handle.Delete(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Info("deleted", "db", ds.DBName, "id", id)
	s.toList(w, r, tab, "notice=deleted")
}

func (s *Server) markSigned(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := dbSession(r).Handle.MarkSigned(r.Context(), id, r.PostFormValue("signed") == "1"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.toItem(w, r, id, "notice=saved")
}

func (s *Server) extractKey(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	kid, err := dbSession(r).Handle.ExtractPublicKey(r.Context(), id)
	if err != nil {
		s.toItem(w, r, id, "error=item.error.extract")
		return
	}
	s.toItem(w, r, kid, "notice=created")
}

func (s *Server) toRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ds := dbSession(r)
	snap, _ := ds.Handle.Snapshot(r.Context())
	kr := ds.Keyring()
	rid, err := ds.Handle.CertToRequest(r.Context(), id, kr, keyPasswords(r, snap))
	switch {
	case errors.Is(err, store.ErrNeedKeyPassword):
		s.toItem(w, r, id, "error=item.error.keypass")
	case err != nil:
		s.log.Warn("transform to request failed", "id", id, "err", err)
		s.toItem(w, r, id, "error=item.error.torequest")
	default:
		s.toItem(w, r, rid, "notice=created")
	}
}

// keyPassword sets or resets a key's own password.
func (s *Server) keyPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ds := dbSession(r)
	kr := ds.Keyring()
	var kp store.KeyPasswords
	if cur := r.PostFormValue("current"); cur != "" {
		kp = store.KeyPasswords{id: []byte(cur)}
	}
	var err error
	if r.PostFormValue("action") == "reset" {
		err = ds.Handle.ResetKeyPassword(r.Context(), id, kr, kp)
	} else {
		n1, n2 := r.PostFormValue("new"), r.PostFormValue("new2")
		if n1 == "" || n1 != n2 {
			s.toItem(w, r, id, "error=keypw.error.mismatch")
			return
		}
		err = ds.Handle.SetKeyPassword(r.Context(), id, kr, kp, []byte(n1))
	}
	switch {
	case errors.Is(err, store.ErrNeedKeyPassword), errors.Is(err, pki.ErrWrongPassword):
		s.toItem(w, r, id, "error=keypw.error.current")
	case err != nil:
		s.fail(w, r, err)
	default:
		s.log.Info("key password changed", "db", ds.DBName, "id", id, "action", r.PostFormValue("action"))
		s.toItem(w, r, id, "notice=keypw")
	}
}

func (s *Server) dbPasswordData(r *http.Request) map[string]any {
	cur, err := dbSession(r).Handle.KDFParams(r.Context())
	if err != nil {
		cur = vault.Default
	}
	return map[string]any{"Memory": cur.MemoryMiB(), "Time": int(cur.Time), "Default": vault.Default,
		"MemoryChoices": vault.MemoryChoicesMiB, "TimeChoices": vault.TimeChoices, "MinLen": store.MinPasswordLen}
}

func (s *Server) dbPasswordPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "dbpassword", &page{Title: "dbpw.title", Tab: "options", Data: s.dbPasswordData(r)})
}

// kdfFromForm reads the Argon2id cost chosen on the password page; only
// the offered values are accepted. Without the fields the current cost
// stays.
func kdfFromForm(r *http.Request) (vault.Params, bool) {
	if r.PostFormValue("kdf_memory") == "" && r.PostFormValue("kdf_time") == "" {
		p, err := dbSession(r).Handle.KDFParams(r.Context())
		return p, err == nil
	}
	m, err1 := strconv.Atoi(r.PostFormValue("kdf_memory"))
	t, err2 := strconv.Atoi(r.PostFormValue("kdf_time"))
	if err1 != nil || err2 != nil || !slices.Contains(vault.MemoryChoicesMiB, m) || !slices.Contains(vault.TimeChoices, t) {
		return vault.Params{}, false
	}
	return vault.Params{MemoryKiB: uint32(m) * 1024, Time: uint32(t), Threads: vault.Default.Threads}, true
}

// dbPassword changes the database password, the Argon2id cost, or both;
// either way the DEK is rotated. An empty new password keeps the current
// one.
func (s *Server) dbPassword(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	old, n1, n2 := []byte(r.PostFormValue("old")), []byte(r.PostFormValue("new")), []byte(r.PostFormValue("new2"))
	defer clear(old)
	defer clear(n1)
	defer clear(n2)
	p := &page{Title: "dbpw.title", Tab: "options", Data: s.dbPasswordData(r)}
	fail := func(key string) {
		p.Error = key
		s.render(w, r, http.StatusUnprocessableEntity, "dbpassword", p)
	}
	params, ok := kdfFromForm(r)
	switch {
	case !ok:
		fail("dbpw.error.kdf")
		return
	case string(n1) != string(n2):
		fail("dbpw.error.mismatch")
		return
	case len(n1) > 0 && len(n1) < store.MinPasswordLen:
		p.ErrorArg = strconv.Itoa(store.MinPasswordLen)
		fail("dbpw.error.short")
		return
	}
	newPass := n1
	if len(newPass) == 0 {
		newPass = old
	}
	if s.keyLimit.Blocked(ds.ID) {
		fail("keycheck.ratelimit")
		return
	}
	kr, err := ds.Handle.ChangeDatabasePassword(r.Context(), old, newPass, params)
	if errors.Is(err, pki.ErrWrongPassword) {
		s.keyLimit.Fail(ds.ID)
		fail("dbpw.error.old")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Other sessions on this database hold the old DEK.
	s.dbs.EndDatabase(ds.DBName, ds.ID)
	ds.SetKeyring(kr)
	s.log.Info("database password or key derivation changed", "db", ds.DBName, "ip", clientIP(r),
		"argon2_mib", params.MemoryMiB(), "argon2_t", params.Time)
	p.Data = s.dbPasswordData(r)
	p.Notice = "dbpw.done"
	s.render(w, r, http.StatusOK, "dbpassword", p)
}

// saveOptions writes the shared XCA options.
func (s *Server) saveOptions(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	vals := map[string]string{}
	for _, o := range optionKeys {
		switch o.kind {
		case "bool":
			if r.PostFormValue(o.key) != "" {
				vals[o.key] = "yes"
			} else {
				vals[o.key] = "no"
			}
		case "expiry":
			n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(o.key + ".n")))
			unit := r.PostFormValue(o.key + ".u")
			if err != nil || n < 0 || !strings.Contains(o.units, unit) || unit == "" {
				s.redirectOptions(w, r, "error=options.error.value&key="+o.key)
				return
			}
			vals[o.key] = strconv.Itoa(n) + unit
		case "number":
			v := strings.TrimSpace(r.PostFormValue(o.key))
			n, err := strconv.Atoi(v)
			if rg := optionRanges[o.key]; err != nil || n < rg[0] || n > rg[1] {
				s.redirectOptions(w, r, "error=options.error.value&key="+o.key)
				return
			}
			vals[o.key] = strconv.Itoa(n)
		default:
			v := strings.TrimSpace(r.PostFormValue(o.key))
			if len(o.choices) > 0 && !contains(o.choices, v) {
				s.redirectOptions(w, r, "error=options.error.value&key="+o.key)
				return
			}
			if o.key == "mandatory_dn" || o.key == "explicit_dn" {
				for _, a := range strings.Split(v, ",") {
					if a = strings.TrimSpace(a); a != "" {
						if _, err := pki.AttrOID(a); err != nil {
							s.redirectOptions(w, r, "error=options.error.value&key="+o.key)
							return
						}
					}
				}
			}
			vals[o.key] = v
		}
	}
	if err := ds.Handle.SetSettings(r.Context(), vals); err != nil {
		s.fail(w, r, err)
		return
	}
	s.redirectOptions(w, r, "notice=saved")
}

// setExpert switches the expert fields on or off and returns to the page
// the form names (a page of the same database).
func (s *Server) setExpert(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	v := "no"
	if r.PostFormValue("expert") == "yes" {
		v = "yes"
	}
	if err := ds.Handle.SetSettings(r.Context(), map[string]string{"expert": v}); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, backPath(r.PostFormValue("back"), ds.DBName), http.StatusSeeOther)
}

// backPath is back when it is a path below the database's pages, else
// the database's home.
func backPath(back, db string) string {
	base := dbPath(db)
	if !strings.HasPrefix(back, base) || strings.ContainsAny(back, "\\\r\n") || strings.Contains(back[1:], "//") {
		return base
	}
	return back
}

func (s *Server) redirectOptions(w http.ResponseWriter, r *http.Request, q string) {
	http.Redirect(w, r, dbPath(dbSession(r).DBName)+"options?"+q, http.StatusSeeOther)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) duplicateTemplate(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	nid, err := dbSession(r).Handle.DuplicateTemplate(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.toItem(w, r, nid, "notice=created")
}

func (s *Server) toTemplate(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	tid, err := dbSession(r).Handle.TemplateFromItem(r.Context(), id)
	if err != nil {
		s.log.Warn("transform to template failed", "id", id, "err", err)
		s.toItem(w, r, id, "error=item.error.totemplate")
		return
	}
	s.toItem(w, r, tid, "notice=created")
}

// oidPage is XCA's OID resolver.
func (s *Server) oidPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	s.render(w, r, http.StatusOK, "oid", &page{Title: "oid.title", Data: map[string]any{"Q": q, "Results": pki.ResolveOID(q),
		"Searched": q != ""}})
}

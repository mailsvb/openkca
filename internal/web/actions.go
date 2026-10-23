package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/store"
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
	pw := ds.Password()
	defer clear(pw)
	rid, err := ds.Handle.CertToRequest(r.Context(), id, pw, keyPasswords(r, snap))
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
	pw := ds.Password()
	defer clear(pw)
	var kp store.KeyPasswords
	if cur := r.PostFormValue("current"); cur != "" {
		kp = store.KeyPasswords{id: []byte(cur)}
	}
	var err error
	if r.PostFormValue("action") == "reset" {
		err = ds.Handle.ResetKeyPassword(r.Context(), id, pw, kp)
	} else {
		n1, n2 := r.PostFormValue("new"), r.PostFormValue("new2")
		if n1 == "" || n1 != n2 {
			s.toItem(w, r, id, "error=keypw.error.mismatch")
			return
		}
		err = ds.Handle.SetKeyPassword(r.Context(), id, pw, kp, []byte(n1))
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

func (s *Server) dbPasswordPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "dbpassword", &page{Title: "dbpw.title", Tab: "options"})
}

func (s *Server) dbPassword(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	old, n1, n2 := r.PostFormValue("old"), r.PostFormValue("new"), r.PostFormValue("new2")
	p := &page{Title: "dbpw.title", Tab: "options"}
	if n1 != n2 {
		p.Error = "dbpw.error.mismatch"
		s.render(w, r, http.StatusUnprocessableEntity, "dbpassword", p)
		return
	}
	err := ds.Handle.ChangeDatabasePassword(r.Context(), []byte(old), []byte(n1))
	if errors.Is(err, pki.ErrWrongPassword) {
		p.Error = "dbpw.error.old"
		s.render(w, r, http.StatusUnprocessableEntity, "dbpassword", p)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Other sessions on this database hold the old password.
	s.dbs.EndDatabase(ds.DBName, ds.ID)
	ds.SetPassword([]byte(n1))
	s.log.Info("database password changed", "db", ds.DBName, "ip", clientIP(r))
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

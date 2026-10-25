package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/store"
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

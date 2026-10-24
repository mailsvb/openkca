package web

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/mailsvb/go-ca/internal/gcadb"
)

type trashRow struct {
	gcadb.Item
	Kind string
}

// trashPage lists the items in the trash.
func (s *Server) trashPage(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	items, err := ds.Handle.Trash(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows := make([]trashRow, len(items))
	for i, it := range items {
		rows[i] = trashRow{it, gcadb.TypeName(it.Type)}
	}
	p := &page{Title: "trash.title", Tab: "trash", Data: map[string]any{"Rows": rows}}
	switch r.URL.Query().Get("notice") {
	case "restored":
		p.Notice = "trash.notice.restored"
	case "purged":
		p.Notice, p.NoticeArg = "trash.notice.purged", r.URL.Query().Get("n")
	}
	switch e := r.URL.Query().Get("error"); e {
	case "trash.error", "trash.error.authority":
		p.Error = e
	}
	s.render(w, r, http.StatusOK, "trash", p)
}

func (s *Server) toTrash(w http.ResponseWriter, r *http.Request, query string) {
	target := dbPath(dbSession(r).DBName) + "trash?" + query
	s.redirect(w, r, target)
}

// restoreItem takes an item out of the trash.
func (s *Server) restoreItem(w http.ResponseWriter, r *http.Request) {
	id, ok := itemID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ds := dbSession(r)
	if err := ds.Handle.Restore(r.Context(), id); err != nil {
		s.log.Warn("restore failed", "db", ds.DBName, "id", id, "err", err)
		if errors.Is(err, gcadb.ErrAuthorityInUse) {
			s.toTrash(w, r, "error=trash.error.authority")
			return
		}
		s.toTrash(w, r, "error=trash.error")
		return
	}
	s.log.Info("restored", "db", ds.DBName, "id", id)
	s.toTrash(w, r, "notice=restored")
}

// purgeItems deletes one item in the trash for good, or all of them.
func (s *Server) purgeItems(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	var ids []int64
	if r.PathValue("id") != "" {
		id, ok := itemID(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		ids = []int64{id}
	}
	n, err := ds.Handle.Purge(r.Context(), ids)
	if err != nil {
		s.log.Warn("purge failed", "db", ds.DBName, "err", err)
		s.toTrash(w, r, "error=trash.error")
		return
	}
	s.log.Info("purged", "db", ds.DBName, "count", n)
	s.toTrash(w, r, "notice=purged&n="+strconv.Itoa(n))
}

const auditPageSize = 100

// auditPage shows the database's audit log, newest first, a page at a time.
func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	ds := dbSession(r)
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	entries, err := ds.Handle.AuditLog(r.Context(), 0, before, auditPageSize+1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var next int64
	if len(entries) > auditPageSize {
		entries = entries[:auditPageSize]
		next = entries[len(entries)-1].ID
	}
	s.render(w, r, http.StatusOK, "audit", &page{Title: "audit.title", Tab: "audit",
		Data: map[string]any{"Entries": entries, "Next": next, "Now": time.Now()}})
}

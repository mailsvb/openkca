package store

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/pki"
)

// auditIf records an action in the database's audit log when err is nil.
// A failing log write is logged and does not undo the action.
func (h *Handle) auditIf(ctx context.Context, err error, action string, id int64, format string, args ...any) {
	if err != nil {
		return
	}
	if err := h.DB.Audit(ctx, action, id, fmt.Sprintf(format, args...)); err != nil {
		slog.Error("writing the audit log failed", "db", h.Name, "action", action, "err", err)
	}
}

// Audit records an action of the web layer (unlock, failed unlock).
func (h *Handle) Audit(ctx context.Context, action string, id int64, detail string) {
	h.auditIf(ctx, nil, action, id, "%s", detail)
}

// AuditLog returns audit entries newest first (all for itemID 0).
func (h *Handle) AuditLog(ctx context.Context, itemID, before int64, limit int) ([]db.AuditEntry, error) {
	return h.DB.AuditLog(ctx, itemID, before, limit)
}

func keySpecText(s pki.KeySpec) string {
	switch {
	case s.Bits != 0:
		return fmt.Sprintf("%s %d", s.Type, s.Bits)
	case s.Curve != "":
		return s.Type + " " + s.Curve
	case s.Param != "":
		return s.Type + " " + s.Param
	}
	return s.Type
}

func issueAction(p IssueParams) string {
	if p.Request {
		return "request.create"
	}
	return "cert.issue"
}

func issueDetail(p IssueParams) string {
	d := "self-signed"
	if p.SignerID != 0 {
		d = fmt.Sprintf("signed by %d", p.SignerID)
	}
	if p.Request {
		d = ""
	}
	if p.NewKey != nil {
		d += ", new key " + keySpecText(*p.NewKey)
	}
	if p.FromReqID != 0 {
		d += fmt.Sprintf(", from request %d", p.FromReqID)
	}
	return strings.TrimPrefix(d, ", ")
}

func settingsText(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s=%s", k, values[k])
	}
	return b.String()
}

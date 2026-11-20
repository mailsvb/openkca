// Package estserver serves the EST connectors (RFC 7030) of the databases
// OpenKCA holds open in the background, at /.well-known/est/<label>/.
//
// A connector signs with the database's background keyring, so it works
// only for a database configured with a password whose CA key is sealed
// with that keyring. Enrollment (simpleenroll) authenticates with HTTP
// Basic; re-enrollment (simplereenroll) with the client's current
// certificate, which this connector must have issued. cacerts and csrattrs
// need no authentication. Every request must have reached OpenKCA, or the
// trusted proxy in front of it, over TLS.
package estserver

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mailsvb/openkca/internal/auth"
	"github.com/mailsvb/openkca/internal/background"
	"github.com/mailsvb/openkca/internal/codec"
	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/est"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/store"
)

// PathPrefix is where the connectors are served.
const PathPrefix = "/.well-known/est/"

// maxBody limits a request body (a base64 CSR).
const maxBody = 64 << 10

// Options configure a Handler. The request functions come from the web
// server, which knows the trusted proxies.
type Options struct {
	Background *background.Holder
	Log        *slog.Logger
	ClientIP   func(*http.Request) string
	Secure     func(*http.Request) bool
	ClientCert func(*http.Request) *x509.Certificate
}

// Handler serves the EST connectors.
type Handler struct {
	opt   Options
	limit *auth.Limiter // failed authentications per client IP
	slots chan struct{} // concurrent password checks (Argon2id)
	now   func() time.Time
}

// New builds a handler.
func New(o Options) *Handler {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Handler{opt: o, limit: auth.NewLimiter(5, time.Minute), slots: make(chan struct{}, 2), now: time.Now}
}

// Sweep forgets failed authentications older than the limiter's window.
func (h *Handler) Sweep() { h.limit.Sweep() }

// target is a connector together with the background database it is in.
type target struct {
	bg   *background.Database
	snap *db.Snapshot
	c    *db.Connector
	cfg  est.Config
}

// Owners returns the background databases (store names) with a connector
// labelled label.
func (h *Handler) Owners(ctx context.Context, label string) []string {
	var out []string
	for _, d := range h.opt.Background.Databases() {
		snap, err := d.Handle.Snapshot(ctx)
		if err == nil && snap.ConnectorByLabel(label) != nil {
			out = append(out, d.Name)
		}
	}
	return out
}

// Served reports whether the database is open in the background, so that
// its connectors can be served.
func (h *Handler) Served(name string) bool { return h.opt.Background.Get(name) != nil }

// Problem reports why a connector of a background database cannot serve
// requests: "" when it can, else a reason code (store.ConnCA*, or
// "disabled", "not_background", "label_conflict", "config").
func (h *Handler) Problem(ctx context.Context, dbName string, snap *db.Snapshot, c *db.Connector) string {
	switch {
	case !c.Enabled:
		return "disabled"
	case !h.Served(dbName):
		return "not_background"
	case len(h.Owners(ctx, c.Label)) > 1:
		return "label_conflict"
	}
	if p := store.ConnectorCAProblem(snap, c, h.now()); p != "" {
		return p
	}
	cfg, err := est.Parse([]byte(c.Config))
	if err != nil || len(cfg.Validate()) > 0 {
		return "config"
	}
	return ""
}

// estError is an error answered with a status code and a text body.
type estError struct {
	status int
	msg    string
}

func (e *estError) Error() string { return e.msg }

func fail(status int, format string, a ...any) error {
	return &estError{status, fmt.Sprintf(format, a...)}
}

// lookup finds the connector for label and checks that it can serve.
func (h *Handler) lookup(ctx context.Context, label string) (*target, error) {
	var found []*target
	for _, d := range h.opt.Background.Databases() {
		snap, err := d.Handle.Snapshot(ctx)
		if err != nil {
			continue
		}
		if c := snap.ConnectorByLabel(label); c != nil {
			found = append(found, &target{bg: d, snap: snap, c: c})
		}
	}
	switch {
	case len(found) == 0:
		return nil, fail(http.StatusNotFound, "no EST connector %q", label)
	case len(found) > 1:
		h.opt.Log.Warn("EST label used by more than one database, not served", "label", label)
		return nil, fail(http.StatusServiceUnavailable, "the connector is not available")
	}
	t := found[0]
	if p := h.Problem(ctx, t.bg.Name, t.snap, t.c); p != "" {
		h.opt.Log.Warn("EST connector not available", "db", t.bg.Name, "label", label, "reason", p)
		return nil, fail(http.StatusServiceUnavailable, "the connector is not available")
	}
	t.cfg, _ = est.Parse([]byte(t.c.Config))
	return t, nil
}

// ServeHTTP answers /.well-known/est/<label>/<operation>.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest, ok := strings.CutPrefix(r.URL.Path, PathPrefix)
	label, op, _ := strings.Cut(rest, "/")
	if !ok || !store.ValidConnectorLabel(label) || strings.Contains(op, "/") {
		http.NotFound(w, r)
		return
	}
	ctx := db.WithClient(r.Context(), h.opt.ClientIP(r))
	r = r.WithContext(ctx)
	err := h.serve(w, r, label, op)
	var e *estError
	switch {
	case err == nil:
		return
	case errors.As(err, &e):
		if e.status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="EST `+label+`", charset="UTF-8"`)
		}
		http.Error(w, e.msg, e.status)
	default:
		h.opt.Log.Error("EST request failed", "label", label, "op", op, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request, label, op string) error {
	if !h.opt.Secure(r) {
		return fail(http.StatusForbidden, "EST requires HTTPS")
	}
	method := http.MethodPost
	if op == "cacerts" || op == "csrattrs" {
		method = http.MethodGet
	}
	switch op {
	case "cacerts", "csrattrs", "simpleenroll", "simplereenroll":
	default:
		return fail(http.StatusNotFound, "operation %q is not supported", op)
	}
	if r.Method != method && !(method == http.MethodGet && r.Method == http.MethodHead) {
		w.Header().Set("Allow", method)
		return fail(http.StatusMethodNotAllowed, "use %s", method)
	}
	if h.limit.Blocked(h.opt.ClientIP(r)) {
		return fail(http.StatusTooManyRequests, "too many failed attempts, try again later")
	}
	t, err := h.lookup(r.Context(), label)
	if err != nil {
		return err
	}
	switch op {
	case "cacerts":
		return h.cacerts(w, t)
	case "csrattrs":
		return h.csrattrs(w, t)
	case "simpleenroll":
		return h.enroll(w, r, t, nil)
	default:
		old, err := h.currentCert(r, t)
		if err != nil {
			return err
		}
		return h.enroll(w, r, t, old)
	}
}

// writeBase64 answers with base64 DER in lines of 64 characters.
func writeBase64(w http.ResponseWriter, contentType string, der []byte) error {
	s := base64.StdEncoding.EncodeToString(der)
	var b strings.Builder
	for len(s) > 64 {
		b.WriteString(s[:64])
		b.WriteString("\r\n")
		s = s[64:]
	}
	b.WriteString(s)
	b.WriteString("\r\n")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	_, err := io.WriteString(w, b.String())
	return err
}

// chain returns the CA certificate followed by its issuers in the database.
func chain(snap *db.Snapshot, caID int64) [][]byte {
	byID := map[int64]*db.Cert{}
	for _, c := range snap.Certs {
		byID[c.ID] = c
	}
	var out [][]byte
	for id, seen := caID, map[int64]bool{}; id != 0 && !seen[id]; {
		c := byID[id]
		if c == nil {
			break
		}
		seen[id] = true
		out = append(out, c.DER)
		id = c.IssuerID
	}
	return out
}

func (h *Handler) caCert(t *target) (*db.Cert, *x509.Certificate, error) {
	for _, c := range t.snap.Certs {
		if c.ID == t.c.CAID {
			cc, err := pki.ParseCertificate(c.DER)
			return c, cc, err
		}
	}
	return nil, nil, fail(http.StatusServiceUnavailable, "the connector is not available")
}

func (h *Handler) cacerts(w http.ResponseWriter, t *target) error {
	p7, err := codec.PKCS7(chain(t.snap, t.c.CAID))
	if err != nil {
		return err
	}
	return writeBase64(w, "application/pkcs7-mime", p7)
}

// basicAuth checks the connector's user name and password. Failures are
// counted per client before the (expensive) password check.
func (h *Handler) basicAuth(r *http.Request, t *target) error {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return fail(http.StatusUnauthorized, "authentication required")
	}
	ip := h.opt.ClientIP(r)
	h.limit.Fail(ip)
	h.slots <- struct{}{}
	good := t.cfg.Auth.User != "" && t.cfg.Auth.PassHash != "" &&
		subtle.ConstantTimeCompare([]byte(user), []byte(t.cfg.Auth.User)) == 1 &&
		auth.CheckPassword(t.cfg.Auth.PassHash, []byte(pass))
	<-h.slots
	if !good {
		h.reject(r, t, "authentication failed")
		return fail(http.StatusUnauthorized, "authentication failed")
	}
	h.limit.Reset(ip)
	return nil
}

// currentCert authenticates a re-enrollment: the client's certificate must
// be one this connector issued, unexpired and not revoked.
func (h *Handler) currentCert(r *http.Request, t *target) (*x509.Certificate, error) {
	if !t.cfg.Auth.Reenroll {
		return nil, fail(http.StatusForbidden, "re-enrollment is not enabled for this connector")
	}
	cc := h.opt.ClientCert(r)
	if cc == nil {
		return nil, fail(http.StatusUnauthorized, "re-enrollment requires the current certificate as TLS client certificate")
	}
	var stored *db.Cert
	for _, c := range t.snap.Certs {
		if c.ConnectorID == t.c.ID && string(c.DER) == string(cc.Raw) {
			stored = c
		}
	}
	now := h.now()
	reason := ""
	switch {
	case stored == nil:
		reason = "the client certificate was not issued by this connector"
	case now.After(cc.NotAfter) || now.Before(cc.NotBefore):
		reason = "the client certificate is not valid now"
	case revoked(t.snap, stored):
		reason = "the client certificate is revoked"
	}
	if reason != "" {
		h.limit.Fail(h.opt.ClientIP(r))
		h.reject(r, t, reason)
		return nil, fail(http.StatusForbidden, "%s", reason)
	}
	return cc, nil
}

func revoked(snap *db.Snapshot, c *db.Cert) bool {
	for _, r := range snap.Revocations {
		if r.CAID == c.IssuerID && r.Serial == c.Serial {
			return true
		}
	}
	return false
}

// readCSR reads a base64 PKCS#10 body; plain DER is accepted too.
func readCSR(r *http.Request) ([]byte, error) {
	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if ct != "" && ct != "application/pkcs10" {
		return nil, fail(http.StatusUnsupportedMediaType, "the request must be application/pkcs10")
	}
	b, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBody))
	if err != nil {
		return nil, fail(http.StatusRequestEntityTooLarge, "the request is too large")
	}
	if len(b) > 0 && b[0] == 0x30 {
		return b, nil
	}
	clean := strings.Map(func(c rune) rune {
		if c == ' ' || c == '\r' || c == '\n' || c == '\t' {
			return -1
		}
		return c
	}, string(b))
	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil || len(der) == 0 {
		return nil, fail(http.StatusBadRequest, "the request is not a base64 PKCS#10 CSR")
	}
	return der, nil
}

func (h *Handler) enroll(w http.ResponseWriter, r *http.Request, t *target, old *x509.Certificate) error {
	if old == nil {
		if err := h.basicAuth(r, t); err != nil {
			return err
		}
	}
	csr, err := readCSR(r)
	if err != nil {
		return err
	}
	ca, cc, err := h.caCert(t)
	if err != nil {
		return err
	}
	now := h.now()
	d, violations := est.Evaluate(t.cfg, cc, csr, now)
	if len(violations) == 0 && old != nil {
		violations = sameIdentity(old, d)
	}
	if len(violations) > 0 {
		reasons := make([]string, len(violations))
		for i, v := range violations {
			reasons[i] = v.String()
		}
		msg := strings.Join(reasons, "\n")
		h.reject(r, t, strings.Join(reasons, "; "))
		status := http.StatusForbidden
		if slices.ContainsFunc(violations, func(v est.Violation) bool { return v.Field == "csr" || v.Field == "signature" }) {
			status = http.StatusBadRequest
		}
		return fail(status, "%s", msg)
	}
	action := "est.enroll"
	if old != nil {
		action = "est.reenroll"
	}
	name := cnOf(d.Subject)
	if name == "" {
		name = t.c.Label
	}
	kr := t.bg.Keyring()
	if kr == nil {
		return fail(http.StatusServiceUnavailable, "the connector is not available")
	}
	_, der, err := t.bg.Handle.IssueCSR(r.Context(), store.CSRIssue{Name: name, Comment: "EST: " + t.c.Name, CSR: csr,
		Subject: d.Subject, Ext: d.Ext, SignerID: ca.ID, NotBefore: d.NotBefore, NotAfter: d.NotAfter, Hash: d.Hash,
		ConnectorID: t.c.ID, Action: action, Detail: "connector " + t.c.Label}, kr)
	if err != nil {
		h.reject(r, t, err.Error())
		return fail(http.StatusBadRequest, "%v", err)
	}
	h.opt.Log.Info("EST certificate issued", "db", t.bg.Name, "label", t.c.Label, "subject", name, "client", h.opt.ClientIP(r))
	p7, err := codec.PKCS7([][]byte{der})
	if err != nil {
		return err
	}
	return writeBase64(w, "application/pkcs7-mime; smime-type=certs-only", p7)
}

// reject records a refused request in the database's audit log.
func (h *Handler) reject(r *http.Request, t *target, reason string) {
	t.bg.Handle.Audit(r.Context(), "est.rejected", 0, fmt.Sprintf("connector %s: %s", t.c.Label, reason))
	h.opt.Log.Warn("EST request refused", "db", t.bg.Name, "label", t.c.Label, "client", h.opt.ClientIP(r), "reason", reason)
}

func cnOf(attrs []pki.DNAttr) string {
	for _, a := range attrs {
		if a.Name == "CN" {
			return a.Value
		}
	}
	return ""
}

// sameIdentity checks RFC 7030 4.2.2: a re-enrollment keeps the subject
// and the alternative names of the certificate it renews.
func sameIdentity(old *x509.Certificate, d est.Decision) []est.Violation {
	var out []est.Violation
	if !slices.Equal(pki.NameAttrs(old.RawSubject), d.Subject) {
		out = append(out, est.Violation{Field: "subject", Reason: "a re-enrollment must keep the subject of the current certificate"})
	}
	if !slices.Equal(sanSet(old), specSANs(d.Ext.SubAltName)) {
		out = append(out, est.Violation{Field: "san", Reason: "a re-enrollment must keep the alternative names of the current certificate"})
	}
	return out
}

func sanSet(c *x509.Certificate) []string {
	var out []string
	for _, n := range c.DNSNames {
		out = append(out, "dns:"+strings.ToLower(n))
	}
	for _, n := range c.IPAddresses {
		out = append(out, "ip:"+n.String())
	}
	for _, n := range c.EmailAddresses {
		out = append(out, "email:"+strings.ToLower(n))
	}
	for _, n := range c.URIs {
		out = append(out, "uri:"+n.String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func specSANs(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ",") {
		typ, v, ok := strings.Cut(strings.TrimSpace(e), ":")
		if !ok {
			continue
		}
		typ = strings.ToLower(typ)
		if typ == "dns" || typ == "email" {
			v = strings.ToLower(v)
		}
		out = append(out, typ+":"+v)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// csrattrs lists the key algorithms the connector accepts (RFC 7030
// 4.5.2): an OID per algorithm, for EC an attribute with the curves.
func (h *Handler) csrattrs(w http.ResponseWriter, t *target) error {
	var attrs []asn1.RawValue
	add := func(v any) {
		if b, err := asn1.Marshal(v); err == nil {
			attrs = append(attrs, asn1.RawValue{FullBytes: b})
		}
	}
	k := t.cfg.Keys
	if k.RSAMinBits > 0 {
		add(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1})
	}
	if len(k.ECCurves) > 0 {
		var curves []asn1.ObjectIdentifier
		for _, c := range k.ECCurves {
			if oid, ok := curveOID(c); ok {
				curves = append(curves, oid)
			}
		}
		add(struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.ObjectIdentifier `asn1:"set"`
		}{asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, curves})
	}
	for _, names := range [][]string{k.EdDSA, k.MLDSA, k.SLHDSA, k.Composite} {
		for _, n := range names {
			if oid, ok := pki.OIDByName(n); ok {
				add(oid)
			}
		}
	}
	der, err := asn1.Marshal(attrs)
	if err != nil {
		return err
	}
	return writeBase64(w, "application/csrattrs", der)
}

var nistCurves = map[string]asn1.ObjectIdentifier{
	"P-256": {1, 2, 840, 10045, 3, 1, 7},
	"P-384": {1, 3, 132, 0, 34},
	"P-521": {1, 3, 132, 0, 35},
}

func curveOID(name string) (asn1.ObjectIdentifier, bool) {
	if oid, ok := nistCurves[name]; ok {
		return oid, true
	}
	return pki.OIDByName(name)
}

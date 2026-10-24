// Package pubserve is the plain HTTP server for what package publish
// writes: each CA's newest CRL and its certificate, addressed by the CA's
// authority ID, the same URLs go-ca puts into CRL distribution points and
// authority information access:
//
//	GET /<authority ID>.crl   the CRL (DER, application/pkix-crl)
//	GET /<authority ID>.crt   the CA certificate (DER, application/pkix-cert)
//	GET /<authority ID>.pem   the CA certificate (PEM)
//
// Any path before the last element is ignored (base URLs may have one).
// Anything else is 404, methods other than GET and HEAD 405. The server
// reads the files from disk on every request, so it serves the CAs of all
// databases, open or not. It also watches the published CRLs' next update
// (Monitor).
package pubserve

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mailsvb/go-ca/internal/cadir"
	"github.com/mailsvb/go-ca/internal/publish"
)

// MaxAge is how long clients and proxies may cache a response: short, so
// that a CRL re-signed after a revocation reaches them quickly.
const MaxAge = 5 * time.Minute

// Handler serves the published files below a data folder.
type Handler struct {
	Dir string // the data folder
	Log *slog.Logger
}

// find returns the newest file of one CA folder (authority IDs are unique,
// but a copied database file brings its CAs' IDs along).
func (h *Handler) find(id, file string) (string, os.FileInfo) {
	matches, _ := filepath.Glob(filepath.Join(h.Dir, cadir.Root, "*", id, file))
	var path string
	var info os.FileInfo
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if info == nil || fi.ModTime().After(info.ModTime()) {
			path, info = m, fi
		}
	}
	return path, info
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Only the last path element counts, so that a base URL with a path
	// (http://host/pki) works whether or not a proxy strips it.
	id, ext, _ := strings.Cut(path.Base(r.URL.Path), ".")
	if !cadir.IsUUID(id) {
		http.NotFound(w, r)
		return
	}
	var file, ctype string
	switch ext {
	case "crl":
		file, ctype = publish.CRLFile, "application/pkix-crl"
	case "crt":
		file, ctype = publish.CertFile, "application/pkix-cert"
	case "pem":
		file, ctype = publish.CertFile, "application/x-pem-file"
	default:
		http.NotFound(w, r)
		return
	}
	file, fi := h.find(id, file)
	if file == "" {
		http.NotFound(w, r)
		return
	}
	data, err := os.ReadFile(file)
	if err != nil {
		h.Log.Error("reading a published file failed", "path", file, "err", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if ext == "pem" {
		data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data})
	}
	sum := sha256.Sum256(data)
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(MaxAge/time.Second)))
	http.ServeContent(w, r, "", fi.ModTime(), bytes.NewReader(data))
}

// NewServer returns the plain HTTP server for h with conservative limits.
func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}

// Warning is how long before its next update a CRL is reported as
// expiring.
const Warning = 7 * 24 * time.Hour

// Alert reports a published CRL that expires soon or has expired.
type Alert struct {
	DB          string // the database's name (its folder below ca/)
	AuthorityID string
	Issuer      string // the CRL issuer's name
	NextUpdate  time.Time
	Expired     bool
}

// Monitor checks the published CRLs of all databases.
type Monitor struct {
	Dir string
	Log *slog.Logger

	mu     sync.Mutex
	alerts []Alert
}

// Check reads every published CRL and returns those whose next update is
// less than Warning away or past, expired ones first. It also keeps them
// for Alerts and logs them.
func (m *Monitor) Check(now time.Time) []Alert {
	matches, _ := filepath.Glob(filepath.Join(m.Dir, cadir.Root, "*", "*", publish.CRLFile))
	var out []Alert
	for _, p := range matches {
		id := filepath.Base(filepath.Dir(p))
		if !cadir.IsUUID(id) {
			continue
		}
		der, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		l, err := x509.ParseRevocationList(der)
		if err != nil || l.NextUpdate.IsZero() {
			continue
		}
		if l.NextUpdate.Sub(now) > Warning {
			continue
		}
		a := Alert{DB: filepath.Base(filepath.Dir(filepath.Dir(p))), AuthorityID: id, Issuer: l.Issuer.String(),
			NextUpdate: l.NextUpdate, Expired: !now.Before(l.NextUpdate)}
		out = append(out, a)
		if a.Expired {
			m.Log.Error("published CRL has expired", "db", a.DB, "ca", a.Issuer, "authority", id, "next_update", a.NextUpdate)
		} else {
			m.Log.Warn("published CRL expires soon", "db", a.DB, "ca", a.Issuer, "authority", id, "next_update", a.NextUpdate)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Expired != out[j].Expired {
			return out[i].Expired
		}
		return out[i].NextUpdate.Before(out[j].NextUpdate)
	})
	m.mu.Lock()
	m.alerts = out
	m.mu.Unlock()
	return out
}

// Alerts returns the result of the last Check.
func (m *Monitor) Alerts() []Alert {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Alert(nil), m.alerts...)
}

// Run checks at once and then every interval until ctx ends.
func (m *Monitor) Run(ctx context.Context, interval time.Duration) {
	m.Check(time.Now())
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Check(time.Now())
		}
	}
}

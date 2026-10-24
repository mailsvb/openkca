package store

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/publish"
	"github.com/mailsvb/go-ca/internal/vault"
)

// AutoCRL says whether and why go-ca signs a CA's CRL on its own.
type AutoCRL string

const (
	AutoCRLOn      AutoCRL = "on"      // the key is sealed with the DEK
	AutoCRLOwnPass AutoCRL = "ownpass" // the key has its own password
	AutoCRLNoKey   AutoCRL = "nokey"   // no private key in the database (or on a token)
)

// AutoCRLState reports whether go-ca can sign a CA's CRL with the
// database keyring alone.
func AutoCRLState(snap *gcadb.Snapshot, ca *gcadb.Cert) AutoCRL {
	k := findKey(snap, ca.KeyID)
	switch {
	case k == nil || !k.HasPrivate || k.Token:
		return AutoCRLNoKey
	case k.Protection != gcadb.ProtDEK:
		return AutoCRLOwnPass
	}
	return AutoCRLOn
}

// CRLDue reports whether a CA needs a new CRL at now, and why: it has none
// yet; half of the newest CRL's validity has passed; or the entries the CA
// publishes (revocations added, edited or removed, or aged out) differ
// from those on it.
func CRLDue(snap *gcadb.Snapshot, ca *gcadb.Cert, newest *gcadb.CRL, now time.Time) (bool, string) {
	if newest == nil {
		return true, "no CRL yet"
	}
	l, err := x509.ParseRevocationList(newest.DER)
	if err != nil {
		return true, "the newest CRL cannot be read"
	}
	if !l.NextUpdate.IsZero() && !now.Before(l.ThisUpdate.Add(l.NextUpdate.Sub(l.ThisUpdate)/2)) {
		return true, "half of its validity has passed"
	}
	want := map[string]bool{}
	for _, r := range snap.Revocations {
		if r.CAID == ca.ID && r.OnCRL(now) {
			want[entryKey(r.Serial, r.Date, r.ReasonBit, r.InvalDate)] = true
		}
	}
	have := map[string]bool{}
	for _, e := range l.RevokedCertificateEntries {
		var inval time.Time
		for _, x := range e.Extensions {
			if x.Id.Equal(oidInvalidityDate) {
				asn1.UnmarshalWithParams(x.Value, &inval, "generalized")
			}
		}
		have[entryKey(pki.SerialHex(e.SerialNumber), e.RevocationTime, e.ReasonCode, inval)] = true
	}
	if len(want) != len(have) {
		return true, "its entries changed"
	}
	for k := range want {
		if !have[k] {
			return true, "its entries changed"
		}
	}
	return false, ""
}

var oidInvalidityDate = asn1.ObjectIdentifier{2, 5, 29, 24}

// entryKey identifies a CRL entry as published: CreateCRL leaves out the
// reason "unspecified" and invalidity dates from year 9999 on.
func entryKey(serial string, date time.Time, reason int, inval time.Time) string {
	if inval.Year() >= 9999 {
		inval = time.Time{}
	}
	if reason == pki.ReasonUnspecified {
		reason = 0
	}
	iv := ""
	if !inval.IsZero() {
		iv = inval.UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	return fmt.Sprintf("%s|%s|%d|%s", strings.ToUpper(serial), date.UTC().Truncate(time.Second).Format(time.RFC3339), reason, iv)
}

// SignDueCRLs signs a new CRL, with the CA's defaults, for every live CA
// whose key the keyring opens and whose CRL is due (CRLDue). It returns
// the IDs of the CAs it signed for; a CA that fails is logged and skipped.
func (h *Handle) SignDueCRLs(ctx context.Context, kr *vault.Keyring, now time.Time) ([]int64, error) {
	h.crlMu.Lock()
	defer h.crlMu.Unlock()
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	newest := publish.NewestCRLs(snap)
	var cas []*gcadb.Cert
	for _, c := range snap.Certs {
		if c.CA && c.Authority != nil && AutoCRLState(snap, c) == AutoCRLOn {
			cas = append(cas, c)
		}
	}
	sort.Slice(cas, func(i, j int) bool { return cas[i].ID < cas[j].ID })
	var signed []int64
	for _, ca := range cas {
		due, why := CRLDue(snap, ca, newest[ca.ID], now)
		if !due {
			continue
		}
		// The snapshot may have changed with the previous CA's CRL.
		cur, err := h.Snapshot(ctx)
		if err != nil {
			return signed, err
		}
		o := DefaultCRLOptions(cur, findCert(cur, ca.ID))
		if _, err := h.GenerateCRL(ctx, ca.ID, o, kr, nil); err != nil {
			slog.Error("automatic CRL failed", "db", h.Name, "ca", ca.Name, "err", err)
			h.Audit(ctx, "crl.auto_failed", ca.ID, err.Error())
			continue
		}
		slog.Info("CRL signed automatically", "db", h.Name, "ca", ca.Name, "reason", why, "number", o.Number,
			"next_update", o.NextUpdate.Format(time.RFC3339))
		signed = append(signed, ca.ID)
	}
	return signed, nil
}

// SignCRLNow signs a new CRL for a CA with its defaults (the one-click
// re-signing in the UI); kp holds the CA key's own password, if it has one.
func (h *Handle) SignCRLNow(ctx context.Context, caID int64, kr *vault.Keyring, kp KeyPasswords) (int64, error) {
	h.crlMu.Lock()
	defer h.crlMu.Unlock()
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	ca := findCert(snap, caID)
	if ca == nil || !ca.CA {
		return 0, fmt.Errorf("item %d is not a CA certificate", caID)
	}
	return h.GenerateCRL(ctx, caID, DefaultCRLOptions(snap, ca), kr, kp)
}

// Watch returns a channel that receives (without blocking the writer, at
// most one pending signal) after every change made through this handle.
func (h *Handle) Watch() <-chan struct{} {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	h.watchers = append(h.watchers, ch)
	h.mu.Unlock()
	return ch
}

func (h *Handle) notify() {
	h.mu.Lock()
	ws := h.watchers
	h.mu.Unlock()
	for _, ch := range ws {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// PublishedURLs returns where a CA's CRL and certificate are published,
// nil when no base URLs are configured or ca is not a CA with an
// authority ID.
func (s *Store) PublishedURLs(ca *gcadb.Cert) (crl, cert []string) {
	if ca == nil || !ca.CA || ca.Authority == nil || len(s.BaseURLs) == 0 {
		return nil, nil
	}
	return pki.PublishedURLs(s.BaseURLs, ca.Authority.UUID)
}

// withPublished resolves spec.PubCDP and spec.PubAIA for issuer ca (nil
// for self-signed certificates and requests, which get neither) into
// CRLMirrors and CAIssuers. Free-text entries naming the same URLs are
// dropped, so a certificate copied into the editor does not list them
// twice.
func (s *Store) withPublished(spec pki.ExtSpec, ca *gcadb.Cert) pki.ExtSpec {
	crl, cert := s.PublishedURLs(ca)
	if spec.PubCDP && len(crl) > 0 {
		spec.CRLMirrors = crl
		spec.CRLDist = dropURIs(spec.CRLDist, crl, "")
	}
	if spec.PubAIA && len(cert) > 0 {
		spec.CAIssuers = cert
		spec.AuthInfAcc = dropURIs(spec.AuthInfAcc, cert, "caissuers;")
	}
	return spec
}

// dropURIs removes the comma separated entries "[method;]URI:<u>" whose
// URL is one of urls (and whose method, lower case, is prefix).
func dropURIs(list string, urls []string, prefix string) string {
	skip := map[string]bool{}
	for _, u := range urls {
		skip[u] = true
	}
	var keep []string
	for _, item := range strings.Split(list, ",") {
		it := strings.TrimSpace(item)
		if it == "" {
			continue
		}
		rest := it
		if prefix != "" {
			m, loc, ok := strings.Cut(it, ";")
			if !ok || strings.ToLower(strings.TrimSpace(m))+";" != prefix {
				keep = append(keep, it)
				continue
			}
			rest = strings.TrimSpace(loc)
		}
		if typ, u, ok := strings.Cut(rest, ":"); ok && strings.EqualFold(typ, "URI") && skip[strings.TrimSpace(u)] {
			continue
		}
		keep = append(keep, it)
	}
	return strings.Join(keep, ", ")
}

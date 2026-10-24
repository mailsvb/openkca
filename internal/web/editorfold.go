package web

import (
	"slices"
	"strings"

	"github.com/mailsvb/go-ca/internal/gcadb"
	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/store"
)

// keyAlgorithmOf is the key type ("EC:P-256", or "RSA:" for a stored RSA
// key) a form's extensions depend on: the existing key's, the request's
// or the new key's.
func keyAlgorithmOf(snap *gcadb.Snapshot, existing bool, keyID, fromReq int64, newKey string) string {
	var spki []byte
	switch {
	case fromReq != 0:
		for _, rq := range snap.Requests {
			if rq.ID == fromReq {
				if req, err := pki.ParseCertificateRequest(rq.DER); err == nil {
					spki = req.RawSubjectPublicKeyInfo
				}
			}
		}
	case existing:
		for _, k := range snap.Keys {
			if k.ID == keyID {
				spki = k.Public
			}
		}
	}
	if spki == nil {
		return newKey
	}
	return pki.DescribePublicKey(spki).Algorithm + ":"
}

func (f *editorForm) keyAlgorithm(snap *gcadb.Snapshot) string {
	fromReq := f.FromReq
	if f.Kind != "cert" {
		fromReq = 0
	}
	return keyAlgorithmOf(snap, f.KeyMode == "existing", f.KeyID, fromReq, f.NewKey)
}

// applyProfile sets key type, validity, hash and extensions of a profile;
// the subject and its alternative names stay.
func (f *editorForm) applyProfile(p *profile, snap *gcadb.Snapshot) {
	if f.KeyMode != "existing" && f.FromReq == 0 {
		f.NewKey = p.Key
	}
	san, pubCDP, pubAIA := f.Ext.SubAltName, f.Ext.PubCDP, f.Ext.PubAIA
	f.Ext = p.ext(f.keyAlgorithm(snap))
	f.Ext.SubAltName, f.Ext.PubCDP, f.Ext.PubAIA = san, pubCDP, pubAIA
	v := p.defaultValidity()
	f.ValidN, f.ValidUnit, f.NotAfter, f.Midnight, f.NoExpiry = v.N, v.Unit, "", false, false
	f.Hash = store.Hash(snap)
	f.Profile, f.TemplateID = p.ID, 0
}

// editorSums are the one-line summaries of the folded editor sections.
type editorSums struct{ Key, Validity, Ext string }

func (f *editorForm) summaries(t func(string, ...any) string, snap *gcadb.Snapshot) editorSums {
	var s editorSums
	switch {
	case f.Kind == "cert" && f.FromReq != 0:
		name := ""
		for _, rq := range snap.Requests {
			if rq.ID == f.FromReq {
				name = rq.Name
			}
		}
		s.Key = t("editor.sum.fromreq", name)
	case f.KeyMode == "existing":
		s.Key = t("editor.sum.nokey")
		for _, k := range snap.Keys {
			if k.ID == f.KeyID {
				s.Key = t("editor.sum.existing", k.Name)
			}
		}
	default:
		s.Key = t("editor.sum.newkey", keyLabel(f.NewKey))
	}
	if f.Hash == pki.HashAuto {
		s.Key += " · " + t("editor.sum.hashauto")
	} else if f.Hash != "" {
		s.Key += " · " + t("hash."+f.Hash)
	}
	switch {
	case f.NoExpiry:
		s.Validity = t("cert.noexpiry")
	case f.NotAfter != "" && f.Kind == "cert":
		s.Validity = t("editor.sum.until", strings.Replace(f.NotAfter, "T", " ", 1))
	case f.ValidN > 0:
		s.Validity = validityText(t, validity{f.ValidN, f.ValidUnit})
	}
	e := f.Ext
	var parts []string
	switch e.CA {
	case 1:
		ca := "CA"
		if e.PathLen != "" {
			ca += ", pathlen " + e.PathLen
		}
		parts = append(parts, ca)
	case 2:
		parts = append(parts, "CA:FALSE")
	}
	var ku []string
	for i, n := range pki.KeyUsageNames {
		if e.KeyUse&(1<<i) != 0 {
			ku = append(ku, n)
		}
	}
	if len(ku) > 0 {
		parts = append(parts, strings.Join(ku, ", "))
	}
	if len(e.EKU) > 0 {
		parts = append(parts, strings.Join(e.EKU, ", "))
	}
	if e.CRLDist != "" || e.PubCDP && f.Kind != "request" {
		parts = append(parts, "CRL")
	}
	if e.AuthInfAcc != "" || e.PubAIA && f.Kind != "request" {
		parts = append(parts, "AIA")
	}
	s.Ext = strings.Join(parts, " · ")
	if s.Ext == "" {
		s.Ext = t("editor.sum.none")
	}
	return s
}

// profileDiff lists where the form differs from the profile it started
// from.
func (f *editorForm) profileDiff(t func(string, ...any) string, snap *gcadb.Snapshot) []string {
	p := profileByID(f.Profile)
	if p == nil || p.Link != "" {
		return nil
	}
	var out []string
	want := p.ext(f.keyAlgorithm(snap))
	e := f.Ext
	if f.Kind != "template" && f.KeyMode != "existing" && f.FromReq == 0 && f.NewKey != p.Key {
		out = append(out, t("editor.diff.key", keyLabel(p.Key), keyLabel(f.NewKey)))
	}
	if v := p.defaultValidity(); f.Kind != "request" && (f.ValidN != v.N || f.ValidUnit != v.Unit || f.NotAfter != "" || f.NoExpiry) {
		out = append(out, t("editor.diff.validity", validityText(t, v)))
	}
	if e.CA != want.CA || e.PathLen != want.PathLen || e.BCCritical != want.BCCritical {
		out = append(out, t("editor.diff.bc"))
	}
	if e.SubKey != want.SubKey || f.Kind != "request" && e.AuthKey != want.AuthKey {
		out = append(out, t("editor.diff.keyids"))
	}
	if e.KeyUse != want.KeyUse || e.KUCritical != want.KUCritical {
		out = append(out, t("editor.diff.ku"))
	}
	if !slices.Equal(e.EKU, want.EKU) || e.EKUCrit != want.EKUCrit {
		out = append(out, t("editor.diff.eku"))
	}
	if f.Kind != "template" && f.Hash != store.Hash(snap) {
		out = append(out, t("editor.diff.hash", t("hash."+f.Hash)))
	}
	if e.CRLDist != "" || e.AuthInfAcc != "" || e.IssAltName != "" || e.NameCons != "" || e.OCSPStaple || e.AdvExt != "" {
		out = append(out, t("editor.diff.more"))
	}
	if netscapeSet(e) {
		out = append(out, t("editor.diff.netscape"))
	}
	return out
}

func netscapeSet(e pki.ExtSpec) bool {
	return e.NSCertType != 0 || e.NSComment != "" || e.NSBaseURL != "" || e.NSRevocationURL != "" ||
		e.NSCARevocationURL != "" || e.NSRenewalURL != "" || e.NSCAPolicyURL != "" || e.NSSSLServerName != ""
}

// expertUsed names the expert fields that hold a value, for the note shown
// while they are hidden ("" when none does).
func (f *editorForm) expertUsed(t func(string, ...any) string, snap *gcadb.Snapshot) string {
	var used []string
	e := f.Ext
	if f.Kind != "template" && f.Hash != store.Hash(snap) {
		used = append(used, t("editor.hash"))
	}
	if e.IssAltName != "" && f.Kind != "request" {
		used = append(used, t("editor.ian"))
	}
	if e.NameCons != "" {
		used = append(used, t("editor.namecons"))
	}
	if e.OCSPStaple {
		used = append(used, t("editor.ocspstaple"))
	}
	if e.AdvExt != "" {
		used = append(used, t("editor.advanced"))
	}
	if netscapeSet(e) && snap.Settings["disable_netscape"] != "yes" {
		used = append(used, t("editor.netscape"))
	}
	return strings.Join(used, ", ")
}

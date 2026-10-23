package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mailsvb/go-ca/internal/pki"
	"github.com/mailsvb/go-ca/internal/tmpl"
	"github.com/mailsvb/go-ca/internal/xdb"
)

// TemplateData is a template as the editor handles it.
type TemplateData struct {
	ID       int64 // 0 = new
	Name     string
	Comment  string
	Subject  []pki.DNAttr
	Ext      pki.ExtSpec
	Validity tmpl.Validity
	Source   int
}

// LoadTemplate decodes a stored template.
func (h *Handle) LoadTemplate(ctx context.Context, id int64) (*TemplateData, error) {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range snap.Templates {
		if t.ID == id {
			tp, err := tmpl.Decode(t.Blob, t.Version)
			if err != nil {
				return nil, err
			}
			return &TemplateData{ID: id, Name: t.Name, Comment: t.Comment, Subject: pki.NameAttrs(tp.Subject),
				Ext: tp.Spec(), Validity: tp.Validity(), Source: t.Source}, nil
		}
	}
	return nil, errors.New("template not found")
}

// SaveTemplate inserts or updates a template. The subject may be empty.
func (h *Handle) SaveTemplate(ctx context.Context, d TemplateData) (int64, error) {
	if strings.TrimSpace(d.Name) == "" {
		return 0, errors.New("the internal name must not be empty")
	}
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	subject := []byte{0x30, 0x00}
	if len(d.Subject) > 0 {
		if subject, err = pki.BuildName(d.Subject, snap.Settings["string_opt"]); err != nil {
			return 0, err
		}
	}
	// The extensions must be valid; check them with a throwaway key.
	if _, err := pki.BuildExtensions(d.Ext, pki.ExtContext{SubjectSPKI: placeholderSPKI(), IssuerSPKI: placeholderSPKI()}); err != nil {
		return 0, err
	}
	blob := tmpl.Encode(tmpl.New(subject, d.Ext, d.Validity))
	id := d.ID
	source := d.Source
	if source == 0 {
		source = 2
	}
	err = h.DB.Write(ctx, func(tx *xdb.Tx) error {
		if id == 0 {
			id, err = tx.InsertTemplate(ctx, d.Name, d.Comment, source, blob)
			return err
		}
		return tx.UpdateTemplate(ctx, id, d.Name, d.Comment, blob)
	})
	h.changed(ctx)
	return id, err
}

var placeholder []byte

func placeholderSPKI() []byte {
	if placeholder == nil {
		k, _ := pki.GenerateKey(pki.KeySpec{Type: "Ed25519"})
		placeholder, _ = pki.MarshalPublicKey(k.Public())
	}
	return placeholder
}

// orderSubject puts explicit_dn entries first, then the rest, as
// pki_temp::fromCert does.
func orderSubject(attrs []pki.DNAttr, explicit string) []pki.DNAttr {
	if explicit == "" {
		explicit = "C,ST,L,O,OU,CN,emailAddress"
	}
	used := make([]bool, len(attrs))
	var out []pki.DNAttr
	for _, e := range strings.Split(explicit, ",") {
		oid, err := pki.AttrOID(strings.TrimSpace(e))
		if err != nil {
			continue
		}
		short := pki.AttrShortName(oid)
		for i, a := range attrs {
			if !used[i] && a.Name == short {
				out, used[i] = append(out, a), true
				break
			}
		}
	}
	for i, a := range attrs {
		if !used[i] {
			out = append(out, a)
		}
	}
	return out
}

// TemplateFromItem turns a certificate or request into a template
// (db_x509super::toTemplate): subject, extensions (others into adv_ext)
// and, for certificates, the validity.
func (h *Handle) TemplateFromItem(ctx context.Context, id int64) (int64, error) {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	d := TemplateData{Source: 3}
	if c := findCert(snap, id); c != nil {
		cc, err := pki.ParseCertificate(c.DER)
		if err != nil {
			return 0, err
		}
		d.Name, d.Subject, d.Ext = c.Name, pki.NameAttrs(cc.RawSubject), pki.SpecWithAdvanced(cc.Extensions)
		if cc.NotAfter.Year() == 9999 {
			d.Validity.NoExpiry = true
		} else {
			d.Validity.Midnight = cc.NotBefore.UTC().Format("150405") == "000000" && cc.NotAfter.UTC().Format("150405") == "235959"
			d.Validity.N, d.Validity.Unit = tmpl.ValidityFromDates(int(cc.NotAfter.Sub(cc.NotBefore).Hours() / 24))
		}
	} else if r := findRequest(snap, id); r != nil {
		rr, err := pki.ParseCertificateRequest(r.DER)
		if err != nil {
			return 0, err
		}
		d.Name, d.Subject, d.Ext = r.Name, pki.NameAttrs(rr.RawSubject), pki.SpecWithAdvanced(rr.Extensions)
		d.Validity = tmpl.Validity{N: 365}
	} else {
		return 0, errors.New("certificate or request not found")
	}
	d.Subject = orderSubject(d.Subject, snap.Settings["explicit_dn"])
	return h.SaveTemplate(ctx, d)
}

// DuplicateTemplate copies a template under a new name.
func (h *Handle) DuplicateTemplate(ctx context.Context, id int64) (int64, error) {
	d, err := h.LoadTemplate(ctx, id)
	if err != nil {
		return 0, err
	}
	d.ID, d.Name = 0, fmt.Sprintf("%s copy", d.Name)
	return h.SaveTemplate(ctx, *d)
}

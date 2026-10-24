package store

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"time"

	"github.com/mailsvb/openkca/internal/codec"
	"github.com/mailsvb/openkca/internal/gcadb"
	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/vault"
)

// Import actions.
const (
	ImportNew      = "new"      // stored as a new item
	ImportExists   = "exists"   // already in the database, skipped
	ImportComplete = "complete" // adds the private part to a stored public key
	ImportPGP      = "pgp"      // adds or replaces the OpenPGP certificate of a stored key
)

// ImportPlan is the review entry of one found object.
type ImportPlan struct {
	codec.Object
	Action   string
	Existing *gcadb.Duplicate
}

// PlanImport checks found objects against the database and each other,
// with XCA's rules: certificates, requests and CRLs that exist are
// skipped, keys are skipped unless they add a private part to a stored
// public key or a new OpenPGP certificate.
func (h *Handle) PlanImport(ctx context.Context, objs []codec.Object) ([]ImportPlan, error) {
	plans := make([]ImportPlan, len(objs))
	seen := map[string]int{}
	err := h.DB.Read(ctx, func(tx *gcadb.Tx) error {
		for i, o := range objs {
			p := ImportPlan{Object: o, Action: ImportNew}
			if o.Type != gcadb.TypeTemplate {
				d, err := tx.FindDuplicate(ctx, o.Type, o.DER)
				if err != nil {
					return err
				}
				if d != nil {
					p.Existing = d
					p.Action = ImportExists
					if o.Type == gcadb.TypeKey && !d.HasPrivate && o.Private != nil {
						p.Action = ImportComplete
					} else if o.PGP != nil {
						cur, err := tx.PGPCert(ctx, d.ID)
						if err != nil {
							return err
						}
						if !bytes.Equal(cur, o.PGP) {
							p.Action = ImportPGP
						}
					}
				}
				// the same object twice in this import: keep the better one
				k := string(rune(o.Type)) + string(o.DER)
				if j, ok := seen[k]; ok {
					if o.Type == gcadb.TypeKey && o.Private != nil && plans[j].Private == nil {
						plans[j].Action = ImportExists
					} else {
						p.Action = ImportExists
					}
				}
				if p.Action != ImportExists {
					seen[k] = i
				}
			}
			plans[i] = p
		}
		return nil
	})
	return plans, err
}

// ImportResult reports one stored object.
type ImportResult struct {
	Index  int
	ID     int64
	Action string
	Err    error
}

var importOrder = map[int]int{gcadb.TypeKey: 0, gcadb.TypeCert: 1, gcadb.TypeRequest: 2, gcadb.TypeCRL: 3, gcadb.TypeTemplate: 4}

// Import stores the selected plans (indexes into plans) in one
// transaction: keys first so that certificates and requests link to them,
// CRLs after the certificates so that revocations reach their CA. Names
// are taken from the plans, which the caller may have edited.
func (h *Handle) Import(ctx context.Context, plans []ImportPlan, selected []int, kr *vault.Keyring, t Translator) ([]ImportResult, error) {
	if t == nil {
		t = func(k string, a ...any) string { return k }
	}
	order := append([]int(nil), selected...)
	sort.SliceStable(order, func(a, b int) bool {
		return importOrder[plans[order[a]].Type] < importOrder[plans[order[b]].Type]
	})
	var results []ImportResult
	err := h.DB.Write(ctx, func(tx *gcadb.Tx) error {
		results = results[:0]
		for _, i := range order {
			if i < 0 || i >= len(plans) {
				return errors.New("invalid selection")
			}
			p := plans[i]
			r := ImportResult{Index: i, Action: p.Action}
			var err error
			switch p.Action {
			case ImportExists:
			case ImportPGP:
				r.ID = p.Existing.ID
			case ImportComplete:
				r.ID = p.Existing.ID
				err = h.completeKey(ctx, tx, p, kr, t)
			default:
				r.ID, err = insertObject(ctx, tx, p.Object, kr)
			}
			if err == nil && p.PGP != nil && r.ID != 0 {
				err = setPGPCert(ctx, tx, r.ID, p.PGP)
			}
			if err != nil {
				return err
			}
			results = append(results, r)
		}
		return nil
	})
	h.changed(ctx)
	h.auditIf(ctx, err, "items.import", 0, "%d items", len(results))
	return results, err
}

func (h *Handle) completeKey(ctx context.Context, tx *gcadb.Tx, p ImportPlan, kr *vault.Keyring, t Translator) error {
	blob, err := kr.Seal(p.Private, p.Object.DER)
	if err != nil {
		return err
	}
	comment, err := tx.Comment(ctx, p.Existing.ID)
	if err != nil {
		return err
	}
	date := p.Existing.Date.UTC().Format(time.DateTime)
	comment = gcadb.AppendComment(comment, t("import.key_extended", date, p.Name))
	return tx.CompleteKey(ctx, p.Existing.ID, blob, gcadb.ProtDEK, comment)
}

const sourceImported = 1

func insertObject(ctx context.Context, tx *gcadb.Tx, o codec.Object, kr *vault.Keyring) (int64, error) {
	switch o.Type {
	case gcadb.TypeKey:
		k := gcadb.NewKey{Name: o.Name, Comment: o.Comment, Source: sourceImported, KeyType: pki.KeyTypeText(o.KeyType), Len: o.KeyBits, SPKI: o.DER}
		if o.Private != nil {
			blob, err := kr.Seal(o.Private, o.DER)
			if err != nil {
				return 0, err
			}
			k.Private, k.Protection = blob, gcadb.ProtDEK
		}
		return tx.InsertKey(ctx, k)
	case gcadb.TypeCert:
		return tx.InsertCert(ctx, gcadb.NewCert{Name: o.Name, Comment: o.Comment, Source: sourceImported, DER: o.DER})
	case gcadb.TypeRequest:
		return tx.InsertRequest(ctx, gcadb.NewRequest{Name: o.Name, Comment: o.Comment, Source: sourceImported, DER: o.DER})
	case gcadb.TypeCRL:
		id, _, err := tx.InsertImportedCRL(ctx, o.Name, o.Comment, o.DER)
		return id, err
	case gcadb.TypeTemplate:
		return tx.InsertTemplate(ctx, o.Name, o.Comment, sourceImported, o.Template)
	}
	return 0, errors.New("unsupported item type")
}

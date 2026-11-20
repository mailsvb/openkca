package store

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/mailsvb/openkca/internal/db"
	"github.com/mailsvb/openkca/internal/pki"
)

var labelRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// reservedLabels are EST operation names: a label must not be mistaken for
// one (RFC 7030, 3.2.2).
var reservedLabels = []string{"cacerts", "simpleenroll", "simplereenroll", "fullcmc", "serverkeygen", "csrattrs"}

// ValidConnectorLabel reports whether label can name a connector's URL
// path: lower case letters, digits and dashes, not an EST operation.
func ValidConnectorLabel(label string) bool {
	return labelRE.MatchString(label) && !slices.Contains(reservedLabels, label)
}

// Connector CA problems, for ConnectorCAProblem.
const (
	ConnCAMissing = "ca_missing" // none chosen, deleted or in the trash
	ConnCANotCA   = "ca_not_ca"  // not a CA certificate
	ConnCAExpired = "ca_expired" // expired or not yet valid
	ConnCAKey     = "ca_key"     // the key is not sealed with the database keyring
)

// ConnectorCAProblem reports why the connector's CA cannot sign without
// anyone logged in at now, "" when it can.
func ConnectorCAProblem(snap *db.Snapshot, c *db.Connector, now time.Time) string {
	ca := findCert(snap, c.CAID)
	switch {
	case c.CAID == 0 || ca == nil:
		return ConnCAMissing
	case !ca.CA:
		return ConnCANotCA
	case AutoCRLState(snap, ca) != AutoCRLOn:
		return ConnCAKey
	}
	cc, err := pki.ParseCertificate(ca.DER)
	if err != nil || now.After(cc.NotAfter) || now.Before(cc.NotBefore) {
		return ConnCAExpired
	}
	return ""
}

// ConnectorCAs lists the CAs a connector can use: live, valid CA
// certificates whose key the database keyring opens.
func ConnectorCAs(snap *db.Snapshot, now time.Time) []*db.Cert {
	var out []*db.Cert
	for _, c := range snap.Certs {
		if c.CA && ConnectorCAProblem(snap, &db.Connector{CAID: c.ID}, now) == "" {
			out = append(out, c)
		}
	}
	return out
}

// IssuedBy returns the live certificates a connector issued.
func IssuedBy(snap *db.Snapshot, connectorID int64) []*db.Cert {
	var out []*db.Cert
	for _, c := range snap.Certs {
		if c.ConnectorID == connectorID {
			out = append(out, c)
		}
	}
	return out
}

// SaveConnector creates (ID 0) or updates a connector. action names the
// audit entry; "" means connector.create or connector.update.
func (h *Handle) SaveConnector(ctx context.Context, c *db.Connector, action string) error {
	if !ValidConnectorLabel(c.Label) {
		return errors.New("invalid connector label")
	}
	if c.Name == "" {
		return errors.New("the name must not be empty")
	}
	if action == "" {
		action = "connector.update"
		if c.ID == 0 {
			action = "connector.create"
		}
	}
	err := h.DB.Write(ctx, func(tx *db.Tx) error {
		var err error
		if c.ID == 0 {
			err = tx.InsertConnector(ctx, c)
		} else {
			err = tx.UpdateConnector(ctx, c)
		}
		if err != nil {
			return err
		}
		return tx.Audit(ctx, action, 0, c.Type+" "+c.Label)
	})
	h.changed(ctx)
	return err
}

// DeleteConnector removes a connector; the certificates it issued stay.
func (h *Handle) DeleteConnector(ctx context.Context, id int64) error {
	snap, err := h.Snapshot(ctx)
	if err != nil {
		return err
	}
	c := snap.Connector(id)
	if c == nil {
		return errors.New("the connector does not exist")
	}
	err = h.DB.Write(ctx, func(tx *db.Tx) error {
		if err := tx.DeleteConnector(ctx, id); err != nil {
			return err
		}
		return tx.Audit(ctx, "connector.delete", 0, c.Type+" "+c.Label)
	})
	h.changed(ctx)
	return err
}

package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ConnectorEST is the type of an EST (RFC 7030) connector.
const ConnectorEST = "est"

// ErrLabelTaken is returned when another connector of the database uses the
// label already.
var ErrLabelTaken = errors.New("db: the connector label is taken")

// Connector is a row of the connectors table: an endpoint that issues
// certificates from one CA of the database.
type Connector struct {
	ID       int64
	UUID     string
	Type     string // ConnectorEST
	Name     string
	Label    string // URL path segment, unique
	CAID     int64  // issuing CA certificate, 0 = missing or in the trash
	Enabled  bool
	Config   string // the type's settings as JSON
	Created  time.Time
	Modified time.Time
	LastUsed time.Time // zero = never
}

// Connector returns the connector with the given ID, nil when there is none.
func (s *Snapshot) Connector(id int64) *Connector {
	for _, c := range s.Connectors {
		if c.ID == id {
			return c
		}
	}
	return nil
}

// ConnectorByLabel returns the connector with the given label, nil when
// there is none.
func (s *Snapshot) ConnectorByLabel(label string) *Connector {
	for _, c := range s.Connectors {
		if c.Label == label {
			return c
		}
	}
	return nil
}

func loadConnectors(ctx context.Context, tx *sql.Tx, s *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `SELECT n.id, n.uuid, n.type, n.name, n.label, lc.id, n.enabled, n.config,
		n.created, n.modified, n.last_used FROM connectors n `+live("lc", "n.ca")+` ORDER BY n.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		c := &Connector{}
		var ca sql.NullInt64
		var created, modified, used sql.NullString
		if err := rows.Scan(&c.ID, &c.UUID, &c.Type, &c.Name, &c.Label, &ca, &c.Enabled, &c.Config,
			&created, &modified, &used); err != nil {
			return err
		}
		c.CAID = ca.Int64
		c.Created, c.Modified, c.LastUsed = parseTime(created), parseTime(modified), parseTime(used)
		s.Connectors = append(s.Connectors, c)
	}
	return rows.Err()
}

func nullID(id int64) sql.NullInt64 { return sql.NullInt64{Int64: id, Valid: id != 0} }

func labelErr(err error) error {
	if err != nil && strings.Contains(err.Error(), "connectors.label") {
		return ErrLabelTaken
	}
	return err
}

// InsertConnector stores a new connector and sets its ID, UUID and dates.
func (t *Tx) InsertConnector(ctx context.Context, c *Connector) error {
	u, err := NewUUID()
	if err != nil {
		return err
	}
	now := time.Now()
	res, err := t.ExecContext(ctx, `INSERT INTO connectors (uuid, type, name, label, ca, enabled, config, created, modified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, u, c.Type, c.Name, c.Label, nullID(c.CAID), c.Enabled, c.Config,
		fmtTime(now), fmtTime(now))
	if err != nil {
		return labelErr(err)
	}
	if c.ID, err = res.LastInsertId(); err != nil {
		return err
	}
	c.UUID, c.Created, c.Modified = u, now, now
	return nil
}

// UpdateConnector writes a connector's name, label, CA, state and settings.
func (t *Tx) UpdateConnector(ctx context.Context, c *Connector) error {
	c.Modified = time.Now()
	res, err := t.ExecContext(ctx, `UPDATE connectors SET name=?, label=?, ca=?, enabled=?, config=?, modified=? WHERE id=?`,
		c.Name, c.Label, nullID(c.CAID), c.Enabled, c.Config, fmtTime(c.Modified), c.ID)
	if err != nil {
		return labelErr(err)
	}
	return oneRow(res, c.ID)
}

// DeleteConnector removes a connector; the certificates it issued stay
// and lose the link.
func (t *Tx) DeleteConnector(ctx context.Context, id int64) error {
	res, err := t.ExecContext(ctx, "DELETE FROM connectors WHERE id=?", id)
	if err != nil {
		return err
	}
	return oneRow(res, id)
}

// TouchConnector records that a connector was used at the given time.
func (t *Tx) TouchConnector(ctx context.Context, id int64, at time.Time) error {
	_, err := t.ExecContext(ctx, "UPDATE connectors SET last_used=? WHERE id=?", fmtTime(at), id)
	return err
}

// SetCertConnector records the connector that issued a certificate.
func (t *Tx) SetCertConnector(ctx context.Context, certID, connectorID int64) error {
	_, err := t.ExecContext(ctx, "UPDATE certs SET connector=? WHERE item=?", nullID(connectorID), certID)
	return err
}

func oneRow(res sql.Result, id int64) error {
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("db: connector %d not found", id)
	}
	return nil
}

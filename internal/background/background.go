// Package background keeps the databases configured with a password open
// for as long as go-ca runs, with their keyring unlocked, so that go-ca can
// do CA work (such as signing revocation lists) without anyone logged in.
//
// Web sessions on the same database share its open handle (store.Acquire
// counts references) but each unlocks its own keyring with the password
// the user enters; the background keyring is never handed to a session.
package background

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mailsvb/openkca/internal/pki"
	"github.com/mailsvb/openkca/internal/store"
	"github.com/mailsvb/openkca/internal/vault"
)

// Database is one database held open in the background.
type Database struct {
	Name   string // the store name (file name without .okca)
	Label  string // the configured name
	Handle *store.Handle

	mu sync.Mutex
	kr *vault.Keyring
}

// Keyring returns the database's keyring, nil once Holder.Close wiped it.
// Callers must not keep it beyond the job at hand.
func (d *Database) Keyring() *vault.Keyring {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.kr
}

// Holder holds the background databases.
type Holder struct {
	mu    sync.Mutex
	dbs   []*Database
	byKey map[string]*Database
}

// Open opens and unlocks every configured database that has a password,
// in the order of the configuration. passwords maps store names to
// database passwords. If any database fails to open (missing, locked by
// another process, wrong password), the ones opened so far are closed
// again and the error says which one failed.
func Open(ctx context.Context, st *store.Store, names []string, passwords map[string][]byte) (*Holder, error) {
	h := &Holder{byKey: map[string]*Database{}}
	for _, name := range names {
		pw, ok := passwords[name]
		if !ok || len(pw) == 0 {
			continue
		}
		label := name
		if c, ok := st.ConfiguredDB(name); ok {
			label = c.Label
		}
		d, err := open(ctx, st, name, label, pw)
		if err != nil {
			h.Close()
			return nil, fmt.Errorf("database %q (%s): %w", label, name, err)
		}
		h.dbs = append(h.dbs, d)
		h.byKey[name] = d
		slog.Info("database open in the background", "db", name, "name", label)
	}
	return h, nil
}

func open(ctx context.Context, st *store.Store, name, label string, pw []byte) (*Database, error) {
	hd, err := st.Acquire(ctx, name)
	if err != nil {
		return nil, err
	}
	kr, err := hd.Unlock(ctx, pw)
	if err != nil {
		if errors.Is(err, pki.ErrWrongPassword) {
			hd.Audit(ctx, "database.unlock_failed", 0, "background")
			err = errors.New("the configured password is wrong")
		}
		hd.Release()
		return nil, err
	}
	hd.Audit(ctx, "database.unlock", 0, "background")
	return &Database{Name: name, Label: label, Handle: hd, kr: kr}, nil
}

// Get returns the background database with this store name, nil if there
// is none.
func (h *Holder) Get(name string) *Database {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.byKey[name]
}

// Databases returns the background databases in configuration order.
func (h *Holder) Databases() []*Database {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*Database(nil), h.dbs...)
}

// TickInterval is how often the background work runs without a change:
// it catches CRLs whose half validity passed and entries that aged out.
var TickInterval = time.Minute

// Run does the background CA work of every database until ctx ends:
// after each change to a database and every TickInterval, it signs the
// CRLs that are due (store.Handle.SignDueCRLs). It returns when ctx ends.
func (h *Holder) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, d := range h.Databases() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.run(ctx)
		}()
	}
	wg.Wait()
}

func (d *Database) run(ctx context.Context) {
	changed := d.Handle.Watch()
	t := time.NewTicker(TickInterval)
	defer t.Stop()
	for {
		if kr := d.Keyring(); kr != nil {
			if _, err := d.Handle.SignDueCRLs(ctx, kr, time.Now()); err != nil && ctx.Err() == nil {
				slog.Error("background CRL check failed", "db", d.Name, "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-t.C:
		}
	}
}

// Close wipes every keyring and releases the databases.
func (h *Holder) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	dbs := h.dbs
	h.dbs, h.byKey = nil, map[string]*Database{}
	h.mu.Unlock()
	for _, d := range dbs {
		d.mu.Lock()
		if d.kr != nil {
			d.kr.Wipe()
			d.kr = nil
		}
		d.mu.Unlock()
		d.Handle.Release()
	}
}

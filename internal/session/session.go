// Package session keeps the database sessions: which browser has which
// database open with which keyring. A keyring (the database's unwrapped
// DEK) lives only in memory and is wiped when its session ends. A session
// whose database is still being converted has a conversion instead and
// no keyring yet.
package session

import (
	"sync"
	"time"

	"github.com/mailsvb/go-ca/internal/auth"
	"github.com/mailsvb/go-ca/internal/store"
	"github.com/mailsvb/go-ca/internal/vault"
)

// Session is one open database in one browser.
type Session struct {
	ID       string
	ServerID string // the server session it belongs to
	DBName   string
	Handle   *store.Handle

	mu         sync.Mutex
	keyring    *vault.Keyring
	conversion *store.Conversion
	lastSeen   time.Time
	pending    Wipeable
}

// Wipeable is per-session state that holds secrets (an import in review
// with decrypted keys) and must be cleared when the session ends.
type Wipeable interface{ Wipe() }

// Pending returns the session's pending state, if any.
func (s *Session) Pending() Wipeable {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending
}

// SetPending replaces the pending state, wiping the previous one.
func (s *Session) SetPending(v Wipeable) {
	s.mu.Lock()
	if s.pending != nil && s.pending != v {
		s.pending.Wipe()
	}
	s.pending = v
	s.mu.Unlock()
}

// Keyring returns the session's keyring, nil while the database is being
// converted.
func (s *Session) Keyring() *vault.Keyring {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keyring
}

// SetKeyring replaces the keyring (after a password change, or when a
// conversion has finished), wiping the previous one.
func (s *Session) SetKeyring(kr *vault.Keyring) {
	s.mu.Lock()
	if s.keyring != nil && s.keyring != kr {
		s.keyring.Wipe()
	}
	s.keyring = kr
	s.conversion = nil
	s.mu.Unlock()
}

// Conversion returns the conversion the session waits for, if any.
func (s *Session) Conversion() *store.Conversion {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conversion
}

// Ready reports whether the session has its keyring.
func (s *Session) Ready() bool { return s.Keyring() != nil }

func (s *Session) wipe() {
	s.mu.Lock()
	if s.keyring != nil {
		s.keyring.Wipe()
		s.keyring = nil
	}
	s.conversion = nil
	if s.pending != nil {
		s.pending.Wipe()
		s.pending = nil
	}
	s.mu.Unlock()
}

// Manager holds all database sessions.
type Manager struct {
	Idle time.Duration

	mu sync.Mutex
	m  map[string]*Session
}

// NewManager creates an empty manager.
func NewManager(idle time.Duration) *Manager {
	return &Manager{Idle: idle, m: map[string]*Session{}}
}

// Create starts a session. It takes ownership of h (released on End) and
// of kr, or, for a database being converted, waits for conv.
func (m *Manager) Create(serverID, dbName string, h *store.Handle, kr *vault.Keyring, conv *store.Conversion) *Session {
	s := &Session{ID: auth.NewID(), ServerID: serverID, DBName: dbName, Handle: h,
		keyring: kr, conversion: conv, lastSeen: time.Now()}
	m.mu.Lock()
	m.m[s.ID] = s
	m.mu.Unlock()
	return s
}

// Get returns a live session for id that belongs to serverID and dbName.
func (m *Manager) Get(id, serverID, dbName string) *Session {
	m.mu.Lock()
	s, ok := m.m[id]
	if !ok {
		m.mu.Unlock()
		return nil
	}
	if time.Since(s.lastSeen) > m.Idle {
		delete(m.m, id)
		m.mu.Unlock()
		m.close(s)
		return nil
	}
	m.mu.Unlock()
	if s.ServerID != serverID || s.DBName != dbName {
		return nil
	}
	s.mu.Lock()
	s.lastSeen = time.Now()
	s.mu.Unlock()
	return s
}

func (m *Manager) close(s *Session) {
	s.wipe()
	s.Handle.Release()
}

// End closes one session.
func (m *Manager) End(id string) {
	m.mu.Lock()
	s, ok := m.m[id]
	delete(m.m, id)
	m.mu.Unlock()
	if ok {
		m.close(s)
	}
}

// EndServer closes every database session of one server session.
func (m *Manager) EndServer(serverID string) {
	m.endWhere(func(s *Session) bool { return s.ServerID == serverID })
}

// EndDatabase closes every session on a database except keep.
func (m *Manager) EndDatabase(dbName, keep string) {
	m.endWhere(func(s *Session) bool { return s.DBName == dbName && s.ID != keep })
}

// Sweep closes idle sessions.
func (m *Manager) Sweep() {
	m.endWhere(func(s *Session) bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return time.Since(s.lastSeen) > m.Idle
	})
}

// CloseAll ends every session (shutdown).
func (m *Manager) CloseAll() { m.endWhere(func(*Session) bool { return true }) }

func (m *Manager) endWhere(f func(*Session) bool) {
	var ended []*Session
	m.mu.Lock()
	for id, s := range m.m {
		if f(s) {
			delete(m.m, id)
			ended = append(ended, s)
		}
	}
	m.mu.Unlock()
	for _, s := range ended {
		m.close(s)
	}
}

// OpenDatabases lists the database names this server session has open.
func (m *Manager) OpenDatabases(serverID string) map[string]bool {
	out := map[string]bool{}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.m {
		if s.ServerID == serverID {
			out[s.DBName] = true
		}
	}
	return out
}

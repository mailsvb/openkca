// Package session keeps the database sessions: which browser has which
// database open with which password. Passwords live only in memory and are
// zeroed when a session ends.
package session

import (
	"sync"
	"time"

	"github.com/mailsvb/go-ca/internal/auth"
	"github.com/mailsvb/go-ca/internal/store"
)

// Session is one open database in one browser.
type Session struct {
	ID       string
	ServerID string // the server session it belongs to
	DBName   string
	Handle   *store.Handle

	mu       sync.Mutex
	password []byte
	lastSeen time.Time
}

// Password returns a copy of the database password; the caller should clear it.
func (s *Session) Password() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.password...)
}

// SetPassword replaces the stored database password.
func (s *Session) SetPassword(pw []byte) {
	s.mu.Lock()
	clear(s.password)
	s.password = append([]byte(nil), pw...)
	s.mu.Unlock()
}

func (s *Session) wipe() {
	s.mu.Lock()
	clear(s.password)
	s.password = nil
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
// copies password.
func (m *Manager) Create(serverID, dbName string, h *store.Handle, password []byte) *Session {
	s := &Session{ID: auth.NewID(), ServerID: serverID, DBName: dbName, Handle: h,
		password: append([]byte(nil), password...), lastSeen: time.Now()}
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

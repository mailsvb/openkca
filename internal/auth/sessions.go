package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// NewID returns 32 random bytes, URL-safe base64 encoded.
func NewID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ServerSession proves the server password for one browser.
type ServerSession struct {
	ID       string
	CSRF     string
	Lang     string // explicit language choice, "" = Accept-Language
	lastSeen time.Time
}

// CSRFOK compares a submitted token in constant time.
func (s *ServerSession) CSRFOK(token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.CSRF)) == 1
}

// Sessions is the in-memory store of server sessions.
type Sessions struct {
	Idle time.Duration

	mu sync.Mutex
	m  map[string]*ServerSession
	// OnEnd is called (outside the lock) for every ended session, so that
	// database sessions of the same browser end too.
	OnEnd func(id string)
}

// NewSessions creates an empty store.
func NewSessions(idle time.Duration) *Sessions {
	return &Sessions{Idle: idle, m: map[string]*ServerSession{}}
}

// Create starts a new session.
func (s *Sessions) Create() *ServerSession {
	ss := &ServerSession{ID: NewID(), CSRF: NewID(), lastSeen: time.Now()}
	s.mu.Lock()
	s.m[ss.ID] = ss
	s.mu.Unlock()
	return ss
}

// Get returns a live session and refreshes its idle timer.
func (s *Sessions) Get(id string) *ServerSession {
	s.mu.Lock()
	ss, ok := s.m[id]
	expired := ok && time.Since(ss.lastSeen) > s.Idle
	if ok && !expired {
		ss.lastSeen = time.Now()
	}
	if expired {
		delete(s.m, id)
	}
	s.mu.Unlock()
	if expired && s.OnEnd != nil {
		s.OnEnd(id)
	}
	if !ok || expired {
		return nil
	}
	return ss
}

// End removes a session.
func (s *Sessions) End(id string) {
	s.mu.Lock()
	_, ok := s.m[id]
	delete(s.m, id)
	s.mu.Unlock()
	if ok && s.OnEnd != nil {
		s.OnEnd(id)
	}
}

// Sweep ends idle sessions; call it periodically.
func (s *Sessions) Sweep() {
	var ended []string
	s.mu.Lock()
	for id, ss := range s.m {
		if time.Since(ss.lastSeen) > s.Idle {
			delete(s.m, id)
			ended = append(ended, id)
		}
	}
	s.mu.Unlock()
	if s.OnEnd != nil {
		for _, id := range ended {
			s.OnEnd(id)
		}
	}
}

// Limiter allows a fixed number of failures per key within a window.
type Limiter struct {
	Max    int
	Window time.Duration

	mu sync.Mutex
	m  map[string][]time.Time
}

// NewLimiter creates a limiter.
func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{Max: max, Window: window, m: map[string][]time.Time{}}
}

func (l *Limiter) prune(key string, now time.Time) []time.Time {
	ts := l.m[key]
	i := 0
	for ; i < len(ts) && now.Sub(ts[i]) > l.Window; i++ {
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(l.m, key)
	} else {
		l.m[key] = ts
	}
	return ts
}

// Blocked reports whether key has used up its failures.
func (l *Limiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key, time.Now())) >= l.Max
}

// Fail records a failed attempt.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.m[key] = append(l.prune(key, now), now)
}

// Reset clears the failures of key after a success.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

// Sweep drops keys whose failures are all older than the window, so that
// the map does not grow with every client that ever failed.
func (l *Limiter) Sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k := range l.m {
		l.prune(k, now)
	}
}

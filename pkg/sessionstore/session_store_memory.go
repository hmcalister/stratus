package sessionstore

import (
	"context"
	"sync"
	"time"
)

var _ SessionStore = &MemorySessionStore{}

// Keeps sessions in process memory.
//
// Sessions are lost when the process exits, and the store is not shared between processes.
// Beware that restarting the server will terminate all sessions!
//
// Expired sessions are removed when DeleteExpired is called. The store never runs a background sweep.
type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
}

// Returns an empty in-memory session store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		sessions: make(map[string]Session),
	}
}

// Stores session, replacing any record with the same token hash.
func (s *MemorySessionStore) Create(_ context.Context, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[session.TokenHash] = session
	return nil
}

// Returns the session with the given token hash, including when it expired.
//
// Returns ErrSessionNotFound when the hash is unknown.
func (s *MemorySessionStore) Get(_ context.Context, tokenHash string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[tokenHash]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	return session, nil
}

// Removes the session with the given token hash.
//
// Deleting an unknown hash is not an error.
func (s *MemorySessionStore) Delete(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, tokenHash)
	return nil
}

// Removes every session belonging to email.
func (s *MemorySessionStore) DeleteByEmail(_ context.Context, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for tokenHash, session := range s.sessions {
		if session.Email == email {
			delete(s.sessions, tokenHash)
		}
	}
	return nil
}

// Removes every session whose ExpiresAt is at or before now.
func (s *MemorySessionStore) DeleteExpired(_ context.Context, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for tokenHash, session := range s.sessions {
		if !session.ExpiresAt.After(now) {
			delete(s.sessions, tokenHash)
		}
	}
	return nil
}

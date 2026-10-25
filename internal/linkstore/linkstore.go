// Keeps outstanding magic-link tokens in memory.
package linkstore

import (
	"sync"
	"time"
)

// Holds outstanding magic-link tokens in memory, keyed by the SHA-256 hash of the raw token. Raw tokens are never stored.
//
// Each link can be consumed once. Inserting a link also removes expired entries, so links that are never followed do not accumulate.
type Store struct {
	now func() time.Time

	mu    sync.Mutex
	links map[string]link
}

// An outstanding magic link that holds the address that requested it and the time when it stops being valid.
type link struct {
	email     string
	expiresAt time.Time
}

// Returns an empty store. The now function supplies the clock for expiry checks and lazy cleanup.
func New(now func() time.Time) *Store {
	return &Store{
		now:   now,
		links: make(map[string]link),
	}
}

// Stores a link keyed by its token hash and removes expired entries.
//
// The link is valid until expiresAt. Storing a hash that is already present replaces the earlier link.
func (s *Store) Create(tokenHash, email string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	for hash, existing := range s.links {
		if !existing.expiresAt.After(now) {
			delete(s.links, hash)
		}
	}

	s.links[tokenHash] = link{email: email, expiresAt: expiresAt}
}

// Removes the link with this token hash and returns the email that it was issued to.
//
// The link is removed whether or not it expired. It reports false when the hash is unknown or the link has expired.
func (s *Store) Consume(tokenHash string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	found, ok := s.links[tokenHash]
	if !ok {
		return "", false
	}
	delete(s.links, tokenHash)

	if !s.now().Before(found.expiresAt) {
		return "", false
	}
	return found.email, true
}

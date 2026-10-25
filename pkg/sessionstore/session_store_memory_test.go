package sessionstore

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// Builds a session with a TTL from createdAt. The token hash is arbitrary hex-shaped text. The store does not interpret it.
func newTestSession(tokenHash, email string, createdAt time.Time, ttl time.Duration) Session {
	return Session{
		TokenHash: tokenHash,
		Email:     email,
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(ttl),
	}
}

func TestMemorySessionStoreCreateAndGet(t *testing.T) {
	store := NewMemorySessionStore()
	createdAt := time.Date(2000, time.January, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		session Session
	}{
		{
			name:    "first session",
			session: newTestSession(strings.Repeat("a", 64), "one@example.com", createdAt, time.Hour),
		},
		{
			name:    "second session for another address",
			session: newTestSession(strings.Repeat("b", 64), "two@example.com", createdAt, 24*time.Hour),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := store.Create(t.Context(), test.session); err != nil {
				t.Fatalf("Create: %v", err)
			}

			got, err := store.Get(t.Context(), test.session.TokenHash)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got != test.session {
				t.Fatalf("Get = %+v, want %+v", got, test.session)
			}
		})
	}
}

func TestMemorySessionStoreCreateReplacesExisting(t *testing.T) {
	store := NewMemorySessionStore()
	createdAt := time.Date(2000, time.January, 1, 12, 0, 0, 0, time.UTC)
	tokenHash := strings.Repeat("a", 64)

	original := newTestSession(tokenHash, "original@example.com", createdAt, time.Hour)
	if err := store.Create(t.Context(), original); err != nil {
		t.Fatalf("Create original: %v", err)
	}

	replacement := newTestSession(tokenHash, "replacement@example.com", createdAt, 2*time.Hour)
	if err := store.Create(t.Context(), replacement); err != nil {
		t.Fatalf("Create replacement: %v", err)
	}

	got, err := store.Get(t.Context(), tokenHash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != replacement {
		t.Fatalf("Get = %+v, want replacement %+v", got, replacement)
	}
}

func TestMemorySessionStoreGetUnknown(t *testing.T) {
	store := NewMemorySessionStore()

	_, err := store.Get(t.Context(), strings.Repeat("f", 64))
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Get error = %v, want ErrSessionNotFound", err)
	}
}

func TestMemorySessionStoreGetReturnsExpiredSession(t *testing.T) {
	store := NewMemorySessionStore()
	createdAt := time.Date(2000, time.January, 1, 12, 0, 0, 0, time.UTC)
	session := newTestSession(strings.Repeat("a", 64), "user@example.com", createdAt, -time.Hour)
	if err := store.Create(t.Context(), session); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get(t.Context(), session.TokenHash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != session {
		t.Fatalf("Get = %+v, want %+v", got, session)
	}
}

func TestMemorySessionStoreDelete(t *testing.T) {
	store := NewMemorySessionStore()
	createdAt := time.Date(2000, time.January, 1, 12, 0, 0, 0, time.UTC)
	existing := newTestSession(strings.Repeat("a", 64), "user@example.com", createdAt, time.Hour)
	if err := store.Create(t.Context(), existing); err != nil {
		t.Fatalf("Create: %v", err)
	}

	tests := []struct {
		name      string
		tokenHash string
	}{
		{"existing session", existing.TokenHash},
		{"same session again", existing.TokenHash},
		{"unknown hash", strings.Repeat("f", 64)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := store.Delete(t.Context(), test.tokenHash); err != nil {
				t.Fatalf("Delete: %v", err)
			}
		})
	}

	if _, err := store.Get(t.Context(), existing.TokenHash); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Get after Delete error = %v, want ErrSessionNotFound", err)
	}
}

func TestMemorySessionStoreDeleteByEmail(t *testing.T) {
	store := NewMemorySessionStore()
	createdAt := time.Date(2000, time.January, 1, 12, 0, 0, 0, time.UTC)

	aliceOne := newTestSession(strings.Repeat("a", 64), "alice@example.com", createdAt, time.Hour)
	aliceTwo := newTestSession(strings.Repeat("b", 64), "alice@example.com", createdAt, time.Hour)
	bob := newTestSession(strings.Repeat("c", 64), "bob@example.com", createdAt, time.Hour)
	for _, session := range []Session{aliceOne, aliceTwo, bob} {
		if err := store.Create(t.Context(), session); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	tests := []struct {
		name  string
		email string
	}{
		// Ordering of these tests is important!!!
		{"existing address", aliceOne.Email},
		{"already deleted address", aliceOne.Email},
		{"unknown address", "nobody@example.com"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := store.DeleteByEmail(t.Context(), test.email); err != nil {
				t.Fatalf("DeleteByEmail: %v", err)
			}

			for _, session := range []Session{aliceOne, aliceTwo} {
				if _, err := store.Get(t.Context(), session.TokenHash); !errors.Is(err, ErrSessionNotFound) {
					t.Fatalf("Get(%s) error = %v, want ErrSessionNotFound", session.TokenHash, err)
				}
			}
			if _, err := store.Get(t.Context(), bob.TokenHash); err != nil {
				t.Fatalf("Get(bob) error = %v, want nil", err)
			}
		})
	}
}

func TestMemorySessionStoreDeleteExpired(t *testing.T) {
	store := NewMemorySessionStore()
	now := time.Date(2000, time.January, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		session   Session
		remaining bool
	}{
		{
			name:    "expired before now",
			session: newTestSession(strings.Repeat("a", 64), "expired@example.com", now.Add(-2*time.Hour), time.Hour),
		},
		{
			name:    "expires exactly at now",
			session: newTestSession(strings.Repeat("b", 64), "boundary@example.com", now.Add(-time.Hour), time.Hour),
		},
		{
			name:      "expires after now",
			session:   newTestSession(strings.Repeat("c", 64), "live@example.com", now, time.Hour),
			remaining: true,
		},
	}

	for _, test := range tests {
		if err := store.Create(t.Context(), test.session); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	if err := store.DeleteExpired(t.Context(), now); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := store.Get(t.Context(), test.session.TokenHash)
			if test.remaining {
				if err != nil {
					t.Fatalf("Get error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrSessionNotFound) {
				t.Fatalf("Get error = %v, want ErrSessionNotFound", err)
			}
		})
	}
}

func TestMemorySessionStoreConcurrentUse(t *testing.T) {
	store := NewMemorySessionStore()
	createdAt := time.Date(2000, time.January, 1, 12, 0, 0, 0, time.UTC)

	const goroutines = 10
	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Go(func() {
			ctx := t.Context()
			session := newTestSession(
				fmt.Sprintf("%064x", i),
				fmt.Sprintf("user%d@example.com", i),
				createdAt,
				time.Hour,
			)

			if err := store.Create(ctx, session); err != nil {
				t.Errorf("Create: %v", err)
				return
			}
			if _, err := store.Get(ctx, session.TokenHash); err != nil {
				t.Errorf("Get: %v", err)
			}
			if err := store.DeleteExpired(ctx, createdAt.Add(-time.Hour)); err != nil {
				t.Errorf("DeleteExpired: %v", err)
			}
			if err := store.DeleteByEmail(ctx, session.Email); err != nil {
				t.Errorf("DeleteByEmail: %v", err)
			}
			if _, err := store.Get(ctx, session.TokenHash); !errors.Is(err, ErrSessionNotFound) {
				t.Errorf("Get after DeleteByEmail error = %v, want ErrSessionNotFound", err)
			}
			if err := store.Delete(ctx, session.TokenHash); err != nil {
				t.Errorf("Delete: %v", err)
			}
		})
	}
	wg.Wait()

	if len(store.sessions) != 0 {
		t.Fatalf("%d sessions remain, want 0", len(store.sessions))
	}
}

package sessionstore

import (
	"context"
	"errors"
	"time"
)

// Returned by SessionStore.Get when the token hash is unknown.
var ErrSessionNotFound = errors.New("session not found")

// A signed-in user session.
//
// Only the hash of the session token is stored. The raw token lives in the client's cookie.
type Session struct {
	// The lowercase hex SHA-256 of the raw session token.
	TokenHash string
	// The normalised address of the signed-in user.
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Interface into a storage for persistent sessions.
//
// Implementations must be safe for concurrent use.
type SessionStore interface {
	// Stores session.
	//
	// Storing an existing TokenHash replaces the previous record.
	Create(ctx context.Context, session Session) error

	// Returns the session with the given token hash.
	//
	// Returns ErrSessionNotFound when the hash is unknown.
	// The returned session may be expired. The caller should check ExpiresAt.
	Get(ctx context.Context, tokenHash string) (Session, error)

	// Removes the session with the given token hash.
	//
	// Deleting an unknown hash is not an error. This prevents enumeration attacks.
	Delete(ctx context.Context, tokenHash string) error

	// Removes every session associated with an email.
	//
	// Callers normalise the address before calling.
	DeleteByEmail(ctx context.Context, email string) error

	// Removes every session whose ExpiresAt is at or before now.
	DeleteExpired(ctx context.Context, now time.Time) error
}

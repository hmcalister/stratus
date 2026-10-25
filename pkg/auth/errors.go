package auth

import "errors"

var (
	// Returned when an address cannot be parsed.
	ErrInvalidEmail = errors.New("invalid email address")

	// Returned when a link request exceeds the rate limit.
	ErrRateLimited = errors.New("rate limited")

	// Returned when a magic link is unknown, expired, or already used.
	ErrInvalidLink = errors.New("invalid magic link")

	// Returned when a session token is missing, unknown, or expired.
	ErrUnauthenticated = errors.New("unauthenticated")
)

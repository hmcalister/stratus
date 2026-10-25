// Handles creating and hashing the opaque tokens used by magic links and sessions.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// The number of random bytes in a magic-link or session token.
const tokenBytes = 32

// The length of a raw token once tokenBytes is hex encoded.
const rawTokenLength = 2 * tokenBytes

// Returns a new random token and its hash.
//
// Tokens are hex encoded so they are safe in URLs and cookies.
func New() (rawToken, tokenHash string, err error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("read random bytes: %w", err)
	}

	rawToken = hex.EncodeToString(buf)
	return rawToken, Hash(rawToken), nil
}

// Validates a raw token. To be used before attempting a hash.
// Prevents denial of service by sending malformed (e.g. very large) tokens.
func Valid(rawToken string) bool {
	return len(rawToken) == rawTokenLength
}

// Returns the lowercase hex SHA-256 of rawToken.
//
// Link and session storage is keyed by this hash, so the raw token is never stored or compared.
// Ensure token is valid (see `Valid`) before calling this method on user-submitted data.
func Hash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

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

// Returns the lowercase hex SHA-256 of rawToken.
//
// Link and session storage is keyed by this hash, so the raw token is never stored or compared.
func Hash(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

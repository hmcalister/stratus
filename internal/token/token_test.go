package token

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewReturnsHexTokenAndHash(t *testing.T) {
	rawToken, tokenHash, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got, want := len(rawToken), 2*tokenBytes; got != want {
		t.Errorf("token length = %d, want %d", got, want)
	}
	if _, err := hex.DecodeString(rawToken); err != nil {
		t.Errorf("token is not hex: %v", err)
	}
	if got, want := len(tokenHash), 64; got != want {
		t.Errorf("hash length = %d, want %d", got, want)
	}
	if tokenHash != Hash(rawToken) {
		t.Error("returned hash does not match Hash of the token")
	}
	if rawToken == tokenHash {
		t.Error("token and hash are equal")
	}
}

func TestNewReturnsDifferentTokens(t *testing.T) {
	first, _, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	second, _, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if first == second {
		t.Fatal("two calls returned the same token")
	}
}

func TestHash(t *testing.T) {
	// SHA-256 of "abc".
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	if got := Hash("abc"); got != want {
		t.Errorf("Hash = %q, want %q", got, want)
	}
}

func TestValid(t *testing.T) {
	rawToken, _, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tests := []struct {
		name     string
		rawToken string
		want     bool
	}{
		{name: "new token", rawToken: rawToken, want: true},
		{name: "empty", rawToken: "", want: false},
		{name: "too short", rawToken: rawToken[:len(rawToken)-1], want: false},
		{name: "too long", rawToken: rawToken + "a", want: false},
		{name: "oversized", rawToken: strings.Repeat("a", 1<<20), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Valid(test.rawToken); got != test.want {
				t.Errorf("Valid(%d bytes) = %t, want %t", len(test.rawToken), got, test.want)
			}
		})
	}
}

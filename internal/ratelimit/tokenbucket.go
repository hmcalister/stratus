package ratelimit

import "time"

// The token-bucket algorithm. The bucket constantly fills with tokens until it reaches the cap burst. A new token is available every interval. Each link request removes one token.
type tokenBucket struct {
	tokens float64
	last   time.Time

	burst    int
	interval time.Duration
}

// Creates a token bucket with burst tokens. It is internal, so it does not validate burst or interval.
func newTokenBucket(burst int, interval time.Duration) *tokenBucket {
	return &tokenBucket{
		tokens:   float64(burst),
		last:     time.Now(),
		burst:    burst,
		interval: interval,
	}
}

// Checks if a token is available. The now argument sets the time used to calculate the refill.
//
// Returns the duration until the next token is available. A zero result means that a token is available now.
func (b *tokenBucket) durationUntilNextToken(now time.Time) time.Duration {
	// Clamps elapsed time at zero so a non-monotonic or backwards clock never removes tokens.
	elapsed := max(now.Sub(b.last), 0)

	// Adds the tokens earned since the last check, capped at burst.
	b.tokens = min(float64(b.burst), b.tokens+float64(elapsed)/float64(b.interval))

	b.last = now
	if b.tokens >= 1 {
		return 0
	}
	return time.Duration((1 - b.tokens) * float64(b.interval))
}

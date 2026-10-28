package auth

import (
	"errors"
	"math"
	"strconv"
	"time"
)

const (
	// An address may make defaultEmailLinkBurst link requests immediately and then one per defaultEmailLinkInterval.
	// A client IP gets defaultIPLinkBurst requests immediately and then one per defaultIPLinkInterval.
	// Idle rate-limit buckets are forgotten every defaultLinkSweepCadence.
	defaultEmailLinkBurst    = 5
	defaultEmailLinkInterval = 3 * time.Minute
	defaultIPLinkBurst       = 20
	defaultIPLinkInterval    = 45 * time.Second
	defaultLinkSweepCadence  = 15 * time.Minute
)

// Configures the token-bucket limits applied to magic-link requests.
//
// A zero field selects the default for that field. Negative values are invalid.
// See `pkg/auth/ratelimit.go` for defaults.
type RateLimitConfig struct {
	// How many link requests one address may make immediately.
	EmailBurst int

	// How long it takes to restore one link request to an address's bucket.
	EmailInterval time.Duration

	// How many link requests one client IP may make immediately.
	IPBurst int

	// How long it takes to restore one link request to a client IP's bucket.
	IPInterval time.Duration

	// Disables link-request rate limiting entirely.
	Disabled bool

	// Answers denied link requests with 429 Too Many Requests and a Retry-After header,
	// instead of the uniform 202 Accepted.
	//
	// This lets a caller learn whether an address made recent link requests, so leave it
	// off if that matters.
	RevealDenials bool
}

// Returned by requestLink when a rate limit refuses the request. It carries the time until another attempt is allowed.
type rateLimitedError struct {
	retryAfter time.Duration
}

func (e *rateLimitedError) Error() string { return ErrRateLimited.Error() }

func (e *rateLimitedError) Unwrap() error { return ErrRateLimited }

// Returns the Retry-After header value for d.
//
// The header carries whole seconds, so the value is rounded up.
func retryAfterHeader(d time.Duration) string {
	seconds := max(int64(math.Ceil(d.Seconds())), 1)
	return strconv.FormatInt(seconds, 10)
}

// Returns cfg with defaults filled in, or an error when a value is negative.
func (cfg RateLimitConfig) withDefaults() (RateLimitConfig, error) {
	if cfg.EmailBurst < 0 {
		return cfg, errors.New("rate limit email burst must not be negative")
	}
	if cfg.EmailInterval < 0 {
		return cfg, errors.New("rate limit email interval must not be negative")
	}
	if cfg.IPBurst < 0 {
		return cfg, errors.New("rate limit ip burst must not be negative")
	}
	if cfg.IPInterval < 0 {
		return cfg, errors.New("rate limit ip interval must not be negative")
	}

	if cfg.EmailBurst == 0 {
		cfg.EmailBurst = defaultEmailLinkBurst
	}
	if cfg.EmailInterval == 0 {
		cfg.EmailInterval = defaultEmailLinkInterval
	}
	if cfg.IPBurst == 0 {
		cfg.IPBurst = defaultIPLinkBurst
	}
	if cfg.IPInterval == 0 {
		cfg.IPInterval = defaultIPLinkInterval
	}

	return cfg, nil
}

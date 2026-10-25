package auth

import (
	"errors"
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

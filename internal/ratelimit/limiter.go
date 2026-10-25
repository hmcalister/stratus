// Applies token-bucket rate limits to magic-link requests.
package ratelimit

import (
	"sync"
	"time"
)

// Sets the token-bucket limits for link requests. Burst sizes and intervals must be positive.
type Config struct {
	// How many requests an address may make immediately.
	EmailBurst int
	// Time for one token to be restored to the address bucket.
	EmailInterval time.Duration

	// How many requests a client IP may make immediately.
	IPBurst int
	// Time for one token to be restored to the client IP bucket.
	IPInterval time.Duration

	// Time between sweeps to delete idle buckets.
	//
	// Idle buckets are those that have lived long enough to be completely full again.
	SweepCadence time.Duration
}

// Wraps magic-link requests with per-address and per-client IP rate limits. Keys are used exactly as given. The caller normalises email addresses before asking.
type Limiter struct {
	// Returns the current time. Tests replace it to control rate-limit windows.
	now func() time.Time

	tokenBucketMutex    sync.Mutex
	emailTokenBucketMap map[string]*tokenBucket
	ipTokenBucketMap    map[string]*tokenBucket
	lastSweepTime       time.Time

	emailBurst    int
	emailInterval time.Duration
	ipBurst       int
	ipInterval    time.Duration
	sweepCadence  time.Duration
}

// Returns a limiter with the limits in cfg. The now function supplies the clock for refill and sweep timing.
func New(cfg Config, now func() time.Time) *Limiter {
	return &Limiter{
		now:                 now,
		emailTokenBucketMap: make(map[string]*tokenBucket),
		ipTokenBucketMap:    make(map[string]*tokenBucket),
		lastSweepTime:       now(),
		emailBurst:          cfg.EmailBurst,
		emailInterval:       cfg.EmailInterval,
		ipBurst:             cfg.IPBurst,
		ipInterval:          cfg.IPInterval,
		sweepCadence:        cfg.SweepCadence,
	}
}

// Checks the email rate limit and, when ip is non-empty, the IP rate limit. Email must already be normalised.
//
// It creates a missing bucket for each limit (address and IP).
//
// If both limits have a token, it removes one from each and returns true.
// If either limit has no token, it returns false without spending from the other.
func (l *Limiter) Allow(email, ip string) bool {
	now := l.now()

	defer l.sweep(now)
	l.tokenBucketMutex.Lock()
	defer l.tokenBucketMutex.Unlock()

	emailBucket := l.emailTokenBucketMap[email]
	if emailBucket == nil {
		emailBucket = newTokenBucket(l.emailBurst, l.emailInterval)
	}
	if emailBucket.durationUntilNextToken(now) > 0 {
		return false
	}

	if ip != "" {
		ipBucket := l.ipTokenBucketMap[ip]
		if ipBucket == nil {
			ipBucket = newTokenBucket(l.ipBurst, l.ipInterval)
		}
		if ipBucket.durationUntilNextToken(now) > 0 {
			return false
		}
		ipBucket.tokens--
		l.ipTokenBucketMap[ip] = ipBucket
	}

	emailBucket.tokens--
	l.emailTokenBucketMap[email] = emailBucket
	return true
}

// Forgets buckets that are idle long enough to be back at full burst.
func (l *Limiter) sweep(now time.Time) {
	l.tokenBucketMutex.Lock()
	defer l.tokenBucketMutex.Unlock()

	if now.Sub(l.lastSweepTime) < l.sweepCadence {
		return
	}
	l.lastSweepTime = now

	for email, bucket := range l.emailTokenBucketMap {
		if now.Sub(bucket.last) >= time.Duration(l.emailBurst)*l.emailInterval {
			delete(l.emailTokenBucketMap, email)
		}
	}
	for ip, bucket := range l.ipTokenBucketMap {
		if now.Sub(bucket.last) >= time.Duration(l.ipBurst)*l.ipInterval {
			delete(l.ipTokenBucketMap, ip)
		}
	}
}

package ratelimit

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A manually advanced clock for tests.
type fakeClock struct {
	mu      sync.Mutex
	current time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{current: time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = c.current.Add(d)
}

// Test limits mirror the defaults chosen by the auth package.
const (
	testEmailBurst    = 5
	testEmailInterval = 3 * time.Minute
	testIPBurst       = 20
	testIPInterval    = 45 * time.Second
	testSweepCadence  = 15 * time.Minute
)

func newTestLimiter(now func() time.Time) *Limiter {
	return New(Config{
		EmailBurst:    testEmailBurst,
		EmailInterval: testEmailInterval,
		IPBurst:       testIPBurst,
		IPInterval:    testIPInterval,
		SweepCadence:  testSweepCadence,
	}, now)
}

// Reports just whether a request was allowed.
func allowed(limiter *Limiter, email, ip string) bool {
	ok, _ := limiter.Allow(email, ip)
	return ok
}

func TestLimiterLimitsEmailBurstAcrossIPs(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock.now)

	for i := range testEmailBurst {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if !allowed(limiter, "user@example.com", ip) {
			t.Fatalf("request %d was denied, want allowed", i+1)
		}
	}
	if allowed(limiter, "user@example.com", "10.0.1.1") {
		t.Fatal("request beyond the email burst was allowed, want denied")
	}
}

func TestLimiterRefillsEmailTokens(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock.now)

	for i := range testEmailBurst {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if !allowed(limiter, "user@example.com", ip) {
			t.Fatalf("request %d was denied, want allowed", i+1)
		}
	}
	if allowed(limiter, "user@example.com", "10.0.1.1") {
		t.Fatal("request beyond the email burst was allowed, want denied")
	}

	clock.advance(testEmailInterval)
	if !allowed(limiter, "user@example.com", "10.0.1.1") {
		t.Fatal("request after the refill interval was denied, want allowed")
	}
}

func TestLimiterLimitsIPBurstAcrossEmails(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock.now)

	for i := range testIPBurst {
		email := fmt.Sprintf("user%d@example.com", i)
		if !allowed(limiter, email, "10.0.0.1") {
			t.Fatalf("request %d was denied, want allowed", i+1)
		}
	}
	if allowed(limiter, "another@example.com", "10.0.0.1") {
		t.Fatal("request beyond the IP burst was allowed, want denied")
	}
}

func TestLimiterEmptyIPSkipsIPLimit(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock.now)

	for i := range testIPBurst + 1 {
		email := fmt.Sprintf("user%d@example.com", i)
		if !allowed(limiter, email, "") {
			t.Fatalf("request %d was denied, want allowed", i+1)
		}
	}
}

func TestLimiterDeniedEmailSpendsNoIPToken(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock.now)

	for i := range testEmailBurst {
		ip := fmt.Sprintf("10.0.0.%d", i)
		if !allowed(limiter, "user@example.com", ip) {
			t.Fatalf("request %d was denied, want allowed", i+1)
		}
	}
	if allowed(limiter, "user@example.com", "10.0.1.1") {
		t.Fatal("request beyond the email burst was allowed, want denied")
	}

	if !allowed(limiter, "other@example.com", "10.0.1.1") {
		t.Fatal("IP token was spent by a request the email limit denied")
	}
}

func TestLimiterBlockedIPSpendsNoEmailToken(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock.now)

	for i := range testIPBurst {
		email := fmt.Sprintf("user%d@example.com", i)
		if !allowed(limiter, email, "10.0.0.1") {
			t.Fatalf("request %d was denied, want allowed", i+1)
		}
	}
	if allowed(limiter, "victim@example.com", "10.0.0.1") {
		t.Fatal("request from a blocked IP was allowed, want denied")
	}

	if !allowed(limiter, "victim@example.com", "10.0.0.2") {
		t.Fatal("email token was spent by a request the IP limit denied")
	}
}

func TestLimiterReturnsWaitUntilNextToken(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock.now)

	for i := range testEmailBurst {
		ip := fmt.Sprintf("10.0.0.%d", i)
		_ = allowed(limiter, "user@example.com", ip)
	}

	ok, wait := limiter.Allow("user@example.com", "10.0.1.1")
	if ok {
		t.Fatal("request beyond the email burst was allowed, want denied")
	}
	if wait != testEmailInterval {
		t.Fatalf("wait = %v, want %v", wait, testEmailInterval)
	}
}

func TestLimiterSweepsIdleBuckets(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock.now)

	if !allowed(limiter, "old@example.com", "10.0.0.1") {
		t.Fatal("first request was denied, want allowed")
	}

	clock.advance(testSweepCadence)
	if !allowed(limiter, "new@example.com", "10.0.0.2") {
		t.Fatal("request after an idle period was denied, want allowed")
	}

	if len(limiter.emailTokenBucketMap) != 1 || len(limiter.ipTokenBucketMap) != 1 {
		t.Fatalf("buckets = (%d email, %d IP), want (1, 1)", len(limiter.emailTokenBucketMap), len(limiter.ipTokenBucketMap))
	}
	if _, ok := limiter.emailTokenBucketMap["old@example.com"]; ok {
		t.Fatal("idle email bucket was not swept")
	}
	if _, ok := limiter.ipTokenBucketMap["10.0.0.1"]; ok {
		t.Fatal("idle IP bucket was not swept")
	}
}

func TestLimiterSweepRespectsCadence(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock.now)

	if !allowed(limiter, "old@example.com", "10.0.0.1") {
		t.Fatal("first request was denied, want allowed")
	}

	clock.advance(time.Minute)
	if !allowed(limiter, "new@example.com", "10.0.0.2") {
		t.Fatal("second request was denied, want allowed")
	}

	if _, ok := limiter.emailTokenBucketMap["old@example.com"]; !ok {
		t.Fatal("bucket was swept before the sweep cadence elapsed")
	}
}

func TestLimiterConcurrentUse(t *testing.T) {
	clock := newFakeClock()
	limiter := newTestLimiter(clock.now)

	var allowedCount atomic.Int64
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			if allowed(limiter, "user@example.com", "10.0.0.1") {
				allowedCount.Add(1)
			}
		})
	}
	wg.Wait()

	if got := allowedCount.Load(); got != testEmailBurst {
		t.Fatalf("%d requests allowed, want %d", got, testEmailBurst)
	}
}

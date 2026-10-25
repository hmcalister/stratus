package auth

import (
	"sync"
	"time"
)

// A manually advanced clock for tests that need expiry or window boundaries without sleeping.
type fakeClock struct {
	mu      sync.Mutex
	current time.Time
}

// Returns a clock that starts at an arbitrary fixed instant.
func newFakeClock() *fakeClock {
	return &fakeClock{current: time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

// Moves the clock forward by d.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = c.current.Add(d)
}

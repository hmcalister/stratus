package linkstore

import (
	"testing"
	"time"
)

// A manually advanced clock for tests.
type fakeClock struct {
	current time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{current: time.Date(2000, time.January, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	return c.current
}

func (c *fakeClock) advance(d time.Duration) {
	c.current = c.current.Add(d)
}

func TestStoreConsumeIsSingleUse(t *testing.T) {
	clock := newFakeClock()
	store := New(clock.now)

	store.Create("hash", "user@example.com", clock.now().Add(time.Minute))

	email, ok := store.Consume("hash")
	if !ok {
		t.Fatal("first consume was rejected, want accepted")
	}
	if email != "user@example.com" {
		t.Fatalf("first consume email = %q, want %q", email, "user@example.com")
	}

	if email, ok := store.Consume("hash"); ok {
		t.Fatalf("second consume = (%q, true), want (\"\", false)", email)
	}
}

func TestStoreConsumeRejectsUnknownHash(t *testing.T) {
	store := New(newFakeClock().now)

	if email, ok := store.Consume("unknown"); ok {
		t.Fatalf("consume of unknown hash = (%q, true), want (\"\", false)", email)
	}
}

func TestStoreConsumeRejectsExpiredLink(t *testing.T) {
	clock := newFakeClock()
	store := New(clock.now)

	store.Create("hash", "user@example.com", clock.now().Add(time.Minute))
	clock.advance(time.Minute)

	if email, ok := store.Consume("hash"); ok {
		t.Fatalf("consume of expired link = (%q, true), want (\"\", false)", email)
	}
	if len(store.links) != 0 {
		t.Fatalf("%d links remain, want 0", len(store.links))
	}
}

func TestStoreCreateRemovesExpiredLinks(t *testing.T) {
	clock := newFakeClock()
	store := New(clock.now)

	store.Create("stale", "stale@example.com", clock.now().Add(time.Minute))
	store.Create("live", "live@example.com", clock.now().Add(time.Hour))
	clock.advance(2 * time.Minute)

	store.Create("fresh", "fresh@example.com", clock.now().Add(time.Hour))

	if len(store.links) != 2 {
		t.Fatalf("%d links remain, want 2", len(store.links))
	}
	if _, ok := store.links["stale"]; ok {
		t.Fatal("expired link was not removed on insert")
	}
}

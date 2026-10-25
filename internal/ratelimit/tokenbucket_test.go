package ratelimit

import (
	"testing"
	"time"
)

func TestNewTokenBucketStartsFull(t *testing.T) {
	b := newTokenBucket(5, time.Second)
	if b.tokens != 5 {
		t.Errorf("tokens = %v, want 5", b.tokens)
	}
	if b.burst != 5 {
		t.Errorf("burst = %v, want 5", b.burst)
	}
	if b.interval != time.Second {
		t.Errorf("interval = %v, want 1s", b.interval)
	}
}

func TestTokenBucketAvailableWhileTokensRemain(t *testing.T) {
	now := time.Now()
	b := newTokenBucket(3, time.Second)
	b.last = now

	for i := range 3 {
		if wait := b.durationUntilNextToken(now); wait != 0 {
			t.Fatalf("call %d: wait = %v, want 0", i, wait)
		}
		b.tokens--
	}

	if wait := b.durationUntilNextToken(now); wait <= 0 {
		t.Errorf("wait = %v, want > 0 after draining", wait)
	}
}

func TestTokenBucketRefillsOverTime(t *testing.T) {
	start := time.Now()
	b := newTokenBucket(1, time.Second)
	b.last = start
	b.tokens = 0

	if wait := b.durationUntilNextToken(start.Add(500 * time.Millisecond)); wait <= 0 {
		t.Errorf("wait = %v, want > 0 at half interval", wait)
	}

	b.tokens = 0
	b.last = start
	if wait := b.durationUntilNextToken(start.Add(time.Second)); wait != 0 {
		t.Errorf("wait = %v, want 0 after full interval", wait)
	}
}

func TestTokenBucketRefillCapsAtBurst(t *testing.T) {
	start := time.Now()
	b := newTokenBucket(2, time.Second)
	b.last = start
	b.tokens = 0

	b.durationUntilNextToken(start.Add(time.Hour))
	if b.tokens != 2 {
		t.Errorf("tokens = %v, want capped at 2", b.tokens)
	}
}

func TestTokenBucketPartialRefillWait(t *testing.T) {
	start := time.Now()
	b := newTokenBucket(1, time.Second)
	b.last = start
	b.tokens = 0

	wait := b.durationUntilNextToken(start.Add(750 * time.Millisecond))
	want := 250 * time.Millisecond
	if wait != want {
		t.Errorf("wait = %v, want %v", wait, want)
	}
}

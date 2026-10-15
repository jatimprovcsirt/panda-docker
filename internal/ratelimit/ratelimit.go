// Package ratelimit bounds request rates per credential.
//
// Applied before any cryptographic work. A rate limiter that runs after the
// expensive path has not limited the cost it exists to limit.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a token bucket per key.
//
// Per credential rather than global: a single noisy application should not
// exhaust the budget for every other organization sharing the service, and a global
// limit gives an attacker a trivial way to deny service to everyone else.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	rate  float64 // tokens per second
	burst float64

	// now is injectable so the tests do not have to sleep.
	now func() time.Time
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// New builds a limiter. A rate of zero or less disables limiting entirely.
func New(ratePerSecond, burst int) *Limiter {
	if burst <= 0 {
		burst = ratePerSecond
	}
	return &Limiter{
		buckets: make(map[string]*bucket),
		rate:    float64(ratePerSecond),
		burst:   float64(burst),
		now:     time.Now,
	}
}

// Allow reports whether a request from `key` may proceed.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.rate <= 0 {
		return true
	}
	if key == "" {
		key = "unknown"
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		// A new key starts with a full bucket, so the first request from a
		// freshly deployed application is never rejected.
		l.buckets[key] = &bucket{tokens: l.burst - 1, lastSeen: now}
		l.evictStaleLocked(now)
		return true
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// staleAfter is how long an idle bucket is kept.
//
// Without eviction the map grows with every distinct key id ever seen, which
// for a service with rotating credentials is a slow leak.
const staleAfter = 10 * time.Minute

func (l *Limiter) evictStaleLocked(now time.Time) {
	for key, b := range l.buckets {
		if now.Sub(b.lastSeen) > staleAfter {
			delete(l.buckets, key)
		}
	}
}

// TrackedKeys reports how many buckets are live, for tests.
func (l *Limiter) TrackedKeys() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// WithClock replaces the clock. Test-only.
func (l *Limiter) WithClock(now func() time.Time) *Limiter {
	l.now = now
	return l
}

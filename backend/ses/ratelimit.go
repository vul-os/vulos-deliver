package ses

import (
	"context"
	"sync"
	"time"
)

// TokenBucket is a thread-safe token-bucket rate limiter used to respect the
// SES per-second send-rate limit.
//
// New SES production accounts start at ~14 sends/second; the quota can be
// raised via the SES console. Sandbox accounts are effectively 200/day.
// Set Config.SendRate to match your actual account quota.
type TokenBucket struct {
	rate     float64 // tokens (sends) added per second
	tokens   float64 // current token count
	cap      float64 // maximum token count (= rate, burst = 1 second)
	lastTime time.Time
	mu       sync.Mutex
}

// NewTokenBucket creates a rate limiter allowing at most rate sends per second.
// The burst capacity is 1 second worth of tokens (i.e. rate tokens).
func NewTokenBucket(rate float64) *TokenBucket {
	return &TokenBucket{
		rate:     rate,
		tokens:   rate, // start full
		cap:      rate,
		lastTime: time.Now(),
	}
}

// refill credits tokens proportional to elapsed time. Must be called with mu held.
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastTime).Seconds()
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.cap {
		tb.tokens = tb.cap
	}
	tb.lastTime = now
}

// Wait blocks until a send token is available or ctx is cancelled.
// It returns ctx.Err() if the context is cancelled before a token is acquired.
func (tb *TokenBucket) Wait(ctx context.Context) error {
	for {
		tb.mu.Lock()
		tb.refill()
		if tb.tokens >= 1 {
			tb.tokens--
			tb.mu.Unlock()
			return nil
		}
		// How long until the next token arrives?
		deficit := 1 - tb.tokens
		waitDur := time.Duration(deficit / tb.rate * float64(time.Second))
		tb.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitDur):
			// loop and try to acquire again
		}
	}
}

// Available returns the current token count (informational / for tests).
func (tb *TokenBucket) Available() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	return tb.tokens
}

// Rate returns the configured tokens-per-second rate.
func (tb *TokenBucket) Rate() float64 { return tb.rate }

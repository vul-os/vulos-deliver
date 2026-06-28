package ses

import (
	"context"
	"testing"
	"time"
)

func TestTokenBucket_ImmediateGrant(t *testing.T) {
	// With a full bucket, the first token should be granted instantly.
	tb := NewTokenBucket(100) // 100 tokens/sec
	start := time.Now()
	if err := tb.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("Wait took %v, expected near-instant with full bucket", elapsed)
	}
}

func TestTokenBucket_Rate(t *testing.T) {
	// 1000 tokens/sec — bucket starts full, so first token is free.
	// After draining, refill should be fast enough that this completes quickly.
	tb := NewTokenBucket(1000)

	// Drain the full bucket.
	for i := 0; i < int(tb.cap); i++ {
		tb.mu.Lock()
		tb.tokens-- // force-drain
		tb.mu.Unlock()
	}
	tb.mu.Lock()
	tb.tokens = 0
	tb.mu.Unlock()

	// With rate=1000/sec and 1 token needed, wait should be ~1ms.
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := tb.Wait(ctx); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("Wait took %v, expected <100ms at 1000 tok/sec", elapsed)
	}
}

func TestTokenBucket_ContextCancellation(t *testing.T) {
	// Rate of 0.001/sec → need to wait ~1000s for a token.
	// Cancel context immediately; Wait must return ctx.Err().
	tb := NewTokenBucket(0.001)
	tb.mu.Lock()
	tb.tokens = 0 // drain
	tb.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	start := time.Now()
	err := tb.Wait(ctx)
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("Wait took %v after cancel, expected near-instant", elapsed)
	}
}

func TestTokenBucket_Available(t *testing.T) {
	tb := NewTokenBucket(10)
	avail := tb.Available()
	if avail < 9.9 || avail > 10.1 {
		t.Errorf("Available() = %v, want ~10", avail)
	}
}

func TestTokenBucket_CapNotExceeded(t *testing.T) {
	tb := NewTokenBucket(5)
	// Simulate long idle time.
	tb.mu.Lock()
	tb.lastTime = time.Now().Add(-1 * time.Hour)
	tb.mu.Unlock()

	avail := tb.Available()
	if avail > tb.cap+0.01 {
		t.Errorf("Available() = %v exceeded cap %v", avail, tb.cap)
	}
}

func TestTokenBucket_Rate_Accessor(t *testing.T) {
	tb := NewTokenBucket(14)
	if tb.Rate() != 14 {
		t.Errorf("Rate() = %v, want 14", tb.Rate())
	}
}

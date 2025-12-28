package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.RequestsPerSecond != 100 {
		t.Errorf("RequestsPerSecond = %v, want 100", config.RequestsPerSecond)
	}
	if config.BurstSize != 200 {
		t.Errorf("BurstSize = %v, want 200", config.BurstSize)
	}
	if config.MaxConcurrent != 50 {
		t.Errorf("MaxConcurrent = %v, want 50", config.MaxConcurrent)
	}
}

func TestNewTokenBucket(t *testing.T) {
	tb := NewTokenBucket(10, 5)

	if tb.maxTokens != 10 {
		t.Errorf("maxTokens = %v, want 10", tb.maxTokens)
	}
	if tb.refillRate != 5 {
		t.Errorf("refillRate = %v, want 5", tb.refillRate)
	}
	if tb.tokens != 10 {
		t.Errorf("Initial tokens = %v, want 10", tb.tokens)
	}
}

func TestTokenBucket_Allow(t *testing.T) {
	tb := NewTokenBucket(5, 1) // 5 tokens, 1 per second refill

	// Should allow first 5 requests
	for i := 0; i < 5; i++ {
		if !tb.Allow() {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied
	if tb.Allow() {
		t.Error("6th request should be denied")
	}
}

func TestTokenBucket_AllowN(t *testing.T) {
	tb := NewTokenBucket(10, 1)

	// Should allow requesting 5 tokens
	if !tb.AllowN(5) {
		t.Error("Should allow 5 tokens")
	}

	// Should allow requesting 5 more
	if !tb.AllowN(5) {
		t.Error("Should allow 5 more tokens")
	}

	// Should not allow more
	if tb.AllowN(1) {
		t.Error("Should not allow more tokens")
	}
}

func TestTokenBucket_Refill(t *testing.T) {
	tb := NewTokenBucket(10, 100) // High refill rate for faster test

	// Consume all tokens
	for i := 0; i < 10; i++ {
		tb.Allow()
	}

	// Should be denied
	if tb.Allow() {
		t.Error("Should be denied after consuming all tokens")
	}

	// Wait for refill
	time.Sleep(50 * time.Millisecond)

	// Should have some tokens now
	if !tb.Allow() {
		t.Error("Should be allowed after refill")
	}
}

func TestTokenBucket_Available(t *testing.T) {
	tb := NewTokenBucket(10, 1)

	available := tb.Available()
	if available != 10 {
		t.Errorf("Initial available = %v, want 10", available)
	}

	tb.Allow()
	available = tb.Available()
	if available != 9 {
		t.Errorf("Available after Allow = %v, want 9", available)
	}
}

func TestLimiter_New(t *testing.T) {
	config := Config{
		RequestsPerSecond: 10,
		BurstSize:         20,
		MaxConcurrent:     5,
		MaxQueueSize:      10,
		QueueTimeout:      5 * time.Second,
	}

	l := New(config)

	if l == nil {
		t.Fatal("New() returned nil")
	}
	if l.maxConcurrent != 5 {
		t.Errorf("maxConcurrent = %v, want 5", l.maxConcurrent)
	}
}

func TestLimiter_SetFunctionConfig(t *testing.T) {
	l := New(DefaultConfig())

	customConfig := Config{
		RequestsPerSecond: 50,
		BurstSize:         100,
	}

	l.SetFunctionConfig("special-func", customConfig)

	// The function bucket should use the custom config
	bucket := l.getFunctionBucket("special-func")
	if bucket.maxTokens != 100 {
		t.Errorf("Function bucket maxTokens = %v, want 100", bucket.maxTokens)
	}
}

func TestLimiter_Allow(t *testing.T) {
	config := Config{
		RequestsPerSecond: 100,
		BurstSize:         10,
		MaxConcurrent:     5,
		MaxQueueSize:      0,
		QueueTimeout:      0,
	}
	l := New(config)

	// First 10 requests should be allowed
	for i := 0; i < 10; i++ {
		if err := l.Allow("key1", "func1"); err != nil {
			t.Errorf("Request %d should be allowed, got error: %v", i+1, err)
		}
	}

	// 11th request should be rate limited
	err := l.Allow("key1", "func1")
	if err == nil {
		t.Error("11th request should be rate limited")
	}
	if err != ErrRateLimited {
		t.Errorf("Error = %v, want ErrRateLimited", err)
	}
}

func TestLimiter_Allow_DifferentKeys(t *testing.T) {
	config := Config{
		RequestsPerSecond: 100,
		BurstSize:         5,
		MaxConcurrent:     5,
		MaxQueueSize:      0,
		QueueTimeout:      0,
	}
	l := New(config)

	// Each key has its own bucket
	for i := 0; i < 5; i++ {
		if err := l.Allow("key1", "func1"); err != nil {
			t.Errorf("key1 request %d should be allowed", i+1)
		}
	}

	// key1 should be rate limited
	if err := l.Allow("key1", "func1"); err == nil {
		t.Error("key1 should be rate limited")
	}

	// key2 should still have tokens
	if err := l.Allow("key2", "func1"); err != nil {
		t.Error("key2 should still be allowed")
	}
}

func TestLimiter_Acquire_Release(t *testing.T) {
	config := Config{
		RequestsPerSecond: 100,
		BurstSize:         100,
		MaxConcurrent:     2,
		MaxQueueSize:      0,
		QueueTimeout:      0,
	}
	l := New(config)

	// Acquire 2 slots
	if err := l.Acquire(context.Background()); err != nil {
		t.Fatalf("First acquire failed: %v", err)
	}
	if err := l.Acquire(context.Background()); err != nil {
		t.Fatalf("Second acquire failed: %v", err)
	}

	// Third acquire should fail (queue disabled)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := l.Acquire(ctx); err == nil {
		t.Error("Third acquire should fail")
	}

	// Release one slot
	l.Release()

	// Now acquire should succeed
	if err := l.Acquire(context.Background()); err != nil {
		t.Errorf("Acquire after release failed: %v", err)
	}
}

func TestLimiter_Acquire_WithQueue(t *testing.T) {
	config := Config{
		RequestsPerSecond: 100,
		BurstSize:         100,
		MaxConcurrent:     1,
		MaxQueueSize:      10,
		QueueTimeout:      1 * time.Second,
	}
	l := New(config)

	// Acquire the only slot
	l.Acquire(context.Background())

	// Start a goroutine to release after delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		l.Release()
	}()

	// This should queue and eventually succeed
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := l.Acquire(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Queued acquire failed: %v", err)
	}

	// Should have waited some time
	if elapsed < 40*time.Millisecond {
		t.Errorf("Acquire returned too quickly: %v", elapsed)
	}
}

func TestLimiter_Stats(t *testing.T) {
	config := Config{
		RequestsPerSecond: 100,
		BurstSize:         10,
		MaxConcurrent:     5,
		MaxQueueSize:      10,
		QueueTimeout:      1 * time.Second,
	}
	l := New(config)

	// Make some requests
	l.Allow("key1", "func1")
	l.Allow("key1", "func1")
	l.Acquire(context.Background())

	stats := l.Stats()

	if stats.GlobalTokens < 0 {
		t.Error("GlobalTokens should be >= 0")
	}
	if stats.CurrentConcurrent != 1 {
		t.Errorf("CurrentConcurrent = %v, want 1", stats.CurrentConcurrent)
	}
	if stats.MaxConcurrent != 5 {
		t.Errorf("MaxConcurrent = %v, want 5", stats.MaxConcurrent)
	}
}

func TestLimiter_KeyStats(t *testing.T) {
	config := DefaultConfig()
	config.BurstSize = 10
	l := New(config)

	// Make some requests for a key
	l.Allow("test-key", "func1")
	l.Allow("test-key", "func1")

	stats := l.Stats()

	// KeyStats is a map of key -> tokens available
	if tokens, exists := stats.KeyStats["test-key"]; exists {
		if tokens >= 10 {
			t.Error("KeyStats tokens should be less than max after requests")
		}
	}
}

func TestErrors(t *testing.T) {
	if ErrRateLimited.Error() != "rate limit exceeded" {
		t.Errorf("ErrRateLimited message = %v", ErrRateLimited.Error())
	}
	if ErrConcurrencyLimit.Error() != "concurrency limit exceeded" {
		t.Errorf("ErrConcurrencyLimit message = %v", ErrConcurrencyLimit.Error())
	}
	if ErrQueueFull.Error() != "request queue is full" {
		t.Errorf("ErrQueueFull message = %v", ErrQueueFull.Error())
	}
}

func TestTokenBucket_Concurrent(t *testing.T) {
	tb := NewTokenBucket(100, 10)

	done := make(chan bool)
	for i := 0; i < 50; i++ {
		go func() {
			tb.Allow()
			tb.Available()
			done <- true
		}()
	}

	for i := 0; i < 50; i++ {
		<-done
	}
}

func TestLimiter_Concurrent(t *testing.T) {
	config := Config{
		RequestsPerSecond: 1000,
		BurstSize:         1000,
		MaxConcurrent:     100,
		MaxQueueSize:      100,
		QueueTimeout:      5 * time.Second,
	}
	l := New(config)

	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(n int) {
			key := "key"
			if n%2 == 0 {
				key = "key2"
			}
			l.Allow(key, "func1")
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

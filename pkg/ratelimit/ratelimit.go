package ratelimit

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/github-lambda/pkg/logging"
)

var (
	ErrRateLimited      = errors.New("rate limit exceeded")
	ErrConcurrencyLimit = errors.New("concurrency limit exceeded")
	ErrQueueFull        = errors.New("request queue is full")
)

// Config holds rate limiter configuration.
type Config struct {
	// RequestsPerSecond is the maximum requests per second (token bucket refill rate)
	RequestsPerSecond float64

	// BurstSize is the maximum burst size (token bucket capacity)
	BurstSize int

	// MaxConcurrent is the maximum number of concurrent requests
	MaxConcurrent int

	// MaxQueueSize is the maximum number of queued requests (0 = no queue)
	MaxQueueSize int

	// QueueTimeout is how long a request can wait in queue
	QueueTimeout time.Duration
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() Config {
	return Config{
		RequestsPerSecond: 100,
		BurstSize:         200,
		MaxConcurrent:     50,
		MaxQueueSize:      100,
		QueueTimeout:      30 * time.Second,
	}
}

// TokenBucket implements the token bucket algorithm for rate limiting.
type TokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

// NewTokenBucket creates a new token bucket.
func NewTokenBucket(maxTokens float64, refillRate float64) *TokenBucket {
	return &TokenBucket{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request is allowed and consumes a token if so.
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

// AllowN checks if n requests are allowed and consumes n tokens if so.
func (tb *TokenBucket) AllowN(n float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}
	return false
}

func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}
	tb.lastRefill = now
}

// Available returns the current number of available tokens.
func (tb *TokenBucket) Available() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	return tb.tokens
}

// Limiter provides comprehensive rate limiting.
type Limiter struct {
	mu sync.RWMutex

	// Global limits
	globalBucket  *TokenBucket
	concurrent    int
	maxConcurrent int
	queueSize     int
	maxQueueSize  int
	queueTimeout  time.Duration

	// Per-key limits (by API key ID or IP)
	keyBuckets    map[string]*TokenBucket
	keyConcurrent map[string]int
	keyConfig     Config

	// Per-function limits
	functionBuckets    map[string]*TokenBucket
	functionConcurrent map[string]int
	functionConfig     map[string]Config

	// Semaphore for concurrency control
	semaphore chan struct{}
	queue     chan *queuedRequest

	logger *logging.Logger
}

type queuedRequest struct {
	done chan error
	ctx  context.Context
}

// New creates a new rate limiter.
func New(config Config) *Limiter {
	l := &Limiter{
		globalBucket:       NewTokenBucket(float64(config.BurstSize), config.RequestsPerSecond),
		maxConcurrent:      config.MaxConcurrent,
		maxQueueSize:       config.MaxQueueSize,
		queueTimeout:       config.QueueTimeout,
		keyBuckets:         make(map[string]*TokenBucket),
		keyConcurrent:      make(map[string]int),
		keyConfig:          config,
		functionBuckets:    make(map[string]*TokenBucket),
		functionConcurrent: make(map[string]int),
		functionConfig:     make(map[string]Config),
		semaphore:          make(chan struct{}, config.MaxConcurrent),
		queue:              make(chan *queuedRequest, config.MaxQueueSize),
		logger:             logging.New("ratelimit"),
	}

	// Start queue processor
	go l.processQueue()

	return l
}

// Default is the global rate limiter instance.
var Default = New(DefaultConfig())

// SetFunctionConfig sets rate limit configuration for a specific function.
func (l *Limiter) SetFunctionConfig(functionName string, config Config) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.functionConfig[functionName] = config
	l.functionBuckets[functionName] = NewTokenBucket(float64(config.BurstSize), config.RequestsPerSecond)
}

// getKeyBucket gets or creates a token bucket for the given key.
func (l *Limiter) getKeyBucket(key string) *TokenBucket {
	l.mu.Lock()
	defer l.mu.Unlock()

	if bucket, exists := l.keyBuckets[key]; exists {
		return bucket
	}

	bucket := NewTokenBucket(float64(l.keyConfig.BurstSize), l.keyConfig.RequestsPerSecond)
	l.keyBuckets[key] = bucket
	return bucket
}

// getFunctionBucket gets or creates a token bucket for the given function.
func (l *Limiter) getFunctionBucket(functionName string) *TokenBucket {
	l.mu.Lock()
	defer l.mu.Unlock()

	if bucket, exists := l.functionBuckets[functionName]; exists {
		return bucket
	}

	// Use default config if no specific config exists
	config := l.keyConfig
	if fc, exists := l.functionConfig[functionName]; exists {
		config = fc
	}

	bucket := NewTokenBucket(float64(config.BurstSize), config.RequestsPerSecond)
	l.functionBuckets[functionName] = bucket
	return bucket
}

// Allow checks if a request should be allowed based on all rate limits.
func (l *Limiter) Allow(key string, functionName string) error {
	// Check global rate limit
	if !l.globalBucket.Allow() {
		l.logger.Warn("global rate limit exceeded", logging.Fields{
			"key":      key,
			"function": functionName,
		})
		return ErrRateLimited
	}

	// Check per-key rate limit
	if key != "" {
		keyBucket := l.getKeyBucket(key)
		if !keyBucket.Allow() {
			l.logger.Warn("key rate limit exceeded", logging.Fields{
				"key":      key,
				"function": functionName,
			})
			return ErrRateLimited
		}
	}

	// Check per-function rate limit
	if functionName != "" {
		funcBucket := l.getFunctionBucket(functionName)
		if !funcBucket.Allow() {
			l.logger.Warn("function rate limit exceeded", logging.Fields{
				"key":      key,
				"function": functionName,
			})
			return ErrRateLimited
		}
	}

	return nil
}

// Acquire attempts to acquire a concurrency slot.
func (l *Limiter) Acquire(ctx context.Context) error {
	select {
	case l.semaphore <- struct{}{}:
		l.mu.Lock()
		l.concurrent++
		l.mu.Unlock()
		return nil
	default:
		// Semaphore full, try to queue
		return l.enqueue(ctx)
	}
}

// Release releases a concurrency slot.
func (l *Limiter) Release() {
	select {
	case <-l.semaphore:
		l.mu.Lock()
		l.concurrent--
		l.mu.Unlock()
	default:
		// Shouldn't happen, but handle gracefully
	}
}

// enqueue adds a request to the queue.
func (l *Limiter) enqueue(ctx context.Context) error {
	l.mu.Lock()
	if l.queueSize >= l.maxQueueSize {
		l.mu.Unlock()
		l.logger.Warn("request queue full")
		return ErrQueueFull
	}
	l.queueSize++
	l.mu.Unlock()

	req := &queuedRequest{
		done: make(chan error, 1),
		ctx:  ctx,
	}

	// Set up timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, l.queueTimeout)
	defer cancel()

	select {
	case l.queue <- req:
		// Queued successfully, wait for processing
		select {
		case err := <-req.done:
			return err
		case <-timeoutCtx.Done():
			l.mu.Lock()
			l.queueSize--
			l.mu.Unlock()
			return ErrQueueFull
		}
	case <-timeoutCtx.Done():
		l.mu.Lock()
		l.queueSize--
		l.mu.Unlock()
		return ErrQueueFull
	}
}

// processQueue processes queued requests.
func (l *Limiter) processQueue() {
	for req := range l.queue {
		select {
		case <-req.ctx.Done():
			// Request cancelled
			l.mu.Lock()
			l.queueSize--
			l.mu.Unlock()
			req.done <- req.ctx.Err()
		case l.semaphore <- struct{}{}:
			l.mu.Lock()
			l.queueSize--
			l.concurrent++
			l.mu.Unlock()
			req.done <- nil
		}
	}
}

// AcquireFunction acquires a concurrency slot for a specific function.
func (l *Limiter) AcquireFunction(ctx context.Context, functionName string) error {
	l.mu.Lock()
	config, exists := l.functionConfig[functionName]
	if !exists {
		config = l.keyConfig
	}
	current := l.functionConcurrent[functionName]
	if current >= config.MaxConcurrent {
		l.mu.Unlock()
		l.logger.Warn("function concurrency limit exceeded", logging.Fields{
			"function": functionName,
			"current":  current,
			"max":      config.MaxConcurrent,
		})
		return ErrConcurrencyLimit
	}
	l.functionConcurrent[functionName]++
	l.mu.Unlock()
	return nil
}

// ReleaseFunction releases a function concurrency slot.
func (l *Limiter) ReleaseFunction(functionName string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.functionConcurrent[functionName] > 0 {
		l.functionConcurrent[functionName]--
	}
}

// Stats returns current rate limiter statistics.
type Stats struct {
	GlobalTokens       float64            `json:"global_tokens_available"`
	CurrentConcurrent  int                `json:"current_concurrent"`
	MaxConcurrent      int                `json:"max_concurrent"`
	QueueSize          int                `json:"queue_size"`
	MaxQueueSize       int                `json:"max_queue_size"`
	FunctionConcurrent map[string]int     `json:"function_concurrent"`
	KeyStats           map[string]float64 `json:"key_tokens_available"`
}

// Stats returns current statistics.
func (l *Limiter) Stats() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	funcConcurrent := make(map[string]int)
	for k, v := range l.functionConcurrent {
		funcConcurrent[k] = v
	}

	keyStats := make(map[string]float64)
	for k, bucket := range l.keyBuckets {
		keyStats[k] = bucket.Available()
	}

	return Stats{
		GlobalTokens:       l.globalBucket.Available(),
		CurrentConcurrent:  l.concurrent,
		MaxConcurrent:      l.maxConcurrent,
		QueueSize:          l.queueSize,
		MaxQueueSize:       l.maxQueueSize,
		FunctionConcurrent: funcConcurrent,
		KeyStats:           keyStats,
	}
}

// Reset resets all rate limit counters (for testing).
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.globalBucket = NewTokenBucket(float64(l.keyConfig.BurstSize), l.keyConfig.RequestsPerSecond)
	l.keyBuckets = make(map[string]*TokenBucket)
	l.functionBuckets = make(map[string]*TokenBucket)
}

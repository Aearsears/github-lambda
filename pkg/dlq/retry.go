package dlq

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/github-lambda/pkg/logging"
)

// RetryPolicy defines how retries should be handled.
type RetryPolicy struct {
	// MaxRetries is the maximum number of retry attempts (0 = no retries).
	MaxRetries int `json:"max_retries"`

	// InitialDelay is the delay before the first retry.
	InitialDelay time.Duration `json:"initial_delay_ms"`

	// MaxDelay is the maximum delay between retries.
	MaxDelay time.Duration `json:"max_delay_ms"`

	// BackoffMultiplier is the factor by which delay increases (for exponential backoff).
	BackoffMultiplier float64 `json:"backoff_multiplier"`

	// Jitter adds randomness to delays to prevent thundering herd.
	Jitter float64 `json:"jitter"` // 0.0 to 1.0

	// RetriableErrors specifies which error types should be retried.
	// If empty, all retriable errors will be retried.
	RetriableErrors []FailureReason `json:"retriable_errors,omitempty"`

	// NonRetriableErrors specifies which error types should NOT be retried.
	NonRetriableErrors []FailureReason `json:"non_retriable_errors,omitempty"`
}

// DefaultRetryPolicy returns a sensible default retry policy.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries:        3,
		InitialDelay:      1 * time.Second,
		MaxDelay:          30 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            0.1,
		NonRetriableErrors: []FailureReason{
			ReasonInvalidPayload,
			ReasonFunctionNotFound,
			ReasonPermissionDenied,
		},
	}
}

// AggressiveRetryPolicy returns a policy for critical operations.
func AggressiveRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries:        5,
		InitialDelay:      500 * time.Millisecond,
		MaxDelay:          1 * time.Minute,
		BackoffMultiplier: 2.0,
		Jitter:            0.2,
		NonRetriableErrors: []FailureReason{
			ReasonInvalidPayload,
			ReasonFunctionNotFound,
			ReasonPermissionDenied,
		},
	}
}

// NoRetryPolicy returns a policy that doesn't retry.
func NoRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries: 0,
	}
}

// ShouldRetry determines if a failure reason should be retried.
func (p RetryPolicy) ShouldRetry(reason FailureReason) bool {
	// Check non-retriable list first
	for _, r := range p.NonRetriableErrors {
		if r == reason {
			return false
		}
	}

	// If retriable list is specified, check it
	if len(p.RetriableErrors) > 0 {
		for _, r := range p.RetriableErrors {
			if r == reason {
				return true
			}
		}
		return false
	}

	// Default: use error type
	return reason.GetErrorType() == ErrorTypeRetriable
}

// CalculateDelay calculates the delay before the next retry attempt.
func (p RetryPolicy) CalculateDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return p.InitialDelay
	}

	// Exponential backoff
	delay := float64(p.InitialDelay) * math.Pow(p.BackoffMultiplier, float64(attempt-1))

	// Apply max delay cap
	if delay > float64(p.MaxDelay) {
		delay = float64(p.MaxDelay)
	}

	// Apply jitter
	if p.Jitter > 0 {
		jitterRange := delay * p.Jitter
		delay = delay - jitterRange + (rand.Float64() * 2 * jitterRange)
	}

	return time.Duration(delay)
}

// Retryer handles retry logic for function invocations.
type Retryer struct {
	mu               sync.RWMutex
	defaultPolicy    RetryPolicy
	functionPolicies map[string]RetryPolicy
	dlq              *Queue
	logger           *logging.Logger
}

// NewRetryer creates a new retryer with a DLQ.
func NewRetryer(dlq *Queue, defaultPolicy RetryPolicy) *Retryer {
	return &Retryer{
		defaultPolicy:    defaultPolicy,
		functionPolicies: make(map[string]RetryPolicy),
		dlq:              dlq,
		logger:           logging.New("retryer"),
	}
}

// SetFunctionPolicy sets a custom retry policy for a specific function.
func (r *Retryer) SetFunctionPolicy(functionName string, policy RetryPolicy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.functionPolicies[functionName] = policy
}

// GetPolicy returns the retry policy for a function.
func (r *Retryer) GetPolicy(functionName string) RetryPolicy {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if policy, ok := r.functionPolicies[functionName]; ok {
		return policy
	}
	return r.defaultPolicy
}

// InvokeFunc is a function that performs the actual invocation.
type InvokeFunc func(ctx context.Context) (interface{}, error)

// RetryResult contains the result of a retry operation.
type RetryResult struct {
	Success      bool
	Result       interface{}
	FinalError   error
	Attempts     int
	TotalTime    time.Duration
	RetryHistory []RetryAttempt
}

// ExecuteWithRetry executes a function with retry logic.
func (r *Retryer) ExecuteWithRetry(ctx context.Context, functionName string, fn InvokeFunc, classifyError func(error) FailureReason) RetryResult {
	policy := r.GetPolicy(functionName)
	result := RetryResult{}
	startTime := time.Now()

	for attempt := 0; attempt <= policy.MaxRetries; attempt++ {
		attemptStart := time.Now()
		res, err := fn(ctx)

		if err == nil {
			result.Success = true
			result.Result = res
			result.Attempts = attempt + 1
			result.TotalTime = time.Since(startTime)
			return result
		}

		// Classify the error
		reason := classifyError(err)
		duration := time.Since(attemptStart)

		// Record attempt
		result.RetryHistory = append(result.RetryHistory, RetryAttempt{
			Attempt:      attempt + 1,
			AttemptedAt:  attemptStart,
			ErrorMessage: err.Error(),
			DurationMs:   duration.Milliseconds(),
		})

		result.FinalError = err

		r.logger.Warn("invocation attempt failed", logging.Fields{
			"function_name": functionName,
			"attempt":       attempt + 1,
			"max_retries":   policy.MaxRetries,
			"error":         err.Error(),
			"reason":        string(reason),
			"duration_ms":   duration.Milliseconds(),
		})

		// Check if we should retry
		if attempt >= policy.MaxRetries {
			break
		}

		if !policy.ShouldRetry(reason) {
			r.logger.Info("error not retriable, stopping retries", logging.Fields{
				"function_name": functionName,
				"reason":        string(reason),
			})
			break
		}

		// Calculate and wait for delay
		delay := policy.CalculateDelay(attempt + 1)

		select {
		case <-ctx.Done():
			result.FinalError = ctx.Err()
			result.Attempts = attempt + 1
			result.TotalTime = time.Since(startTime)
			return result
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	result.Attempts = len(result.RetryHistory)
	result.TotalTime = time.Since(startTime)
	return result
}

// SendToDLQ sends a failed event to the dead letter queue.
func (r *Retryer) SendToDLQ(event *FailedEvent) error {
	if r.dlq == nil {
		return fmt.Errorf("DLQ not configured")
	}
	return r.dlq.Add(event)
}

// ClassifyError attempts to classify an error into a FailureReason.
func ClassifyError(err error) FailureReason {
	if err == nil {
		return ReasonUnknown
	}

	errStr := err.Error()

	// Check for common error patterns
	switch {
	case contains(errStr, "timeout", "deadline exceeded", "context deadline"):
		return ReasonTimeout
	case contains(errStr, "rate limit", "too many requests", "429"):
		return ReasonRateLimited
	case contains(errStr, "not found", "404", "no such function"):
		return ReasonFunctionNotFound
	case contains(errStr, "permission denied", "forbidden", "403", "unauthorized", "401"):
		return ReasonPermissionDenied
	case contains(errStr, "invalid", "malformed", "bad request", "400"):
		return ReasonInvalidPayload
	case contains(errStr, "connection", "network", "dns", "dial"):
		return ReasonNetworkError
	case contains(errStr, "resource exhausted", "out of memory", "quota"):
		return ReasonResourceExhausted
	case contains(errStr, "internal", "500", "service unavailable", "503"):
		return ReasonServiceError
	default:
		return ReasonFunctionError
	}
}

func contains(s string, substrs ...string) bool {
	for _, substr := range substrs {
		if containsIgnoreCase(s, substr) {
			return true
		}
	}
	return false
}

func containsIgnoreCase(s, substr string) bool {
	// Simple case-insensitive contains
	sLower := toLower(s)
	substrLower := toLower(substr)
	return len(sLower) >= len(substrLower) && findSubstring(sLower, substrLower) >= 0
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

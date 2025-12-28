package dlq

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetryPolicy_ShouldRetry(t *testing.T) {
	policy := DefaultRetryPolicy()

	tests := []struct {
		reason   FailureReason
		expected bool
	}{
		{ReasonTimeout, true},
		{ReasonRateLimited, true},
		{ReasonNetworkError, true},
		{ReasonInvalidPayload, false},       // Non-retriable in default policy
		{ReasonFunctionNotFound, false},     // Non-retriable in default policy
		{ReasonPermissionDenied, false},     // Non-retriable in default policy
		{ReasonServiceError, true},          // Retriable by default
		{ReasonResourceExhausted, true},     // Retriable by default
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			if got := policy.ShouldRetry(tt.reason); got != tt.expected {
				t.Errorf("ShouldRetry(%v) = %v, want %v", tt.reason, got, tt.expected)
			}
		})
	}
}

func TestRetryPolicy_ShouldRetry_CustomRetriableErrors(t *testing.T) {
	policy := RetryPolicy{
		MaxRetries:      3,
		RetriableErrors: []FailureReason{ReasonTimeout, ReasonNetworkError},
	}

	if !policy.ShouldRetry(ReasonTimeout) {
		t.Error("Should retry timeout with custom retriable list")
	}
	if policy.ShouldRetry(ReasonRateLimited) {
		t.Error("Should not retry rate limited (not in custom list)")
	}
}

func TestRetryPolicy_CalculateDelay(t *testing.T) {
	policy := RetryPolicy{
		InitialDelay:      1 * time.Second,
		MaxDelay:          30 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            0, // No jitter for predictable tests
	}

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, 1 * time.Second},  // First attempt
		{1, 1 * time.Second},  // After 1 retry: 1s * 2^0 = 1s
		{2, 2 * time.Second},  // After 2 retries: 1s * 2^1 = 2s
		{3, 4 * time.Second},  // After 3 retries: 1s * 2^2 = 4s
		{4, 8 * time.Second},  // After 4 retries: 1s * 2^3 = 8s
		{5, 16 * time.Second}, // After 5 retries: 1s * 2^4 = 16s
	}

	for _, tt := range tests {
		delay := policy.CalculateDelay(tt.attempt)
		if delay != tt.expected {
			t.Errorf("CalculateDelay(%v) = %v, want %v", tt.attempt, delay, tt.expected)
		}
	}
}

func TestRetryPolicy_CalculateDelay_MaxDelayCap(t *testing.T) {
	policy := RetryPolicy{
		InitialDelay:      1 * time.Second,
		MaxDelay:          10 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            0,
	}

	// Attempt 10 would give 1s * 2^9 = 512s without cap
	delay := policy.CalculateDelay(10)
	if delay > policy.MaxDelay {
		t.Errorf("CalculateDelay exceeded max delay: got %v, max %v", delay, policy.MaxDelay)
	}
}

func TestRetryPolicy_CalculateDelay_WithJitter(t *testing.T) {
	policy := RetryPolicy{
		InitialDelay:      1 * time.Second,
		MaxDelay:          30 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            0.2,
	}

	// With 20% jitter on 1s delay, should be in range [0.8s, 1.2s]
	for i := 0; i < 10; i++ {
		delay := policy.CalculateDelay(1)
		if delay < 800*time.Millisecond || delay > 1200*time.Millisecond {
			t.Errorf("Delay with jitter out of expected range: %v", delay)
		}
	}
}

func TestDefaultRetryPolicy(t *testing.T) {
	policy := DefaultRetryPolicy()

	if policy.MaxRetries != 3 {
		t.Errorf("MaxRetries = %v, want 3", policy.MaxRetries)
	}
	if policy.InitialDelay != 1*time.Second {
		t.Errorf("InitialDelay = %v, want 1s", policy.InitialDelay)
	}
	if policy.MaxDelay != 30*time.Second {
		t.Errorf("MaxDelay = %v, want 30s", policy.MaxDelay)
	}
	if policy.BackoffMultiplier != 2.0 {
		t.Errorf("BackoffMultiplier = %v, want 2.0", policy.BackoffMultiplier)
	}
}

func TestAggressiveRetryPolicy(t *testing.T) {
	policy := AggressiveRetryPolicy()

	if policy.MaxRetries != 5 {
		t.Errorf("MaxRetries = %v, want 5", policy.MaxRetries)
	}
}

func TestNoRetryPolicy(t *testing.T) {
	policy := NoRetryPolicy()

	if policy.MaxRetries != 0 {
		t.Errorf("MaxRetries = %v, want 0", policy.MaxRetries)
	}
}

func TestRetryer_GetPolicy(t *testing.T) {
	dlq := NewQueue(DefaultConfig())
	retryer := NewRetryer(dlq, DefaultRetryPolicy())

	// Default policy
	policy := retryer.GetPolicy("any-func")
	if policy.MaxRetries != 3 {
		t.Errorf("Default policy MaxRetries = %v, want 3", policy.MaxRetries)
	}

	// Set custom policy
	customPolicy := RetryPolicy{MaxRetries: 10}
	retryer.SetFunctionPolicy("custom-func", customPolicy)

	policy = retryer.GetPolicy("custom-func")
	if policy.MaxRetries != 10 {
		t.Errorf("Custom policy MaxRetries = %v, want 10", policy.MaxRetries)
	}

	// Other functions still get default
	policy = retryer.GetPolicy("other-func")
	if policy.MaxRetries != 3 {
		t.Errorf("Other func should get default policy")
	}
}

func TestRetryer_ExecuteWithRetry_Success(t *testing.T) {
	dlq := NewQueue(DefaultConfig())
	retryer := NewRetryer(dlq, DefaultRetryPolicy())

	callCount := 0
	fn := func(ctx context.Context) (interface{}, error) {
		callCount++
		return "success", nil
	}

	result := retryer.ExecuteWithRetry(context.Background(), "test-func", fn, ClassifyError)

	if !result.Success {
		t.Error("Expected success")
	}
	if result.Attempts != 1 {
		t.Errorf("Attempts = %v, want 1", result.Attempts)
	}
	if result.Result != "success" {
		t.Errorf("Result = %v, want success", result.Result)
	}
	if callCount != 1 {
		t.Errorf("Function called %v times, want 1", callCount)
	}
}

func TestRetryer_ExecuteWithRetry_RetrySuccess(t *testing.T) {
	dlq := NewQueue(DefaultConfig())
	policy := RetryPolicy{
		MaxRetries:        3,
		InitialDelay:      1 * time.Millisecond, // Fast for testing
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		Jitter:            0,
	}
	retryer := NewRetryer(dlq, policy)

	callCount := 0
	fn := func(ctx context.Context) (interface{}, error) {
		callCount++
		if callCount < 3 {
			return nil, errors.New("timeout error")
		}
		return "success", nil
	}

	result := retryer.ExecuteWithRetry(context.Background(), "test-func", fn, ClassifyError)

	if !result.Success {
		t.Error("Expected success after retries")
	}
	if result.Attempts != 3 {
		t.Errorf("Attempts = %v, want 3", result.Attempts)
	}
	if len(result.RetryHistory) != 2 {
		t.Errorf("RetryHistory length = %v, want 2", len(result.RetryHistory))
	}
}

func TestRetryer_ExecuteWithRetry_AllRetrysFail(t *testing.T) {
	dlq := NewQueue(DefaultConfig())
	policy := RetryPolicy{
		MaxRetries:        2,
		InitialDelay:      1 * time.Millisecond,
		MaxDelay:          10 * time.Millisecond,
		BackoffMultiplier: 2.0,
		Jitter:            0,
	}
	retryer := NewRetryer(dlq, policy)

	fn := func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("timeout error")
	}

	result := retryer.ExecuteWithRetry(context.Background(), "test-func", fn, ClassifyError)

	if result.Success {
		t.Error("Expected failure after all retries")
	}
	if result.Attempts != 3 { // Initial + 2 retries
		t.Errorf("Attempts = %v, want 3", result.Attempts)
	}
	if result.FinalError == nil {
		t.Error("FinalError should be set")
	}
}

func TestRetryer_ExecuteWithRetry_NonRetriableError(t *testing.T) {
	dlq := NewQueue(DefaultConfig())
	policy := DefaultRetryPolicy()
	policy.InitialDelay = 1 * time.Millisecond
	retryer := NewRetryer(dlq, policy)

	callCount := 0
	fn := func(ctx context.Context) (interface{}, error) {
		callCount++
		return nil, errors.New("invalid payload - malformed request")
	}

	result := retryer.ExecuteWithRetry(context.Background(), "test-func", fn, ClassifyError)

	if result.Success {
		t.Error("Should fail with non-retriable error")
	}
	if callCount != 1 {
		t.Errorf("Function called %v times, want 1 (no retries for non-retriable)", callCount)
	}
}

func TestRetryer_ExecuteWithRetry_ContextCancel(t *testing.T) {
	dlq := NewQueue(DefaultConfig())
	policy := RetryPolicy{
		MaxRetries:        10,
		InitialDelay:      100 * time.Millisecond,
		MaxDelay:          1 * time.Second,
		BackoffMultiplier: 2.0,
		Jitter:            0,
	}
	retryer := NewRetryer(dlq, policy)

	ctx, cancel := context.WithCancel(context.Background())

	callCount := 0
	fn := func(ctx context.Context) (interface{}, error) {
		callCount++
		return nil, errors.New("timeout error")
	}

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	result := retryer.ExecuteWithRetry(ctx, "test-func", fn, ClassifyError)

	if result.Success {
		t.Error("Should fail on context cancel")
	}
	if !errors.Is(result.FinalError, context.Canceled) {
		t.Error("Final error should be context.Canceled")
	}
}

func TestRetryer_SendToDLQ(t *testing.T) {
	dlq := NewQueue(DefaultConfig())
	retryer := NewRetryer(dlq, DefaultRetryPolicy())

	event := &FailedEvent{
		FunctionName:  "test-func",
		ErrorMessage:  "test error",
		FailureReason: ReasonTimeout,
		FailedTime:    time.Now(),
	}

	err := retryer.SendToDLQ(event)
	if err != nil {
		t.Fatalf("SendToDLQ() error = %v", err)
	}

	// Verify event is in DLQ
	events := dlq.List(ListFilter{})
	if len(events) != 1 {
		t.Errorf("DLQ has %v events, want 1", len(events))
	}
}

func TestRetryer_SendToDLQ_NoDLQ(t *testing.T) {
	retryer := NewRetryer(nil, DefaultRetryPolicy())

	event := &FailedEvent{
		FunctionName: "test-func",
	}

	err := retryer.SendToDLQ(event)
	if err == nil {
		t.Error("SendToDLQ() should return error when DLQ is nil")
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		errMsg   string
		expected FailureReason
	}{
		{"nil error", "", ReasonUnknown},
		{"timeout", "context deadline exceeded", ReasonTimeout},
		{"timeout2", "request timeout", ReasonTimeout},
		{"rate limit", "rate limit exceeded", ReasonRateLimited},
		{"429", "HTTP 429 too many requests", ReasonRateLimited},
		{"not found", "function not found", ReasonFunctionNotFound},
		{"404", "HTTP 404", ReasonFunctionNotFound},
		{"permission denied", "permission denied", ReasonPermissionDenied},
		{"403", "HTTP 403 forbidden", ReasonPermissionDenied},
		{"401", "HTTP 401 unauthorized", ReasonPermissionDenied},
		{"invalid payload", "invalid request body", ReasonInvalidPayload},
		{"400", "HTTP 400 bad request", ReasonInvalidPayload},
		{"network error", "connection refused", ReasonNetworkError},
		{"dns error", "dns lookup failed", ReasonNetworkError},
		{"resource exhausted", "resource exhausted", ReasonResourceExhausted},
		{"quota", "quota exceeded", ReasonResourceExhausted},
		{"service error", "internal server error", ReasonServiceError},
		{"500", "HTTP 500", ReasonServiceError},
		{"503", "service unavailable", ReasonServiceError},
		{"unknown", "some other error", ReasonFunctionError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errMsg != "" {
				err = errors.New(tt.errMsg)
			}
			reason := ClassifyError(err)
			if reason != tt.expected {
				t.Errorf("ClassifyError(%q) = %v, want %v", tt.errMsg, reason, tt.expected)
			}
		})
	}
}

func TestRetryResult_TotalTime(t *testing.T) {
	dlq := NewQueue(DefaultConfig())
	policy := RetryPolicy{
		MaxRetries:        1,
		InitialDelay:      50 * time.Millisecond,
		MaxDelay:          100 * time.Millisecond,
		BackoffMultiplier: 1.0,
		Jitter:            0,
	}
	retryer := NewRetryer(dlq, policy)

	fn := func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("timeout")
	}

	start := time.Now()
	result := retryer.ExecuteWithRetry(context.Background(), "test", fn, ClassifyError)
	elapsed := time.Since(start)

	// Should have some total time recorded
	if result.TotalTime <= 0 {
		t.Error("TotalTime should be positive")
	}

	// Total time should be close to elapsed time
	diff := elapsed - result.TotalTime
	if diff < 0 {
		diff = -diff
	}
	if diff > 10*time.Millisecond {
		t.Errorf("TotalTime %v differs from elapsed %v", result.TotalTime, elapsed)
	}
}

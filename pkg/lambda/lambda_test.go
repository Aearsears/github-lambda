package lambda

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Test Handler implementations
func TestHandlerFunc_Handle(t *testing.T) {
	called := false
	fn := HandlerFunc(func(ctx context.Context, event Event) (Response, error) {
		called = true
		return Success("ok"), nil
	})

	event := Event{
		FunctionName: "test",
		Payload:      json.RawMessage(`{}`),
	}

	resp, err := fn.Handle(context.Background(), event)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if !called {
		t.Error("Handler function was not called")
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %v, want 200", resp.StatusCode)
	}
}

func TestSuccess(t *testing.T) {
	resp := Success(map[string]string{"message": "hello"})

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %v, want 200", resp.StatusCode)
	}
	if resp.Body == nil {
		t.Error("Body should not be nil")
	}
	if resp.Error != "" {
		t.Errorf("Error = %v, want empty", resp.Error)
	}
}

func TestError(t *testing.T) {
	resp := Error(500, "internal error")

	if resp.StatusCode != 500 {
		t.Errorf("StatusCode = %v, want 500", resp.StatusCode)
	}
	if resp.Error != "internal error" {
		t.Errorf("Error = %v, want 'internal error'", resp.Error)
	}
}

// Test Registry
func TestRegistry_Register(t *testing.T) {
	registry := NewRegistry()

	handler := HandlerFunc(func(ctx context.Context, event Event) (Response, error) {
		return Success("ok"), nil
	})

	err := registry.Register("test-func", handler)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Verify registration
	h, err := registry.Get("test-func")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if h == nil {
		t.Error("Handler should not be nil")
	}
}

func TestRegistry_Register_Duplicate(t *testing.T) {
	registry := NewRegistry()

	handler := HandlerFunc(func(ctx context.Context, event Event) (Response, error) {
		return Success("ok"), nil
	})

	registry.Register("test-func", handler)
	err := registry.Register("test-func", handler)

	if err == nil {
		t.Error("Register() should return error for duplicate name")
	}
}

func TestRegistry_RegisterFunc(t *testing.T) {
	registry := NewRegistry()

	err := registry.RegisterFunc("test-func", func(ctx context.Context, event Event) (Response, error) {
		return Success("ok"), nil
	})

	if err != nil {
		t.Fatalf("RegisterFunc() error = %v", err)
	}

	h, err := registry.Get("test-func")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if h == nil {
		t.Error("Handler should not be nil")
	}
}

func TestRegistry_Get_NotFound(t *testing.T) {
	registry := NewRegistry()

	_, err := registry.Get("non-existent")
	if err == nil {
		t.Error("Get() should return error for non-existent handler")
	}
}

func TestRegistry_List(t *testing.T) {
	registry := NewRegistry()

	registry.RegisterFunc("func-a", func(ctx context.Context, event Event) (Response, error) {
		return Success("a"), nil
	})
	registry.RegisterFunc("func-b", func(ctx context.Context, event Event) (Response, error) {
		return Success("b"), nil
	})
	registry.RegisterFunc("func-c", func(ctx context.Context, event Event) (Response, error) {
		return Success("c"), nil
	})

	names := registry.List()
	if len(names) != 3 {
		t.Errorf("List() returned %v names, want 3", len(names))
	}

	// Check that all names are present (order may vary)
	nameMap := make(map[string]bool)
	for _, name := range names {
		nameMap[name] = true
	}

	for _, expected := range []string{"func-a", "func-b", "func-c"} {
		if !nameMap[expected] {
			t.Errorf("List() missing %v", expected)
		}
	}
}

// Test global registry functions
func TestGlobalRegister(t *testing.T) {
	// Reset default registry for test
	DefaultRegistry = NewRegistry()

	err := Register("global-func", HandlerFunc(func(ctx context.Context, event Event) (Response, error) {
		return Success("global"), nil
	}))

	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	names := DefaultRegistry.List()
	if len(names) != 1 {
		t.Errorf("DefaultRegistry should have 1 handler, got %v", len(names))
	}
}

func TestGlobalRegisterFunc(t *testing.T) {
	// Reset default registry for test
	DefaultRegistry = NewRegistry()

	err := RegisterFunc("global-func", func(ctx context.Context, event Event) (Response, error) {
		return Success("global"), nil
	})

	if err != nil {
		t.Fatalf("RegisterFunc() error = %v", err)
	}
}

// Test Context
func TestNewContext(t *testing.T) {
	parent := context.Background()
	ctx := NewContext(parent, "inv-123", "test-func", 5*time.Second)

	if ctx.InvocationID() != "inv-123" {
		t.Errorf("InvocationID() = %v, want inv-123", ctx.InvocationID())
	}
	if ctx.FunctionName() != "test-func" {
		t.Errorf("FunctionName() = %v, want test-func", ctx.FunctionName())
	}
}

func TestContext_RemainingTime(t *testing.T) {
	parent := context.Background()
	ctx := NewContext(parent, "inv-123", "test-func", 5*time.Second)

	remaining := ctx.RemainingTime()

	// Should be close to 5 seconds (within 100ms tolerance)
	if remaining < 4900*time.Millisecond || remaining > 5*time.Second {
		t.Errorf("RemainingTime() = %v, expected ~5s", remaining)
	}

	// After some time, remaining should decrease
	time.Sleep(100 * time.Millisecond)
	newRemaining := ctx.RemainingTime()

	if newRemaining >= remaining {
		t.Error("RemainingTime() should decrease over time")
	}
}

func TestContext_Timeout(t *testing.T) {
	parent := context.Background()
	ctx := NewContext(parent, "inv-123", "test-func", 50*time.Millisecond)

	select {
	case <-ctx.Done():
		// Expected - context should timeout
	case <-time.After(200 * time.Millisecond):
		t.Error("Context did not timeout as expected")
	}
}

// Test environment helpers
func TestGetEnv(t *testing.T) {
	// Set test env var
	os.Setenv("TEST_VAR", "test-value")
	defer os.Unsetenv("TEST_VAR")

	value := GetEnv("TEST_VAR", "default")
	if value != "test-value" {
		t.Errorf("GetEnv() = %v, want test-value", value)
	}

	// Non-existent var should return default
	value = GetEnv("NON_EXISTENT_VAR", "default")
	if value != "default" {
		t.Errorf("GetEnv() = %v, want default", value)
	}
}

func TestMustGetEnv(t *testing.T) {
	// Set test env var
	os.Setenv("REQUIRED_VAR", "required-value")
	defer os.Unsetenv("REQUIRED_VAR")

	value := MustGetEnv("REQUIRED_VAR")
	if value != "required-value" {
		t.Errorf("MustGetEnv() = %v, want required-value", value)
	}
}

func TestMustGetEnv_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustGetEnv() should panic for missing var")
		}
	}()

	MustGetEnv("DEFINITELY_NOT_SET_VAR_12345")
}

// Test Event struct
func TestEvent_Payload(t *testing.T) {
	event := Event{
		FunctionName: "test",
		Payload:      json.RawMessage(`{"key": "value"}`),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		InvocationID: "inv-123",
	}

	if event.FunctionName != "test" {
		t.Errorf("FunctionName = %v, want test", event.FunctionName)
	}

	// Parse payload
	var payload map[string]string
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	if payload["key"] != "value" {
		t.Errorf("Payload key = %v, want value", payload["key"])
	}
}

// Test Response struct
func TestResponse_WithHeaders(t *testing.T) {
	resp := Response{
		StatusCode: 200,
		Body:       "ok",
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
		},
	}

	if resp.Headers["X-Custom-Header"] != "custom-value" {
		t.Error("Headers should be preserved")
	}
}

// Test concurrent registry access
func TestRegistry_Concurrent(t *testing.T) {
	registry := NewRegistry()

	// Concurrent registrations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			registry.RegisterFunc(
				string(rune('a'+n)),
				func(ctx context.Context, event Event) (Response, error) {
					return Success("ok"), nil
				},
			)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			registry.List()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test handler execution with real context
func TestHandler_ExecutionWithContext(t *testing.T) {
	registry := NewRegistry()

	var receivedInvocationID string
	var receivedFunctionName string

	registry.RegisterFunc("context-test", func(ctx context.Context, event Event) (Response, error) {
		if lambdaCtx, ok := ctx.(*Context); ok {
			receivedInvocationID = lambdaCtx.InvocationID()
			receivedFunctionName = lambdaCtx.FunctionName()
		}
		return Success("ok"), nil
	})

	handler, _ := registry.Get("context-test")
	ctx := NewContext(context.Background(), "test-inv-456", "context-test", 5*time.Second)

	event := Event{
		FunctionName: "context-test",
		InvocationID: "test-inv-456",
		Payload:      json.RawMessage(`{}`),
	}

	_, err := handler.Handle(ctx, event)
	if err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if receivedInvocationID != "test-inv-456" {
		t.Errorf("InvocationID = %v, want test-inv-456", receivedInvocationID)
	}
	if receivedFunctionName != "context-test" {
		t.Errorf("FunctionName = %v, want context-test", receivedFunctionName)
	}
}

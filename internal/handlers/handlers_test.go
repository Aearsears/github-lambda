package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/github-lambda/internal/dispatcher"
	"github.com/github-lambda/pkg/dlq"
	"github.com/github-lambda/pkg/ratelimit"
	"github.com/github-lambda/pkg/versioning"
)

// newTestDispatcher creates a test dispatcher
func newTestDispatcher() *dispatcher.Dispatcher {
	return dispatcher.New("test-token", "test-owner", "test-repo")
}

// newTestDLQ creates test DLQ components
func newTestDLQ() (*dlq.Queue, *dlq.Retryer) {
	queue := dlq.NewQueue(dlq.DefaultConfig())
	policy := dlq.DefaultRetryPolicy()
	retryer := dlq.NewRetryer(queue, policy)
	return queue, retryer
}

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	HealthHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status = %v, want %v", rec.Code, http.StatusOK)
	}
}

func TestInvokeHandler_MethodNotAllowed(t *testing.T) {
	d := newTestDispatcher()
	limiter := ratelimit.New(ratelimit.DefaultConfig())
	resolver := versioning.NewResolver(versioning.NewManager())
	dlqQueue, retryer := newTestDLQ()

	handler := InvokeHandler(d, limiter, resolver, retryer, dlqQueue, nil)

	req := httptest.NewRequest(http.MethodGet, "/invoke", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %v, want %v", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestInvokeHandler_InvalidBody(t *testing.T) {
	d := newTestDispatcher()
	limiter := ratelimit.New(ratelimit.DefaultConfig())
	resolver := versioning.NewResolver(versioning.NewManager())
	dlqQueue, retryer := newTestDLQ()

	handler := InvokeHandler(d, limiter, resolver, retryer, dlqQueue, nil)

	req := httptest.NewRequest(http.MethodPost, "/invoke", bytes.NewReader([]byte("invalid json")))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %v, want %v", rec.Code, http.StatusBadRequest)
	}
}

func TestInvokeHandler_MissingFunctionName(t *testing.T) {
	d := newTestDispatcher()
	limiter := ratelimit.New(ratelimit.DefaultConfig())
	resolver := versioning.NewResolver(versioning.NewManager())
	dlqQueue, retryer := newTestDLQ()

	handler := InvokeHandler(d, limiter, resolver, retryer, dlqQueue, nil)

	body := `{"payload": {}}`
	req := httptest.NewRequest(http.MethodPost, "/invoke", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %v, want %v", rec.Code, http.StatusBadRequest)
	}
}

func TestAsyncInvokeHandler_MethodNotAllowed(t *testing.T) {
	d := newTestDispatcher()
	limiter := ratelimit.New(ratelimit.DefaultConfig())
	resolver := versioning.NewResolver(versioning.NewManager())
	dlqQueue, retryer := newTestDLQ()

	handler := AsyncInvokeHandler(d, limiter, resolver, retryer, dlqQueue)

	req := httptest.NewRequest(http.MethodGet, "/invoke/async", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %v, want %v", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestAsyncInvokeHandler_InvalidBody(t *testing.T) {
	d := newTestDispatcher()
	limiter := ratelimit.New(ratelimit.DefaultConfig())
	resolver := versioning.NewResolver(versioning.NewManager())
	dlqQueue, retryer := newTestDLQ()

	handler := AsyncInvokeHandler(d, limiter, resolver, retryer, dlqQueue)

	req := httptest.NewRequest(http.MethodPost, "/invoke/async", bytes.NewReader([]byte("invalid json")))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %v, want %v", rec.Code, http.StatusBadRequest)
	}
}

func TestAsyncInvokeHandler_MissingFunctionName(t *testing.T) {
	d := newTestDispatcher()
	limiter := ratelimit.New(ratelimit.DefaultConfig())
	resolver := versioning.NewResolver(versioning.NewManager())
	dlqQueue, retryer := newTestDLQ()

	handler := AsyncInvokeHandler(d, limiter, resolver, retryer, dlqQueue)

	body := `{"payload": {}}`
	req := httptest.NewRequest(http.MethodPost, "/invoke/async", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status = %v, want %v", rec.Code, http.StatusBadRequest)
	}
}

func TestStatusHandler(t *testing.T) {
	d := newTestDispatcher()
	handler := StatusHandler(d)

	req := httptest.NewRequest(http.MethodGet, "/status/test-id", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Without a valid execution ID, it should return not found
	if rec.Code != http.StatusNotFound {
		t.Errorf("Status = %v, want %v", rec.Code, http.StatusNotFound)
	}
}

func TestStatusHandler_MethodNotAllowed(t *testing.T) {
	d := newTestDispatcher()
	handler := StatusHandler(d)

	req := httptest.NewRequest(http.MethodPost, "/status/test-id", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %v, want %v", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestInvokeRequest_JSON(t *testing.T) {
	req := dispatcher.InvokeRequest{
		FunctionName: "test-func",
		Payload:      json.RawMessage(`{"key": "value"}`),
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded dispatcher.InvokeRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.FunctionName != req.FunctionName {
		t.Errorf("FunctionName = %v, want %v", decoded.FunctionName, req.FunctionName)
	}
}

func TestCallbackHandler_MethodNotAllowed(t *testing.T) {
	d := newTestDispatcher()
	handler := CallbackHandler(d, nil)

	req := httptest.NewRequest(http.MethodGet, "/callback/test-id", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %v, want %v", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestCallbackHandler_MissingID(t *testing.T) {
	d := newTestDispatcher()
	handler := CallbackHandler(d, nil)

	// Empty path after /callback/
	req := httptest.NewRequest(http.MethodPost, "/callback/", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should fail because execution ID is required
	if rec.Code == http.StatusOK {
		t.Error("Should fail for missing execution ID")
	}
}

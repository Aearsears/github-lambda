package dispatcher

import (
	"encoding/json"
	"testing"
	"time"
)

func TestExecutionStatus_Constants(t *testing.T) {
	tests := []struct {
		status ExecutionStatus
		value  string
	}{
		{StatusPending, "pending"},
		{StatusRunning, "running"},
		{StatusCompleted, "completed"},
		{StatusFailed, "failed"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.value {
			t.Errorf("ExecutionStatus %v = %v, want %v", tt.status, string(tt.status), tt.value)
		}
	}
}

func TestExecution(t *testing.T) {
	now := time.Now()
	completed := now.Add(5 * time.Second)
	exec := &Execution{
		ID:           "exec-123",
		FunctionName: "test-func",
		Version:      1,
		Alias:        "prod",
		Status:       StatusCompleted,
		RunID:        12345,
		StartedAt:    now,
		CompletedAt:  &completed,
		Result:       json.RawMessage(`{"data": "result"}`),
	}

	if exec.ID != "exec-123" {
		t.Error("ID not set correctly")
	}
	if exec.FunctionName != "test-func" {
		t.Error("FunctionName not set correctly")
	}
	if exec.Version != 1 {
		t.Error("Version not set correctly")
	}
	if exec.Alias != "prod" {
		t.Error("Alias not set correctly")
	}
	if exec.Status != StatusCompleted {
		t.Error("Status not set correctly")
	}
}

func TestExecution_Failed(t *testing.T) {
	exec := &Execution{
		ID:           "exec-456",
		FunctionName: "test-func",
		Status:       StatusFailed,
		Error:        "Function execution failed: timeout",
	}

	if exec.Status != StatusFailed {
		t.Error("Status should be failed")
	}
	if exec.Error == "" {
		t.Error("Error should be set for failed executions")
	}
}

func TestInvokeRequest(t *testing.T) {
	req := InvokeRequest{
		FunctionName: "test-func",
		Version:      2,
		Alias:        "staging",
		Payload:      json.RawMessage(`{"input": "data"}`),
		Timeout:      30 * time.Second,
		EnvVars: map[string]string{
			"ENV":     "production",
			"API_KEY": "secret",
		},
	}

	if req.FunctionName != "test-func" {
		t.Error("FunctionName not set correctly")
	}
	if req.Version != 2 {
		t.Error("Version not set correctly")
	}
	if req.Timeout != 30*time.Second {
		t.Error("Timeout not set correctly")
	}
	if len(req.EnvVars) != 2 {
		t.Errorf("EnvVars count = %v, want 2", len(req.EnvVars))
	}
}

func TestInvokeRequest_JSON(t *testing.T) {
	req := InvokeRequest{
		FunctionName: "test-func",
		Payload:      json.RawMessage(`{"key": "value"}`),
		Timeout:      1 * time.Minute,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded InvokeRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.FunctionName != req.FunctionName {
		t.Error("FunctionName not preserved after JSON roundtrip")
	}
}

func TestExecution_JSON(t *testing.T) {
	now := time.Now()
	exec := &Execution{
		ID:           "exec-789",
		FunctionName: "test-func",
		Status:       StatusRunning,
		RunID:        67890,
		StartedAt:    now,
	}

	data, err := json.Marshal(exec)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded Execution
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.ID != exec.ID {
		t.Error("ID not preserved after JSON roundtrip")
	}
	if decoded.Status != exec.Status {
		t.Error("Status not preserved after JSON roundtrip")
	}
}

func TestExecution_Duration(t *testing.T) {
	start := time.Now()
	time.Sleep(10 * time.Millisecond)
	completed := time.Now()

	exec := &Execution{
		ID:          "exec-dur",
		StartedAt:   start,
		CompletedAt: &completed,
		Status:      StatusCompleted,
	}

	duration := exec.CompletedAt.Sub(exec.StartedAt)
	if duration < 10*time.Millisecond {
		t.Errorf("Duration = %v, expected >= 10ms", duration)
	}
}

func TestInvokeRequest_DefaultTimeout(t *testing.T) {
	req := InvokeRequest{
		FunctionName: "test-func",
		Payload:      json.RawMessage(`{}`),
	}

	// Timeout should be zero (to be set to default by dispatcher)
	if req.Timeout != 0 {
		t.Errorf("Default Timeout = %v, want 0", req.Timeout)
	}
}

func TestExecution_WithResult(t *testing.T) {
	exec := &Execution{
		ID:           "exec-result",
		FunctionName: "test-func",
		Status:       StatusCompleted,
		Result: json.RawMessage(`{
			"statusCode": 200,
			"body": {"message": "success"}
		}`),
	}

	var result map[string]interface{}
	if err := json.Unmarshal(exec.Result, &result); err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if result["statusCode"] != float64(200) {
		t.Error("Result statusCode not correct")
	}
}

func TestExecution_StatusTransitions(t *testing.T) {
	exec := &Execution{
		ID:        "exec-status",
		Status:    StatusPending,
		StartedAt: time.Now(),
	}

	// Pending -> Running
	exec.Status = StatusRunning
	if exec.Status != StatusRunning {
		t.Error("Failed to transition to Running")
	}

	// Running -> Completed
	exec.Status = StatusCompleted
	completed := time.Now()
	exec.CompletedAt = &completed
	if exec.Status != StatusCompleted {
		t.Error("Failed to transition to Completed")
	}
}

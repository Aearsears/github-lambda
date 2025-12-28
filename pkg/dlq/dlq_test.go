package dlq

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFailureReason_GetErrorType(t *testing.T) {
	tests := []struct {
		reason   FailureReason
		expected ErrorType
	}{
		{ReasonTimeout, ErrorTypeRetriable},
		{ReasonRateLimited, ErrorTypeRetriable},
		{ReasonServiceError, ErrorTypeRetriable},
		{ReasonNetworkError, ErrorTypeRetriable},
		{ReasonResourceExhausted, ErrorTypeRetriable},
		{ReasonInvalidPayload, ErrorTypePermanent},
		{ReasonFunctionNotFound, ErrorTypePermanent},
		{ReasonPermissionDenied, ErrorTypePermanent},
		{ReasonFunctionError, ErrorTypeUnknown},
		{ReasonUnknown, ErrorTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			if got := tt.reason.GetErrorType(); got != tt.expected {
				t.Errorf("GetErrorType() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestQueue_Add(t *testing.T) {
	config := QueueConfig{
		MaxSize:       100,
		RetentionDays: 0, // No expiration for tests
	}
	q := NewQueue(config)

	event := &FailedEvent{
		FunctionName:  "test-func",
		Payload:       json.RawMessage(`{"test": "data"}`),
		ErrorMessage:  "test error",
		ErrorType:     ErrorTypeRetriable,
		FailureReason: ReasonTimeout,
		FailedTime:    time.Now(),
	}

	err := q.Add(event)
	if err != nil {
		t.Fatalf("Add() error = %v", err)
	}

	// Event should have ID assigned
	if event.ID == "" {
		t.Error("Event ID should be assigned")
	}

	// Event should be retrievable
	retrieved, err := q.Get(event.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if retrieved.FunctionName != event.FunctionName {
		t.Errorf("Retrieved FunctionName = %v, want %v", retrieved.FunctionName, event.FunctionName)
	}
}

func TestQueue_Get_NotFound(t *testing.T) {
	q := NewQueue(DefaultConfig())

	_, err := q.Get("non-existent-id")
	if err == nil {
		t.Error("Get() should return error for non-existent ID")
	}
}

func TestQueue_Delete(t *testing.T) {
	q := NewQueue(DefaultConfig())

	event := &FailedEvent{
		FunctionName:  "test-func",
		Payload:       json.RawMessage(`{}`),
		ErrorMessage:  "test error",
		FailureReason: ReasonTimeout,
		FailedTime:    time.Now(),
	}
	q.Add(event)

	err := q.Delete(event.ID)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Event should no longer be retrievable
	_, err = q.Get(event.ID)
	if err == nil {
		t.Error("Get() should return error after delete")
	}
}

func TestQueue_Delete_NotFound(t *testing.T) {
	q := NewQueue(DefaultConfig())

	err := q.Delete("non-existent-id")
	if err == nil {
		t.Error("Delete() should return error for non-existent ID")
	}
}

func TestQueue_List_NoFilter(t *testing.T) {
	q := NewQueue(DefaultConfig())

	// Add multiple events
	for i := 0; i < 5; i++ {
		q.Add(&FailedEvent{
			FunctionName:  "test-func",
			Payload:       json.RawMessage(`{}`),
			ErrorMessage:  "test error",
			FailureReason: ReasonTimeout,
			FailedTime:    time.Now(),
		})
	}

	events := q.List(ListFilter{})
	if len(events) != 5 {
		t.Errorf("List() returned %v events, want 5", len(events))
	}
}

func TestQueue_List_WithFilter(t *testing.T) {
	q := NewQueue(DefaultConfig())

	// Add events for different functions
	q.Add(&FailedEvent{
		FunctionName:  "func-a",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonTimeout,
		ErrorType:     ErrorTypeRetriable,
		FailedTime:    time.Now(),
	})
	q.Add(&FailedEvent{
		FunctionName:  "func-b",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonInvalidPayload,
		ErrorType:     ErrorTypePermanent,
		FailedTime:    time.Now(),
	})

	// Filter by function name
	events := q.List(ListFilter{FunctionName: "func-a"})
	if len(events) != 1 {
		t.Errorf("List(FunctionName) returned %v events, want 1", len(events))
	}

	// Filter by error type
	events = q.List(ListFilter{ErrorType: ErrorTypePermanent})
	if len(events) != 1 {
		t.Errorf("List(ErrorType) returned %v events, want 1", len(events))
	}

	// Filter by failure reason
	events = q.List(ListFilter{FailureReason: ReasonTimeout})
	if len(events) != 1 {
		t.Errorf("List(FailureReason) returned %v events, want 1", len(events))
	}
}

func TestQueue_List_WithLimit(t *testing.T) {
	q := NewQueue(DefaultConfig())

	for i := 0; i < 10; i++ {
		q.Add(&FailedEvent{
			FunctionName:  "test-func",
			Payload:       json.RawMessage(`{}`),
			FailureReason: ReasonTimeout,
			FailedTime:    time.Now(),
		})
	}

	events := q.List(ListFilter{Limit: 3})
	if len(events) != 3 {
		t.Errorf("List(Limit) returned %v events, want 3", len(events))
	}
}

func TestQueue_List_TimeFilter(t *testing.T) {
	q := NewQueue(DefaultConfig())

	baseTime := time.Now()

	q.Add(&FailedEvent{
		FunctionName:  "old-event",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonTimeout,
		FailedTime:    baseTime.Add(-2 * time.Hour),
	})
	q.Add(&FailedEvent{
		FunctionName:  "new-event",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonTimeout,
		FailedTime:    baseTime,
	})

	since := baseTime.Add(-1 * time.Hour)
	events := q.List(ListFilter{Since: &since})

	if len(events) != 1 {
		t.Errorf("List(Since) returned %v events, want 1", len(events))
	}
	if events[0].FunctionName != "new-event" {
		t.Errorf("Expected new-event, got %v", events[0].FunctionName)
	}
}

func TestQueue_MarkReplayed(t *testing.T) {
	q := NewQueue(DefaultConfig())

	event := &FailedEvent{
		FunctionName:  "test-func",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonTimeout,
		FailedTime:    time.Now(),
	}
	q.Add(event)

	err := q.MarkReplayed(event.ID, "success")
	if err != nil {
		t.Fatalf("MarkReplayed() error = %v", err)
	}

	retrieved, _ := q.Get(event.ID)
	if retrieved.ReplayedAt == nil {
		t.Error("ReplayedAt should be set")
	}
	if retrieved.ReplayCount != 1 {
		t.Errorf("ReplayCount = %v, want 1", retrieved.ReplayCount)
	}
	if retrieved.ReplayStatus != "success" {
		t.Errorf("ReplayStatus = %v, want success", retrieved.ReplayStatus)
	}
}

func TestQueue_MarkReplayed_NotFound(t *testing.T) {
	q := NewQueue(DefaultConfig())

	err := q.MarkReplayed("non-existent", "success")
	if err == nil {
		t.Error("MarkReplayed() should return error for non-existent ID")
	}
}

func TestQueue_Stats(t *testing.T) {
	q := NewQueue(DefaultConfig())

	// Add events
	q.Add(&FailedEvent{
		FunctionName:  "func-a",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonTimeout,
		ErrorType:     ErrorTypeRetriable,
		FailedTime:    time.Now(),
	})
	q.Add(&FailedEvent{
		FunctionName:  "func-a",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonNetworkError,
		ErrorType:     ErrorTypeRetriable,
		FailedTime:    time.Now(),
	})
	q.Add(&FailedEvent{
		FunctionName:  "func-b",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonInvalidPayload,
		ErrorType:     ErrorTypePermanent,
		FailedTime:    time.Now(),
	})

	stats := q.Stats()

	if stats.TotalEvents != 3 {
		t.Errorf("TotalEvents = %v, want 3", stats.TotalEvents)
	}
	if stats.PendingEvents != 3 {
		t.Errorf("PendingEvents = %v, want 3", stats.PendingEvents)
	}
	if stats.ByFunction["func-a"] != 2 {
		t.Errorf("ByFunction[func-a] = %v, want 2", stats.ByFunction["func-a"])
	}
	if stats.ByFunction["func-b"] != 1 {
		t.Errorf("ByFunction[func-b] = %v, want 1", stats.ByFunction["func-b"])
	}
	if stats.ByErrorType[ErrorTypeRetriable] != 2 {
		t.Errorf("ByErrorType[Retriable] = %v, want 2", stats.ByErrorType[ErrorTypeRetriable])
	}
}

func TestQueue_Purge(t *testing.T) {
	q := NewQueue(DefaultConfig())

	// Add events
	q.Add(&FailedEvent{
		FunctionName:  "to-purge",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonTimeout,
		FailedTime:    time.Now(),
	})
	q.Add(&FailedEvent{
		FunctionName:  "to-purge",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonTimeout,
		FailedTime:    time.Now(),
	})
	q.Add(&FailedEvent{
		FunctionName:  "keep",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonTimeout,
		FailedTime:    time.Now(),
	})

	count := q.Purge(ListFilter{FunctionName: "to-purge"})

	if count != 2 {
		t.Errorf("Purge() returned %v, want 2", count)
	}

	events := q.List(ListFilter{})
	if len(events) != 1 {
		t.Errorf("After purge, %v events remain, want 1", len(events))
	}
}

func TestQueue_MaxSize(t *testing.T) {
	q := NewQueue(QueueConfig{MaxSize: 3, RetentionDays: 0})

	// Add more events than max size
	for i := 0; i < 5; i++ {
		q.Add(&FailedEvent{
			FunctionName:  "test-func",
			Payload:       json.RawMessage(`{}`),
			FailureReason: ReasonTimeout,
			FailedTime:    time.Now().Add(time.Duration(i) * time.Second),
		})
	}

	events := q.List(ListFilter{})
	if len(events) != 3 {
		t.Errorf("Queue has %v events, want max 3", len(events))
	}
}

func TestQueue_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "dlq.json")

	// Create and populate queue
	q1 := NewQueue(DefaultConfig())
	q1.Add(&FailedEvent{
		ID:            "event-1",
		FunctionName:  "test-func",
		Payload:       json.RawMessage(`{"key": "value"}`),
		ErrorMessage:  "test error",
		FailureReason: ReasonTimeout,
		ErrorType:     ErrorTypeRetriable,
		FailedTime:    time.Now(),
	})

	err := q1.SaveToFile(filePath)
	if err != nil {
		t.Fatalf("SaveToFile() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Fatal("File was not created")
	}

	// Load into new queue
	q2 := NewQueue(DefaultConfig())
	err = q2.LoadFromFile(filePath)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	// Verify data
	event, err := q2.Get("event-1")
	if err != nil {
		t.Fatalf("Get() error after load = %v", err)
	}

	if event.FunctionName != "test-func" {
		t.Errorf("Loaded FunctionName = %v, want test-func", event.FunctionName)
	}
}

func TestQueue_LoadFromFile_NotFound(t *testing.T) {
	q := NewQueue(DefaultConfig())
	err := q.LoadFromFile("/nonexistent/path.json")
	if err == nil {
		t.Error("LoadFromFile() should return error for non-existent file")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.MaxSize != 10000 {
		t.Errorf("MaxSize = %v, want 10000", config.MaxSize)
	}
	if config.RetentionDays != 14 {
		t.Errorf("RetentionDays = %v, want 14", config.RetentionDays)
	}
}

func TestQueue_List_ExcludeReplayed(t *testing.T) {
	q := NewQueue(DefaultConfig())

	// Add and replay one event
	event1 := &FailedEvent{
		FunctionName:  "func",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonTimeout,
		FailedTime:    time.Now(),
	}
	q.Add(event1)
	q.MarkReplayed(event1.ID, "success")

	// Add another non-replayed event
	q.Add(&FailedEvent{
		FunctionName:  "func",
		Payload:       json.RawMessage(`{}`),
		FailureReason: ReasonTimeout,
		FailedTime:    time.Now(),
	})

	// By default, replayed events should be excluded
	events := q.List(ListFilter{})
	if len(events) != 1 {
		t.Errorf("List() without IncludeReplayed returned %v events, want 1", len(events))
	}

	// Include replayed
	events = q.List(ListFilter{IncludeReplayed: true})
	if len(events) != 2 {
		t.Errorf("List() with IncludeReplayed returned %v events, want 2", len(events))
	}
}

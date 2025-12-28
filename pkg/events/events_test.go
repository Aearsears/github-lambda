package events

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEventType_Constants(t *testing.T) {
	tests := []struct {
		eventType EventType
		value     string
	}{
		{EventTypeHTTP, "http"},
		{EventTypeSchedule, "schedule"},
		{EventTypeGitHub, "github"},
		{EventTypeWebhook, "webhook"},
	}

	for _, tt := range tests {
		if string(tt.eventType) != tt.value {
			t.Errorf("EventType %v = %v, want %v", tt.eventType, string(tt.eventType), tt.value)
		}
	}
}

func TestEventSource(t *testing.T) {
	now := time.Now()
	source := &EventSource{
		ID:            "src-123",
		Name:          "Test Source",
		Type:          EventTypeHTTP,
		FunctionName:  "test-func",
		Enabled:       true,
		Config:        json.RawMessage(`{"path": "/api/test"}`),
		CreatedAt:     now,
		UpdatedAt:     now,
		LastTriggered: &now,
		TriggerCount:  100,
	}

	if source.ID != "src-123" {
		t.Error("ID not set correctly")
	}
	if source.Type != EventTypeHTTP {
		t.Error("Type not set correctly")
	}
	if !source.Enabled {
		t.Error("Enabled should be true")
	}
	if source.TriggerCount != 100 {
		t.Errorf("TriggerCount = %v, want 100", source.TriggerCount)
	}
}

func TestEvent(t *testing.T) {
	event := &Event{
		ID:           "evt-123",
		SourceID:     "src-456",
		SourceType:   EventTypeWebhook,
		FunctionName: "test-func",
		Payload:      json.RawMessage(`{"data": "test"}`),
		Headers: map[string]string{
			"Content-Type": "application/json",
			"X-Custom":     "value",
		},
		Metadata: map[string]string{
			"trace_id": "abc123",
		},
		ReceivedAt: time.Now(),
	}

	if event.ID != "evt-123" {
		t.Error("ID not set correctly")
	}
	if event.SourceType != EventTypeWebhook {
		t.Error("SourceType not set correctly")
	}
	if event.Headers["Content-Type"] != "application/json" {
		t.Error("Headers not set correctly")
	}
}

func TestScheduleConfig(t *testing.T) {
	config := &ScheduleConfig{
		Cron:        "0 * * * *",
		Timezone:    "UTC",
		Payload:     json.RawMessage(`{"scheduled": true}`),
		EnabledDays: []int{1, 2, 3, 4, 5}, // Monday-Friday
		StartTime:   "09:00",
		EndTime:     "17:00",
	}

	if config.Cron != "0 * * * *" {
		t.Error("Cron not set correctly")
	}
	if len(config.EnabledDays) != 5 {
		t.Errorf("EnabledDays count = %v, want 5", len(config.EnabledDays))
	}
}

func TestScheduleConfig_Rate(t *testing.T) {
	config := &ScheduleConfig{
		Rate:    "5m",
		Payload: json.RawMessage(`{}`),
	}

	if config.Rate != "5m" {
		t.Error("Rate not set correctly")
	}
	if config.Cron != "" {
		t.Error("Cron should be empty when using Rate")
	}
}

func TestNewScheduler(t *testing.T) {
	// Create scheduler without a manager
	s := NewScheduler(nil)

	if s == nil {
		t.Fatal("NewScheduler() returned nil")
	}
	if s.jobs == nil {
		t.Error("jobs map should be initialized")
	}
	if s.running {
		t.Error("Scheduler should not be running initially")
	}
}

func TestScheduler_StartStop(t *testing.T) {
	s := NewScheduler(nil)

	// Start scheduler
	s.Start()
	if !s.running {
		t.Error("Scheduler should be running after Start()")
	}

	// Start again (should be idempotent)
	s.Start()
	if !s.running {
		t.Error("Scheduler should still be running")
	}

	// Stop scheduler
	s.Stop()
	if s.running {
		t.Error("Scheduler should not be running after Stop()")
	}

	// Stop again (should be idempotent)
	s.Stop()
	if s.running {
		t.Error("Scheduler should still not be running")
	}
}

func TestScheduler_Remove_NonExistent(t *testing.T) {
	s := NewScheduler(nil)

	// Should not panic
	s.Remove("non-existent-source")
}

func TestScheduler_EmptyOnCreate(t *testing.T) {
	s := NewScheduler(nil)
	defer s.Stop()

	// Scheduler should start empty with no jobs
	if s.running {
		t.Error("Scheduler should not be running on create")
	}
}

func TestEventSource_JSON(t *testing.T) {
	source := &EventSource{
		ID:           "src-123",
		Name:         "Test Source",
		Type:         EventTypeSchedule,
		FunctionName: "test-func",
		Enabled:      true,
		Config:       json.RawMessage(`{"cron": "0 * * * *"}`),
	}

	data, err := json.Marshal(source)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded EventSource
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.ID != source.ID {
		t.Error("ID not preserved after JSON roundtrip")
	}
	if decoded.Type != source.Type {
		t.Error("Type not preserved after JSON roundtrip")
	}
}

func TestEvent_JSON(t *testing.T) {
	event := &Event{
		ID:           "evt-123",
		SourceType:   EventTypeGitHub,
		FunctionName: "test-func",
		Payload:      json.RawMessage(`{"action": "push"}`),
		ReceivedAt:   time.Now(),
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.ID != event.ID {
		t.Error("ID not preserved after JSON roundtrip")
	}
}

func TestScheduleConfig_JSON(t *testing.T) {
	config := &ScheduleConfig{
		Cron:        "*/5 * * * *",
		Timezone:    "America/New_York",
		EnabledDays: []int{1, 2, 3, 4, 5},
	}

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded ScheduleConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.Cron != config.Cron {
		t.Error("Cron not preserved after JSON roundtrip")
	}
	if decoded.Timezone != config.Timezone {
		t.Error("Timezone not preserved after JSON roundtrip")
	}
}

func TestEventSource_WithTriggerCount(t *testing.T) {
	source := &EventSource{
		ID:           "src-123",
		Type:         EventTypeWebhook,
		TriggerCount: 0,
	}

	// Simulate triggers
	for i := 0; i < 10; i++ {
		source.TriggerCount++
		now := time.Now()
		source.LastTriggered = &now
	}

	if source.TriggerCount != 10 {
		t.Errorf("TriggerCount = %v, want 10", source.TriggerCount)
	}
	if source.LastTriggered == nil {
		t.Error("LastTriggered should be set")
	}
}

func TestEvent_WithMetadata(t *testing.T) {
	event := &Event{
		ID:           "evt-123",
		FunctionName: "test-func",
		Metadata: map[string]string{
			"trace_id":    "trace-abc",
			"request_id":  "req-123",
			"environment": "production",
		},
	}

	if len(event.Metadata) != 3 {
		t.Errorf("Metadata count = %v, want 3", len(event.Metadata))
	}
	if event.Metadata["trace_id"] != "trace-abc" {
		t.Error("Metadata trace_id not set correctly")
	}
}

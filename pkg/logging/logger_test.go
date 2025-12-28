package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestLevel_String(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{Level(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.expected {
			t.Errorf("Level(%d).String() = %v, want %v", tt.level, got, tt.expected)
		}
	}
}

func TestNew(t *testing.T) {
	logger := New("test-component")

	if logger == nil {
		t.Fatal("New() returned nil")
	}
	if logger.component != "test-component" {
		t.Errorf("component = %v, want test-component", logger.component)
	}
}

func TestLogger_SetOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test")
	logger.SetOutput(&buf)

	logger.Info("test message")

	if buf.Len() == 0 {
		t.Error("No output written to buffer")
	}
}

func TestLogger_SetLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test")
	logger.SetOutput(&buf)
	logger.SetLevel(LevelWarn)

	// Debug and Info should not be logged
	logger.Debug("debug message")
	logger.Info("info message")
	if buf.Len() != 0 {
		t.Error("Debug/Info messages should not be logged at Warn level")
	}

	// Warn and Error should be logged
	logger.Warn("warn message")
	if buf.Len() == 0 {
		t.Error("Warn messages should be logged at Warn level")
	}
}

func TestLogger_Debug(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test")
	logger.SetOutput(&buf)
	logger.SetLevel(LevelDebug)

	logger.Debug("debug message")

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if entry.Level != "DEBUG" {
		t.Errorf("Level = %v, want DEBUG", entry.Level)
	}
	if entry.Message != "debug message" {
		t.Errorf("Message = %v, want 'debug message'", entry.Message)
	}
}

func TestLogger_Info(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test")
	logger.SetOutput(&buf)

	logger.Info("info message", Fields{"key": "value"})

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if entry.Level != "INFO" {
		t.Errorf("Level = %v, want INFO", entry.Level)
	}
	if entry.Fields["key"] != "value" {
		t.Errorf("Fields[key] = %v, want value", entry.Fields["key"])
	}
}

func TestLogger_Warn(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test")
	logger.SetOutput(&buf)

	logger.Warn("warn message")

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if entry.Level != "WARN" {
		t.Errorf("Level = %v, want WARN", entry.Level)
	}
}

func TestLogger_Error(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test")
	logger.SetOutput(&buf)

	logger.Error("error message")

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if entry.Level != "ERROR" {
		t.Errorf("Level = %v, want ERROR", entry.Level)
	}
	// Error logs should include caller info
	if entry.Caller == "" {
		t.Error("Caller should be set for error logs")
	}
}

func TestLogger_WithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test")
	logger.SetOutput(&buf)

	loggerWithFields := logger.WithFields(Fields{"service": "test-service"})
	loggerWithFields.Info("test message")

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if entry.Fields["service"] != "test-service" {
		t.Errorf("Fields[service] = %v, want test-service", entry.Fields["service"])
	}
}

func TestLogger_WithFields_Merge(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test")
	logger.SetOutput(&buf)

	logger1 := logger.WithFields(Fields{"key1": "value1"})
	logger2 := logger1.WithFields(Fields{"key2": "value2"})
	logger2.Info("test message")

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if entry.Fields["key1"] != "value1" {
		t.Errorf("Fields[key1] = %v, want value1", entry.Fields["key1"])
	}
	if entry.Fields["key2"] != "value2" {
		t.Errorf("Fields[key2] = %v, want value2", entry.Fields["key2"])
	}
}

func TestLogger_WithInvocation(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test")
	logger.SetOutput(&buf)

	loggerWithInvocation := logger.WithInvocation("inv-123", "test-func")
	loggerWithInvocation.Info("test message")

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if entry.InvocationID != "inv-123" {
		t.Errorf("InvocationID = %v, want inv-123", entry.InvocationID)
	}
	if entry.FunctionName != "test-func" {
		t.Errorf("FunctionName = %v, want test-func", entry.FunctionName)
	}
}

func TestLogger_WithComponent(t *testing.T) {
	var buf bytes.Buffer
	logger := New("original")
	logger.SetOutput(&buf)

	loggerNewComponent := logger.WithComponent("new-component")
	loggerNewComponent.Info("test message")

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if entry.Component != "new-component" {
		t.Errorf("Component = %v, want new-component", entry.Component)
	}
}

func TestLogger_SpecialFields(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test")
	logger.SetOutput(&buf)

	logger.Info("test", Fields{
		"duration_ms": int64(123),
		"error":       "test error",
	})

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if entry.DurationMs == nil || *entry.DurationMs != 123 {
		t.Error("DurationMs should be extracted from fields")
	}
	if entry.Error != "test error" {
		t.Errorf("Error = %v, want 'test error'", entry.Error)
	}
}

func TestLogEntry_Timestamp(t *testing.T) {
	var buf bytes.Buffer
	logger := New("test")
	logger.SetOutput(&buf)

	logger.Info("test message")

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse log entry: %v", err)
	}

	if entry.Timestamp == "" {
		t.Error("Timestamp should be set")
	}
}

func TestFromContext(t *testing.T) {
	logger := New("test-component")
	ctx := WithContext(context.Background(), logger)

	retrieved := FromContext(ctx)
	if retrieved.component != "test-component" {
		t.Errorf("Retrieved logger component = %v, want test-component", retrieved.component)
	}
}

func TestFromContext_Default(t *testing.T) {
	// Context without logger should return default
	retrieved := FromContext(context.Background())
	if retrieved != Default {
		t.Error("FromContext should return Default when no logger in context")
	}
}

func TestWithContext(t *testing.T) {
	logger := New("test")
	ctx := WithContext(context.Background(), logger)

	value := ctx.Value(loggerKey)
	if value == nil {
		t.Error("Logger should be stored in context")
	}
}

// Test package-level functions
func TestPackageLevel_Debug(t *testing.T) {
	var buf bytes.Buffer
	originalDefault := Default
	defer func() { Default = originalDefault }()

	Default = New("pkg-test")
	Default.SetOutput(&buf)
	Default.SetLevel(LevelDebug)

	Debug("debug message")

	if buf.Len() == 0 {
		t.Error("Package-level Debug should work")
	}
}

func TestPackageLevel_Info(t *testing.T) {
	var buf bytes.Buffer
	originalDefault := Default
	defer func() { Default = originalDefault }()

	Default = New("pkg-test")
	Default.SetOutput(&buf)

	Info("info message")

	if buf.Len() == 0 {
		t.Error("Package-level Info should work")
	}
}

func TestPackageLevel_Warn(t *testing.T) {
	var buf bytes.Buffer
	originalDefault := Default
	defer func() { Default = originalDefault }()

	Default = New("pkg-test")
	Default.SetOutput(&buf)

	Warn("warn message")

	if buf.Len() == 0 {
		t.Error("Package-level Warn should work")
	}
}

func TestPackageLevel_Error(t *testing.T) {
	var buf bytes.Buffer
	originalDefault := Default
	defer func() { Default = originalDefault }()

	Default = New("pkg-test")
	Default.SetOutput(&buf)

	Error("error message")

	if buf.Len() == 0 {
		t.Error("Package-level Error should work")
	}
}

func TestLogger_Concurrent(t *testing.T) {
	var buf bytes.Buffer
	logger := New("concurrent-test")
	logger.SetOutput(&buf)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			logger.Info("message", Fields{"n": n})
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

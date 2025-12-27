package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
)

// Level represents a logging level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Fields represents structured log fields.
type Fields map[string]any

// Logger provides structured logging capabilities.
type Logger struct {
	mu        sync.Mutex
	output    io.Writer
	level     Level
	fields    Fields
	component string
}

// LogEntry represents a single log entry.
type LogEntry struct {
	Timestamp    string `json:"timestamp"`
	Level        string `json:"level"`
	Message      string `json:"message"`
	Component    string `json:"component,omitempty"`
	InvocationID string `json:"invocation_id,omitempty"`
	FunctionName string `json:"function_name,omitempty"`
	DurationMs   *int64 `json:"duration_ms,omitempty"`
	Error        string `json:"error,omitempty"`
	Caller       string `json:"caller,omitempty"`
	Fields       Fields `json:"fields,omitempty"`
}

// New creates a new logger.
func New(component string) *Logger {
	level := LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		level = LevelDebug
	}

	return &Logger{
		output:    os.Stdout,
		level:     level,
		fields:    make(Fields),
		component: component,
	}
}

// Default is the default logger instance.
var Default = New("github-lambda")

// SetOutput sets the output destination for the logger.
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

// SetLevel sets the minimum logging level.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// WithFields returns a new logger with additional fields.
func (l *Logger) WithFields(fields Fields) *Logger {
	newFields := make(Fields)
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}

	return &Logger{
		output:    l.output,
		level:     l.level,
		fields:    newFields,
		component: l.component,
	}
}

// WithInvocation returns a logger with invocation context.
func (l *Logger) WithInvocation(invocationID, functionName string) *Logger {
	return l.WithFields(Fields{
		"invocation_id": invocationID,
		"function_name": functionName,
	})
}

// WithComponent returns a logger with a specific component name.
func (l *Logger) WithComponent(component string) *Logger {
	newLogger := l.WithFields(nil)
	newLogger.component = component
	return newLogger
}

func (l *Logger) log(level Level, msg string, fields Fields) {
	if level < l.level {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level.String(),
		Message:   msg,
		Component: l.component,
	}

	// Merge fields
	allFields := make(Fields)
	for k, v := range l.fields {
		allFields[k] = v
	}
	for k, v := range fields {
		allFields[k] = v
	}

	// Extract known fields
	if id, ok := allFields["invocation_id"].(string); ok {
		entry.InvocationID = id
		delete(allFields, "invocation_id")
	}
	if fn, ok := allFields["function_name"].(string); ok {
		entry.FunctionName = fn
		delete(allFields, "function_name")
	}
	if dur, ok := allFields["duration_ms"].(int64); ok {
		entry.DurationMs = &dur
		delete(allFields, "duration_ms")
	}
	if err, ok := allFields["error"].(string); ok {
		entry.Error = err
		delete(allFields, "error")
	}
	if err, ok := allFields["error"].(error); ok {
		entry.Error = err.Error()
		delete(allFields, "error")
	}

	// Add caller info for errors
	if level >= LevelError {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			entry.Caller = fmt.Sprintf("%s:%d", file, line)
		}
	}

	if len(allFields) > 0 {
		entry.Fields = allFields
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	data, _ := json.Marshal(entry)
	fmt.Fprintln(l.output, string(data))
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string, fields ...Fields) {
	f := Fields{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelDebug, msg, f)
}

// Info logs an info message.
func (l *Logger) Info(msg string, fields ...Fields) {
	f := Fields{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelInfo, msg, f)
}

// Warn logs a warning message.
func (l *Logger) Warn(msg string, fields ...Fields) {
	f := Fields{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelWarn, msg, f)
}

// Error logs an error message.
func (l *Logger) Error(msg string, fields ...Fields) {
	f := Fields{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelError, msg, f)
}

// Package-level convenience functions

// Debug logs a debug message using the default logger.
func Debug(msg string, fields ...Fields) {
	Default.Debug(msg, fields...)
}

// Info logs an info message using the default logger.
func Info(msg string, fields ...Fields) {
	Default.Info(msg, fields...)
}

// Warn logs a warning message using the default logger.
func Warn(msg string, fields ...Fields) {
	Default.Warn(msg, fields...)
}

// Error logs an error message using the default logger.
func Error(msg string, fields ...Fields) {
	Default.Error(msg, fields...)
}

// Context key for logger
type contextKey string

const loggerKey contextKey = "logger"

// FromContext retrieves the logger from context.
func FromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerKey).(*Logger); ok {
		return logger
	}
	return Default
}

// WithContext adds a logger to the context.
func WithContext(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

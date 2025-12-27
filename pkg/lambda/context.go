package lambda

import (
	"context"
	"os"
	"time"
)

type contextKey string

const (
	invocationIDKey contextKey = "invocation_id"
	functionNameKey contextKey = "function_name"
	deadlineKey     contextKey = "deadline"
)

// Context wraps a standard context with lambda-specific functionality.
type Context struct {
	context.Context
	invocationID string
	functionName string
	deadline     time.Time
}

// NewContext creates a new lambda context.
func NewContext(parent context.Context, invocationID, functionName string, timeout time.Duration) *Context {
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(parent, deadline)

	// Store cancel function for cleanup - in practice, the context will be
	// canceled when the function execution completes or times out
	go func() {
		<-ctx.Done()
		cancel()
	}()

	return &Context{
		Context:      ctx,
		invocationID: invocationID,
		functionName: functionName,
		deadline:     deadline,
	}
}

// InvocationID returns the unique ID for this invocation.
func (c *Context) InvocationID() string {
	return c.invocationID
}

// FunctionName returns the name of the function being executed.
func (c *Context) FunctionName() string {
	return c.functionName
}

// RemainingTime returns the time remaining before the function times out.
func (c *Context) RemainingTime() time.Duration {
	return time.Until(c.deadline)
}

// GetEnv retrieves an environment variable, returning a default if not set.
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// MustGetEnv retrieves an environment variable, panicking if not set.
func MustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic("required environment variable not set: " + key)
	}
	return value
}

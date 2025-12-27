package lambda

import (
	"context"
	"encoding/json"
)

// Handler is the interface that lambda functions must implement.
type Handler interface {
	Handle(ctx context.Context, event Event) (Response, error)
}

// HandlerFunc is an adapter to allow ordinary functions to be used as handlers.
type HandlerFunc func(ctx context.Context, event Event) (Response, error)

// Handle calls f(ctx, event).
func (f HandlerFunc) Handle(ctx context.Context, event Event) (Response, error) {
	return f(ctx, event)
}

// Event represents the input to a lambda function.
type Event struct {
	// FunctionName is the name of the function being invoked.
	FunctionName string `json:"function_name"`

	// Payload contains the raw JSON payload passed to the function.
	Payload json.RawMessage `json:"payload"`

	// Headers contains any HTTP headers from the original request.
	Headers map[string]string `json:"headers,omitempty"`

	// InvocationID is a unique identifier for this invocation.
	InvocationID string `json:"invocation_id"`
}

// Response represents the output from a lambda function.
type Response struct {
	// StatusCode is the HTTP status code to return.
	StatusCode int `json:"status_code"`

	// Body contains the response body.
	Body any `json:"body,omitempty"`

	// Headers contains any HTTP headers to include in the response.
	Headers map[string]string `json:"headers,omitempty"`

	// Error contains error information if the function failed.
	Error string `json:"error,omitempty"`
}

// Success creates a successful response with the given body.
func Success(body any) Response {
	return Response{
		StatusCode: 200,
		Body:       body,
	}
}

// Error creates an error response with the given status code and message.
func Error(statusCode int, message string) Response {
	return Response{
		StatusCode: statusCode,
		Error:      message,
	}
}

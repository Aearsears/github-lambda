package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/github-lambda/internal/dispatcher"
	"github.com/github-lambda/pkg/auth"
	"github.com/github-lambda/pkg/logging"
	"github.com/github-lambda/pkg/metrics"
)

var logger = logging.New("handlers")

// InvokeHandler handles synchronous function invocations.
func InvokeHandler(d *dispatcher.Dispatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req dispatcher.InvokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn("invalid request body", logging.Fields{"error": err.Error()})
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.FunctionName == "" {
			http.Error(w, "function_name is required", http.StatusBadRequest)
			return
		}

		// Check function-level access
		if err := auth.RequireFunctionAccess(req.FunctionName, r); err != nil {
			logger.Warn("function access denied", logging.Fields{
				"function_name": req.FunctionName,
				"error":         err.Error(),
			})
			http.Error(w, `{"error": "access denied for function"}`, http.StatusForbidden)
			return
		}

		logger.Info("handling sync invocation", logging.Fields{
			"function_name": req.FunctionName,
		})

		exec, err := d.Invoke(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(exec)
	}
}

// AsyncInvokeHandler handles asynchronous function invocations.
func AsyncInvokeHandler(d *dispatcher.Dispatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req dispatcher.InvokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn("invalid request body", logging.Fields{"error": err.Error()})
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.FunctionName == "" {
			http.Error(w, "function_name is required", http.StatusBadRequest)
			return
		}

		// Check function-level access
		if err := auth.RequireFunctionAccess(req.FunctionName, r); err != nil {
			logger.Warn("function access denied", logging.Fields{
				"function_name": req.FunctionName,
				"error":         err.Error(),
			})
			http.Error(w, `{"error": "access denied for function"}`, http.StatusForbidden)
			return
		}

		logger.Info("handling async invocation", logging.Fields{
			"function_name": req.FunctionName,
		})

		exec, err := d.InvokeAsync(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(exec)
	}
}

// StatusHandler handles execution status queries.
func StatusHandler(d *dispatcher.Dispatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract execution ID from path: /status/{id}
		id := strings.TrimPrefix(r.URL.Path, "/status/")
		if id == "" {
			http.Error(w, "execution ID is required", http.StatusBadRequest)
			return
		}

		exec, err := d.GetExecution(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(exec)
	}
}

// HealthHandler handles health check requests.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// CallbackHandler handles workflow completion callbacks.
func CallbackHandler(d *dispatcher.Dispatcher, authMiddleware *auth.Middleware) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read the body for signature verification
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// Verify callback signature if configured
		if !authMiddleware.VerifyCallbackSignature(r, body) {
			logger.Warn("invalid callback signature", logging.Fields{
				"ip": r.RemoteAddr,
			})
			http.Error(w, `{"error": "invalid signature"}`, http.StatusUnauthorized)
			return
		}

		var callback struct {
			InvocationID string          `json:"invocation_id"`
			FunctionName string          `json:"function_name"`
			Status       string          `json:"status"`
			Result       json.RawMessage `json:"result,omitempty"`
			Error        string          `json:"error,omitempty"`
			DurationMs   float64         `json:"duration_ms,omitempty"`
		}

		if err := json.Unmarshal(body, &callback); err != nil {
			logger.Warn("invalid callback request", logging.Fields{"error": err.Error()})
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		logger.Info("received callback", logging.Fields{
			"invocation_id": callback.InvocationID,
			"function_name": callback.FunctionName,
			"status":        callback.Status,
		})

		status := dispatcher.StatusCompleted
		if callback.Status == "failed" {
			status = dispatcher.StatusFailed
			metrics.InvocationFailed(callback.FunctionName, callback.DurationMs)
		} else {
			metrics.InvocationCompleted(callback.FunctionName, callback.DurationMs)
		}

		if err := d.UpdateExecution(callback.InvocationID, status, callback.Result, callback.Error); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

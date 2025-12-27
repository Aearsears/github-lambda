package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/github-lambda/internal/dispatcher"
)

// InvokeHandler handles synchronous function invocations.
func InvokeHandler(d *dispatcher.Dispatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req dispatcher.InvokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.FunctionName == "" {
			http.Error(w, "function_name is required", http.StatusBadRequest)
			return
		}

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
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.FunctionName == "" {
			http.Error(w, "function_name is required", http.StatusBadRequest)
			return
		}

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
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
	})
}

// CallbackHandler handles workflow completion callbacks.
func CallbackHandler(d *dispatcher.Dispatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var callback struct {
			InvocationID string          `json:"invocation_id"`
			Status       string          `json:"status"`
			Result       json.RawMessage `json:"result,omitempty"`
			Error        string          `json:"error,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&callback); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		status := dispatcher.StatusCompleted
		if callback.Status == "failed" {
			status = dispatcher.StatusFailed
		}

		if err := d.UpdateExecution(callback.InvocationID, status, callback.Result, callback.Error); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

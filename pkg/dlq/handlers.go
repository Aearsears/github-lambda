package dlq

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/github-lambda/pkg/logging"
)

// HTTPHandler provides HTTP handlers for DLQ management.
type HTTPHandler struct {
	queue   *Queue
	retryer *Retryer
	logger  *logging.Logger

	// ReplayFunc is called to replay a failed event.
	ReplayFunc func(event *FailedEvent) error
}

// NewHTTPHandler creates a new HTTP handler for DLQ operations.
func NewHTTPHandler(queue *Queue, retryer *Retryer) *HTTPHandler {
	return &HTTPHandler{
		queue:   queue,
		retryer: retryer,
		logger:  logging.New("dlq-api"),
	}
}

// SetReplayFunc sets the function used to replay events.
func (h *HTTPHandler) SetReplayFunc(fn func(event *FailedEvent) error) {
	h.ReplayFunc = fn
}

// RegisterRoutes registers all DLQ routes.
func (h *HTTPHandler) RegisterRoutes(mux *http.ServeMux) {
	// DLQ event management
	mux.HandleFunc("/dlq/events", h.handleEvents)
	mux.HandleFunc("/dlq/events/", h.handleEvent)

	// Statistics
	mux.HandleFunc("/dlq/stats", h.handleStats)

	// Bulk operations
	mux.HandleFunc("/dlq/purge", h.handlePurge)
	mux.HandleFunc("/dlq/replay", h.handleBulkReplay)

	// Retry policies
	mux.HandleFunc("/dlq/policies", h.handlePolicies)
	mux.HandleFunc("/dlq/policies/", h.handlePolicy)
}

// handleEvents handles GET /dlq/events (list)
func (h *HTTPHandler) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filter := h.parseListFilter(r)
	events := h.queue.List(filter)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"count":  len(events),
	})
}

// handleEvent handles /dlq/events/{id} routes
func (h *HTTPHandler) handleEvent(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/dlq/events/")

	// Check for sub-routes
	parts := strings.SplitN(id, "/", 2)
	id = parts[0]

	if id == "" {
		http.Error(w, "Event ID required", http.StatusBadRequest)
		return
	}

	// Handle replay action
	if len(parts) > 1 && parts[1] == "replay" {
		if r.Method == http.MethodPost {
			h.replayEvent(w, r, id)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getEvent(w, r, id)
	case http.MethodDelete:
		h.deleteEvent(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPHandler) parseListFilter(r *http.Request) ListFilter {
	q := r.URL.Query()
	filter := ListFilter{}

	if fn := q.Get("function"); fn != "" {
		filter.FunctionName = fn
	}
	if et := q.Get("error_type"); et != "" {
		filter.ErrorType = ErrorType(et)
	}
	if fr := q.Get("reason"); fr != "" {
		filter.FailureReason = FailureReason(fr)
	}
	if since := q.Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			filter.Since = &t
		}
	}
	if until := q.Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			filter.Until = &t
		}
	}
	if limit := q.Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil {
			filter.Limit = l
		}
	}
	if q.Get("include_replayed") == "true" {
		filter.IncludeReplayed = true
	}

	return filter
}

func (h *HTTPHandler) getEvent(w http.ResponseWriter, r *http.Request, id string) {
	event, err := h.queue.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(event)
}

func (h *HTTPHandler) deleteEvent(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.queue.Delete(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTPHandler) replayEvent(w http.ResponseWriter, r *http.Request, id string) {
	event, err := h.queue.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if h.ReplayFunc == nil {
		http.Error(w, "Replay function not configured", http.StatusServiceUnavailable)
		return
	}

	// Attempt replay
	if err := h.ReplayFunc(event); err != nil {
		h.queue.MarkReplayed(id, "failed")
		h.logger.Error("replay failed", logging.Fields{
			"event_id": id,
			"error":    err.Error(),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "failed",
			"error":  err.Error(),
		})
		return
	}

	h.queue.MarkReplayed(id, "success")
	h.logger.Info("event replayed successfully", logging.Fields{
		"event_id":      id,
		"function_name": event.FunctionName,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "success",
		"event_id": id,
	})
}

// handleStats handles GET /dlq/stats
func (h *HTTPHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.queue.Stats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handlePurge handles POST /dlq/purge
func (h *HTTPHandler) handlePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filter := h.parseListFilter(r)

	// Safety check - require at least one filter to prevent accidental purge all
	if filter.FunctionName == "" && filter.ErrorType == "" && filter.FailureReason == "" && filter.Since == nil {
		// Check for explicit purge_all parameter
		if r.URL.Query().Get("purge_all") != "true" {
			http.Error(w, "At least one filter required, or set purge_all=true", http.StatusBadRequest)
			return
		}
	}

	count := h.queue.Purge(filter)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"purged": count,
	})
}

// handleBulkReplay handles POST /dlq/replay
func (h *HTTPHandler) handleBulkReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.ReplayFunc == nil {
		http.Error(w, "Replay function not configured", http.StatusServiceUnavailable)
		return
	}

	var req struct {
		EventIDs []string `json:"event_ids"`
		Filter   *struct {
			FunctionName  string `json:"function"`
			ErrorType     string `json:"error_type"`
			FailureReason string `json:"reason"`
			Limit         int    `json:"limit"`
		} `json:"filter,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var events []*FailedEvent

	if len(req.EventIDs) > 0 {
		// Replay specific events
		for _, id := range req.EventIDs {
			if event, err := h.queue.Get(id); err == nil {
				events = append(events, event)
			}
		}
	} else if req.Filter != nil {
		// Replay by filter
		filter := ListFilter{
			FunctionName:  req.Filter.FunctionName,
			ErrorType:     ErrorType(req.Filter.ErrorType),
			FailureReason: FailureReason(req.Filter.FailureReason),
			Limit:         req.Filter.Limit,
		}
		events = h.queue.List(filter)
	} else {
		http.Error(w, "Either event_ids or filter required", http.StatusBadRequest)
		return
	}

	results := make([]map[string]interface{}, 0, len(events))
	successCount := 0
	failCount := 0

	for _, event := range events {
		result := map[string]interface{}{
			"event_id":      event.ID,
			"function_name": event.FunctionName,
		}

		if err := h.ReplayFunc(event); err != nil {
			h.queue.MarkReplayed(event.ID, "failed")
			result["status"] = "failed"
			result["error"] = err.Error()
			failCount++
		} else {
			h.queue.MarkReplayed(event.ID, "success")
			result["status"] = "success"
			successCount++
		}

		results = append(results, result)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":     len(events),
		"succeeded": successCount,
		"failed":    failCount,
		"results":   results,
	})
}

// handlePolicies handles GET /dlq/policies
func (h *HTTPHandler) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.retryer.mu.RLock()
	policies := make(map[string]RetryPolicy)
	policies["default"] = h.retryer.defaultPolicy
	for name, policy := range h.retryer.functionPolicies {
		policies[name] = policy
	}
	h.retryer.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"policies": policies,
	})
}

// handlePolicy handles /dlq/policies/{function} routes
func (h *HTTPHandler) handlePolicy(w http.ResponseWriter, r *http.Request) {
	functionName := strings.TrimPrefix(r.URL.Path, "/dlq/policies/")
	if functionName == "" {
		http.Error(w, "Function name required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getPolicy(w, r, functionName)
	case http.MethodPut:
		h.setPolicy(w, r, functionName)
	case http.MethodDelete:
		h.deletePolicy(w, r, functionName)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPHandler) getPolicy(w http.ResponseWriter, r *http.Request, functionName string) {
	policy := h.retryer.GetPolicy(functionName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policy)
}

func (h *HTTPHandler) setPolicy(w http.ResponseWriter, r *http.Request, functionName string) {
	var policy RetryPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	h.retryer.SetFunctionPolicy(functionName, policy)

	h.logger.Info("retry policy updated", logging.Fields{
		"function_name": functionName,
		"max_retries":   policy.MaxRetries,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"function": functionName,
		"policy":   policy,
	})
}

func (h *HTTPHandler) deletePolicy(w http.ResponseWriter, r *http.Request, functionName string) {
	h.retryer.mu.Lock()
	delete(h.retryer.functionPolicies, functionName)
	h.retryer.mu.Unlock()

	h.logger.Info("retry policy removed, using default", logging.Fields{
		"function_name": functionName,
	})

	w.WriteHeader(http.StatusNoContent)
}

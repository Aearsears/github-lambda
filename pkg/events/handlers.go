package events

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/github-lambda/pkg/logging"
)

// HTTPHandler provides HTTP handlers for event source management.
type HTTPHandler struct {
	manager        *Manager
	githubHandler  *GitHubHandler
	webhookHandler *WebhookHandler
	logger         *logging.Logger
}

// NewHTTPHandler creates a new HTTP handler.
func NewHTTPHandler(manager *Manager) *HTTPHandler {
	githubHandler := NewGitHubHandler(manager)
	webhookHandler := NewWebhookHandler(manager)

	// Register handlers with manager
	manager.RegisterHandler(EventTypeSchedule, &ScheduleHandler{})
	manager.RegisterHandler(EventTypeGitHub, githubHandler)
	manager.RegisterHandler(EventTypeWebhook, webhookHandler)

	return &HTTPHandler{
		manager:        manager,
		githubHandler:  githubHandler,
		webhookHandler: webhookHandler,
		logger:         logging.New("events-api"),
	}
}

// RegisterRoutes registers all event source routes.
func (h *HTTPHandler) RegisterRoutes(mux *http.ServeMux) {
	// Event source management
	mux.HandleFunc("/events/sources", h.handleSources)
	mux.HandleFunc("/events/sources/", h.handleSource)

	// Webhook endpoints
	mux.HandleFunc("/webhooks/github", h.githubHandler.WebhookHandler())
	mux.HandleFunc("/webhooks/", h.webhookHandler.Handler())
}

// handleSources handles GET /events/sources (list) and POST /events/sources (create)
func (h *HTTPHandler) handleSources(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listSources(w, r)
	case http.MethodPost:
		h.createSource(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSource handles GET/PUT/DELETE /events/sources/{id}
func (h *HTTPHandler) handleSource(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path
	id := strings.TrimPrefix(r.URL.Path, "/events/sources/")
	if id == "" {
		http.Error(w, "Source ID required", http.StatusBadRequest)
		return
	}

	// Handle sub-paths like /events/sources/{id}/enable
	parts := strings.Split(id, "/")
	id = parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch {
	case action == "enable" && r.Method == http.MethodPost:
		h.enableSource(w, r, id)
	case action == "disable" && r.Method == http.MethodPost:
		h.disableSource(w, r, id)
	case r.Method == http.MethodGet:
		h.getSource(w, r, id)
	case r.Method == http.MethodPut:
		h.updateSource(w, r, id)
	case r.Method == http.MethodDelete:
		h.deleteSource(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPHandler) listSources(w http.ResponseWriter, r *http.Request) {
	// Optional filters
	eventType := r.URL.Query().Get("type")
	functionName := r.URL.Query().Get("function")

	var sources []*EventSource
	if eventType != "" {
		sources = h.manager.ListSourcesByType(EventType(eventType))
	} else if functionName != "" {
		sources = h.manager.ListSourcesByFunction(functionName)
	} else {
		sources = h.manager.ListSources()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sources": sources,
		"count":   len(sources),
	})
}

// CreateSourceRequest represents a request to create an event source.
type CreateSourceRequest struct {
	Name         string          `json:"name"`
	Type         EventType       `json:"type"`
	FunctionName string          `json:"function_name"`
	Config       json.RawMessage `json:"config"`
}

func (h *HTTPHandler) createSource(w http.ResponseWriter, r *http.Request) {
	var req CreateSourceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.Type == "" || req.FunctionName == "" {
		http.Error(w, "name, type, and function_name are required", http.StatusBadRequest)
		return
	}

	source := &EventSource{
		Name:         req.Name,
		Type:         req.Type,
		FunctionName: req.FunctionName,
		Config:       req.Config,
	}

	if err := h.manager.CreateSource(source); err != nil {
		h.logger.Error("failed to create event source", logging.Fields{"error": err.Error()})
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Register webhook path if applicable
	if source.Type == EventTypeWebhook {
		if err := h.webhookHandler.RegisterPath(source); err != nil {
			h.logger.Warn("failed to register webhook path", logging.Fields{"error": err.Error()})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(source)
}

func (h *HTTPHandler) getSource(w http.ResponseWriter, r *http.Request, id string) {
	source, err := h.manager.GetSource(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(source)
}

func (h *HTTPHandler) updateSource(w http.ResponseWriter, r *http.Request, id string) {
	var updates EventSource
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.manager.UpdateSource(id, &updates); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	source, _ := h.manager.GetSource(id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(source)
}

func (h *HTTPHandler) deleteSource(w http.ResponseWriter, r *http.Request, id string) {
	// Get source first to unregister webhook if needed
	source, err := h.manager.GetSource(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	// Unregister webhook path if applicable
	if source.Type == EventTypeWebhook {
		var cfg WebhookConfig
		if err := json.Unmarshal(source.Config, &cfg); err == nil {
			h.webhookHandler.UnregisterPath(cfg.Path)
		}
	}

	if err := h.manager.DeleteSource(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *HTTPHandler) enableSource(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.manager.EnableSource(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	source, _ := h.manager.GetSource(id)

	// Re-register webhook path if applicable
	if source.Type == EventTypeWebhook {
		h.webhookHandler.RegisterPath(source)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "enabled",
		"source": source,
	})
}

func (h *HTTPHandler) disableSource(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.manager.DisableSource(id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	source, _ := h.manager.GetSource(id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "disabled",
		"source": source,
	})
}

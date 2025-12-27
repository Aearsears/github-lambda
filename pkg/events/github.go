package events

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/github-lambda/pkg/logging"
)

// GitHubConfig represents configuration for a GitHub event source.
type GitHubConfig struct {
	// Events to listen for (e.g., "push", "pull_request", "issues")
	Events []string `json:"events"`

	// Repository filter (e.g., "owner/repo"). Empty means all repos.
	Repository string `json:"repository,omitempty"`

	// Branch filter for push events. Empty means all branches.
	Branches []string `json:"branches,omitempty"`

	// Secret for validating webhook signatures
	Secret string `json:"secret,omitempty"`

	// Filter by action (for events like pull_request: opened, closed, etc.)
	Actions []string `json:"actions,omitempty"`
}

// GitHubHandler handles GitHub webhook events.
type GitHubHandler struct {
	manager *Manager
	logger  *logging.Logger
}

// NewGitHubHandler creates a new GitHub event handler.
func NewGitHubHandler(manager *Manager) *GitHubHandler {
	return &GitHubHandler{
		manager: manager,
		logger:  logging.New("github-events"),
	}
}

// Handle processes a GitHub event.
func (h *GitHubHandler) Handle(ctx context.Context, event *Event) error {
	// Event is processed, dispatch to function
	_, err := h.manager.ProcessEvent(ctx, event)
	return err
}

// Validate validates GitHub configuration.
func (h *GitHubHandler) Validate(config json.RawMessage) error {
	var cfg GitHubConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return err
	}

	if len(cfg.Events) == 0 {
		return fmt.Errorf("at least one event type must be specified")
	}

	return nil
}

// GitHubWebhookHandler returns an HTTP handler for GitHub webhooks.
func (h *GitHubHandler) WebhookHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			h.logger.Error("failed to read webhook body", logging.Fields{"error": err.Error()})
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		// Get event type
		eventType := r.Header.Get("X-GitHub-Event")
		if eventType == "" {
			http.Error(w, "Missing X-GitHub-Event header", http.StatusBadRequest)
			return
		}

		deliveryID := r.Header.Get("X-GitHub-Delivery")
		signature := r.Header.Get("X-Hub-Signature-256")

		h.logger.Debug("received GitHub webhook", logging.Fields{
			"event_type":  eventType,
			"delivery_id": deliveryID,
		})

		// Parse payload to extract repository info
		var payload map[string]interface{}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		// Extract repository name
		repoName := ""
		if repo, ok := payload["repository"].(map[string]interface{}); ok {
			if fullName, ok := repo["full_name"].(string); ok {
				repoName = fullName
			}
		}

		// Extract action if present
		action := ""
		if a, ok := payload["action"].(string); ok {
			action = a
		}

		// Extract branch for push events
		branch := ""
		if ref, ok := payload["ref"].(string); ok {
			if strings.HasPrefix(ref, "refs/heads/") {
				branch = strings.TrimPrefix(ref, "refs/heads/")
			}
		}

		// Find matching event sources
		sources := h.manager.ListSourcesByType(EventTypeGitHub)
		triggered := 0

		for _, source := range sources {
			if !source.Enabled {
				continue
			}

			var cfg GitHubConfig
			if err := json.Unmarshal(source.Config, &cfg); err != nil {
				continue
			}

			// Check if event type matches
			if !h.eventMatches(eventType, cfg.Events) {
				continue
			}

			// Check repository filter
			if cfg.Repository != "" && cfg.Repository != repoName {
				continue
			}

			// Check branch filter for push events
			if eventType == "push" && len(cfg.Branches) > 0 {
				if !h.branchMatches(branch, cfg.Branches) {
					continue
				}
			}

			// Check action filter
			if len(cfg.Actions) > 0 && action != "" {
				if !h.actionMatches(action, cfg.Actions) {
					continue
				}
			}

			// Validate signature if secret is configured
			if cfg.Secret != "" {
				if !h.validateSignature(body, signature, cfg.Secret) {
					h.logger.Warn("invalid webhook signature", logging.Fields{
						"source_id":   source.ID,
						"delivery_id": deliveryID,
					})
					continue
				}
			}

			// Create event
			event := &Event{
				ID:           deliveryID + "-" + source.ID,
				SourceID:     source.ID,
				SourceType:   EventTypeGitHub,
				FunctionName: source.FunctionName,
				Payload:      body,
				Headers: map[string]string{
					"X-GitHub-Event":    eventType,
					"X-GitHub-Delivery": deliveryID,
				},
				Metadata: map[string]string{
					"event_type": eventType,
					"repository": repoName,
					"branch":     branch,
					"action":     action,
				},
				ReceivedAt: time.Now(),
			}

			// Process asynchronously
			go func(e *Event, s *EventSource) {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				if _, err := h.manager.ProcessEvent(ctx, e); err != nil {
					h.logger.Error("failed to process GitHub event", logging.Fields{
						"source_id": s.ID,
						"error":     err.Error(),
					})
				}
			}(event, source)

			triggered++
		}

		h.logger.Info("GitHub webhook processed", logging.Fields{
			"event_type":        eventType,
			"delivery_id":       deliveryID,
			"repository":        repoName,
			"sources_triggered": triggered,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"received":  true,
			"triggered": triggered,
		})
	}
}

func (h *GitHubHandler) eventMatches(eventType string, events []string) bool {
	for _, e := range events {
		if e == "*" || e == eventType {
			return true
		}
	}
	return false
}

func (h *GitHubHandler) branchMatches(branch string, branches []string) bool {
	for _, b := range branches {
		if b == "*" || b == branch {
			return true
		}
		// Support wildcards like "feature/*"
		if strings.HasSuffix(b, "*") {
			prefix := strings.TrimSuffix(b, "*")
			if strings.HasPrefix(branch, prefix) {
				return true
			}
		}
	}
	return false
}

func (h *GitHubHandler) actionMatches(action string, actions []string) bool {
	for _, a := range actions {
		if a == "*" || a == action {
			return true
		}
	}
	return false
}

func (h *GitHubHandler) validateSignature(body []byte, signature, secret string) bool {
	if signature == "" {
		return false
	}

	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}

	sig, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)

	return hmac.Equal(sig, expected)
}

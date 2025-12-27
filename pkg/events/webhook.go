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

// WebhookConfig represents configuration for a generic webhook event source.
type WebhookConfig struct {
	// Path is the URL path for this webhook (e.g., "/webhooks/my-service")
	Path string `json:"path"`

	// Secret for validating signatures (optional)
	Secret string `json:"secret,omitempty"`

	// SignatureHeader is the header containing the signature
	SignatureHeader string `json:"signature_header,omitempty"`

	// SignaturePrefix is the prefix in the signature (e.g., "sha256=")
	SignaturePrefix string `json:"signature_prefix,omitempty"`

	// RequiredHeaders are headers that must be present
	RequiredHeaders []string `json:"required_headers,omitempty"`

	// Transform specifies how to transform the payload
	Transform *PayloadTransform `json:"transform,omitempty"`

	// Methods allowed (default: POST)
	Methods []string `json:"methods,omitempty"`
}

// PayloadTransform specifies how to transform incoming payloads.
type PayloadTransform struct {
	// WrapInField wraps the entire payload in a field
	WrapInField string `json:"wrap_in_field,omitempty"`

	// AddFields adds static fields to the payload
	AddFields map[string]interface{} `json:"add_fields,omitempty"`

	// ExtractFields extracts specific fields from the payload
	ExtractFields []string `json:"extract_fields,omitempty"`
}

// WebhookHandler handles generic webhook events.
type WebhookHandler struct {
	manager *Manager
	logger  *logging.Logger
	paths   map[string]*EventSource // path -> source mapping
}

// NewWebhookHandler creates a new webhook handler.
func NewWebhookHandler(manager *Manager) *WebhookHandler {
	return &WebhookHandler{
		manager: manager,
		logger:  logging.New("webhook-events"),
		paths:   make(map[string]*EventSource),
	}
}

// Handle processes a webhook event.
func (h *WebhookHandler) Handle(ctx context.Context, event *Event) error {
	_, err := h.manager.ProcessEvent(ctx, event)
	return err
}

// Validate validates webhook configuration.
func (h *WebhookHandler) Validate(config json.RawMessage) error {
	var cfg WebhookConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return err
	}

	if cfg.Path == "" {
		return fmt.Errorf("path is required")
	}

	if !strings.HasPrefix(cfg.Path, "/") {
		return fmt.Errorf("path must start with /")
	}

	return nil
}

// RegisterPath registers a webhook path.
func (h *WebhookHandler) RegisterPath(source *EventSource) error {
	var cfg WebhookConfig
	if err := json.Unmarshal(source.Config, &cfg); err != nil {
		return err
	}

	h.paths[cfg.Path] = source
	return nil
}

// UnregisterPath unregisters a webhook path.
func (h *WebhookHandler) UnregisterPath(path string) {
	delete(h.paths, path)
}

// Handler returns an HTTP handler for webhooks.
func (h *WebhookHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Find matching source
		source, exists := h.paths[path]
		if !exists {
			// Try to find by prefix match
			for p, s := range h.paths {
				if strings.HasPrefix(path, p) {
					source = s
					exists = true
					break
				}
			}
		}

		if !exists {
			http.NotFound(w, r)
			return
		}

		if !source.Enabled {
			http.Error(w, "Webhook is disabled", http.StatusServiceUnavailable)
			return
		}

		var cfg WebhookConfig
		if err := json.Unmarshal(source.Config, &cfg); err != nil {
			http.Error(w, "Invalid webhook configuration", http.StatusInternalServerError)
			return
		}

		// Check method
		allowedMethods := cfg.Methods
		if len(allowedMethods) == 0 {
			allowedMethods = []string{"POST"}
		}

		methodAllowed := false
		for _, m := range allowedMethods {
			if strings.EqualFold(m, r.Method) {
				methodAllowed = true
				break
			}
		}
		if !methodAllowed {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check required headers
		for _, header := range cfg.RequiredHeaders {
			if r.Header.Get(header) == "" {
				h.logger.Warn("missing required header", logging.Fields{
					"source_id": source.ID,
					"header":    header,
				})
				http.Error(w, "Missing required header: "+header, http.StatusBadRequest)
				return
			}
		}

		// Read body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		// Validate signature if configured
		if cfg.Secret != "" && cfg.SignatureHeader != "" {
			signature := r.Header.Get(cfg.SignatureHeader)
			if !h.validateSignature(body, signature, cfg.Secret, cfg.SignaturePrefix) {
				h.logger.Warn("invalid webhook signature", logging.Fields{
					"source_id": source.ID,
					"path":      path,
				})
				http.Error(w, "Invalid signature", http.StatusUnauthorized)
				return
			}
		}

		// Transform payload if configured
		payload := body
		if cfg.Transform != nil {
			payload, err = h.transformPayload(body, cfg.Transform)
			if err != nil {
				h.logger.Error("failed to transform payload", logging.Fields{
					"source_id": source.ID,
					"error":     err.Error(),
				})
				http.Error(w, "Failed to transform payload", http.StatusBadRequest)
				return
			}
		}

		// Build headers map
		headers := make(map[string]string)
		for key := range r.Header {
			headers[key] = r.Header.Get(key)
		}

		// Create event
		event := &Event{
			ID:           generateID(),
			SourceID:     source.ID,
			SourceType:   EventTypeWebhook,
			FunctionName: source.FunctionName,
			Payload:      payload,
			Headers:      headers,
			Metadata: map[string]string{
				"path":   path,
				"method": r.Method,
				"ip":     r.RemoteAddr,
			},
			ReceivedAt: time.Now(),
		}

		// Process asynchronously
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if _, err := h.manager.ProcessEvent(ctx, event); err != nil {
				h.logger.Error("failed to process webhook event", logging.Fields{
					"source_id": source.ID,
					"error":     err.Error(),
				})
			}
		}()

		h.logger.Info("webhook received", logging.Fields{
			"source_id":     source.ID,
			"function_name": source.FunctionName,
			"path":          path,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"received": true,
			"event_id": event.ID,
		})
	}
}

func (h *WebhookHandler) validateSignature(body []byte, signature, secret, prefix string) bool {
	if signature == "" {
		return false
	}

	// Remove prefix if present
	sigHex := signature
	if prefix != "" && strings.HasPrefix(signature, prefix) {
		sigHex = strings.TrimPrefix(signature, prefix)
	}

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)

	return hmac.Equal(sig, expected)
}

func (h *WebhookHandler) transformPayload(body []byte, transform *PayloadTransform) ([]byte, error) {
	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		// If not valid JSON, wrap as string
		data = string(body)
	}

	result := make(map[string]interface{})

	// Wrap in field if specified
	if transform.WrapInField != "" {
		result[transform.WrapInField] = data
	} else if dataMap, ok := data.(map[string]interface{}); ok {
		// Copy existing fields
		for k, v := range dataMap {
			result[k] = v
		}
	} else {
		result["data"] = data
	}

	// Add static fields
	for k, v := range transform.AddFields {
		result[k] = v
	}

	// Extract specific fields if specified
	if len(transform.ExtractFields) > 0 {
		if dataMap, ok := data.(map[string]interface{}); ok {
			extracted := make(map[string]interface{})
			for _, field := range transform.ExtractFields {
				if v, exists := dataMap[field]; exists {
					extracted[field] = v
				}
			}
			if transform.WrapInField != "" {
				result[transform.WrapInField] = extracted
			} else {
				result = extracted
			}
		}
	}

	return json.Marshal(result)
}

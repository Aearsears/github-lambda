package auth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/github-lambda/pkg/logging"
)

// AdminHandler provides HTTP handlers for API key management.
type AdminHandler struct {
	keyStore *KeyStore
	logger   *logging.Logger
}

// NewAdminHandler creates a new admin handler.
func NewAdminHandler(keyStore *KeyStore) *AdminHandler {
	return &AdminHandler{
		keyStore: keyStore,
		logger:   logging.New("admin"),
	}
}

// CreateKeyRequest represents a request to create an API key.
type CreateKeyRequest struct {
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
	Functions   []string     `json:"functions,omitempty"`
	TTLHours    *int         `json:"ttl_hours,omitempty"`
}

// CreateKeyResponse represents the response when creating an API key.
type CreateKeyResponse struct {
	Key     string  `json:"key"` // Only returned once at creation
	KeyInfo *APIKey `json:"key_info"`
}

// HandleCreateKey handles POST /admin/keys
func (h *AdminHandler) HandleCreateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, `{"error": "name is required"}`, http.StatusBadRequest)
		return
	}

	if len(req.Permissions) == 0 {
		http.Error(w, `{"error": "at least one permission is required"}`, http.StatusBadRequest)
		return
	}

	var ttl *time.Duration
	if req.TTLHours != nil {
		d := time.Duration(*req.TTLHours) * time.Hour
		ttl = &d
	}

	keyString, keyInfo, err := h.keyStore.GenerateAPIKey(req.Name, req.Permissions, req.Functions, ttl)
	if err != nil {
		h.logger.Error("failed to generate API key", logging.Fields{"error": err.Error()})
		http.Error(w, `{"error": "failed to generate key"}`, http.StatusInternalServerError)
		return
	}

	h.logger.Info("API key created", logging.Fields{
		"key_id": keyInfo.ID,
		"name":   keyInfo.Name,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(CreateKeyResponse{
		Key:     keyString,
		KeyInfo: keyInfo,
	})
}

// HandleListKeys handles GET /admin/keys
func (h *AdminHandler) HandleListKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keys := h.keyStore.ListKeys()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys":  keys,
		"count": len(keys),
	})
}

// HandleRevokeKey handles POST /admin/keys/{id}/revoke
func (h *AdminHandler) HandleRevokeKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract key ID from query parameter
	keyID := r.URL.Query().Get("id")
	if keyID == "" {
		http.Error(w, `{"error": "key ID is required"}`, http.StatusBadRequest)
		return
	}

	if err := h.keyStore.RevokeKey(keyID); err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusNotFound)
		return
	}

	h.logger.Info("API key revoked via admin", logging.Fields{"key_id": keyID})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "revoked",
		"key_id": keyID,
	})
}

// HandleDeleteKey handles DELETE /admin/keys/{id}
func (h *AdminHandler) HandleDeleteKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keyID := r.URL.Query().Get("id")
	if keyID == "" {
		http.Error(w, `{"error": "key ID is required"}`, http.StatusBadRequest)
		return
	}

	if err := h.keyStore.DeleteKey(keyID); err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusNotFound)
		return
	}

	h.logger.Info("API key deleted via admin", logging.Fields{"key_id": keyID})

	w.WriteHeader(http.StatusNoContent)
}

// RegisterRoutes registers all admin routes on the given mux.
func (h *AdminHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/keys", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.HandleListKeys(w, r)
		case http.MethodPost:
			h.HandleCreateKey(w, r)
		case http.MethodDelete:
			h.HandleDeleteKey(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/admin/keys/revoke", h.HandleRevokeKey)
}

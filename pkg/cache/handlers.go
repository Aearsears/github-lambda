package cache

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Handler provides HTTP endpoints for cache management.
type Handler struct {
	cache *Cache
}

// NewHandler creates a new cache HTTP handler.
func NewHandler(cache *Cache) *Handler {
	return &Handler{cache: cache}
}

// RegisterRoutes registers cache management routes.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/cache/entries", h.handleEntries)
	mux.HandleFunc("/cache/entries/", h.handleEntry)
	mux.HandleFunc("/cache/stats", h.handleStats)
	mux.HandleFunc("/cache/invalidate", h.handleInvalidateAll)
	mux.HandleFunc("/cache/invalidate/", h.handleInvalidate)
	mux.HandleFunc("/cache/config", h.handleDefaultConfig)
	mux.HandleFunc("/cache/config/", h.handleFunctionConfig)
}

// handleEntries handles GET /cache/entries - list cache entries.
func (h *Handler) handleEntries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	functionName := r.URL.Query().Get("function")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	entries := h.cache.List(functionName, limit)

	// Convert to response format
	type entryResponse struct {
		Key            string            `json:"key"`
		FunctionName   string            `json:"function_name"`
		Version        int               `json:"version,omitempty"`
		InputHash      string            `json:"input_hash"`
		StatusCode     int               `json:"status_code"`
		CreatedAt      time.Time         `json:"created_at"`
		ExpiresAt      time.Time         `json:"expires_at"`
		TTL            string            `json:"ttl"`
		HitCount       int64             `json:"hit_count"`
		LastAccessedAt time.Time         `json:"last_accessed_at"`
		ResponseSize   int               `json:"response_size_bytes"`
		Metadata       map[string]string `json:"metadata,omitempty"`
	}

	response := make([]entryResponse, 0, len(entries))
	for _, entry := range entries {
		response = append(response, entryResponse{
			Key:            entry.Key,
			FunctionName:   entry.FunctionName,
			Version:        entry.Version,
			InputHash:      entry.InputHash,
			StatusCode:     entry.StatusCode,
			CreatedAt:      entry.CreatedAt,
			ExpiresAt:      entry.ExpiresAt,
			TTL:            entry.TTL.String(),
			HitCount:       entry.HitCount,
			LastAccessedAt: entry.LastAccessedAt,
			ResponseSize:   len(entry.Response),
			Metadata:       entry.Metadata,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"entries": response,
		"count":   len(response),
	})
}

// handleEntry handles GET/DELETE /cache/entries/{key} - get or delete a specific entry.
func (h *Handler) handleEntry(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/cache/entries/")
	if key == "" {
		http.Error(w, "Cache key is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		entry, exists := h.cache.GetEntry(key)
		if !exists {
			http.Error(w, `{"error": "cache entry not found"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entry)

	case http.MethodDelete:
		if h.cache.Invalidate(key) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status": "invalidated",
				"key":    key,
			})
		} else {
			http.Error(w, `{"error": "cache entry not found"}`, http.StatusNotFound)
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleStats handles GET /cache/stats - get cache statistics.
func (h *Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.cache.Stats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// handleInvalidateAll handles POST /cache/invalidate - invalidate entire cache.
func (h *Handler) handleInvalidateAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	count := h.cache.InvalidateAll()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "invalidated",
		"entries_removed": count,
	})
}

// handleInvalidate handles POST /cache/invalidate/{function} - invalidate function cache.
func (h *Handler) handleInvalidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	functionName := strings.TrimPrefix(r.URL.Path, "/cache/invalidate/")
	if functionName == "" {
		http.Error(w, "Function name is required", http.StatusBadRequest)
		return
	}

	// Check for version parameter
	versionStr := r.URL.Query().Get("version")
	if versionStr != "" {
		version, err := strconv.Atoi(versionStr)
		if err != nil {
			http.Error(w, "Invalid version number", http.StatusBadRequest)
			return
		}

		count := h.cache.InvalidateFunctionVersion(functionName, version)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":          "invalidated",
			"function_name":   functionName,
			"version":         version,
			"entries_removed": count,
		})
		return
	}

	count := h.cache.InvalidateFunction(functionName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "invalidated",
		"function_name":   functionName,
		"entries_removed": count,
	})
}

// handleDefaultConfig handles GET/PUT /cache/config - manage default configuration.
func (h *Handler) handleDefaultConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		config := h.cache.GetDefaultConfig()
		configs := h.cache.GetAllConfigs()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"default":   configToResponse(config),
			"functions": configsToResponse(configs),
		})

	case http.MethodPut:
		var req configRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		config := requestToConfig(req, h.cache.GetDefaultConfig())
		h.cache.SetDefaultConfig(config)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "updated",
			"config": configToResponse(config),
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFunctionConfig handles GET/PUT/DELETE /cache/config/{function} - manage function config.
func (h *Handler) handleFunctionConfig(w http.ResponseWriter, r *http.Request) {
	functionName := strings.TrimPrefix(r.URL.Path, "/cache/config/")
	if functionName == "" {
		http.Error(w, "Function name is required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		config := h.cache.GetConfig(functionName)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"function_name": functionName,
			"config":        configToResponse(config),
		})

	case http.MethodPut:
		var req configRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		config := requestToConfig(req, h.cache.GetConfig(functionName))
		h.cache.SetConfig(functionName, config)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "updated",
			"function_name": functionName,
			"config":        configToResponse(config),
		})

	case http.MethodDelete:
		h.cache.DeleteConfig(functionName)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":        "deleted",
			"function_name": functionName,
			"message":       "Function will now use default cache configuration",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// configRequest represents a cache configuration API request.
type configRequest struct {
	Enabled              *bool    `json:"enabled,omitempty"`
	TTLSeconds           *int     `json:"ttl_seconds,omitempty"`
	MaxEntries           *int     `json:"max_entries,omitempty"`
	CacheErrors          *bool    `json:"cache_errors,omitempty"`
	ErrorTTLSeconds      *int     `json:"error_ttl_seconds,omitempty"`
	VaryByHeaders        []string `json:"vary_by_headers,omitempty"`
	ExcludePayloadFields []string `json:"exclude_payload_fields,omitempty"`
}

// configResponse represents a cache configuration API response.
type configResponse struct {
	Enabled              bool     `json:"enabled"`
	TTLSeconds           int      `json:"ttl_seconds"`
	MaxEntries           int      `json:"max_entries"`
	CacheErrors          bool     `json:"cache_errors"`
	ErrorTTLSeconds      int      `json:"error_ttl_seconds"`
	VaryByHeaders        []string `json:"vary_by_headers,omitempty"`
	ExcludePayloadFields []string `json:"exclude_payload_fields,omitempty"`
}

// requestToConfig converts a request to a CacheConfig.
func requestToConfig(req configRequest, base CacheConfig) CacheConfig {
	config := base

	if req.Enabled != nil {
		config.Enabled = *req.Enabled
	}
	if req.TTLSeconds != nil {
		config.TTL = time.Duration(*req.TTLSeconds) * time.Second
	}
	if req.MaxEntries != nil {
		config.MaxEntries = *req.MaxEntries
	}
	if req.CacheErrors != nil {
		config.CacheErrors = *req.CacheErrors
	}
	if req.ErrorTTLSeconds != nil {
		config.ErrorTTL = time.Duration(*req.ErrorTTLSeconds) * time.Second
	}
	if req.VaryByHeaders != nil {
		config.VaryByHeaders = req.VaryByHeaders
	}
	if req.ExcludePayloadFields != nil {
		config.ExcludePayloadFields = req.ExcludePayloadFields
	}

	return config
}

// configToResponse converts a CacheConfig to an API response.
func configToResponse(config CacheConfig) configResponse {
	return configResponse{
		Enabled:              config.Enabled,
		TTLSeconds:           int(config.TTL.Seconds()),
		MaxEntries:           config.MaxEntries,
		CacheErrors:          config.CacheErrors,
		ErrorTTLSeconds:      int(config.ErrorTTL.Seconds()),
		VaryByHeaders:        config.VaryByHeaders,
		ExcludePayloadFields: config.ExcludePayloadFields,
	}
}

// configsToResponse converts a map of configs to responses.
func configsToResponse(configs map[string]CacheConfig) map[string]configResponse {
	result := make(map[string]configResponse)
	for name, config := range configs {
		result[name] = configToResponse(config)
	}
	return result
}

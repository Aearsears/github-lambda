package warmpool

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/github-lambda/pkg/logging"
)

// Handler provides HTTP handlers for warm pool and prebuild management.
type Handler struct {
	manager     *Manager
	prebuildMgr *PrebuildManager
	logger      *logging.Logger
}

// NewHandler creates a new warm pool HTTP handler.
func NewHandler(manager *Manager, prebuildMgr *PrebuildManager) *Handler {
	return &Handler{
		manager:     manager,
		prebuildMgr: prebuildMgr,
		logger:      logging.New("warmpool-handler"),
	}
}

// RegisterRoutes registers HTTP routes on a ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Function registration
	mux.HandleFunc("/api/warmpool/functions", h.handleFunctions)
	mux.HandleFunc("/api/warmpool/functions/", h.handleFunction)

	// Cache status
	mux.HandleFunc("/api/warmpool/cache/check", h.CheckCache)
	mux.HandleFunc("/api/warmpool/cache/record", h.RecordArtifact)
	mux.HandleFunc("/api/warmpool/cache/", h.handleCacheEntry)

	// Warm instances
	mux.HandleFunc("/api/warmpool/instances/", h.handleInstances)

	// Pool stats
	mux.HandleFunc("/api/warmpool/stats", h.GetPoolStats)
	mux.HandleFunc("/api/warmpool/export", h.ExportWarmPool)

	// Prebuild management
	mux.HandleFunc("/api/prebuild/specs", h.handlePrebuildSpecs)
	mux.HandleFunc("/api/prebuild/specs/", h.handlePrebuildSpec)

	// Prebuild triggers and builds
	mux.HandleFunc("/api/prebuild/trigger/", h.handleTrigger)
	mux.HandleFunc("/api/prebuild/builds", h.ListBuilds)
	mux.HandleFunc("/api/prebuild/builds/", h.handleBuild)

	// Prebuilt images
	mux.HandleFunc("/api/prebuild/images", h.RecordImage)
	mux.HandleFunc("/api/prebuild/images/", h.handleImages)

	// Workflow generation
	mux.HandleFunc("/api/prebuild/workflow/", h.handleWorkflow)
	mux.HandleFunc("/api/prebuild/dispatch/", h.handleDispatch)

	// Prebuild stats
	mux.HandleFunc("/api/prebuild/stats", h.GetPrebuildStats)
	mux.HandleFunc("/api/prebuild/export", h.ExportPrebuild)
}

// handleFunctions routes /api/warmpool/functions requests
func (h *Handler) handleFunctions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.ListFunctions(w, r)
	case http.MethodPost:
		h.RegisterFunction(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFunction routes /api/warmpool/functions/{name}... requests
func (h *Handler) handleFunction(w http.ResponseWriter, r *http.Request) {
	// Parse path: /api/warmpool/functions/{name}[/action]
	path := strings.TrimPrefix(r.URL.Path, "/api/warmpool/functions/")
	parts := strings.Split(path, "/")
	name := parts[0]

	if name == "" {
		h.jsonError(w, "Function name is required", http.StatusBadRequest)
		return
	}

	// Check for sub-paths
	if len(parts) > 1 {
		switch parts[1] {
		case "cache-config":
			h.getCacheConfig(w, r, name)
			return
		case "workflow-cache":
			h.getWorkflowCache(w, r, name)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		h.getFunction(w, r, name)
	case http.MethodDelete:
		h.unregisterFunction(w, r, name)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCacheEntry routes /api/warmpool/cache/{key} requests
func (h *Handler) handleCacheEntry(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/api/warmpool/cache/")
	if key == "" {
		h.jsonError(w, "Cache key is required", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		h.getArtifact(w, r, key)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleInstances routes /api/warmpool/instances/{name}... requests
func (h *Handler) handleInstances(w http.ResponseWriter, r *http.Request) {
	// Parse path: /api/warmpool/instances/{name}[/action]
	path := strings.TrimPrefix(r.URL.Path, "/api/warmpool/instances/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		h.jsonError(w, "Instance name or ID is required", http.StatusBadRequest)
		return
	}

	// Check for sub-paths
	if len(parts) > 1 {
		switch parts[1] {
		case "warmup":
			h.warmUp(w, r, parts[0])
			return
		case "release":
			h.releaseInstance(w, r, parts[0])
			return
		}
	}

	// Default: get warm instance
	h.getWarmInstance(w, r, parts[0])
}

// handlePrebuildSpecs routes /api/prebuild/specs requests
func (h *Handler) handlePrebuildSpecs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.ListPrebuildSpecs(w, r)
	case http.MethodPost:
		h.RegisterPrebuild(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePrebuildSpec routes /api/prebuild/specs/{name} requests
func (h *Handler) handlePrebuildSpec(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/prebuild/specs/")
	if name == "" {
		h.jsonError(w, "Function name is required", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		h.getPrebuildSpec(w, r, name)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTrigger routes /api/prebuild/trigger/{name} requests
func (h *Handler) handleTrigger(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/prebuild/trigger/")
	if name == "" {
		h.jsonError(w, "Function name is required", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodPost {
		h.triggerBuild(w, r, name)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBuild routes /api/prebuild/builds/{id} requests
func (h *Handler) handleBuild(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/prebuild/builds/")
	if id == "" {
		h.jsonError(w, "Build ID is required", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		h.getBuild(w, r, id)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleImages routes /api/prebuild/images/{name}[/digest] requests
func (h *Handler) handleImages(w http.ResponseWriter, r *http.Request) {
	// Parse path: /api/prebuild/images/{name}[/latest or /digest]
	path := strings.TrimPrefix(r.URL.Path, "/api/prebuild/images/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		h.jsonError(w, "Function name is required", http.StatusBadRequest)
		return
	}

	name := parts[0]

	if len(parts) > 1 {
		if parts[1] == "latest" {
			h.getLatestImage(w, r, name)
		} else {
			h.getImageByDigest(w, r, name, parts[1])
		}
	} else {
		h.jsonError(w, "Image identifier is required", http.StatusBadRequest)
	}
}

// handleWorkflow routes /api/prebuild/workflow/{name} requests
func (h *Handler) handleWorkflow(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/prebuild/workflow/")
	if name == "" {
		h.jsonError(w, "Function name is required", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		h.getWorkflowBuildConfig(w, r, name)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDispatch routes /api/prebuild/dispatch/{name} requests
func (h *Handler) handleDispatch(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/prebuild/dispatch/")
	if name == "" {
		h.jsonError(w, "Function name is required", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		h.getDispatchPayload(w, r, name)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// RegisterFunction handles POST /api/warmpool/functions
func (h *Handler) RegisterFunction(w http.ResponseWriter, r *http.Request) {
	var spec FunctionSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.manager.RegisterFunction(&spec); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.logger.Info("function registered via API", logging.Fields{
		"function_name": spec.Name,
	})

	h.jsonResponse(w, map[string]interface{}{
		"success":  true,
		"message":  "Function registered for warm pool",
		"function": spec,
	})
}

// ListFunctions handles GET /api/warmpool/functions
func (h *Handler) ListFunctions(w http.ResponseWriter, r *http.Request) {
	functions := h.manager.ListFunctions()
	h.jsonResponse(w, map[string]interface{}{
		"functions": functions,
		"count":     len(functions),
	})
}

// getFunction handles GET /api/warmpool/functions/{name}
func (h *Handler) getFunction(w http.ResponseWriter, r *http.Request, name string) {
	spec, err := h.manager.GetFunction(name)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.jsonResponse(w, spec)
}

// unregisterFunction handles DELETE /api/warmpool/functions/{name}
func (h *Handler) unregisterFunction(w http.ResponseWriter, r *http.Request, name string) {
	if err := h.manager.UnregisterFunction(name); err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.logger.Info("function unregistered via API", logging.Fields{
		"function_name": name,
	})

	h.jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": "Function unregistered from warm pool",
	})
}

// getCacheConfig handles GET /api/warmpool/functions/{name}/cache-config
func (h *Handler) getCacheConfig(w http.ResponseWriter, r *http.Request, name string) {
	config, err := h.manager.GetGitHubCacheConfig(name)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.jsonResponse(w, config)
}

// getWorkflowCache handles GET /api/warmpool/functions/{name}/workflow-cache
func (h *Handler) getWorkflowCache(w http.ResponseWriter, r *http.Request, name string) {
	step, err := h.manager.GenerateWorkflowCache(name)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.jsonResponse(w, step)
}

// CheckCache handles POST /api/warmpool/cache/check
func (h *Handler) CheckCache(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		FunctionName   string `json:"function_name"`
		DependencyHash string `json:"dependency_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	result, err := h.manager.CheckCache(req.FunctionName, req.DependencyHash)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, result)
}

// RecordArtifact handles POST /api/warmpool/cache/record
func (h *Handler) RecordArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var artifact CachedArtifact
	if err := json.NewDecoder(r.Body).Decode(&artifact); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.manager.RecordArtifact(&artifact); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.jsonResponse(w, map[string]interface{}{
		"success":  true,
		"message":  "Artifact recorded",
		"artifact": artifact,
	})
}

// getArtifact handles GET /api/warmpool/cache/{key}
func (h *Handler) getArtifact(w http.ResponseWriter, r *http.Request, key string) {
	artifact, err := h.manager.GetArtifact(key)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.jsonResponse(w, artifact)
}

// warmUp handles POST /api/warmpool/instances/{name}/warmup
func (h *Handler) warmUp(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	countStr := r.URL.Query().Get("count")
	count := 1
	if countStr != "" {
		var err error
		count, err = strconv.Atoi(countStr)
		if err != nil || count < 1 {
			h.jsonError(w, "Invalid count parameter", http.StatusBadRequest)
			return
		}
	}

	instances, err := h.manager.WarmUp(r.Context(), name, count)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.logger.Info("instances warmed up via API", logging.Fields{
		"function_name": name,
		"count":         count,
	})

	h.jsonResponse(w, map[string]interface{}{
		"success":   true,
		"message":   "Instances warmed up",
		"instances": instances,
	})
}

// getWarmInstance handles GET /api/warmpool/instances/{name}
func (h *Handler) getWarmInstance(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	instance, err := h.manager.GetWarmInstance(name)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.jsonResponse(w, instance)
}

// releaseInstance handles POST /api/warmpool/instances/{id}/release
func (h *Handler) releaseInstance(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := h.manager.ReleaseInstance(id); err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": "Instance released",
	})
}

// GetPoolStats handles GET /api/warmpool/stats
func (h *Handler) GetPoolStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.manager.GetPoolStats()
	h.jsonResponse(w, stats)
}

// ExportWarmPool handles GET /api/warmpool/export
func (h *Handler) ExportWarmPool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	exported := h.manager.Export()
	h.jsonResponse(w, exported)
}

// Prebuild handlers

// RegisterPrebuild handles POST /api/prebuild/specs
func (h *Handler) RegisterPrebuild(w http.ResponseWriter, r *http.Request) {
	var spec PrebuildSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.prebuildMgr.RegisterPrebuild(&spec); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.logger.Info("prebuild spec registered via API", logging.Fields{
		"function_name": spec.FunctionName,
	})

	h.jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": "Prebuild spec registered",
		"spec":    spec,
	})
}

// ListPrebuildSpecs handles GET /api/prebuild/specs
func (h *Handler) ListPrebuildSpecs(w http.ResponseWriter, r *http.Request) {
	h.prebuildMgr.mu.RLock()
	specs := make([]*PrebuildSpec, 0, len(h.prebuildMgr.specs))
	for _, spec := range h.prebuildMgr.specs {
		specs = append(specs, spec)
	}
	h.prebuildMgr.mu.RUnlock()

	h.jsonResponse(w, map[string]interface{}{
		"specs": specs,
		"count": len(specs),
	})
}

// getPrebuildSpec handles GET /api/prebuild/specs/{name}
func (h *Handler) getPrebuildSpec(w http.ResponseWriter, r *http.Request, name string) {
	h.prebuildMgr.mu.RLock()
	spec, exists := h.prebuildMgr.specs[name]
	h.prebuildMgr.mu.RUnlock()

	if !exists {
		h.jsonError(w, "Prebuild spec not found", http.StatusNotFound)
		return
	}

	h.jsonResponse(w, spec)
}

// triggerBuild handles POST /api/prebuild/trigger/{name}
func (h *Handler) triggerBuild(w http.ResponseWriter, r *http.Request, name string) {
	record, err := h.prebuildMgr.TriggerBuild(r.Context(), name, BuildTriggerAPI)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.logger.Info("prebuild triggered via API", logging.Fields{
		"function_name": name,
		"build_id":      record.ID,
	})

	h.jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": "Build triggered",
		"build":   record,
	})
}

// ListBuilds handles GET /api/prebuild/builds
func (h *Handler) ListBuilds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	functionName := r.URL.Query().Get("function")
	builds := h.prebuildMgr.ListBuilds(functionName)

	h.jsonResponse(w, map[string]interface{}{
		"builds": builds,
		"count":  len(builds),
	})
}

// getBuild handles GET /api/prebuild/builds/{id}
func (h *Handler) getBuild(w http.ResponseWriter, r *http.Request, id string) {
	build, err := h.prebuildMgr.GetBuild(id)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.jsonResponse(w, build)
}

// getLatestImage handles GET /api/prebuild/images/{name}/latest
func (h *Handler) getLatestImage(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	image, err := h.prebuildMgr.GetLatestImage(name)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.jsonResponse(w, image)
}

// getImageByDigest handles GET /api/prebuild/images/{name}/{digest}
func (h *Handler) getImageByDigest(w http.ResponseWriter, r *http.Request, name, digest string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	image, err := h.prebuildMgr.GetImageByDigest(name, digest)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.jsonResponse(w, image)
}

// RecordImage handles POST /api/prebuild/images
func (h *Handler) RecordImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var image PrebuiltImage
	if err := json.NewDecoder(r.Body).Decode(&image); err != nil {
		h.jsonError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.prebuildMgr.RecordImage(&image); err != nil {
		h.jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	h.jsonResponse(w, map[string]interface{}{
		"success": true,
		"message": "Image recorded",
		"image":   image,
	})
}

// getWorkflowBuildConfig handles GET /api/prebuild/workflow/{name}
func (h *Handler) getWorkflowBuildConfig(w http.ResponseWriter, r *http.Request, name string) {
	config, err := h.prebuildMgr.GenerateWorkflowBuildStep(name)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.jsonResponse(w, config)
}

// getDispatchPayload handles GET /api/prebuild/dispatch/{name}
func (h *Handler) getDispatchPayload(w http.ResponseWriter, r *http.Request, name string) {
	depHash := r.URL.Query().Get("dependency_hash")
	payload, err := h.prebuildMgr.GenerateDispatchPayload(name, depHash)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	h.jsonResponse(w, payload)
}

// GetPrebuildStats handles GET /api/prebuild/stats
func (h *Handler) GetPrebuildStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.prebuildMgr.GetStats()
	h.jsonResponse(w, stats)
}

// ExportPrebuild handles GET /api/prebuild/export
func (h *Handler) ExportPrebuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	exported := h.prebuildMgr.Export()
	h.jsonResponse(w, exported)
}

// Helper methods

func (h *Handler) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (h *Handler) jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   true,
		"message": message,
	})
}

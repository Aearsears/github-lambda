package versioning

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/github-lambda/pkg/logging"
)

// HTTPHandler provides HTTP handlers for version and alias management.
type HTTPHandler struct {
	manager *Manager
	logger  *logging.Logger
}

// NewHTTPHandler creates a new HTTP handler.
func NewHTTPHandler(manager *Manager) *HTTPHandler {
	return &HTTPHandler{
		manager: manager,
		logger:  logging.New("versioning-api"),
	}
}

// RegisterRoutes registers all versioning routes.
func (h *HTTPHandler) RegisterRoutes(mux *http.ServeMux) {
	// Function management
	mux.HandleFunc("/functions", h.handleFunctions)
	mux.HandleFunc("/functions/", h.handleFunction)

	// Version management
	mux.HandleFunc("/versions/", h.handleVersions)

	// Alias management
	mux.HandleFunc("/aliases/", h.handleAliases)
}

// handleFunctions handles GET /functions (list) and POST /functions (create)
func (h *HTTPHandler) handleFunctions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listFunctions(w, r)
	case http.MethodPost:
		h.createFunction(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFunction handles /functions/{name}/* routes
func (h *HTTPHandler) handleFunction(w http.ResponseWriter, r *http.Request) {
	// Parse path: /functions/{name} or /functions/{name}/versions or /functions/{name}/aliases
	path := strings.TrimPrefix(r.URL.Path, "/functions/")
	parts := strings.SplitN(path, "/", 2)
	functionName := parts[0]

	if functionName == "" {
		http.Error(w, "Function name required", http.StatusBadRequest)
		return
	}

	// If there's a subpath, route to specific handler
	if len(parts) > 1 {
		subpath := parts[1]
		switch {
		case subpath == "versions":
			h.handleFunctionVersions(w, r, functionName)
		case strings.HasPrefix(subpath, "versions/"):
			versionStr := strings.TrimPrefix(subpath, "versions/")
			h.handleFunctionVersion(w, r, functionName, versionStr)
		case subpath == "aliases":
			h.handleFunctionAliases(w, r, functionName)
		case strings.HasPrefix(subpath, "aliases/"):
			aliasName := strings.TrimPrefix(subpath, "aliases/")
			h.handleFunctionAlias(w, r, functionName, aliasName)
		default:
			http.Error(w, "Not found", http.StatusNotFound)
		}
		return
	}

	// Handle /functions/{name}
	switch r.Method {
	case http.MethodGet:
		h.getFunction(w, r, functionName)
	case http.MethodPut:
		h.updateFunction(w, r, functionName)
	case http.MethodDelete:
		h.deleteFunction(w, r, functionName)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleVersions handles /versions/{function}:{version} routes
func (h *HTTPHandler) handleVersions(w http.ResponseWriter, r *http.Request) {
	// Parse path: /versions/{function}:{version}
	path := strings.TrimPrefix(r.URL.Path, "/versions/")
	parts := strings.SplitN(path, ":", 2)

	if len(parts) != 2 {
		http.Error(w, "Invalid version path. Use /versions/{function}:{version}", http.StatusBadRequest)
		return
	}

	functionName := parts[0]
	versionStr := parts[1]

	h.handleFunctionVersion(w, r, functionName, versionStr)
}

// handleAliases handles /aliases/{function}:{alias} routes
func (h *HTTPHandler) handleAliases(w http.ResponseWriter, r *http.Request) {
	// Parse path: /aliases/{function}:{alias}
	path := strings.TrimPrefix(r.URL.Path, "/aliases/")
	parts := strings.SplitN(path, ":", 2)

	if len(parts) != 2 {
		http.Error(w, "Invalid alias path. Use /aliases/{function}:{alias}", http.StatusBadRequest)
		return
	}

	functionName := parts[0]
	aliasName := parts[1]

	h.handleFunctionAlias(w, r, functionName, aliasName)
}

// Function handlers

func (h *HTTPHandler) listFunctions(w http.ResponseWriter, r *http.Request) {
	functions := h.manager.ListFunctions()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"functions": functions,
	})
}

func (h *HTTPHandler) createFunction(w http.ResponseWriter, r *http.Request) {
	var config FunctionConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.manager.CreateFunction(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(config)
}

func (h *HTTPHandler) getFunction(w http.ResponseWriter, r *http.Request, functionName string) {
	config, err := h.manager.GetFunction(functionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (h *HTTPHandler) updateFunction(w http.ResponseWriter, r *http.Request, functionName string) {
	var config FunctionConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	config.Name = functionName // Ensure name matches path

	if err := h.manager.CreateFunction(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (h *HTTPHandler) deleteFunction(w http.ResponseWriter, r *http.Request, functionName string) {
	if err := h.manager.DeleteFunction(functionName); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Version handlers

func (h *HTTPHandler) handleFunctionVersions(w http.ResponseWriter, r *http.Request, functionName string) {
	switch r.Method {
	case http.MethodGet:
		h.listVersions(w, r, functionName)
	case http.MethodPost:
		h.publishVersion(w, r, functionName)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPHandler) handleFunctionVersion(w http.ResponseWriter, r *http.Request, functionName, versionStr string) {
	version, err := strconv.Atoi(versionStr)
	if err != nil {
		http.Error(w, "Invalid version number", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getVersion(w, r, functionName, version)
	case http.MethodDelete:
		h.deleteVersion(w, r, functionName, version)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPHandler) listVersions(w http.ResponseWriter, r *http.Request, functionName string) {
	versions, err := h.manager.ListVersions(functionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"versions": versions,
	})
}

func (h *HTTPHandler) publishVersion(w http.ResponseWriter, r *http.Request, functionName string) {
	var req struct {
		Description string `json:"description"`
		CodeHash    string `json:"code_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get creator from context if available
	createdBy := "unknown"
	if keyID := r.Context().Value("api_key_id"); keyID != nil {
		createdBy = keyID.(string)
	}

	version, err := h.manager.PublishVersion(functionName, req.Description, req.CodeHash, createdBy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(version)
}

func (h *HTTPHandler) getVersion(w http.ResponseWriter, r *http.Request, functionName string, version int) {
	v, err := h.manager.GetVersion(functionName, version)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (h *HTTPHandler) deleteVersion(w http.ResponseWriter, r *http.Request, functionName string, version int) {
	if err := h.manager.DeleteVersion(functionName, version); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Alias handlers

func (h *HTTPHandler) handleFunctionAliases(w http.ResponseWriter, r *http.Request, functionName string) {
	switch r.Method {
	case http.MethodGet:
		h.listAliases(w, r, functionName)
	case http.MethodPost:
		h.createAlias(w, r, functionName)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPHandler) handleFunctionAlias(w http.ResponseWriter, r *http.Request, functionName, aliasName string) {
	switch r.Method {
	case http.MethodGet:
		h.getAlias(w, r, functionName, aliasName)
	case http.MethodPut:
		h.updateAlias(w, r, functionName, aliasName)
	case http.MethodDelete:
		h.deleteAlias(w, r, functionName, aliasName)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *HTTPHandler) listAliases(w http.ResponseWriter, r *http.Request, functionName string) {
	aliases, err := h.manager.ListAliases(functionName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"aliases": aliases,
	})
}

func (h *HTTPHandler) createAlias(w http.ResponseWriter, r *http.Request, functionName string) {
	var req struct {
		Name          string         `json:"name"`
		Description   string         `json:"description"`
		Version       int            `json:"function_version"`
		RoutingConfig *RoutingConfig `json:"routing_config,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	alias, err := h.manager.CreateAlias(functionName, req.Name, req.Description, req.Version, req.RoutingConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(alias)
}

func (h *HTTPHandler) getAlias(w http.ResponseWriter, r *http.Request, functionName, aliasName string) {
	alias, err := h.manager.GetAlias(functionName, aliasName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alias)
}

func (h *HTTPHandler) updateAlias(w http.ResponseWriter, r *http.Request, functionName, aliasName string) {
	var req struct {
		Description   *string        `json:"description,omitempty"`
		Version       *int           `json:"function_version,omitempty"`
		RoutingConfig *RoutingConfig `json:"routing_config,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	alias, err := h.manager.UpdateAlias(functionName, aliasName, req.Version, req.Description, req.RoutingConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alias)
}

func (h *HTTPHandler) deleteAlias(w http.ResponseWriter, r *http.Request, functionName, aliasName string) {
	if err := h.manager.DeleteAlias(functionName, aliasName); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

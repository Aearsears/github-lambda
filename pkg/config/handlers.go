package config

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/github-lambda/pkg/logging"
)

var handlerLogger = logging.New("config-handlers")

// Handlers provides HTTP handlers for configuration management.
type Handlers struct {
	manager *Manager
}

// NewHandlers creates new configuration handlers.
func NewHandlers(manager *Manager) *Handlers {
	return &Handlers{manager: manager}
}

// ListFunctionsHandler returns all configured functions.
func (h *Handlers) ListFunctionsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		functions := h.manager.ListFunctions()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"functions": functions,
			"count":     len(functions),
		})
	}
}

// GetConfigHandler returns a function's configuration.
func (h *Handlers) GetConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		functionName := r.URL.Query().Get("function")
		if functionName == "" {
			// Extract from path: /config/functions/{name}
			parts := strings.Split(r.URL.Path, "/")
			if len(parts) >= 4 {
				functionName = parts[3]
			}
		}

		if functionName == "" {
			// Return global config export
			exported := h.manager.Export()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(exported)
			return
		}

		config, err := h.manager.GetFunctionConfig(functionName)
		if err != nil {
			http.Error(w, `{"error": "function not found"}`, http.StatusNotFound)
			return
		}

		// Return sanitized config
		exported := &ExportedFunctionConfig{
			FunctionName: config.FunctionName,
			EnvVars:      make(map[string]*ExportedEnvVar),
			Inherit:      config.Inherit,
			CreatedAt:    config.CreatedAt,
			UpdatedAt:    config.UpdatedAt,
			Version:      config.Version,
		}
		for name, envVar := range config.EnvVars {
			exported.EnvVars[name] = exportEnvVar(envVar)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(exported)
	}
}

// SetEnvVarRequest represents a request to set an environment variable.
type SetEnvVarRequest struct {
	FunctionName string `json:"function_name"`
	Name         string `json:"name"`
	Value        string `json:"value"`
	IsSecret     bool   `json:"is_secret"`
	Description  string `json:"description,omitempty"`
	Required     bool   `json:"required,omitempty"`
	Sensitive    bool   `json:"sensitive,omitempty"`
}

// SetEnvVarHandler sets an environment variable.
func (h *Handlers) SetEnvVarHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req SetEnvVarRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
			return
		}

		if req.FunctionName == "" || req.Name == "" {
			http.Error(w, `{"error": "function_name and name are required"}`, http.StatusBadRequest)
			return
		}

		var opts []EnvVarOption
		if req.Description != "" {
			opts = append(opts, WithDescription(req.Description))
		}
		if req.Required {
			opts = append(opts, WithRequired())
		}
		if req.Sensitive {
			opts = append(opts, WithSensitive())
		}

		if req.IsSecret {
			if err := h.manager.SetSecret(req.FunctionName, req.Name, req.Value); err != nil {
				handlerLogger.Error("failed to set secret", logging.Fields{
					"function_name": req.FunctionName,
					"name":          req.Name,
					"error":         err.Error(),
				})
				http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
				return
			}
		} else {
			if err := h.manager.SetEnvVar(req.FunctionName, req.Name, req.Value, opts...); err != nil {
				handlerLogger.Error("failed to set env var", logging.Fields{
					"function_name": req.FunctionName,
					"name":          req.Name,
					"error":         err.Error(),
				})
				http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
				return
			}
		}

		handlerLogger.Info("env var set via API", logging.Fields{
			"function_name": req.FunctionName,
			"name":          req.Name,
			"is_secret":     req.IsSecret,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":       "environment variable set",
			"function_name": req.FunctionName,
			"name":          req.Name,
			"is_secret":     req.IsSecret,
		})
	}
}

// SetSecretRefRequest represents a request to set a secret reference.
type SetSecretRefRequest struct {
	FunctionName string       `json:"function_name"`
	Name         string       `json:"name"`
	Source       SecretSource `json:"source"`
	Key          string       `json:"key"`
	Version      string       `json:"version,omitempty"`
	Field        string       `json:"field,omitempty"`
}

// SetSecretRefHandler sets a secret reference.
func (h *Handlers) SetSecretRefHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req SetSecretRefRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
			return
		}

		if req.FunctionName == "" || req.Name == "" || req.Source == "" || req.Key == "" {
			http.Error(w, `{"error": "function_name, name, source, and key are required"}`, http.StatusBadRequest)
			return
		}

		ref := &SecretReference{
			Source:  req.Source,
			Key:     req.Key,
			Version: req.Version,
			Field:   req.Field,
		}

		if err := h.manager.SetSecretRef(req.FunctionName, req.Name, ref); err != nil {
			handlerLogger.Error("failed to set secret ref", logging.Fields{
				"function_name": req.FunctionName,
				"name":          req.Name,
				"error":         err.Error(),
			})
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		handlerLogger.Info("secret ref set via API", logging.Fields{
			"function_name": req.FunctionName,
			"name":          req.Name,
			"source":        req.Source,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":       "secret reference set",
			"function_name": req.FunctionName,
			"name":          req.Name,
			"source":        req.Source,
		})
	}
}

// DeleteEnvVarHandler deletes an environment variable.
func (h *Handlers) DeleteEnvVarHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		functionName := r.URL.Query().Get("function")
		name := r.URL.Query().Get("name")

		if functionName == "" || name == "" {
			http.Error(w, `{"error": "function and name query parameters required"}`, http.StatusBadRequest)
			return
		}

		if err := h.manager.DeleteEnvVar(functionName, name); err != nil {
			if err == ErrFunctionNotFound {
				http.Error(w, `{"error": "function not found"}`, http.StatusNotFound)
				return
			}
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		handlerLogger.Info("env var deleted via API", logging.Fields{
			"function_name": functionName,
			"name":          name,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":       "environment variable deleted",
			"function_name": functionName,
			"name":          name,
		})
	}
}

// SetGlobalEnvVarRequest represents a request to set a global environment variable.
type SetGlobalEnvVarRequest struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	IsSecret    bool   `json:"is_secret"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Sensitive   bool   `json:"sensitive,omitempty"`
}

// SetGlobalEnvVarHandler sets a global environment variable.
func (h *Handlers) SetGlobalEnvVarHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req SetGlobalEnvVarRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			http.Error(w, `{"error": "name is required"}`, http.StatusBadRequest)
			return
		}

		var opts []EnvVarOption
		if req.Description != "" {
			opts = append(opts, WithDescription(req.Description))
		}
		if req.Required {
			opts = append(opts, WithRequired())
		}
		if req.Sensitive || req.IsSecret {
			opts = append(opts, WithSensitive())
		}

		if err := h.manager.SetGlobalEnvVar(req.Name, req.Value, opts...); err != nil {
			handlerLogger.Error("failed to set global env var", logging.Fields{
				"name":  req.Name,
				"error": err.Error(),
			})
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		handlerLogger.Info("global env var set via API", logging.Fields{
			"name":      req.Name,
			"is_secret": req.IsSecret,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":   "global environment variable set",
			"name":      req.Name,
			"is_secret": req.IsSecret,
		})
	}
}

// ValidateConfigHandler validates a function's configuration.
func (h *Handlers) ValidateConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		functionName := r.URL.Query().Get("function")
		if functionName == "" {
			http.Error(w, `{"error": "function query parameter required"}`, http.StatusBadRequest)
			return
		}

		errors := h.manager.ValidateConfig(functionName)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"function_name": functionName,
			"valid":         len(errors) == 0,
			"errors":        errors,
			"validated_at":  time.Now(),
		})
	}
}

// ExportConfigHandler exports the entire configuration.
func (h *Handlers) ExportConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		exported := h.manager.Export()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Export-Time", time.Now().Format(time.RFC3339))
		json.NewEncoder(w).Encode(exported)
	}
}

// ClearCacheHandler clears the secret cache.
func (h *Handlers) ClearCacheHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		h.manager.ClearSecretCache()

		handlerLogger.Info("secret cache cleared via API", nil)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":    "secret cache cleared",
			"cleared_at": time.Now(),
		})
	}
}

// CreateFunctionConfigRequest represents a request to create a function configuration.
type CreateFunctionConfigRequest struct {
	FunctionName string   `json:"function_name"`
	Inherit      []string `json:"inherit,omitempty"`
}

// CreateFunctionConfigHandler creates a new function configuration.
func (h *Handlers) CreateFunctionConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req CreateFunctionConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
			return
		}

		if req.FunctionName == "" {
			http.Error(w, `{"error": "function_name is required"}`, http.StatusBadRequest)
			return
		}

		// Check if config already exists
		if _, err := h.manager.GetFunctionConfig(req.FunctionName); err == nil {
			http.Error(w, `{"error": "function configuration already exists"}`, http.StatusConflict)
			return
		}

		config := h.manager.CreateFunctionConfig(req.FunctionName)
		if len(req.Inherit) > 0 {
			config.Inherit = req.Inherit
		}

		handlerLogger.Info("function config created via API", logging.Fields{
			"function_name": req.FunctionName,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":       "function configuration created",
			"function_name": req.FunctionName,
			"created_at":    config.CreatedAt,
		})
	}
}

// DeleteFunctionConfigHandler deletes a function's configuration.
func (h *Handlers) DeleteFunctionConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		functionName := r.URL.Query().Get("function")
		if functionName == "" {
			// Extract from path
			parts := strings.Split(r.URL.Path, "/")
			if len(parts) >= 4 {
				functionName = parts[3]
			}
		}

		if functionName == "" {
			http.Error(w, `{"error": "function parameter required"}`, http.StatusBadRequest)
			return
		}

		if err := h.manager.DeleteFunctionConfig(functionName); err != nil {
			if err == ErrFunctionNotFound {
				http.Error(w, `{"error": "function not found"}`, http.StatusNotFound)
				return
			}
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		handlerLogger.Info("function config deleted via API", logging.Fields{
			"function_name": functionName,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":       "function configuration deleted",
			"function_name": functionName,
		})
	}
}

// SetInheritanceRequest represents a request to set inheritance.
type SetInheritanceRequest struct {
	FunctionName string   `json:"function_name"`
	Parents      []string `json:"parents"`
}

// SetInheritanceHandler sets the inheritance chain for a function.
func (h *Handlers) SetInheritanceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req SetInheritanceRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
			return
		}

		if req.FunctionName == "" {
			http.Error(w, `{"error": "function_name is required"}`, http.StatusBadRequest)
			return
		}

		if err := h.manager.SetInheritance(req.FunctionName, req.Parents); err != nil {
			if err == ErrFunctionNotFound {
				http.Error(w, `{"error": "function not found"}`, http.StatusNotFound)
				return
			}
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}

		handlerLogger.Info("inheritance set via API", logging.Fields{
			"function_name": req.FunctionName,
			"parents":       req.Parents,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":       "inheritance updated",
			"function_name": req.FunctionName,
			"parents":       req.Parents,
		})
	}
}

// GetInheritanceChainHandler returns the inheritance chain for a function.
func (h *Handlers) GetInheritanceChainHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		functionName := r.URL.Query().Get("function")
		if functionName == "" {
			http.Error(w, `{"error": "function query parameter required"}`, http.StatusBadRequest)
			return
		}

		chain, err := h.manager.GetInheritanceChain(functionName)
		if err != nil {
			if err == ErrFunctionNotFound {
				http.Error(w, `{"error": "function not found"}`, http.StatusNotFound)
				return
			}
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"function_name":     functionName,
			"inheritance_chain": chain,
		})
	}
}

// AdvancedValidateHandler performs comprehensive validation with options.
func (h *Handlers) AdvancedValidateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		functionName := r.URL.Query().Get("function")
		if functionName == "" {
			http.Error(w, `{"error": "function query parameter required"}`, http.StatusBadRequest)
			return
		}

		// Parse validation options from query params or body
		opts := DefaultValidationOptions()

		if r.URL.Query().Get("strict") == "true" {
			opts.StrictMode = true
		}
		if r.URL.Query().Get("validate_secrets") == "true" {
			opts.ValidateSecrets = true
		}
		if r.URL.Query().Get("resolve_env_vars") == "false" {
			opts.ResolveEnvVars = false
		}

		// Parse required/forbidden vars from query
		if required := r.URL.Query().Get("required_vars"); required != "" {
			opts.RequiredEnvVars = strings.Split(required, ",")
		}
		if forbidden := r.URL.Query().Get("forbidden_vars"); forbidden != "" {
			opts.ForbiddenEnvVars = strings.Split(forbidden, ",")
		}

		validator := NewValidator(h.manager)
		result := validator.Validate(functionName, opts)

		w.Header().Set("Content-Type", "application/json")
		if !result.Valid {
			w.WriteHeader(http.StatusUnprocessableEntity)
		}
		json.NewEncoder(w).Encode(result)
	}
}

// DeploymentReadinessHandler checks if a function is ready for deployment.
func (h *Handlers) DeploymentReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		functionName := r.URL.Query().Get("function")
		if functionName == "" {
			http.Error(w, `{"error": "function query parameter required"}`, http.StatusBadRequest)
			return
		}

		validator := NewValidator(h.manager)
		readiness := validator.CheckDeploymentReadiness(r.Context(), functionName)

		w.Header().Set("Content-Type", "application/json")
		if !readiness.Ready {
			w.WriteHeader(http.StatusUnprocessableEntity)
		}
		json.NewEncoder(w).Encode(readiness)
	}
}

// ValidateAllHandler validates all configured functions.
func (h *Handlers) ValidateAllHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		opts := DefaultValidationOptions()
		if r.URL.Query().Get("strict") == "true" {
			opts.StrictMode = true
		}

		validator := NewValidator(h.manager)
		results := validator.ValidateAll(opts)

		// Build summary
		allValid := true
		totalErrors := 0
		totalWarnings := 0

		for _, result := range results {
			if !result.Valid {
				allValid = false
			}
			totalErrors += result.Summary.Errors
			totalWarnings += result.Summary.Warnings
		}

		w.Header().Set("Content-Type", "application/json")
		if !allValid {
			w.WriteHeader(http.StatusUnprocessableEntity)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"all_valid":      allValid,
			"total_errors":   totalErrors,
			"total_warnings": totalWarnings,
			"functions":      results,
			"validated_at":   time.Now(),
		})
	}
}

// ResolveEnvVarsHandler returns the fully resolved environment variables for a function.
func (h *Handlers) ResolveEnvVarsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		functionName := r.URL.Query().Get("function")
		if functionName == "" {
			http.Error(w, `{"error": "function query parameter required"}`, http.StatusBadRequest)
			return
		}

		// Get the inheritance chain
		chain, err := h.manager.GetInheritanceChain(functionName)
		if err != nil {
			if err == ErrFunctionNotFound {
				http.Error(w, `{"error": "function not found"}`, http.StatusNotFound)
				return
			}
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		// Build the resolved view using the validator
		validator := NewValidator(h.manager)
		resolved := validator.resolveAllEnvVars(functionName, chain)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"function_name":     functionName,
			"inheritance_chain": chain,
			"resolved_vars":     resolved,
			"total_vars":        len(resolved),
			"resolved_at":       time.Now(),
		})
	}
}

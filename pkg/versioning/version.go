package versioning

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/github-lambda/pkg/logging"
)

// Version represents an immutable version of a function.
type Version struct {
	FunctionName string            `json:"function_name"`
	Version      int               `json:"version"`
	Description  string            `json:"description,omitempty"`
	CodeHash     string            `json:"code_hash,omitempty"`
	Runtime      string            `json:"runtime,omitempty"`
	Handler      string            `json:"handler,omitempty"`
	Timeout      int               `json:"timeout_seconds,omitempty"`
	MemorySize   int               `json:"memory_size_mb,omitempty"`
	Environment  map[string]string `json:"environment,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	CreatedBy    string            `json:"created_by,omitempty"`
}

// VersionID returns the unique identifier for this version.
func (v *Version) VersionID() string {
	return fmt.Sprintf("%s:%d", v.FunctionName, v.Version)
}

// Alias represents a named pointer to a specific function version.
type Alias struct {
	FunctionName    string         `json:"function_name"`
	Name            string         `json:"name"`
	Description     string         `json:"description,omitempty"`
	FunctionVersion int            `json:"function_version"`
	RoutingConfig   *RoutingConfig `json:"routing_config,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// AliasID returns the unique identifier for this alias.
func (a *Alias) AliasID() string {
	return fmt.Sprintf("%s:%s", a.FunctionName, a.Name)
}

// RoutingConfig allows traffic splitting between versions for canary deployments.
type RoutingConfig struct {
	// AdditionalVersionWeights maps version numbers to traffic weights (0.0-1.0)
	// The primary version gets the remaining traffic
	AdditionalVersionWeights map[int]float64 `json:"additional_version_weights,omitempty"`
}

// FunctionConfig represents the configuration for a function that can be versioned.
type FunctionConfig struct {
	Name          string            `json:"name"`
	Description   string            `json:"description,omitempty"`
	Runtime       string            `json:"runtime,omitempty"`
	Handler       string            `json:"handler,omitempty"`
	Timeout       int               `json:"timeout_seconds,omitempty"`
	MemorySize    int               `json:"memory_size_mb,omitempty"`
	Environment   map[string]string `json:"environment,omitempty"`
	LatestVersion int               `json:"latest_version"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// Manager manages function versions and aliases.
type Manager struct {
	mu        sync.RWMutex
	functions map[string]*FunctionConfig   // functionName -> config
	versions  map[string]map[int]*Version  // functionName -> version -> Version
	aliases   map[string]map[string]*Alias // functionName -> aliasName -> Alias
	logger    *logging.Logger
}

// NewManager creates a new versioning manager.
func NewManager() *Manager {
	return &Manager{
		functions: make(map[string]*FunctionConfig),
		versions:  make(map[string]map[int]*Version),
		aliases:   make(map[string]map[string]*Alias),
		logger:    logging.New("versioning"),
	}
}

// CreateFunction creates or updates a function configuration.
func (m *Manager) CreateFunction(config *FunctionConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if config.Name == "" {
		return fmt.Errorf("function name is required")
	}

	if existing, ok := m.functions[config.Name]; ok {
		// Update existing function
		existing.Description = config.Description
		existing.Runtime = config.Runtime
		existing.Handler = config.Handler
		existing.Timeout = config.Timeout
		existing.MemorySize = config.MemorySize
		existing.Environment = config.Environment
		existing.UpdatedAt = time.Now()
	} else {
		// Create new function
		config.LatestVersion = 0
		config.UpdatedAt = time.Now()
		m.functions[config.Name] = config
		m.versions[config.Name] = make(map[int]*Version)
		m.aliases[config.Name] = make(map[string]*Alias)
	}

	m.logger.Info("function configuration updated", logging.Fields{
		"function_name": config.Name,
	})

	return nil
}

// PublishVersion creates a new immutable version of a function.
func (m *Manager) PublishVersion(functionName, description, codeHash, createdBy string) (*Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	config, ok := m.functions[functionName]
	if !ok {
		return nil, fmt.Errorf("function not found: %s", functionName)
	}

	// Increment version number
	newVersion := config.LatestVersion + 1
	config.LatestVersion = newVersion
	config.UpdatedAt = time.Now()

	version := &Version{
		FunctionName: functionName,
		Version:      newVersion,
		Description:  description,
		CodeHash:     codeHash,
		Runtime:      config.Runtime,
		Handler:      config.Handler,
		Timeout:      config.Timeout,
		MemorySize:   config.MemorySize,
		Environment:  copyEnv(config.Environment),
		CreatedAt:    time.Now(),
		CreatedBy:    createdBy,
	}

	m.versions[functionName][newVersion] = version

	m.logger.Info("version published", logging.Fields{
		"function_name": functionName,
		"version":       newVersion,
	})

	return version, nil
}

// GetVersion retrieves a specific version of a function.
func (m *Manager) GetVersion(functionName string, version int) (*Version, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versions, ok := m.versions[functionName]
	if !ok {
		return nil, fmt.Errorf("function not found: %s", functionName)
	}

	v, ok := versions[version]
	if !ok {
		return nil, fmt.Errorf("version not found: %s:%d", functionName, version)
	}

	return v, nil
}

// ListVersions lists all versions of a function.
func (m *Manager) ListVersions(functionName string) ([]*Version, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versions, ok := m.versions[functionName]
	if !ok {
		return nil, fmt.Errorf("function not found: %s", functionName)
	}

	result := make([]*Version, 0, len(versions))
	for _, v := range versions {
		result = append(result, v)
	}

	// Sort by version number descending
	sort.Slice(result, func(i, j int) bool {
		return result[i].Version > result[j].Version
	})

	return result, nil
}

// DeleteVersion deletes a specific version (if not referenced by any alias).
func (m *Manager) DeleteVersion(functionName string, version int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	versions, ok := m.versions[functionName]
	if !ok {
		return fmt.Errorf("function not found: %s", functionName)
	}

	if _, ok := versions[version]; !ok {
		return fmt.Errorf("version not found: %s:%d", functionName, version)
	}

	// Check if any alias references this version
	for _, alias := range m.aliases[functionName] {
		if alias.FunctionVersion == version {
			return fmt.Errorf("cannot delete version %d: referenced by alias '%s'", version, alias.Name)
		}
		if alias.RoutingConfig != nil {
			for v := range alias.RoutingConfig.AdditionalVersionWeights {
				if v == version {
					return fmt.Errorf("cannot delete version %d: referenced in routing config of alias '%s'", version, alias.Name)
				}
			}
		}
	}

	delete(versions, version)

	m.logger.Info("version deleted", logging.Fields{
		"function_name": functionName,
		"version":       version,
	})

	return nil
}

// CreateAlias creates a new alias for a function.
func (m *Manager) CreateAlias(functionName, aliasName, description string, version int, routing *RoutingConfig) (*Alias, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if aliasName == "" {
		return nil, fmt.Errorf("alias name is required")
	}

	// Validate reserved alias names
	if aliasName == "$LATEST" {
		return nil, fmt.Errorf("'$LATEST' is a reserved alias name")
	}

	aliases, ok := m.aliases[functionName]
	if !ok {
		return nil, fmt.Errorf("function not found: %s", functionName)
	}

	// Verify version exists
	if _, ok := m.versions[functionName][version]; !ok {
		return nil, fmt.Errorf("version not found: %s:%d", functionName, version)
	}

	// Validate routing config versions exist
	if routing != nil {
		for v := range routing.AdditionalVersionWeights {
			if _, ok := m.versions[functionName][v]; !ok {
				return nil, fmt.Errorf("routing version not found: %s:%d", functionName, v)
			}
		}
	}

	if _, exists := aliases[aliasName]; exists {
		return nil, fmt.Errorf("alias already exists: %s:%s", functionName, aliasName)
	}

	now := time.Now()
	alias := &Alias{
		FunctionName:    functionName,
		Name:            aliasName,
		Description:     description,
		FunctionVersion: version,
		RoutingConfig:   routing,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	aliases[aliasName] = alias

	m.logger.Info("alias created", logging.Fields{
		"function_name": functionName,
		"alias":         aliasName,
		"version":       version,
	})

	return alias, nil
}

// UpdateAlias updates an existing alias.
func (m *Manager) UpdateAlias(functionName, aliasName string, version *int, description *string, routing *RoutingConfig) (*Alias, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	aliases, ok := m.aliases[functionName]
	if !ok {
		return nil, fmt.Errorf("function not found: %s", functionName)
	}

	alias, ok := aliases[aliasName]
	if !ok {
		return nil, fmt.Errorf("alias not found: %s:%s", functionName, aliasName)
	}

	if version != nil {
		// Verify new version exists
		if _, ok := m.versions[functionName][*version]; !ok {
			return nil, fmt.Errorf("version not found: %s:%d", functionName, *version)
		}
		alias.FunctionVersion = *version
	}

	if description != nil {
		alias.Description = *description
	}

	if routing != nil {
		// Validate routing config versions exist
		for v := range routing.AdditionalVersionWeights {
			if _, ok := m.versions[functionName][v]; !ok {
				return nil, fmt.Errorf("routing version not found: %s:%d", functionName, v)
			}
		}
		alias.RoutingConfig = routing
	}

	alias.UpdatedAt = time.Now()

	m.logger.Info("alias updated", logging.Fields{
		"function_name": functionName,
		"alias":         aliasName,
		"version":       alias.FunctionVersion,
	})

	return alias, nil
}

// GetAlias retrieves a specific alias.
func (m *Manager) GetAlias(functionName, aliasName string) (*Alias, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	aliases, ok := m.aliases[functionName]
	if !ok {
		return nil, fmt.Errorf("function not found: %s", functionName)
	}

	alias, ok := aliases[aliasName]
	if !ok {
		return nil, fmt.Errorf("alias not found: %s:%s", functionName, aliasName)
	}

	return alias, nil
}

// ListAliases lists all aliases for a function.
func (m *Manager) ListAliases(functionName string) ([]*Alias, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	aliases, ok := m.aliases[functionName]
	if !ok {
		return nil, fmt.Errorf("function not found: %s", functionName)
	}

	result := make([]*Alias, 0, len(aliases))
	for _, a := range aliases {
		result = append(result, a)
	}

	// Sort by name
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result, nil
}

// DeleteAlias deletes an alias.
func (m *Manager) DeleteAlias(functionName, aliasName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	aliases, ok := m.aliases[functionName]
	if !ok {
		return fmt.Errorf("function not found: %s", functionName)
	}

	if _, ok := aliases[aliasName]; !ok {
		return fmt.Errorf("alias not found: %s:%s", functionName, aliasName)
	}

	delete(aliases, aliasName)

	m.logger.Info("alias deleted", logging.Fields{
		"function_name": functionName,
		"alias":         aliasName,
	})

	return nil
}

// GetFunction retrieves a function configuration.
func (m *Manager) GetFunction(functionName string) (*FunctionConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	config, ok := m.functions[functionName]
	if !ok {
		return nil, fmt.Errorf("function not found: %s", functionName)
	}

	return config, nil
}

// ListFunctions lists all registered functions.
func (m *Manager) ListFunctions() []*FunctionConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*FunctionConfig, 0, len(m.functions))
	for _, f := range m.functions {
		result = append(result, f)
	}

	// Sort by name
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result
}

// DeleteFunction deletes a function and all its versions and aliases.
func (m *Manager) DeleteFunction(functionName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.functions[functionName]; !ok {
		return fmt.Errorf("function not found: %s", functionName)
	}

	delete(m.functions, functionName)
	delete(m.versions, functionName)
	delete(m.aliases, functionName)

	m.logger.Info("function deleted", logging.Fields{
		"function_name": functionName,
	})

	return nil
}

// SaveToFile saves the versioning state to a JSON file.
func (m *Manager) SaveToFile(path string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state := struct {
		Functions map[string]*FunctionConfig   `json:"functions"`
		Versions  map[string]map[int]*Version  `json:"versions"`
		Aliases   map[string]map[string]*Alias `json:"aliases"`
	}{
		Functions: m.functions,
		Versions:  m.versions,
		Aliases:   m.aliases,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// LoadFromFile loads the versioning state from a JSON file.
func (m *Manager) LoadFromFile(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var state struct {
		Functions map[string]*FunctionConfig   `json:"functions"`
		Versions  map[string]map[int]*Version  `json:"versions"`
		Aliases   map[string]map[string]*Alias `json:"aliases"`
	}

	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("failed to unmarshal state: %w", err)
	}

	if state.Functions != nil {
		m.functions = state.Functions
	}
	if state.Versions != nil {
		m.versions = state.Versions
	}
	if state.Aliases != nil {
		m.aliases = state.Aliases
	}

	m.logger.Info("versioning state loaded", logging.Fields{
		"path":      path,
		"functions": len(m.functions),
	})

	return nil
}

// copyEnv creates a copy of an environment map.
func copyEnv(env map[string]string) map[string]string {
	if env == nil {
		return nil
	}
	copy := make(map[string]string, len(env))
	for k, v := range env {
		copy[k] = v
	}
	return copy
}

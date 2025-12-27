package warmpool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/github-lambda/pkg/logging"
)

var logger = logging.New("warmpool")

// Common errors
var (
	ErrFunctionNotFound    = errors.New("function not found in warm pool")
	ErrArtifactNotFound    = errors.New("artifact not found")
	ErrCacheKeyNotFound    = errors.New("cache key not found")
	ErrBuildInProgress     = errors.New("build already in progress")
	ErrWarmPoolFull        = errors.New("warm pool at capacity")
	ErrInvalidDependencies = errors.New("invalid dependencies specification")
)

// Runtime represents a supported function runtime.
type Runtime string

const (
	RuntimePython Runtime = "python"
	RuntimeNode   Runtime = "node"
	RuntimeGo     Runtime = "go"
	RuntimeJava   Runtime = "java"
	RuntimeRuby   Runtime = "ruby"
	RuntimeRust   Runtime = "rust"
	RuntimeDotNet Runtime = "dotnet"
	RuntimeCustom Runtime = "custom"
)

// DependencyManager represents the package manager for a runtime.
type DependencyManager string

const (
	DepManagerPip     DependencyManager = "pip"
	DepManagerNpm     DependencyManager = "npm"
	DepManagerYarn    DependencyManager = "yarn"
	DepManagerPnpm    DependencyManager = "pnpm"
	DepManagerGoMod   DependencyManager = "go-mod"
	DepManagerMaven   DependencyManager = "maven"
	DepManagerGradle  DependencyManager = "gradle"
	DepManagerBundler DependencyManager = "bundler"
	DepManagerCargo   DependencyManager = "cargo"
	DepManagerNuGet   DependencyManager = "nuget"
)

// FunctionSpec defines a function's build and runtime configuration.
type FunctionSpec struct {
	// Name is the unique identifier for the function.
	Name string `json:"name"`

	// Runtime is the function's runtime environment.
	Runtime Runtime `json:"runtime"`

	// RuntimeVersion is the specific version of the runtime (e.g., "3.11", "20").
	RuntimeVersion string `json:"runtime_version,omitempty"`

	// DependencyManager specifies how to manage dependencies.
	DependencyManager DependencyManager `json:"dependency_manager,omitempty"`

	// DependencyFile is the path to the dependency manifest (e.g., requirements.txt).
	DependencyFile string `json:"dependency_file,omitempty"`

	// LockFile is the path to the lock file (e.g., package-lock.json).
	LockFile string `json:"lock_file,omitempty"`

	// BuildCommand is a custom build command to run.
	BuildCommand string `json:"build_command,omitempty"`

	// CacheKey is a custom cache key (auto-generated if empty).
	CacheKey string `json:"cache_key,omitempty"`

	// CachePaths are additional paths to cache beyond dependencies.
	CachePaths []string `json:"cache_paths,omitempty"`

	// PrewarmInstances is the number of instances to keep warm.
	PrewarmInstances int `json:"prewarm_instances,omitempty"`

	// IdleTimeout is how long to keep warm instances alive.
	IdleTimeout time.Duration `json:"idle_timeout,omitempty"`

	// ContainerImage is a pre-built container image to use.
	ContainerImage string `json:"container_image,omitempty"`

	// Metadata contains additional function metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// CacheStatus represents the state of cached artifacts.
type CacheStatus string

const (
	CacheStatusHit      CacheStatus = "hit"
	CacheStatusMiss     CacheStatus = "miss"
	CacheStatusBuilding CacheStatus = "building"
	CacheStatusExpired  CacheStatus = "expired"
	CacheStatusInvalid  CacheStatus = "invalid"
)

// CachedArtifact represents cached build artifacts for a function.
type CachedArtifact struct {
	// FunctionName is the function this artifact belongs to.
	FunctionName string `json:"function_name"`

	// CacheKey uniquely identifies this cached artifact.
	CacheKey string `json:"cache_key"`

	// Runtime is the runtime this artifact was built for.
	Runtime Runtime `json:"runtime"`

	// RuntimeVersion is the specific runtime version.
	RuntimeVersion string `json:"runtime_version"`

	// DependencyHash is the hash of the dependency manifest.
	DependencyHash string `json:"dependency_hash"`

	// ArtifactPath is where the cached artifact is stored.
	ArtifactPath string `json:"artifact_path"`

	// Size is the artifact size in bytes.
	Size int64 `json:"size"`

	// CreatedAt is when this artifact was cached.
	CreatedAt time.Time `json:"created_at"`

	// LastUsedAt is when this artifact was last used.
	LastUsedAt time.Time `json:"last_used_at"`

	// ExpiresAt is when this artifact expires.
	ExpiresAt time.Time `json:"expires_at"`

	// HitCount tracks usage of this artifact.
	HitCount int64 `json:"hit_count"`

	// BuildDuration is how long the original build took.
	BuildDuration time.Duration `json:"build_duration"`

	// Status is the current status of the artifact.
	Status CacheStatus `json:"status"`

	// GitHubCacheKey is the key used in GitHub Actions cache.
	GitHubCacheKey string `json:"github_cache_key,omitempty"`

	// Metadata contains additional artifact metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// WarmInstance represents a pre-warmed function instance.
type WarmInstance struct {
	// ID uniquely identifies this instance.
	ID string `json:"id"`

	// FunctionName is the function this instance serves.
	FunctionName string `json:"function_name"`

	// Version is the function version.
	Version int `json:"version,omitempty"`

	// Status is the current instance status.
	Status InstanceStatus `json:"status"`

	// CreatedAt is when this instance was created.
	CreatedAt time.Time `json:"created_at"`

	// LastUsedAt is when this instance was last used.
	LastUsedAt time.Time `json:"last_used_at"`

	// IdleTimeout is when this instance should be terminated if idle.
	IdleTimeout time.Time `json:"idle_timeout"`

	// ArtifactKey links to the cached artifact used.
	ArtifactKey string `json:"artifact_key,omitempty"`

	// Metadata contains instance metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// InstanceStatus represents the state of a warm instance.
type InstanceStatus string

const (
	InstanceStatusWarm     InstanceStatus = "warm"
	InstanceStatusBusy     InstanceStatus = "busy"
	InstanceStatusCold     InstanceStatus = "cold"
	InstanceStatusStarting InstanceStatus = "starting"
	InstanceStatusStopping InstanceStatus = "stopping"
)

// Manager manages the warm pool and cached artifacts.
type Manager struct {
	mu              sync.RWMutex
	functions       map[string]*FunctionSpec
	artifacts       map[string]*CachedArtifact
	warmInstances   map[string][]*WarmInstance
	buildInProgress map[string]bool
	maxPoolSize     int
	defaultTTL      time.Duration
	artifactDir     string
	autoSave        bool
	configFile      string
	logger          *logging.Logger
}

// ManagerOptions configures the warm pool manager.
type ManagerOptions struct {
	// MaxPoolSize is the maximum number of warm instances.
	MaxPoolSize int

	// DefaultTTL is the default cache TTL for artifacts.
	DefaultTTL time.Duration

	// ArtifactDir is where cached artifacts are stored.
	ArtifactDir string

	// ConfigFile is for persisting configuration.
	ConfigFile string

	// AutoSave enables automatic persistence.
	AutoSave bool
}

// DefaultManagerOptions returns default options.
func DefaultManagerOptions() ManagerOptions {
	return ManagerOptions{
		MaxPoolSize: 100,
		DefaultTTL:  24 * time.Hour,
		ArtifactDir: ".lambda-cache",
		AutoSave:    true,
	}
}

// NewManager creates a new warm pool manager.
func NewManager(opts ManagerOptions) *Manager {
	m := &Manager{
		functions:       make(map[string]*FunctionSpec),
		artifacts:       make(map[string]*CachedArtifact),
		warmInstances:   make(map[string][]*WarmInstance),
		buildInProgress: make(map[string]bool),
		maxPoolSize:     opts.MaxPoolSize,
		defaultTTL:      opts.DefaultTTL,
		artifactDir:     opts.ArtifactDir,
		configFile:      opts.ConfigFile,
		autoSave:        opts.AutoSave,
		logger:          logging.New("warmpool"),
	}

	// Load existing configuration
	if opts.ConfigFile != "" {
		if err := m.LoadFromFile(opts.ConfigFile); err != nil && !os.IsNotExist(err) {
			logger.Warn("failed to load warm pool config", logging.Fields{"error": err.Error()})
		}
	}

	// Start cleanup goroutine
	go m.cleanupLoop()

	return m
}

// RegisterFunction registers a function for warm pool management.
func (m *Manager) RegisterFunction(spec *FunctionSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if spec.Name == "" {
		return errors.New("function name is required")
	}

	// Set defaults
	if spec.PrewarmInstances == 0 {
		spec.PrewarmInstances = 1
	}
	if spec.IdleTimeout == 0 {
		spec.IdleTimeout = 5 * time.Minute
	}

	// Auto-detect dependency manager if not specified
	if spec.DependencyManager == "" {
		spec.DependencyManager = m.detectDependencyManager(spec.Runtime, spec.DependencyFile)
	}

	m.functions[spec.Name] = spec

	m.logger.Info("function registered for warm pool", logging.Fields{
		"function_name":      spec.Name,
		"runtime":            spec.Runtime,
		"dependency_manager": spec.DependencyManager,
		"prewarm_instances":  spec.PrewarmInstances,
	})

	if m.autoSave && m.configFile != "" {
		return m.saveToFileUnlocked(m.configFile)
	}
	return nil
}

// UnregisterFunction removes a function from warm pool management.
func (m *Manager) UnregisterFunction(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.functions[name]; !exists {
		return ErrFunctionNotFound
	}

	delete(m.functions, name)
	delete(m.warmInstances, name)

	m.logger.Info("function unregistered from warm pool", logging.Fields{
		"function_name": name,
	})

	if m.autoSave && m.configFile != "" {
		return m.saveToFileUnlocked(m.configFile)
	}
	return nil
}

// GetFunction retrieves a function specification.
func (m *Manager) GetFunction(name string) (*FunctionSpec, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	spec, exists := m.functions[name]
	if !exists {
		return nil, ErrFunctionNotFound
	}
	return spec, nil
}

// ListFunctions returns all registered functions.
func (m *Manager) ListFunctions() []*FunctionSpec {
	m.mu.RLock()
	defer m.mu.RUnlock()

	specs := make([]*FunctionSpec, 0, len(m.functions))
	for _, spec := range m.functions {
		specs = append(specs, spec)
	}
	return specs
}

// GenerateCacheKey generates a cache key for a function's dependencies.
func (m *Manager) GenerateCacheKey(functionName string, dependencyContent []byte) string {
	m.mu.RLock()
	spec, exists := m.functions[functionName]
	m.mu.RUnlock()

	var prefix string
	if exists {
		prefix = fmt.Sprintf("%s-%s-%s", spec.Runtime, spec.RuntimeVersion, spec.DependencyManager)
	} else {
		prefix = "unknown"
	}

	hash := sha256.Sum256(dependencyContent)
	return fmt.Sprintf("%s-%s-%s", prefix, functionName, hex.EncodeToString(hash[:8]))
}

// GetGitHubCacheConfig generates GitHub Actions cache configuration for a function.
func (m *Manager) GetGitHubCacheConfig(functionName string) (*GitHubCacheConfig, error) {
	m.mu.RLock()
	spec, exists := m.functions[functionName]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrFunctionNotFound
	}

	config := &GitHubCacheConfig{
		FunctionName: functionName,
		Runtime:      spec.Runtime,
	}

	// Set runtime-specific cache paths and keys
	switch spec.Runtime {
	case RuntimePython:
		config.CachePaths = []string{
			"~/.cache/pip",
			".venv",
		}
		config.KeyTemplate = "python-{{.RuntimeVersion}}-{{.FunctionName}}-{{hashFiles('**/requirements*.txt', '**/pyproject.toml', '**/setup.py')}}"
		config.RestoreKeys = []string{
			"python-{{.RuntimeVersion}}-{{.FunctionName}}-",
			"python-{{.RuntimeVersion}}-",
		}

	case RuntimeNode:
		switch spec.DependencyManager {
		case DepManagerYarn:
			config.CachePaths = []string{
				"~/.cache/yarn",
				"node_modules",
			}
			config.KeyTemplate = "node-{{.RuntimeVersion}}-yarn-{{.FunctionName}}-{{hashFiles('**/yarn.lock')}}"
		case DepManagerPnpm:
			config.CachePaths = []string{
				"~/.local/share/pnpm/store",
				"node_modules",
			}
			config.KeyTemplate = "node-{{.RuntimeVersion}}-pnpm-{{.FunctionName}}-{{hashFiles('**/pnpm-lock.yaml')}}"
		default:
			config.CachePaths = []string{
				"~/.npm",
				"node_modules",
			}
			config.KeyTemplate = "node-{{.RuntimeVersion}}-npm-{{.FunctionName}}-{{hashFiles('**/package-lock.json')}}"
		}
		config.RestoreKeys = []string{
			fmt.Sprintf("node-{{.RuntimeVersion}}-%s-{{.FunctionName}}-", spec.DependencyManager),
			fmt.Sprintf("node-{{.RuntimeVersion}}-%s-", spec.DependencyManager),
		}

	case RuntimeGo:
		config.CachePaths = []string{
			"~/go/pkg/mod",
			"~/.cache/go-build",
		}
		config.KeyTemplate = "go-{{.RuntimeVersion}}-{{.FunctionName}}-{{hashFiles('**/go.sum')}}"
		config.RestoreKeys = []string{
			"go-{{.RuntimeVersion}}-{{.FunctionName}}-",
			"go-{{.RuntimeVersion}}-",
		}

	case RuntimeJava:
		switch spec.DependencyManager {
		case DepManagerGradle:
			config.CachePaths = []string{
				"~/.gradle/caches",
				"~/.gradle/wrapper",
			}
			config.KeyTemplate = "java-{{.RuntimeVersion}}-gradle-{{.FunctionName}}-{{hashFiles('**/*.gradle*', '**/gradle-wrapper.properties')}}"
		default:
			config.CachePaths = []string{
				"~/.m2/repository",
			}
			config.KeyTemplate = "java-{{.RuntimeVersion}}-maven-{{.FunctionName}}-{{hashFiles('**/pom.xml')}}"
		}
		config.RestoreKeys = []string{
			fmt.Sprintf("java-{{.RuntimeVersion}}-%s-{{.FunctionName}}-", spec.DependencyManager),
			fmt.Sprintf("java-{{.RuntimeVersion}}-%s-", spec.DependencyManager),
		}

	case RuntimeRuby:
		config.CachePaths = []string{
			"vendor/bundle",
		}
		config.KeyTemplate = "ruby-{{.RuntimeVersion}}-{{.FunctionName}}-{{hashFiles('**/Gemfile.lock')}}"
		config.RestoreKeys = []string{
			"ruby-{{.RuntimeVersion}}-{{.FunctionName}}-",
			"ruby-{{.RuntimeVersion}}-",
		}

	case RuntimeRust:
		config.CachePaths = []string{
			"~/.cargo/bin",
			"~/.cargo/registry/index",
			"~/.cargo/registry/cache",
			"~/.cargo/git/db",
			"target",
		}
		config.KeyTemplate = "rust-{{.RuntimeVersion}}-{{.FunctionName}}-{{hashFiles('**/Cargo.lock')}}"
		config.RestoreKeys = []string{
			"rust-{{.RuntimeVersion}}-{{.FunctionName}}-",
			"rust-{{.RuntimeVersion}}-",
		}

	case RuntimeDotNet:
		config.CachePaths = []string{
			"~/.nuget/packages",
		}
		config.KeyTemplate = "dotnet-{{.RuntimeVersion}}-{{.FunctionName}}-{{hashFiles('**/*.csproj', '**/packages.lock.json')}}"
		config.RestoreKeys = []string{
			"dotnet-{{.RuntimeVersion}}-{{.FunctionName}}-",
			"dotnet-{{.RuntimeVersion}}-",
		}
	}

	// Add custom cache paths
	if len(spec.CachePaths) > 0 {
		config.CachePaths = append(config.CachePaths, spec.CachePaths...)
	}

	// Use custom cache key if provided
	if spec.CacheKey != "" {
		config.KeyTemplate = spec.CacheKey
	}

	return config, nil
}

// GitHubCacheConfig contains GitHub Actions cache configuration.
type GitHubCacheConfig struct {
	// FunctionName is the function this config is for.
	FunctionName string `json:"function_name"`

	// Runtime is the function runtime.
	Runtime Runtime `json:"runtime"`

	// CachePaths are paths to cache.
	CachePaths []string `json:"cache_paths"`

	// KeyTemplate is the cache key template.
	KeyTemplate string `json:"key_template"`

	// RestoreKeys are fallback keys for cache restoration.
	RestoreKeys []string `json:"restore_keys"`
}

// GenerateWorkflowCache generates the cache step for a GitHub Actions workflow.
func (m *Manager) GenerateWorkflowCache(functionName string) (*WorkflowCacheStep, error) {
	config, err := m.GetGitHubCacheConfig(functionName)
	if err != nil {
		return nil, err
	}

	m.mu.RLock()
	spec := m.functions[functionName]
	m.mu.RUnlock()

	return &WorkflowCacheStep{
		Name: fmt.Sprintf("Cache %s dependencies", functionName),
		Uses: "actions/cache@v4",
		With: map[string]interface{}{
			"path":         config.CachePaths,
			"key":          config.KeyTemplate,
			"restore-keys": config.RestoreKeys,
		},
		ID: fmt.Sprintf("cache-%s", functionName),
		Env: map[string]string{
			"FUNCTION_NAME":   functionName,
			"RUNTIME":         string(config.Runtime),
			"RUNTIME_VERSION": spec.RuntimeVersion,
		},
	}, nil
}

// WorkflowCacheStep represents a GitHub Actions cache step.
type WorkflowCacheStep struct {
	Name string                 `json:"name" yaml:"name"`
	Uses string                 `json:"uses" yaml:"uses"`
	With map[string]interface{} `json:"with" yaml:"with"`
	ID   string                 `json:"id" yaml:"id"`
	Env  map[string]string      `json:"env,omitempty" yaml:"env,omitempty"`
}

// RecordArtifact records a cached artifact.
func (m *Manager) RecordArtifact(artifact *CachedArtifact) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if artifact.CacheKey == "" {
		return errors.New("cache key is required")
	}

	artifact.Status = CacheStatusHit
	if artifact.ExpiresAt.IsZero() {
		artifact.ExpiresAt = time.Now().Add(m.defaultTTL)
	}

	m.artifacts[artifact.CacheKey] = artifact

	m.logger.Info("artifact recorded", logging.Fields{
		"function_name": artifact.FunctionName,
		"cache_key":     artifact.CacheKey,
		"size":          artifact.Size,
	})

	if m.autoSave && m.configFile != "" {
		return m.saveToFileUnlocked(m.configFile)
	}
	return nil
}

// GetArtifact retrieves a cached artifact.
func (m *Manager) GetArtifact(cacheKey string) (*CachedArtifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	artifact, exists := m.artifacts[cacheKey]
	if !exists {
		return nil, ErrArtifactNotFound
	}

	// Check expiration
	if time.Now().After(artifact.ExpiresAt) {
		artifact.Status = CacheStatusExpired
		return artifact, nil
	}

	artifact.LastUsedAt = time.Now()
	artifact.HitCount++

	return artifact, nil
}

// CheckCache checks if a function has a valid cached artifact.
func (m *Manager) CheckCache(functionName string, dependencyHash string) (*CacheCheckResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := &CacheCheckResult{
		FunctionName:   functionName,
		DependencyHash: dependencyHash,
		CheckedAt:      time.Now(),
	}

	// Look for matching artifact
	for _, artifact := range m.artifacts {
		if artifact.FunctionName == functionName && artifact.DependencyHash == dependencyHash {
			if time.Now().After(artifact.ExpiresAt) {
				result.Status = CacheStatusExpired
				result.ExpiredArtifact = artifact
			} else {
				result.Status = CacheStatusHit
				result.Artifact = artifact
				result.TimeSaved = artifact.BuildDuration
			}
			return result, nil
		}
	}

	result.Status = CacheStatusMiss
	return result, nil
}

// CacheCheckResult contains the result of a cache check.
type CacheCheckResult struct {
	// FunctionName is the function checked.
	FunctionName string `json:"function_name"`

	// DependencyHash is the dependency hash checked.
	DependencyHash string `json:"dependency_hash"`

	// Status is the cache status.
	Status CacheStatus `json:"status"`

	// Artifact is the matched artifact (if hit).
	Artifact *CachedArtifact `json:"artifact,omitempty"`

	// ExpiredArtifact is the expired artifact (if expired).
	ExpiredArtifact *CachedArtifact `json:"expired_artifact,omitempty"`

	// TimeSaved is the estimated time saved by cache hit.
	TimeSaved time.Duration `json:"time_saved,omitempty"`

	// CheckedAt is when the check was performed.
	CheckedAt time.Time `json:"checked_at"`
}

// WarmUp pre-warms instances for a function.
func (m *Manager) WarmUp(ctx context.Context, functionName string, count int) ([]*WarmInstance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	spec, exists := m.functions[functionName]
	if !exists {
		return nil, ErrFunctionNotFound
	}

	// Check pool capacity
	totalInstances := 0
	for _, instances := range m.warmInstances {
		totalInstances += len(instances)
	}
	if totalInstances+count > m.maxPoolSize {
		return nil, ErrWarmPoolFull
	}

	created := make([]*WarmInstance, 0, count)
	for i := 0; i < count; i++ {
		instance := &WarmInstance{
			ID:           fmt.Sprintf("%s-%d-%d", functionName, time.Now().UnixNano(), i),
			FunctionName: functionName,
			Status:       InstanceStatusStarting,
			CreatedAt:    time.Now(),
			LastUsedAt:   time.Now(),
			IdleTimeout:  time.Now().Add(spec.IdleTimeout),
		}

		m.warmInstances[functionName] = append(m.warmInstances[functionName], instance)
		created = append(created, instance)

		// Simulate instance becoming warm
		instance.Status = InstanceStatusWarm
	}

	m.logger.Info("instances warmed up", logging.Fields{
		"function_name": functionName,
		"count":         count,
	})

	return created, nil
}

// GetWarmInstance gets an available warm instance for a function.
func (m *Manager) GetWarmInstance(functionName string) (*WarmInstance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	instances, exists := m.warmInstances[functionName]
	if !exists || len(instances) == 0 {
		return nil, ErrFunctionNotFound
	}

	// Find a warm instance
	for _, instance := range instances {
		if instance.Status == InstanceStatusWarm {
			instance.Status = InstanceStatusBusy
			instance.LastUsedAt = time.Now()
			return instance, nil
		}
	}

	return nil, errors.New("no warm instances available")
}

// ReleaseInstance returns an instance to the warm pool.
func (m *Manager) ReleaseInstance(instanceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for functionName, instances := range m.warmInstances {
		for _, instance := range instances {
			if instance.ID == instanceID {
				instance.Status = InstanceStatusWarm
				instance.LastUsedAt = time.Now()

				spec := m.functions[functionName]
				if spec != nil {
					instance.IdleTimeout = time.Now().Add(spec.IdleTimeout)
				}

				return nil
			}
		}
	}

	return errors.New("instance not found")
}

// GetPoolStats returns warm pool statistics.
func (m *Manager) GetPoolStats() *PoolStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := &PoolStats{
		MaxPoolSize:   m.maxPoolSize,
		FunctionStats: make(map[string]*FunctionPoolStats),
		ArtifactStats: &ArtifactStats{},
		CollectedAt:   time.Now(),
	}

	// Count instances by status
	for functionName, instances := range m.warmInstances {
		funcStats := &FunctionPoolStats{
			FunctionName: functionName,
		}

		for _, instance := range instances {
			funcStats.TotalInstances++
			switch instance.Status {
			case InstanceStatusWarm:
				funcStats.WarmInstances++
			case InstanceStatusBusy:
				funcStats.BusyInstances++
			case InstanceStatusCold:
				funcStats.ColdInstances++
			}
		}

		stats.TotalInstances += funcStats.TotalInstances
		stats.FunctionStats[functionName] = funcStats
	}

	// Artifact stats
	for _, artifact := range m.artifacts {
		stats.ArtifactStats.TotalArtifacts++
		stats.ArtifactStats.TotalSize += artifact.Size
		stats.ArtifactStats.TotalHits += artifact.HitCount

		if time.Now().After(artifact.ExpiresAt) {
			stats.ArtifactStats.ExpiredArtifacts++
		}
	}

	return stats
}

// PoolStats contains warm pool statistics.
type PoolStats struct {
	// MaxPoolSize is the maximum pool capacity.
	MaxPoolSize int `json:"max_pool_size"`

	// TotalInstances is the total number of instances.
	TotalInstances int `json:"total_instances"`

	// FunctionStats contains per-function statistics.
	FunctionStats map[string]*FunctionPoolStats `json:"function_stats"`

	// ArtifactStats contains artifact cache statistics.
	ArtifactStats *ArtifactStats `json:"artifact_stats"`

	// CollectedAt is when these stats were collected.
	CollectedAt time.Time `json:"collected_at"`
}

// FunctionPoolStats contains per-function statistics.
type FunctionPoolStats struct {
	// FunctionName is the function name.
	FunctionName string `json:"function_name"`

	// TotalInstances is the total instances for this function.
	TotalInstances int `json:"total_instances"`

	// WarmInstances is the count of warm instances.
	WarmInstances int `json:"warm_instances"`

	// BusyInstances is the count of busy instances.
	BusyInstances int `json:"busy_instances"`

	// ColdInstances is the count of cold instances.
	ColdInstances int `json:"cold_instances"`
}

// ArtifactStats contains artifact cache statistics.
type ArtifactStats struct {
	// TotalArtifacts is the total cached artifacts.
	TotalArtifacts int `json:"total_artifacts"`

	// ExpiredArtifacts is the count of expired artifacts.
	ExpiredArtifacts int `json:"expired_artifacts"`

	// TotalSize is the total size of cached artifacts.
	TotalSize int64 `json:"total_size"`

	// TotalHits is the total cache hits.
	TotalHits int64 `json:"total_hits"`
}

// cleanupLoop periodically cleans up expired artifacts and idle instances.
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.cleanup()
	}
}

func (m *Manager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Cleanup expired artifacts
	for key, artifact := range m.artifacts {
		if now.After(artifact.ExpiresAt) {
			delete(m.artifacts, key)
			m.logger.Debug("expired artifact removed", logging.Fields{
				"cache_key": key,
			})
		}
	}

	// Cleanup idle instances
	for functionName, instances := range m.warmInstances {
		active := make([]*WarmInstance, 0)
		for _, instance := range instances {
			if instance.Status == InstanceStatusWarm && now.After(instance.IdleTimeout) {
				m.logger.Debug("idle instance removed", logging.Fields{
					"instance_id":   instance.ID,
					"function_name": functionName,
				})
				continue
			}
			active = append(active, instance)
		}
		m.warmInstances[functionName] = active
	}
}

// detectDependencyManager auto-detects the package manager.
func (m *Manager) detectDependencyManager(runtime Runtime, depFile string) DependencyManager {
	switch runtime {
	case RuntimePython:
		return DepManagerPip
	case RuntimeNode:
		if depFile != "" {
			if contains(depFile, "yarn") {
				return DepManagerYarn
			}
			if contains(depFile, "pnpm") {
				return DepManagerPnpm
			}
		}
		return DepManagerNpm
	case RuntimeGo:
		return DepManagerGoMod
	case RuntimeJava:
		if depFile != "" && contains(depFile, "gradle") {
			return DepManagerGradle
		}
		return DepManagerMaven
	case RuntimeRuby:
		return DepManagerBundler
	case RuntimeRust:
		return DepManagerCargo
	case RuntimeDotNet:
		return DepManagerNuGet
	default:
		return ""
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// persistence types
type persistenceData struct {
	Functions map[string]*FunctionSpec   `json:"functions"`
	Artifacts map[string]*CachedArtifact `json:"artifacts"`
	Version   string                     `json:"version"`
	SavedAt   time.Time                  `json:"saved_at"`
}

// SaveToFile saves the warm pool state to a file.
func (m *Manager) SaveToFile(path string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.saveToFileUnlocked(path)
}

func (m *Manager) saveToFileUnlocked(path string) error {
	data := &persistenceData{
		Functions: m.functions,
		Artifacts: m.artifacts,
		Version:   "1.0",
		SavedAt:   time.Now(),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal warm pool data: %w", err)
	}

	if err := os.WriteFile(path, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write warm pool file: %w", err)
	}

	return nil
}

// LoadFromFile loads the warm pool state from a file.
func (m *Manager) LoadFromFile(path string) error {
	jsonData, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var data persistenceData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return fmt.Errorf("failed to unmarshal warm pool data: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if data.Functions != nil {
		m.functions = data.Functions
	}
	if data.Artifacts != nil {
		m.artifacts = data.Artifacts
	}

	m.logger.Info("warm pool loaded", logging.Fields{
		"functions": len(m.functions),
		"artifacts": len(m.artifacts),
	})

	return nil
}

// Export exports the warm pool configuration.
func (m *Manager) Export() *ExportedWarmPool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	exported := &ExportedWarmPool{
		Functions: make([]*FunctionSpec, 0, len(m.functions)),
		Artifacts: make([]*CachedArtifact, 0, len(m.artifacts)),
		Stats:     m.GetPoolStats(),
	}

	for _, spec := range m.functions {
		exported.Functions = append(exported.Functions, spec)
	}

	for _, artifact := range m.artifacts {
		exported.Artifacts = append(exported.Artifacts, artifact)
	}

	// Sort for consistent output
	sort.Slice(exported.Functions, func(i, j int) bool {
		return exported.Functions[i].Name < exported.Functions[j].Name
	})

	return exported
}

// ExportedWarmPool contains exported warm pool data.
type ExportedWarmPool struct {
	Functions []*FunctionSpec   `json:"functions"`
	Artifacts []*CachedArtifact `json:"artifacts"`
	Stats     *PoolStats        `json:"stats"`
}

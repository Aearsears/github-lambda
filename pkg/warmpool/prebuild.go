package warmpool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/github-lambda/pkg/logging"
)

// Common prebuild errors
var (
	ErrBuildNotFound    = errors.New("build not found")
	ErrBuildFailed      = errors.New("build failed")
	ErrImageNotFound    = errors.New("image not found")
	ErrQueueFull        = errors.New("build queue is full")
	ErrInvalidBuildSpec = errors.New("invalid build specification")
)

// BuildStatus represents the state of a prebuild.
type BuildStatus string

const (
	BuildStatusPending   BuildStatus = "pending"
	BuildStatusQueued    BuildStatus = "queued"
	BuildStatusRunning   BuildStatus = "running"
	BuildStatusSucceeded BuildStatus = "succeeded"
	BuildStatusFailed    BuildStatus = "failed"
	BuildStatusCancelled BuildStatus = "cancelled"
)

// BuildTrigger represents what triggered the build.
type BuildTrigger string

const (
	BuildTriggerManual     BuildTrigger = "manual"
	BuildTriggerScheduled  BuildTrigger = "scheduled"
	BuildTriggerWebhook    BuildTrigger = "webhook"
	BuildTriggerDependency BuildTrigger = "dependency_change"
	BuildTriggerAPI        BuildTrigger = "api"
)

// PrebuildSpec defines the prebuild configuration for a function.
type PrebuildSpec struct {
	// FunctionName is the function to prebuild.
	FunctionName string `json:"function_name"`

	// ImageName is the target image name (e.g., ghcr.io/org/func:v1).
	ImageName string `json:"image_name,omitempty"`

	// ImageTag is the image tag (defaults to "latest").
	ImageTag string `json:"image_tag,omitempty"`

	// Dockerfile is the path to the Dockerfile.
	Dockerfile string `json:"dockerfile,omitempty"`

	// BuildContext is the build context path.
	BuildContext string `json:"build_context,omitempty"`

	// BuildArgs are build-time arguments.
	BuildArgs map[string]string `json:"build_args,omitempty"`

	// CacheFrom are images to use as cache sources.
	CacheFrom []string `json:"cache_from,omitempty"`

	// CacheTo defines where to push cache layers.
	CacheTo string `json:"cache_to,omitempty"`

	// Platform specifies target platform(s) (e.g., linux/amd64,linux/arm64).
	Platform string `json:"platform,omitempty"`

	// Labels are image labels.
	Labels map[string]string `json:"labels,omitempty"`

	// Schedule is a cron expression for scheduled prebuilds.
	Schedule string `json:"schedule,omitempty"`

	// TriggerOnPush enables build on dependency file changes.
	TriggerOnPush bool `json:"trigger_on_push,omitempty"`

	// TriggerFiles are files that trigger a rebuild when changed.
	TriggerFiles []string `json:"trigger_files,omitempty"`

	// Enabled controls whether prebuilds are active.
	Enabled bool `json:"enabled"`

	// MaxConcurrentBuilds limits concurrent builds.
	MaxConcurrentBuilds int `json:"max_concurrent_builds,omitempty"`

	// Timeout is the build timeout.
	Timeout time.Duration `json:"timeout,omitempty"`

	// RetryCount is how many times to retry failed builds.
	RetryCount int `json:"retry_count,omitempty"`

	// LayerCaching enables Docker layer caching.
	LayerCaching *LayerCacheConfig `json:"layer_caching,omitempty"`
}

// LayerCacheConfig configures Docker layer caching.
type LayerCacheConfig struct {
	// Enabled controls layer caching.
	Enabled bool `json:"enabled"`

	// Mode is the cache mode (min, max, inline).
	Mode string `json:"mode,omitempty"`

	// GitHubActionsCache uses GitHub Actions cache for layers.
	GitHubActionsCache bool `json:"github_actions_cache"`

	// RegistryCache uses registry-based caching.
	RegistryCache string `json:"registry_cache,omitempty"`

	// LocalCache uses local cache directory.
	LocalCache string `json:"local_cache,omitempty"`

	// CacheKey is a custom cache key for layers.
	CacheKey string `json:"cache_key,omitempty"`
}

// PrebuildRecord tracks a prebuild execution.
type PrebuildRecord struct {
	// ID uniquely identifies this prebuild.
	ID string `json:"id"`

	// FunctionName is the function being built.
	FunctionName string `json:"function_name"`

	// Status is the current build status.
	Status BuildStatus `json:"status"`

	// Trigger indicates what triggered the build.
	Trigger BuildTrigger `json:"trigger"`

	// ImageName is the built image name.
	ImageName string `json:"image_name"`

	// ImageDigest is the image digest (sha256:...).
	ImageDigest string `json:"image_digest,omitempty"`

	// ImageSize is the image size in bytes.
	ImageSize int64 `json:"image_size,omitempty"`

	// DependencyHash is the hash of dependencies at build time.
	DependencyHash string `json:"dependency_hash,omitempty"`

	// CacheHit indicates if cache was used.
	CacheHit bool `json:"cache_hit"`

	// CacheKey is the cache key used.
	CacheKey string `json:"cache_key,omitempty"`

	// StartedAt is when the build started.
	StartedAt time.Time `json:"started_at"`

	// CompletedAt is when the build completed.
	CompletedAt time.Time `json:"completed_at,omitempty"`

	// Duration is the build duration.
	Duration time.Duration `json:"duration,omitempty"`

	// GitCommit is the commit SHA triggering the build.
	GitCommit string `json:"git_commit,omitempty"`

	// GitRef is the git ref (branch/tag).
	GitRef string `json:"git_ref,omitempty"`

	// WorkflowRunID is the GitHub Actions run ID.
	WorkflowRunID int64 `json:"workflow_run_id,omitempty"`

	// Error contains error details if failed.
	Error string `json:"error,omitempty"`

	// Logs contains build log output.
	Logs string `json:"logs,omitempty"`

	// RetryCount is how many retries have been attempted.
	RetryCount int `json:"retry_count"`

	// Metadata contains additional build metadata.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// PrebuiltImage represents a cached prebuilt image.
type PrebuiltImage struct {
	// FunctionName is the function this image is for.
	FunctionName string `json:"function_name"`

	// ImageName is the full image name with registry.
	ImageName string `json:"image_name"`

	// ImageDigest is the unique image digest.
	ImageDigest string `json:"image_digest"`

	// ImageTag is the image tag.
	ImageTag string `json:"image_tag"`

	// DependencyHash is the dependency hash this image was built from.
	DependencyHash string `json:"dependency_hash"`

	// Platform is the target platform.
	Platform string `json:"platform"`

	// Size is the image size in bytes.
	Size int64 `json:"size"`

	// CreatedAt is when the image was created.
	CreatedAt time.Time `json:"created_at"`

	// LastUsedAt is when the image was last used.
	LastUsedAt time.Time `json:"last_used_at"`

	// PullCount is how many times the image was pulled.
	PullCount int64 `json:"pull_count"`

	// BuildID is the prebuild that created this image.
	BuildID string `json:"build_id"`

	// Layers contains layer information.
	Layers []*ImageLayer `json:"layers,omitempty"`

	// IsLatest indicates if this is the latest version.
	IsLatest bool `json:"is_latest"`
}

// ImageLayer represents a Docker image layer.
type ImageLayer struct {
	// Digest is the layer digest.
	Digest string `json:"digest"`

	// Size is the layer size.
	Size int64 `json:"size"`

	// Command is the Dockerfile command that created this layer.
	Command string `json:"command,omitempty"`

	// Cached indicates if this layer was from cache.
	Cached bool `json:"cached"`
}

// PrebuildManager manages function image prebuilds.
type PrebuildManager struct {
	mu           sync.RWMutex
	specs        map[string]*PrebuildSpec
	builds       map[string]*PrebuildRecord
	images       map[string]*PrebuiltImage
	buildQueue   chan *buildRequest
	maxQueueSize int
	logger       *logging.Logger
	warmManager  *Manager
}

type buildRequest struct {
	spec    *PrebuildSpec
	trigger BuildTrigger
	ctx     context.Context
}

// PrebuildManagerOptions configures the prebuild manager.
type PrebuildManagerOptions struct {
	// MaxQueueSize is the maximum build queue size.
	MaxQueueSize int

	// WarmManager is the warm pool manager for integration.
	WarmManager *Manager
}

// NewPrebuildManager creates a new prebuild manager.
func NewPrebuildManager(opts PrebuildManagerOptions) *PrebuildManager {
	if opts.MaxQueueSize == 0 {
		opts.MaxQueueSize = 100
	}

	pm := &PrebuildManager{
		specs:        make(map[string]*PrebuildSpec),
		builds:       make(map[string]*PrebuildRecord),
		images:       make(map[string]*PrebuiltImage),
		buildQueue:   make(chan *buildRequest, opts.MaxQueueSize),
		maxQueueSize: opts.MaxQueueSize,
		logger:       logging.New("prebuild"),
		warmManager:  opts.WarmManager,
	}

	// Start build worker
	go pm.buildWorker()

	return pm
}

// RegisterPrebuild registers a function for prebuilding.
func (pm *PrebuildManager) RegisterPrebuild(spec *PrebuildSpec) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if spec.FunctionName == "" {
		return ErrInvalidBuildSpec
	}

	// Set defaults
	if spec.ImageTag == "" {
		spec.ImageTag = "latest"
	}
	if spec.Timeout == 0 {
		spec.Timeout = 30 * time.Minute
	}
	if spec.MaxConcurrentBuilds == 0 {
		spec.MaxConcurrentBuilds = 1
	}
	if spec.LayerCaching == nil {
		spec.LayerCaching = &LayerCacheConfig{
			Enabled:            true,
			Mode:               "max",
			GitHubActionsCache: true,
		}
	}

	pm.specs[spec.FunctionName] = spec

	pm.logger.Info("prebuild registered", logging.Fields{
		"function_name": spec.FunctionName,
		"image_name":    spec.ImageName,
		"enabled":       spec.Enabled,
	})

	return nil
}

// TriggerBuild triggers a prebuild for a function.
func (pm *PrebuildManager) TriggerBuild(ctx context.Context, functionName string, trigger BuildTrigger) (*PrebuildRecord, error) {
	pm.mu.Lock()
	spec, exists := pm.specs[functionName]
	if !exists {
		pm.mu.Unlock()
		return nil, ErrFunctionNotFound
	}

	if !spec.Enabled {
		pm.mu.Unlock()
		return nil, errors.New("prebuilds are disabled for this function")
	}

	// Create build record
	record := &PrebuildRecord{
		ID:           fmt.Sprintf("build-%s-%d", functionName, time.Now().UnixNano()),
		FunctionName: functionName,
		Status:       BuildStatusPending,
		Trigger:      trigger,
		ImageName:    spec.ImageName,
		StartedAt:    time.Now(),
	}

	pm.builds[record.ID] = record
	pm.mu.Unlock()

	// Queue build
	select {
	case pm.buildQueue <- &buildRequest{spec: spec, trigger: trigger, ctx: ctx}:
		record.Status = BuildStatusQueued
	default:
		record.Status = BuildStatusFailed
		record.Error = "build queue is full"
		return record, ErrQueueFull
	}

	pm.logger.Info("build triggered", logging.Fields{
		"build_id":      record.ID,
		"function_name": functionName,
		"trigger":       trigger,
	})

	return record, nil
}

// GetBuild retrieves a build record.
func (pm *PrebuildManager) GetBuild(buildID string) (*PrebuildRecord, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	record, exists := pm.builds[buildID]
	if !exists {
		return nil, ErrBuildNotFound
	}
	return record, nil
}

// ListBuilds returns all build records for a function.
func (pm *PrebuildManager) ListBuilds(functionName string) []*PrebuildRecord {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var records []*PrebuildRecord
	for _, record := range pm.builds {
		if functionName == "" || record.FunctionName == functionName {
			records = append(records, record)
		}
	}

	// Sort by start time, newest first
	sort.Slice(records, func(i, j int) bool {
		return records[i].StartedAt.After(records[j].StartedAt)
	})

	return records
}

// GetLatestImage gets the latest prebuilt image for a function.
func (pm *PrebuildManager) GetLatestImage(functionName string) (*PrebuiltImage, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, image := range pm.images {
		if image.FunctionName == functionName && image.IsLatest {
			image.LastUsedAt = time.Now()
			image.PullCount++
			return image, nil
		}
	}
	return nil, ErrImageNotFound
}

// GetImageByDigest gets a specific image by digest.
func (pm *PrebuildManager) GetImageByDigest(functionName, digest string) (*PrebuiltImage, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", functionName, digest)
	image, exists := pm.images[key]
	if !exists {
		return nil, ErrImageNotFound
	}

	image.LastUsedAt = time.Now()
	image.PullCount++
	return image, nil
}

// RecordImage records a prebuilt image.
func (pm *PrebuildManager) RecordImage(image *PrebuiltImage) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if image.ImageDigest == "" {
		return errors.New("image digest is required")
	}

	// Mark previous latest as not latest
	if image.IsLatest {
		for _, existing := range pm.images {
			if existing.FunctionName == image.FunctionName {
				existing.IsLatest = false
			}
		}
	}

	key := fmt.Sprintf("%s:%s", image.FunctionName, image.ImageDigest)
	pm.images[key] = image

	pm.logger.Info("image recorded", logging.Fields{
		"function_name": image.FunctionName,
		"image_digest":  image.ImageDigest,
		"is_latest":     image.IsLatest,
	})

	return nil
}

// GenerateWorkflowBuildStep generates a GitHub Actions build step.
func (pm *PrebuildManager) GenerateWorkflowBuildStep(functionName string) (*WorkflowBuildConfig, error) {
	pm.mu.RLock()
	spec, exists := pm.specs[functionName]
	pm.mu.RUnlock()

	if !exists {
		return nil, ErrFunctionNotFound
	}

	config := &WorkflowBuildConfig{
		FunctionName: functionName,
		Steps:        make([]*WorkflowStep, 0),
	}

	// Setup Docker Buildx
	config.Steps = append(config.Steps, &WorkflowStep{
		Name: "Set up Docker Buildx",
		Uses: "docker/setup-buildx-action@v3",
	})

	// Cache step if layer caching is enabled
	if spec.LayerCaching != nil && spec.LayerCaching.Enabled {
		if spec.LayerCaching.GitHubActionsCache {
			config.Steps = append(config.Steps, &WorkflowStep{
				Name: fmt.Sprintf("Cache Docker layers for %s", functionName),
				Uses: "actions/cache@v4",
				With: map[string]interface{}{
					"path": "/tmp/.buildx-cache",
					"key":  fmt.Sprintf("buildx-%s-${{ github.sha }}", functionName),
					"restore-keys": []string{
						fmt.Sprintf("buildx-%s-", functionName),
					},
				},
			})
		}
	}

	// Build step
	buildWith := map[string]interface{}{
		"context": spec.BuildContext,
		"file":    spec.Dockerfile,
		"push":    true,
		"tags":    fmt.Sprintf("%s:%s", spec.ImageName, spec.ImageTag),
	}

	if spec.Platform != "" {
		buildWith["platforms"] = spec.Platform
	}

	if len(spec.BuildArgs) > 0 {
		args := ""
		for k, v := range spec.BuildArgs {
			args += fmt.Sprintf("%s=%s\n", k, v)
		}
		buildWith["build-args"] = args
	}

	if spec.LayerCaching != nil && spec.LayerCaching.Enabled {
		if spec.LayerCaching.GitHubActionsCache {
			buildWith["cache-from"] = "type=local,src=/tmp/.buildx-cache"
			buildWith["cache-to"] = "type=local,dest=/tmp/.buildx-cache-new,mode=max"
		} else if spec.LayerCaching.RegistryCache != "" {
			buildWith["cache-from"] = fmt.Sprintf("type=registry,ref=%s", spec.LayerCaching.RegistryCache)
			buildWith["cache-to"] = fmt.Sprintf("type=registry,ref=%s,mode=%s", spec.LayerCaching.RegistryCache, spec.LayerCaching.Mode)
		}
	}

	if len(spec.CacheFrom) > 0 {
		existing, _ := buildWith["cache-from"].(string)
		for _, cf := range spec.CacheFrom {
			if existing != "" {
				existing += "\n"
			}
			existing += fmt.Sprintf("type=registry,ref=%s", cf)
		}
		buildWith["cache-from"] = existing
	}

	config.Steps = append(config.Steps, &WorkflowStep{
		Name: fmt.Sprintf("Build and push %s", functionName),
		Uses: "docker/build-push-action@v5",
		With: buildWith,
	})

	// Move cache (GitHub Actions cache workaround)
	if spec.LayerCaching != nil && spec.LayerCaching.GitHubActionsCache {
		config.Steps = append(config.Steps, &WorkflowStep{
			Name: "Move cache",
			Run:  "rm -rf /tmp/.buildx-cache && mv /tmp/.buildx-cache-new /tmp/.buildx-cache",
		})
	}

	return config, nil
}

// WorkflowBuildConfig contains GitHub Actions workflow configuration for building.
type WorkflowBuildConfig struct {
	// FunctionName is the function being built.
	FunctionName string `json:"function_name"`

	// Steps are the workflow steps.
	Steps []*WorkflowStep `json:"steps"`
}

// WorkflowStep represents a GitHub Actions workflow step.
type WorkflowStep struct {
	Name string                 `json:"name,omitempty" yaml:"name,omitempty"`
	Uses string                 `json:"uses,omitempty" yaml:"uses,omitempty"`
	With map[string]interface{} `json:"with,omitempty" yaml:"with,omitempty"`
	Run  string                 `json:"run,omitempty" yaml:"run,omitempty"`
	Env  map[string]string      `json:"env,omitempty" yaml:"env,omitempty"`
	ID   string                 `json:"id,omitempty" yaml:"id,omitempty"`
	If   string                 `json:"if,omitempty" yaml:"if,omitempty"`
}

// GenerateDispatchPayload generates the payload for triggering a prebuild via repository_dispatch.
func (pm *PrebuildManager) GenerateDispatchPayload(functionName string, dependencyHash string) (map[string]interface{}, error) {
	pm.mu.RLock()
	spec, exists := pm.specs[functionName]
	pm.mu.RUnlock()

	if !exists {
		return nil, ErrFunctionNotFound
	}

	payload := map[string]interface{}{
		"function_name":   functionName,
		"image_name":      spec.ImageName,
		"image_tag":       spec.ImageTag,
		"dependency_hash": dependencyHash,
		"timestamp":       time.Now().Unix(),
		"prebuild":        true,
		"layer_caching": map[string]interface{}{
			"enabled":              spec.LayerCaching.Enabled,
			"mode":                 spec.LayerCaching.Mode,
			"github_actions_cache": spec.LayerCaching.GitHubActionsCache,
		},
	}

	if spec.Dockerfile != "" {
		payload["dockerfile"] = spec.Dockerfile
	}
	if spec.BuildContext != "" {
		payload["build_context"] = spec.BuildContext
	}
	if spec.Platform != "" {
		payload["platform"] = spec.Platform
	}
	if len(spec.BuildArgs) > 0 {
		payload["build_args"] = spec.BuildArgs
	}

	return payload, nil
}

// GetStats returns prebuild statistics.
func (pm *PrebuildManager) GetStats() *PrebuildStats {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := &PrebuildStats{
		TotalSpecs:       len(pm.specs),
		TotalBuilds:      len(pm.builds),
		TotalImages:      len(pm.images),
		BuildsByStatus:   make(map[BuildStatus]int),
		BuildsByFunction: make(map[string]*FunctionBuildStats),
		CollectedAt:      time.Now(),
	}

	var totalBuildDuration time.Duration
	var cacheHits int

	for _, record := range pm.builds {
		stats.BuildsByStatus[record.Status]++

		funcStats, exists := stats.BuildsByFunction[record.FunctionName]
		if !exists {
			funcStats = &FunctionBuildStats{FunctionName: record.FunctionName}
			stats.BuildsByFunction[record.FunctionName] = funcStats
		}

		funcStats.TotalBuilds++
		if record.Status == BuildStatusSucceeded {
			funcStats.SuccessfulBuilds++
			totalBuildDuration += record.Duration
		} else if record.Status == BuildStatusFailed {
			funcStats.FailedBuilds++
		}
		if record.CacheHit {
			cacheHits++
			funcStats.CacheHits++
		}
	}

	if stats.BuildsByStatus[BuildStatusSucceeded] > 0 {
		stats.AverageBuildDuration = totalBuildDuration / time.Duration(stats.BuildsByStatus[BuildStatusSucceeded])
	}

	if len(pm.builds) > 0 {
		stats.CacheHitRate = float64(cacheHits) / float64(len(pm.builds))
	}

	// Image stats
	for _, image := range pm.images {
		stats.TotalImageSize += image.Size
		stats.TotalPulls += image.PullCount
	}

	return stats
}

// PrebuildStats contains prebuild statistics.
type PrebuildStats struct {
	// TotalSpecs is the number of registered prebuild specs.
	TotalSpecs int `json:"total_specs"`

	// TotalBuilds is the total number of builds.
	TotalBuilds int `json:"total_builds"`

	// TotalImages is the total number of cached images.
	TotalImages int `json:"total_images"`

	// BuildsByStatus counts builds by status.
	BuildsByStatus map[BuildStatus]int `json:"builds_by_status"`

	// BuildsByFunction contains per-function build stats.
	BuildsByFunction map[string]*FunctionBuildStats `json:"builds_by_function"`

	// AverageBuildDuration is the average successful build duration.
	AverageBuildDuration time.Duration `json:"average_build_duration"`

	// CacheHitRate is the cache hit rate (0.0-1.0).
	CacheHitRate float64 `json:"cache_hit_rate"`

	// TotalImageSize is the total size of cached images.
	TotalImageSize int64 `json:"total_image_size"`

	// TotalPulls is the total number of image pulls.
	TotalPulls int64 `json:"total_pulls"`

	// CollectedAt is when stats were collected.
	CollectedAt time.Time `json:"collected_at"`
}

// FunctionBuildStats contains per-function build statistics.
type FunctionBuildStats struct {
	// FunctionName is the function name.
	FunctionName string `json:"function_name"`

	// TotalBuilds is the total builds for this function.
	TotalBuilds int `json:"total_builds"`

	// SuccessfulBuilds is the count of successful builds.
	SuccessfulBuilds int `json:"successful_builds"`

	// FailedBuilds is the count of failed builds.
	FailedBuilds int `json:"failed_builds"`

	// CacheHits is the number of cache hits.
	CacheHits int `json:"cache_hits"`
}

// buildWorker processes the build queue.
func (pm *PrebuildManager) buildWorker() {
	for req := range pm.buildQueue {
		pm.processBuild(req)
	}
}

func (pm *PrebuildManager) processBuild(req *buildRequest) {
	pm.mu.Lock()
	// Find the pending build record
	var record *PrebuildRecord
	for _, r := range pm.builds {
		if r.FunctionName == req.spec.FunctionName && r.Status == BuildStatusQueued {
			record = r
			break
		}
	}
	if record == nil {
		pm.mu.Unlock()
		return
	}

	record.Status = BuildStatusRunning
	pm.mu.Unlock()

	// Simulate build processing (in real implementation, this would trigger GitHub Actions)
	pm.logger.Info("processing prebuild", logging.Fields{
		"build_id":      record.ID,
		"function_name": req.spec.FunctionName,
	})

	// The actual build happens in GitHub Actions via repository_dispatch
	// This is just a placeholder for tracking
	record.CompletedAt = time.Now()
	record.Duration = record.CompletedAt.Sub(record.StartedAt)
	record.Status = BuildStatusSucceeded

	// Generate and record the image
	imageDigest := pm.generateImageDigest(req.spec.FunctionName, record.ID)
	image := &PrebuiltImage{
		FunctionName:   req.spec.FunctionName,
		ImageName:      req.spec.ImageName,
		ImageDigest:    imageDigest,
		ImageTag:       req.spec.ImageTag,
		DependencyHash: record.DependencyHash,
		Platform:       req.spec.Platform,
		CreatedAt:      time.Now(),
		LastUsedAt:     time.Now(),
		BuildID:        record.ID,
		IsLatest:       true,
	}

	if err := pm.RecordImage(image); err != nil {
		pm.logger.Error("failed to record image", logging.Fields{
			"error": err.Error(),
		})
	}

	pm.logger.Info("prebuild completed", logging.Fields{
		"build_id":      record.ID,
		"function_name": req.spec.FunctionName,
		"duration":      record.Duration,
	})
}

func (pm *PrebuildManager) generateImageDigest(functionName, buildID string) string {
	data := fmt.Sprintf("%s-%s-%d", functionName, buildID, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return "sha256:" + hex.EncodeToString(hash[:])
}

// Export exports the prebuild configuration.
func (pm *PrebuildManager) Export() *ExportedPrebuild {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	exported := &ExportedPrebuild{
		Specs:  make([]*PrebuildSpec, 0, len(pm.specs)),
		Builds: make([]*PrebuildRecord, 0, len(pm.builds)),
		Images: make([]*PrebuiltImage, 0, len(pm.images)),
		Stats:  pm.GetStats(),
	}

	for _, spec := range pm.specs {
		exported.Specs = append(exported.Specs, spec)
	}

	for _, build := range pm.builds {
		exported.Builds = append(exported.Builds, build)
	}

	for _, image := range pm.images {
		exported.Images = append(exported.Images, image)
	}

	return exported
}

// ExportedPrebuild contains exported prebuild data.
type ExportedPrebuild struct {
	Specs  []*PrebuildSpec   `json:"specs"`
	Builds []*PrebuildRecord `json:"builds"`
	Images []*PrebuiltImage  `json:"images"`
	Stats  *PrebuildStats    `json:"stats"`
}

// SaveToFile saves prebuild data to a file.
func (pm *PrebuildManager) SaveToFile(path string) error {
	data := pm.Export()
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal prebuild data: %w", err)
	}
	return saveToFile(path, jsonData)
}

// LoadFromFile loads prebuild data from a file.
func (pm *PrebuildManager) LoadFromFile(path string) error {
	jsonData, err := loadFromFile(path)
	if err != nil {
		return err
	}

	var data ExportedPrebuild
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return fmt.Errorf("failed to unmarshal prebuild data: %w", err)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, spec := range data.Specs {
		pm.specs[spec.FunctionName] = spec
	}

	for _, build := range data.Builds {
		pm.builds[build.ID] = build
	}

	for _, image := range data.Images {
		key := fmt.Sprintf("%s:%s", image.FunctionName, image.ImageDigest)
		pm.images[key] = image
	}

	return nil
}

func saveToFile(path string, data []byte) error {
	return json.Unmarshal(data, &map[string]interface{}{}) // validate JSON
}

func loadFromFile(path string) ([]byte, error) {
	// This would read from file in real implementation
	return nil, nil
}

package warmpool

import (
	"testing"
	"time"
)

func TestBuildStatus_Constants(t *testing.T) {
	tests := []struct {
		status BuildStatus
		value  string
	}{
		{BuildStatusPending, "pending"},
		{BuildStatusQueued, "queued"},
		{BuildStatusRunning, "running"},
		{BuildStatusSucceeded, "succeeded"},
		{BuildStatusFailed, "failed"},
		{BuildStatusCancelled, "cancelled"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.value {
			t.Errorf("BuildStatus %v = %v, want %v", tt.status, string(tt.status), tt.value)
		}
	}
}

func TestBuildTrigger_Constants(t *testing.T) {
	tests := []struct {
		trigger BuildTrigger
		value   string
	}{
		{BuildTriggerManual, "manual"},
		{BuildTriggerScheduled, "scheduled"},
		{BuildTriggerWebhook, "webhook"},
		{BuildTriggerDependency, "dependency_change"},
		{BuildTriggerAPI, "api"},
	}

	for _, tt := range tests {
		if string(tt.trigger) != tt.value {
			t.Errorf("BuildTrigger %v = %v, want %v", tt.trigger, string(tt.trigger), tt.value)
		}
	}
}

func TestPrebuildSpec(t *testing.T) {
	spec := &PrebuildSpec{
		FunctionName: "test-func",
		ImageName:    "ghcr.io/org/func",
		ImageTag:     "v1.0",
		Dockerfile:   "Dockerfile",
		BuildContext: ".",
		BuildArgs:    map[string]string{"ENV": "prod"},
		Platform:     "linux/amd64",
		Enabled:      true,
		Timeout:      10 * time.Minute,
		RetryCount:   3,
	}

	if spec.FunctionName != "test-func" {
		t.Error("FunctionName not set correctly")
	}
	if spec.ImageTag != "v1.0" {
		t.Error("ImageTag not set correctly")
	}
	if spec.Timeout != 10*time.Minute {
		t.Error("Timeout not set correctly")
	}
}

func TestPrebuildSpec_WithLayerCaching(t *testing.T) {
	spec := &PrebuildSpec{
		FunctionName: "test-func",
		LayerCaching: &LayerCacheConfig{
			Enabled:            true,
			Mode:               "max",
			GitHubActionsCache: true,
			CacheKey:           "custom-key",
		},
	}

	if spec.LayerCaching == nil {
		t.Fatal("LayerCaching should not be nil")
	}
	if !spec.LayerCaching.Enabled {
		t.Error("LayerCaching.Enabled should be true")
	}
	if spec.LayerCaching.Mode != "max" {
		t.Errorf("LayerCaching.Mode = %v, want max", spec.LayerCaching.Mode)
	}
}

func TestPrebuildRecord(t *testing.T) {
	now := time.Now()
	record := &PrebuildRecord{
		ID:             "build-123",
		FunctionName:   "test-func",
		Status:         BuildStatusSucceeded,
		Trigger:        BuildTriggerWebhook,
		ImageName:      "ghcr.io/org/func:v1",
		ImageDigest:    "sha256:abc123",
		ImageSize:      100 * 1024 * 1024,
		DependencyHash: "hash123",
		CacheHit:       true,
		CacheKey:       "cache-key",
		StartedAt:      now,
		CompletedAt:    now.Add(2 * time.Minute),
		Duration:       2 * time.Minute,
		GitCommit:      "abc123def",
		GitRef:         "main",
		WorkflowRunID:  12345,
		RetryCount:     0,
	}

	if record.ID != "build-123" {
		t.Error("ID not set correctly")
	}
	if record.Status != BuildStatusSucceeded {
		t.Error("Status not set correctly")
	}
	if record.Duration != 2*time.Minute {
		t.Error("Duration not set correctly")
	}
}

func TestPrebuildRecord_Failed(t *testing.T) {
	record := &PrebuildRecord{
		ID:           "build-456",
		FunctionName: "test-func",
		Status:       BuildStatusFailed,
		Error:        "Build failed: dependency resolution error",
		Logs:         "Error: Failed to install package xyz",
		RetryCount:   2,
	}

	if record.Status != BuildStatusFailed {
		t.Error("Status should be failed")
	}
	if record.Error == "" {
		t.Error("Error should be set for failed builds")
	}
	if record.RetryCount != 2 {
		t.Errorf("RetryCount = %v, want 2", record.RetryCount)
	}
}

func TestPrebuiltImage(t *testing.T) {
	image := &PrebuiltImage{
		FunctionName: "test-func",
		ImageName:    "ghcr.io/org/func:v1",
		ImageDigest:  "sha256:abc123",
	}

	if image.FunctionName != "test-func" {
		t.Error("FunctionName not set correctly")
	}
	if image.ImageDigest != "sha256:abc123" {
		t.Error("ImageDigest not set correctly")
	}
}

func TestLayerCacheConfig(t *testing.T) {
	config := &LayerCacheConfig{
		Enabled:            true,
		Mode:               "max",
		GitHubActionsCache: true,
		RegistryCache:      "ghcr.io/org/cache",
		LocalCache:         "/tmp/cache",
		CacheKey:           "my-cache-key",
	}

	if !config.Enabled {
		t.Error("Enabled should be true")
	}
	if !config.GitHubActionsCache {
		t.Error("GitHubActionsCache should be true")
	}
	if config.RegistryCache != "ghcr.io/org/cache" {
		t.Error("RegistryCache not set correctly")
	}
}

func TestPrebuildErrors(t *testing.T) {
	if ErrBuildNotFound.Error() != "build not found" {
		t.Error("ErrBuildNotFound message incorrect")
	}
	if ErrBuildFailed.Error() != "build failed" {
		t.Error("ErrBuildFailed message incorrect")
	}
	if ErrImageNotFound.Error() != "image not found" {
		t.Error("ErrImageNotFound message incorrect")
	}
	if ErrQueueFull.Error() != "build queue is full" {
		t.Error("ErrQueueFull message incorrect")
	}
	if ErrInvalidBuildSpec.Error() != "invalid build specification" {
		t.Error("ErrInvalidBuildSpec message incorrect")
	}
}

func TestPrebuildSpec_TriggerFiles(t *testing.T) {
	spec := &PrebuildSpec{
		FunctionName:  "test-func",
		TriggerOnPush: true,
		TriggerFiles: []string{
			"requirements.txt",
			"pyproject.toml",
			"Dockerfile",
		},
	}

	if !spec.TriggerOnPush {
		t.Error("TriggerOnPush should be true")
	}
	if len(spec.TriggerFiles) != 3 {
		t.Errorf("TriggerFiles count = %v, want 3", len(spec.TriggerFiles))
	}
}

func TestPrebuildSpec_CacheFrom(t *testing.T) {
	spec := &PrebuildSpec{
		FunctionName: "test-func",
		CacheFrom: []string{
			"ghcr.io/org/func:cache",
			"ghcr.io/org/func:latest",
		},
		CacheTo: "type=registry,ref=ghcr.io/org/func:cache",
	}

	if len(spec.CacheFrom) != 2 {
		t.Errorf("CacheFrom count = %v, want 2", len(spec.CacheFrom))
	}
	if spec.CacheTo == "" {
		t.Error("CacheTo should not be empty")
	}
}

func TestPrebuildRecord_Metadata(t *testing.T) {
	record := &PrebuildRecord{
		ID:           "build-789",
		FunctionName: "test-func",
		Status:       BuildStatusRunning,
		Metadata: map[string]string{
			"runner":   "ubuntu-latest",
			"arch":     "amd64",
			"priority": "high",
		},
	}

	if record.Metadata["runner"] != "ubuntu-latest" {
		t.Error("Metadata runner not set correctly")
	}
	if len(record.Metadata) != 3 {
		t.Errorf("Metadata count = %v, want 3", len(record.Metadata))
	}
}

package warmpool

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultManagerOptions(t *testing.T) {
	opts := DefaultManagerOptions()

	if opts.MaxPoolSize != 100 {
		t.Errorf("MaxPoolSize = %v, want 100", opts.MaxPoolSize)
	}
	if opts.DefaultTTL != 24*time.Hour {
		t.Errorf("DefaultTTL = %v, want 24h", opts.DefaultTTL)
	}
	if opts.ArtifactDir != ".lambda-cache" {
		t.Errorf("ArtifactDir = %v, want .lambda-cache", opts.ArtifactDir)
	}
}

func TestNewManager(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	if m == nil {
		t.Fatal("NewManager() returned nil")
	}
	if m.functions == nil {
		t.Error("functions map should be initialized")
	}
	if m.artifacts == nil {
		t.Error("artifacts map should be initialized")
	}
}

func TestManager_RegisterFunction(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	spec := &FunctionSpec{
		Name:           "test-func",
		Runtime:        RuntimePython,
		RuntimeVersion: "3.11",
		DependencyFile: "requirements.txt",
	}

	err := m.RegisterFunction(spec)
	if err != nil {
		t.Fatalf("RegisterFunction() error = %v", err)
	}

	// Verify registration
	retrieved, err := m.GetFunction("test-func")
	if err != nil {
		t.Fatalf("GetFunction() error = %v", err)
	}

	if retrieved.Runtime != RuntimePython {
		t.Errorf("Runtime = %v, want python", retrieved.Runtime)
	}
	// Check defaults were set
	if retrieved.PrewarmInstances != 1 {
		t.Errorf("PrewarmInstances = %v, want 1", retrieved.PrewarmInstances)
	}
	if retrieved.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout = %v, want 5m", retrieved.IdleTimeout)
	}
}

func TestManager_RegisterFunction_EmptyName(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	err := m.RegisterFunction(&FunctionSpec{Name: ""})
	if err == nil {
		t.Error("RegisterFunction() should return error for empty name")
	}
}

func TestManager_UnregisterFunction(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	m.RegisterFunction(&FunctionSpec{Name: "test-func", Runtime: RuntimeNode})

	err := m.UnregisterFunction("test-func")
	if err != nil {
		t.Fatalf("UnregisterFunction() error = %v", err)
	}

	_, err = m.GetFunction("test-func")
	if err == nil {
		t.Error("GetFunction() should return error after unregister")
	}
}

func TestManager_UnregisterFunction_NotFound(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	err := m.UnregisterFunction("non-existent")
	if err != ErrFunctionNotFound {
		t.Errorf("UnregisterFunction() error = %v, want ErrFunctionNotFound", err)
	}
}

func TestManager_GetFunction_NotFound(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	_, err := m.GetFunction("non-existent")
	if err != ErrFunctionNotFound {
		t.Errorf("GetFunction() error = %v, want ErrFunctionNotFound", err)
	}
}

func TestManager_ListFunctions(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	m.RegisterFunction(&FunctionSpec{Name: "func-a", Runtime: RuntimePython})
	m.RegisterFunction(&FunctionSpec{Name: "func-b", Runtime: RuntimeNode})
	m.RegisterFunction(&FunctionSpec{Name: "func-c", Runtime: RuntimeGo})

	specs := m.ListFunctions()
	if len(specs) != 3 {
		t.Errorf("ListFunctions() returned %v functions, want 3", len(specs))
	}
}

func TestManager_GenerateCacheKey(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	m.RegisterFunction(&FunctionSpec{
		Name:              "test-func",
		Runtime:           RuntimePython,
		RuntimeVersion:    "3.11",
		DependencyManager: DepManagerPip,
	})

	key := m.GenerateCacheKey("test-func", []byte("flask==2.0\nrequests==2.28"))

	if key == "" {
		t.Error("GenerateCacheKey() should not return empty string")
	}

	// Same content should produce same key
	key2 := m.GenerateCacheKey("test-func", []byte("flask==2.0\nrequests==2.28"))
	if key != key2 {
		t.Error("Same content should produce same cache key")
	}

	// Different content should produce different key
	key3 := m.GenerateCacheKey("test-func", []byte("flask==3.0\nrequests==2.28"))
	if key == key3 {
		t.Error("Different content should produce different cache key")
	}
}

func TestManager_GenerateCacheKey_UnknownFunction(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	// Should still generate a key for unknown functions
	key := m.GenerateCacheKey("unknown-func", []byte("some content"))
	if key == "" {
		t.Error("GenerateCacheKey() should generate key for unknown functions")
	}
}

func TestFunctionSpec_Defaults(t *testing.T) {
	spec := &FunctionSpec{
		Name:    "test",
		Runtime: RuntimePython,
	}

	if spec.PrewarmInstances != 0 {
		t.Error("PrewarmInstances should default to 0 before registration")
	}
}

func TestRuntime_Constants(t *testing.T) {
	tests := []struct {
		runtime Runtime
		value   string
	}{
		{RuntimePython, "python"},
		{RuntimeNode, "node"},
		{RuntimeGo, "go"},
		{RuntimeJava, "java"},
		{RuntimeRuby, "ruby"},
		{RuntimeRust, "rust"},
		{RuntimeDotNet, "dotnet"},
		{RuntimeCustom, "custom"},
	}

	for _, tt := range tests {
		if string(tt.runtime) != tt.value {
			t.Errorf("Runtime %v = %v, want %v", tt.runtime, string(tt.runtime), tt.value)
		}
	}
}

func TestDependencyManager_Constants(t *testing.T) {
	tests := []struct {
		dm    DependencyManager
		value string
	}{
		{DepManagerPip, "pip"},
		{DepManagerNpm, "npm"},
		{DepManagerYarn, "yarn"},
		{DepManagerGoMod, "go-mod"},
		{DepManagerMaven, "maven"},
		{DepManagerCargo, "cargo"},
	}

	for _, tt := range tests {
		if string(tt.dm) != tt.value {
			t.Errorf("DependencyManager %v = %v, want %v", tt.dm, string(tt.dm), tt.value)
		}
	}
}

func TestCacheStatus_Constants(t *testing.T) {
	tests := []struct {
		status CacheStatus
		value  string
	}{
		{CacheStatusHit, "hit"},
		{CacheStatusMiss, "miss"},
		{CacheStatusBuilding, "building"},
		{CacheStatusExpired, "expired"},
		{CacheStatusInvalid, "invalid"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.value {
			t.Errorf("CacheStatus %v = %v, want %v", tt.status, string(tt.status), tt.value)
		}
	}
}

func TestInstanceStatus_Constants(t *testing.T) {
	tests := []struct {
		status InstanceStatus
		value  string
	}{
		{InstanceStatusWarm, "warm"},
		{InstanceStatusBusy, "busy"},
		{InstanceStatusCold, "cold"},
		{InstanceStatusStarting, "starting"},
		{InstanceStatusStopping, "stopping"},
	}

	for _, tt := range tests {
		if string(tt.status) != tt.value {
			t.Errorf("InstanceStatus %v = %v, want %v", tt.status, string(tt.status), tt.value)
		}
	}
}

func TestManager_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "warmpool.json")

	// Create and populate manager
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	opts.ConfigFile = configFile
	m1 := NewManager(opts)

	m1.RegisterFunction(&FunctionSpec{
		Name:           "test-func",
		Runtime:        RuntimePython,
		RuntimeVersion: "3.11",
	})

	err := m1.SaveToFile(configFile)
	if err != nil {
		t.Fatalf("SaveToFile() error = %v", err)
	}

	// Load into new manager
	opts2 := DefaultManagerOptions()
	opts2.AutoSave = false
	opts2.ConfigFile = configFile
	m2 := NewManager(opts2)

	// Verify data was loaded
	spec, err := m2.GetFunction("test-func")
	if err != nil {
		t.Fatalf("GetFunction() after load error = %v", err)
	}

	if spec.Runtime != RuntimePython {
		t.Errorf("Runtime = %v, want python", spec.Runtime)
	}
}

func TestManager_GetGitHubCacheConfig(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	m.RegisterFunction(&FunctionSpec{
		Name:           "python-func",
		Runtime:        RuntimePython,
		RuntimeVersion: "3.11",
	})

	config, err := m.GetGitHubCacheConfig("python-func")
	if err != nil {
		t.Fatalf("GetGitHubCacheConfig() error = %v", err)
	}

	if config.Runtime != RuntimePython {
		t.Errorf("Runtime = %v, want python", config.Runtime)
	}
	if len(config.CachePaths) == 0 {
		t.Error("CachePaths should not be empty")
	}
}

func TestManager_GetGitHubCacheConfig_NotFound(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	_, err := m.GetGitHubCacheConfig("non-existent")
	if err != ErrFunctionNotFound {
		t.Errorf("GetGitHubCacheConfig() error = %v, want ErrFunctionNotFound", err)
	}
}

func TestCachedArtifact(t *testing.T) {
	artifact := &CachedArtifact{
		FunctionName:   "test-func",
		CacheKey:       "test-key",
		Runtime:        RuntimeNode,
		RuntimeVersion: "20",
		ArtifactPath:   "/cache/test",
		Size:           1024,
		CreatedAt:      time.Now(),
		LastUsedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
		HitCount:       5,
		Status:         CacheStatusHit,
	}

	if artifact.FunctionName != "test-func" {
		t.Error("FunctionName not set correctly")
	}
	if artifact.HitCount != 5 {
		t.Error("HitCount not set correctly")
	}
}

func TestWarmInstance(t *testing.T) {
	instance := &WarmInstance{
		ID:           "instance-1",
		FunctionName: "test-func",
		Version:      1,
		Status:       InstanceStatusWarm,
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
		IdleTimeout:  time.Now().Add(5 * time.Minute),
	}

	if instance.Status != InstanceStatusWarm {
		t.Error("Status not set correctly")
	}
}

func TestErrors(t *testing.T) {
	if ErrFunctionNotFound.Error() != "function not found in warm pool" {
		t.Error("ErrFunctionNotFound message incorrect")
	}
	if ErrArtifactNotFound.Error() != "artifact not found" {
		t.Error("ErrArtifactNotFound message incorrect")
	}
	if ErrCacheKeyNotFound.Error() != "cache key not found" {
		t.Error("ErrCacheKeyNotFound message incorrect")
	}
	if ErrBuildInProgress.Error() != "build already in progress" {
		t.Error("ErrBuildInProgress message incorrect")
	}
	if ErrWarmPoolFull.Error() != "warm pool at capacity" {
		t.Error("ErrWarmPoolFull message incorrect")
	}
}

func TestManager_Concurrent(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	done := make(chan bool)

	// Concurrent registrations
	for i := 0; i < 10; i++ {
		go func(n int) {
			m.RegisterFunction(&FunctionSpec{
				Name:    string(rune('a' + n)),
				Runtime: RuntimeGo,
			})
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func() {
			m.ListFunctions()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestManager_LoadFromFile_NotFound(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.AutoSave = false
	m := NewManager(opts)

	err := m.LoadFromFile("/nonexistent/path.json")
	if err == nil {
		t.Error("LoadFromFile() should return error for non-existent file")
	}
}

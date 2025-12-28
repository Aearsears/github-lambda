package cache

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCacheEntry_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		entry   *CacheEntry
		expired bool
	}{
		{
			name: "not expired",
			entry: &CacheEntry{
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			expired: false,
		},
		{
			name: "expired",
			entry: &CacheEntry{
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			expired: true,
		},
		{
			name: "exactly now",
			entry: &CacheEntry{
				ExpiresAt: time.Now(),
			},
			expired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entry.IsExpired(); got != tt.expired {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expired)
			}
		})
	}
}

func TestDefaultCacheConfig(t *testing.T) {
	config := DefaultCacheConfig()

	if !config.Enabled {
		t.Error("Default config should be enabled")
	}
	if config.TTL != 5*time.Minute {
		t.Errorf("Default TTL = %v, want 5m", config.TTL)
	}
	if config.MaxEntries != 1000 {
		t.Errorf("Default MaxEntries = %v, want 1000", config.MaxEntries)
	}
	if config.CacheErrors {
		t.Error("Default CacheErrors should be false")
	}
}

func TestNewCache(t *testing.T) {
	cache := NewCache(1000, 5*time.Minute)
	defer cache.Close()

	if cache == nil {
		t.Fatal("NewCache() returned nil")
	}
}

func TestCache_SetAndGet(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	response := json.RawMessage(`{"result": "success"}`)

	// Set
	entry, err := cache.Set("test-function", 1, "test-input", response, 200, nil)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if entry == nil {
		t.Fatal("Set() returned nil entry")
	}
	if entry.FunctionName != "test-function" {
		t.Errorf("FunctionName = %v, want test-function", entry.FunctionName)
	}

	// Get
	retrieved, err := cache.Get("test-function", 1, "test-input")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(retrieved.Response) != `{"result": "success"}` {
		t.Errorf("Response = %v, want {\"result\": \"success\"}", string(retrieved.Response))
	}

	// Get non-existent
	_, err = cache.Get("test-function", 1, "non-existent-input")
	if err != ErrCacheMiss {
		t.Errorf("Get() error = %v, want ErrCacheMiss", err)
	}
}

func TestCache_GetByKey(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	response := json.RawMessage(`{"data": "test"}`)
	entry, _ := cache.Set("test-func", 1, "input", response, 200, nil)

	retrieved, err := cache.GetByKey(entry.Key)
	if err != nil {
		t.Fatalf("GetByKey() error = %v", err)
	}

	if string(retrieved.Response) != `{"data": "test"}` {
		t.Error("Response mismatch")
	}
}

func TestCache_Invalidate(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	// Add entries
	cache.Set("func1", 1, "input1", json.RawMessage(`{}`), 200, nil)
	cache.Set("func1", 1, "input2", json.RawMessage(`{}`), 200, nil)
	cache.Set("func2", 1, "input3", json.RawMessage(`{}`), 200, nil)

	// Invalidate by function
	invalidated := cache.InvalidateFunction("func1")
	if invalidated != 2 {
		t.Errorf("InvalidateFunction() = %v, want 2", invalidated)
	}

	// Verify func1 entries are gone
	_, err := cache.Get("func1", 1, "input1")
	if err != ErrCacheMiss {
		t.Error("func1 input1 should be invalidated")
	}

	// Verify func2 entry still exists
	_, err = cache.Get("func2", 1, "input3")
	if err != nil {
		t.Error("func2 entry should still exist")
	}
}

func TestCache_InvalidateByInput(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	cache.Set("func1", 1, "input1", json.RawMessage(`{}`), 200, nil)
	cache.Set("func1", 1, "input2", json.RawMessage(`{}`), 200, nil)

	removed, err := cache.InvalidateByInput("func1", 1, "input1")
	if err != nil {
		t.Fatalf("InvalidateByInput() error = %v", err)
	}
	if !removed {
		t.Error("InvalidateByInput() should return true")
	}

	// Verify input1 is gone
	_, err = cache.Get("func1", 1, "input1")
	if err != ErrCacheMiss {
		t.Error("input1 should be invalidated")
	}

	// Verify input2 still exists
	_, err = cache.Get("func1", 1, "input2")
	if err != nil {
		t.Error("input2 should still exist")
	}
}

func TestCache_InvalidateAll(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	// Add entries
	cache.Set("func1", 1, "input1", json.RawMessage(`{}`), 200, nil)
	cache.Set("func2", 1, "input2", json.RawMessage(`{}`), 200, nil)
	cache.Set("func3", 1, "input3", json.RawMessage(`{}`), 200, nil)

	// Invalidate all
	invalidated := cache.InvalidateAll()
	if invalidated != 3 {
		t.Errorf("InvalidateAll() = %v, want 3", invalidated)
	}

	// Verify
	stats := cache.Stats()
	if stats.TotalEntries != 0 {
		t.Errorf("TotalEntries = %v, want 0", stats.TotalEntries)
	}
}

func TestCache_Stats(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	// Add entries
	cache.Set("func1", 1, "input1", json.RawMessage(`{}`), 200, nil)
	cache.Set("func1", 1, "input2", json.RawMessage(`{}`), 200, nil)
	cache.Set("func2", 1, "input3", json.RawMessage(`{}`), 200, nil)

	// Get (hit)
	cache.Get("func1", 1, "input1")
	cache.Get("func1", 1, "input1")

	// Get (miss)
	cache.Get("func1", 1, "non-existent")

	stats := cache.Stats()
	if stats.TotalEntries != 3 {
		t.Errorf("TotalEntries = %v, want 3", stats.TotalEntries)
	}
	if stats.TotalHits != 2 {
		t.Errorf("TotalHits = %v, want 2", stats.TotalHits)
	}
	if stats.TotalMisses != 1 {
		t.Errorf("TotalMisses = %v, want 1", stats.TotalMisses)
	}
}

func TestCache_SetConfig(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	config := CacheConfig{
		Enabled:    true,
		TTL:        10 * time.Minute,
		MaxEntries: 500,
	}

	cache.SetConfig("test-func", config)
	retrieved := cache.GetConfig("test-func")

	if retrieved.TTL != 10*time.Minute {
		t.Errorf("Config TTL = %v, want 10m", retrieved.TTL)
	}
	if retrieved.MaxEntries != 500 {
		t.Errorf("Config MaxEntries = %v, want 500", retrieved.MaxEntries)
	}
}

func TestCache_DeleteConfig(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	customConfig := CacheConfig{
		Enabled:    true,
		TTL:        10 * time.Minute,
		MaxEntries: 500,
	}

	cache.SetConfig("test-func", customConfig)
	cache.DeleteConfig("test-func")

	// Should return default config after deletion
	retrieved := cache.GetConfig("test-func")
	if retrieved.TTL != 5*time.Minute {
		t.Errorf("After delete, Config TTL = %v, want default 5m", retrieved.TTL)
	}
}

func TestCache_SetWithTTL(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	entry, err := cache.SetWithTTL("test-func", 1, "input", json.RawMessage(`{}`), 200, 1*time.Hour, nil)
	if err != nil {
		t.Fatalf("SetWithTTL() error = %v", err)
	}

	if entry.TTL != 1*time.Hour {
		t.Errorf("TTL = %v, want 1h", entry.TTL)
	}
}

func TestCache_SetWithTTL_InvalidTTL(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	_, err := cache.SetWithTTL("test-func", 1, "input", json.RawMessage(`{}`), 200, 0, nil)
	if err != ErrInvalidTTL {
		t.Errorf("SetWithTTL() with TTL=0 error = %v, want ErrInvalidTTL", err)
	}

	_, err = cache.SetWithTTL("test-func", 1, "input", json.RawMessage(`{}`), 200, -1*time.Hour, nil)
	if err != ErrInvalidTTL {
		t.Errorf("SetWithTTL() with negative TTL error = %v, want ErrInvalidTTL", err)
	}
}

func TestCache_Metadata(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	metadata := map[string]string{
		"source":  "test",
		"version": "1.0",
	}

	cache.Set("func1", 1, "input1", json.RawMessage(`{}`), 200, metadata)

	entry, err := cache.Get("func1", 1, "input1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if entry.Metadata["source"] != "test" {
		t.Error("Metadata 'source' not preserved")
	}
	if entry.Metadata["version"] != "1.0" {
		t.Error("Metadata 'version' not preserved")
	}
}

func TestCache_HitCount(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	cache.Set("func1", 1, "input1", json.RawMessage(`{}`), 200, nil)

	// Multiple gets should increment hit count
	for i := 0; i < 5; i++ {
		cache.Get("func1", 1, "input1")
	}

	entry, _ := cache.Get("func1", 1, "input1")
	if entry.HitCount != 6 { // 5 + 1 for the final get
		t.Errorf("HitCount = %v, want 6", entry.HitCount)
	}
}

func TestCache_DisabledConfig(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	cache.SetConfig("disabled-func", CacheConfig{
		Enabled: false,
	})

	// Set should return error when caching is disabled
	_, err := cache.Set("disabled-func", 1, "input", json.RawMessage(`{}`), 200, nil)
	if err != ErrCacheDisabled {
		t.Errorf("Set() on disabled cache error = %v, want ErrCacheDisabled", err)
	}

	// Get should return error when caching is disabled
	_, err = cache.Get("disabled-func", 1, "input")
	if err != ErrCacheDisabled {
		t.Errorf("Get() on disabled cache error = %v, want ErrCacheDisabled", err)
	}
}

func TestCache_ErrorCaching(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	// By default, errors should not be cached
	entry, err := cache.Set("func1", 1, "input", json.RawMessage(`{"error": "test"}`), 500, nil)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if entry != nil {
		t.Error("Error response should not be cached by default")
	}

	// Enable error caching
	cache.SetConfig("func1", CacheConfig{
		Enabled:     true,
		TTL:         5 * time.Minute,
		MaxEntries:  1000,
		CacheErrors: true,
		ErrorTTL:    30 * time.Second,
	})

	// Now errors should be cached
	entry, err = cache.Set("func1", 1, "input", json.RawMessage(`{"error": "test"}`), 500, nil)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if entry == nil {
		t.Error("Error response should be cached when CacheErrors=true")
	}
	if entry != nil && entry.TTL != 30*time.Second {
		t.Errorf("Error response TTL = %v, want 30s", entry.TTL)
	}
}

func TestCache_InvalidateFunctionVersion(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	cache.Set("func1", 1, "input1", json.RawMessage(`{}`), 200, nil)
	cache.Set("func1", 2, "input2", json.RawMessage(`{}`), 200, nil)
	cache.Set("func1", 1, "input3", json.RawMessage(`{}`), 200, nil)

	// Invalidate only version 1
	invalidated := cache.InvalidateFunctionVersion("func1", 1)
	if invalidated != 2 {
		t.Errorf("InvalidateFunctionVersion() = %v, want 2", invalidated)
	}

	// Version 1 entries should be gone
	_, err := cache.Get("func1", 1, "input1")
	if err != ErrCacheMiss {
		t.Error("func1 v1 input1 should be invalidated")
	}

	// Version 2 should still exist
	_, err = cache.Get("func1", 2, "input2")
	if err != nil {
		t.Error("func1 v2 should still exist")
	}
}

func TestGenerateKey(t *testing.T) {
	// Same inputs should generate same key
	key1, err := GenerateKey("func1", 1, "input")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	key2, err := GenerateKey("func1", 1, "input")
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if key1 != key2 {
		t.Error("Same inputs should generate same key")
	}

	// Different inputs should generate different keys
	key3, _ := GenerateKey("func1", 1, "different-input")
	if key1 == key3 {
		t.Error("Different inputs should generate different keys")
	}

	key4, _ := GenerateKey("func2", 1, "input")
	if key1 == key4 {
		t.Error("Different function names should generate different keys")
	}

	key5, _ := GenerateKey("func1", 2, "input")
	if key1 == key5 {
		t.Error("Different versions should generate different keys")
	}
}

func TestHashInput(t *testing.T) {
	hash1, err := HashInput("test-input")
	if err != nil {
		t.Fatalf("HashInput() error = %v", err)
	}

	hash2, err := HashInput("test-input")
	if err != nil {
		t.Fatalf("HashInput() error = %v", err)
	}

	if hash1 != hash2 {
		t.Error("Same inputs should generate same hash")
	}

	hash3, _ := HashInput("different-input")
	if hash1 == hash3 {
		t.Error("Different inputs should generate different hashes")
	}
}

func TestCacheStats_HitRate(t *testing.T) {
	cache := NewCache(100, 5*time.Minute)
	defer cache.Close()

	cache.Set("func1", 1, "input1", json.RawMessage(`{}`), 200, nil)

	// 2 hits
	cache.Get("func1", 1, "input1")
	cache.Get("func1", 1, "input1")
	// 2 misses
	cache.Get("func1", 1, "missing1")
	cache.Get("func1", 1, "missing2")

	stats := cache.Stats()

	expectedHitRate := float64(2) / float64(4)
	if stats.HitRate < expectedHitRate-0.01 || stats.HitRate > expectedHitRate+0.01 {
		t.Errorf("HitRate = %v, want %v", stats.HitRate, expectedHitRate)
	}
}

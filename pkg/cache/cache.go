package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/github-lambda/pkg/logging"
)

var logger = logging.New("cache")

// Common errors
var (
	ErrCacheMiss     = errors.New("cache miss")
	ErrCacheDisabled = errors.New("caching disabled for this function")
	ErrInvalidTTL    = errors.New("invalid TTL value")
)

// CacheEntry represents a cached function response.
type CacheEntry struct {
	// Key is the cache key (hash of function name + input).
	Key string `json:"key"`

	// FunctionName is the name of the function that produced this result.
	FunctionName string `json:"function_name"`

	// Version is the function version that produced this result.
	Version int `json:"version,omitempty"`

	// InputHash is the hash of the input payload.
	InputHash string `json:"input_hash"`

	// Response is the cached function response.
	Response json.RawMessage `json:"response"`

	// StatusCode is the HTTP status code of the original response.
	StatusCode int `json:"status_code"`

	// CreatedAt is when this entry was cached.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when this entry expires.
	ExpiresAt time.Time `json:"expires_at"`

	// TTL is the time-to-live duration for this entry.
	TTL time.Duration `json:"ttl"`

	// HitCount tracks how many times this entry was retrieved.
	HitCount int64 `json:"hit_count"`

	// LastAccessedAt is when this entry was last accessed.
	LastAccessedAt time.Time `json:"last_accessed_at"`

	// Metadata contains additional information about the cached response.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// IsExpired checks if the cache entry has expired.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// CacheConfig holds configuration for a function's caching behavior.
type CacheConfig struct {
	// Enabled determines if caching is enabled for this function.
	Enabled bool `json:"enabled"`

	// TTL is the default time-to-live for cached responses.
	TTL time.Duration `json:"ttl"`

	// MaxEntries is the maximum number of entries to cache for this function.
	MaxEntries int `json:"max_entries"`

	// CacheErrors determines if error responses should be cached.
	CacheErrors bool `json:"cache_errors"`

	// ErrorTTL is the TTL for cached error responses (usually shorter).
	ErrorTTL time.Duration `json:"error_ttl,omitempty"`

	// VaryByHeaders specifies headers to include in cache key generation.
	VaryByHeaders []string `json:"vary_by_headers,omitempty"`

	// ExcludePayloadFields specifies payload fields to exclude from hash.
	ExcludePayloadFields []string `json:"exclude_payload_fields,omitempty"`
}

// DefaultCacheConfig returns a default cache configuration.
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		Enabled:     true,
		TTL:         5 * time.Minute,
		MaxEntries:  1000,
		CacheErrors: false,
		ErrorTTL:    30 * time.Second,
	}
}

// CacheStats holds statistics for the cache.
type CacheStats struct {
	// TotalEntries is the total number of entries in the cache.
	TotalEntries int `json:"total_entries"`

	// TotalHits is the total number of cache hits.
	TotalHits int64 `json:"total_hits"`

	// TotalMisses is the total number of cache misses.
	TotalMisses int64 `json:"total_misses"`

	// TotalEvictions is the total number of evictions.
	TotalEvictions int64 `json:"total_evictions"`

	// TotalInvalidations is the total number of manual invalidations.
	TotalInvalidations int64 `json:"total_invalidations"`

	// HitRate is the cache hit rate (hits / (hits + misses)).
	HitRate float64 `json:"hit_rate"`

	// MemoryUsageBytes is an estimate of memory usage.
	MemoryUsageBytes int64 `json:"memory_usage_bytes"`

	// OldestEntry is the timestamp of the oldest entry.
	OldestEntry *time.Time `json:"oldest_entry,omitempty"`

	// NewestEntry is the timestamp of the newest entry.
	NewestEntry *time.Time `json:"newest_entry,omitempty"`

	// PerFunction holds per-function statistics.
	PerFunction map[string]*FunctionCacheStats `json:"per_function,omitempty"`
}

// FunctionCacheStats holds per-function cache statistics.
type FunctionCacheStats struct {
	Entries   int     `json:"entries"`
	Hits      int64   `json:"hits"`
	Misses    int64   `json:"misses"`
	HitRate   float64 `json:"hit_rate"`
	AvgTTL    float64 `json:"avg_ttl_seconds"`
	TotalSize int64   `json:"total_size_bytes"`
}

// Cache provides result caching for function invocations.
type Cache struct {
	mu sync.RWMutex

	// entries stores cached results by key.
	entries map[string]*CacheEntry

	// functionIndex maps function names to their cache keys.
	functionIndex map[string]map[string]struct{}

	// configs stores per-function cache configurations.
	configs map[string]CacheConfig

	// defaultConfig is the default cache configuration.
	defaultConfig CacheConfig

	// maxTotalEntries is the maximum total entries across all functions.
	maxTotalEntries int

	// stats tracks cache statistics.
	hits          int64
	misses        int64
	evictions     int64
	invalidations int64

	// cleanupInterval is how often to run cleanup.
	cleanupInterval time.Duration

	// stopCleanup signals the cleanup goroutine to stop.
	stopCleanup chan struct{}
}

// NewCache creates a new result cache.
func NewCache(maxTotalEntries int, defaultTTL time.Duration) *Cache {
	c := &Cache{
		entries:       make(map[string]*CacheEntry),
		functionIndex: make(map[string]map[string]struct{}),
		configs:       make(map[string]CacheConfig),
		defaultConfig: CacheConfig{
			Enabled:     true,
			TTL:         defaultTTL,
			MaxEntries:  1000,
			CacheErrors: false,
			ErrorTTL:    30 * time.Second,
		},
		maxTotalEntries: maxTotalEntries,
		cleanupInterval: time.Minute,
		stopCleanup:     make(chan struct{}),
	}

	// Start background cleanup
	go c.cleanupLoop()

	return c
}

// cleanupLoop periodically removes expired entries.
func (c *Cache) cleanupLoop() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCleanup:
			return
		}
	}
}

// cleanup removes expired entries.
func (c *Cache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var expired []string

	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			expired = append(expired, key)
		}
	}

	for _, key := range expired {
		c.removeEntryLocked(key)
		c.evictions++
	}

	if len(expired) > 0 {
		logger.Debug("cleaned up expired cache entries", logging.Fields{
			"expired_count": len(expired),
			"remaining":     len(c.entries),
		})
	}
}

// Close stops the cache cleanup goroutine.
func (c *Cache) Close() {
	close(c.stopCleanup)
}

// GenerateKey generates a cache key from function name, version, and input.
func GenerateKey(functionName string, version int, input interface{}) (string, error) {
	// Serialize input to JSON for consistent hashing
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return "", err
	}

	return GenerateKeyFromBytes(functionName, version, inputBytes), nil
}

// GenerateKeyFromBytes generates a cache key from function name, version, and raw input bytes.
func GenerateKeyFromBytes(functionName string, version int, inputBytes []byte) string {
	// Create hash of function name + version + input
	h := sha256.New()
	h.Write([]byte(functionName))
	h.Write([]byte{byte(version >> 8), byte(version)})
	h.Write(inputBytes)
	hash := hex.EncodeToString(h.Sum(nil))

	return hash[:32] // Use first 32 chars for shorter keys
}

// HashInput creates a hash of the input payload.
func HashInput(input interface{}) (string, error) {
	inputBytes, err := json.Marshal(input)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	h.Write(inputBytes)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SetConfig sets the cache configuration for a specific function.
func (c *Cache) SetConfig(functionName string, config CacheConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.configs[functionName] = config

	logger.Info("cache config updated", logging.Fields{
		"function_name": functionName,
		"enabled":       config.Enabled,
		"ttl":           config.TTL.String(),
		"max_entries":   config.MaxEntries,
	})
}

// GetConfig gets the cache configuration for a function.
func (c *Cache) GetConfig(functionName string) CacheConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if config, exists := c.configs[functionName]; exists {
		return config
	}
	return c.defaultConfig
}

// DeleteConfig removes the custom cache configuration for a function.
func (c *Cache) DeleteConfig(functionName string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.configs, functionName)
}

// Get retrieves a cached response.
func (c *Cache) Get(functionName string, version int, input interface{}) (*CacheEntry, error) {
	config := c.GetConfig(functionName)
	if !config.Enabled {
		return nil, ErrCacheDisabled
	}

	key, err := GenerateKey(functionName, version, input)
	if err != nil {
		return nil, err
	}

	return c.GetByKey(key)
}

// GetByKey retrieves a cached response by key.
func (c *Cache) GetByKey(key string) (*CacheEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[key]
	if !exists {
		c.misses++
		return nil, ErrCacheMiss
	}

	// Check if expired
	if entry.IsExpired() {
		c.removeEntryLocked(key)
		c.misses++
		c.evictions++
		return nil, ErrCacheMiss
	}

	// Update access stats
	entry.HitCount++
	entry.LastAccessedAt = time.Now()
	c.hits++

	logger.Debug("cache hit", logging.Fields{
		"key":           key,
		"function_name": entry.FunctionName,
		"hit_count":     entry.HitCount,
	})

	return entry, nil
}

// Set stores a response in the cache.
func (c *Cache) Set(functionName string, version int, input interface{}, response json.RawMessage, statusCode int, metadata map[string]string) (*CacheEntry, error) {
	config := c.GetConfig(functionName)
	if !config.Enabled {
		return nil, ErrCacheDisabled
	}

	// Don't cache errors unless configured to do so
	if statusCode >= 400 && !config.CacheErrors {
		return nil, nil
	}

	key, err := GenerateKey(functionName, version, input)
	if err != nil {
		return nil, err
	}

	inputHash, err := HashInput(input)
	if err != nil {
		return nil, err
	}

	ttl := config.TTL
	if statusCode >= 400 && config.CacheErrors {
		ttl = config.ErrorTTL
	}

	now := time.Now()
	entry := &CacheEntry{
		Key:            key,
		FunctionName:   functionName,
		Version:        version,
		InputHash:      inputHash,
		Response:       response,
		StatusCode:     statusCode,
		CreatedAt:      now,
		ExpiresAt:      now.Add(ttl),
		TTL:            ttl,
		HitCount:       0,
		LastAccessedAt: now,
		Metadata:       metadata,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check function-specific entry limit
	if idx, exists := c.functionIndex[functionName]; exists {
		if len(idx) >= config.MaxEntries {
			c.evictOldestForFunctionLocked(functionName)
		}
	}

	// Check total entry limit
	if len(c.entries) >= c.maxTotalEntries {
		c.evictOldestLocked()
	}

	// Store entry
	c.entries[key] = entry

	// Update function index
	if c.functionIndex[functionName] == nil {
		c.functionIndex[functionName] = make(map[string]struct{})
	}
	c.functionIndex[functionName][key] = struct{}{}

	logger.Debug("cache set", logging.Fields{
		"key":           key,
		"function_name": functionName,
		"version":       version,
		"ttl":           ttl.String(),
		"status_code":   statusCode,
	})

	return entry, nil
}

// SetWithTTL stores a response with a custom TTL.
func (c *Cache) SetWithTTL(functionName string, version int, input interface{}, response json.RawMessage, statusCode int, ttl time.Duration, metadata map[string]string) (*CacheEntry, error) {
	if ttl <= 0 {
		return nil, ErrInvalidTTL
	}

	key, err := GenerateKey(functionName, version, input)
	if err != nil {
		return nil, err
	}

	inputHash, err := HashInput(input)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	entry := &CacheEntry{
		Key:            key,
		FunctionName:   functionName,
		Version:        version,
		InputHash:      inputHash,
		Response:       response,
		StatusCode:     statusCode,
		CreatedAt:      now,
		ExpiresAt:      now.Add(ttl),
		TTL:            ttl,
		HitCount:       0,
		LastAccessedAt: now,
		Metadata:       metadata,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check total entry limit
	if len(c.entries) >= c.maxTotalEntries {
		c.evictOldestLocked()
	}

	// Store entry
	c.entries[key] = entry

	// Update function index
	if c.functionIndex[functionName] == nil {
		c.functionIndex[functionName] = make(map[string]struct{})
	}
	c.functionIndex[functionName][key] = struct{}{}

	return entry, nil
}

// Invalidate removes a specific cache entry.
func (c *Cache) Invalidate(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[key]; !exists {
		return false
	}

	c.removeEntryLocked(key)
	c.invalidations++

	logger.Info("cache entry invalidated", logging.Fields{"key": key})
	return true
}

// InvalidateByInput removes a cache entry by function name and input.
func (c *Cache) InvalidateByInput(functionName string, version int, input interface{}) (bool, error) {
	key, err := GenerateKey(functionName, version, input)
	if err != nil {
		return false, err
	}

	return c.Invalidate(key), nil
}

// InvalidateFunction removes all cache entries for a function.
func (c *Cache) InvalidateFunction(functionName string) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	keys, exists := c.functionIndex[functionName]
	if !exists {
		return 0
	}

	count := 0
	for key := range keys {
		c.removeEntryLocked(key)
		count++
	}

	c.invalidations += int64(count)

	logger.Info("function cache invalidated", logging.Fields{
		"function_name": functionName,
		"entries":       count,
	})

	return count
}

// InvalidateFunctionVersion removes cache entries for a specific function version.
func (c *Cache) InvalidateFunctionVersion(functionName string, version int) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	keys, exists := c.functionIndex[functionName]
	if !exists {
		return 0
	}

	var toRemove []string
	for key := range keys {
		if entry, ok := c.entries[key]; ok && entry.Version == version {
			toRemove = append(toRemove, key)
		}
	}

	for _, key := range toRemove {
		c.removeEntryLocked(key)
	}

	c.invalidations += int64(len(toRemove))

	logger.Info("function version cache invalidated", logging.Fields{
		"function_name": functionName,
		"version":       version,
		"entries":       len(toRemove),
	})

	return len(toRemove)
}

// InvalidateAll clears the entire cache.
func (c *Cache) InvalidateAll() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := len(c.entries)
	c.entries = make(map[string]*CacheEntry)
	c.functionIndex = make(map[string]map[string]struct{})
	c.invalidations += int64(count)

	logger.Info("entire cache invalidated", logging.Fields{"entries": count})
	return count
}

// removeEntryLocked removes an entry (must hold lock).
func (c *Cache) removeEntryLocked(key string) {
	entry, exists := c.entries[key]
	if !exists {
		return
	}

	delete(c.entries, key)

	// Update function index
	if idx, ok := c.functionIndex[entry.FunctionName]; ok {
		delete(idx, key)
		if len(idx) == 0 {
			delete(c.functionIndex, entry.FunctionName)
		}
	}
}

// evictOldestLocked evicts the oldest entry (must hold lock).
func (c *Cache) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.LastAccessedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.LastAccessedAt
		}
	}

	if oldestKey != "" {
		c.removeEntryLocked(oldestKey)
		c.evictions++
	}
}

// evictOldestForFunctionLocked evicts the oldest entry for a function (must hold lock).
func (c *Cache) evictOldestForFunctionLocked(functionName string) {
	keys, exists := c.functionIndex[functionName]
	if !exists {
		return
	}

	var oldestKey string
	var oldestTime time.Time

	for key := range keys {
		if entry, ok := c.entries[key]; ok {
			if oldestKey == "" || entry.LastAccessedAt.Before(oldestTime) {
				oldestKey = key
				oldestTime = entry.LastAccessedAt
			}
		}
	}

	if oldestKey != "" {
		c.removeEntryLocked(oldestKey)
		c.evictions++
	}
}

// Stats returns cache statistics.
func (c *Cache) Stats() *CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := &CacheStats{
		TotalEntries:       len(c.entries),
		TotalHits:          c.hits,
		TotalMisses:        c.misses,
		TotalEvictions:     c.evictions,
		TotalInvalidations: c.invalidations,
		PerFunction:        make(map[string]*FunctionCacheStats),
	}

	if c.hits+c.misses > 0 {
		stats.HitRate = float64(c.hits) / float64(c.hits+c.misses)
	}

	// Calculate per-function stats and find oldest/newest
	var oldestTime, newestTime *time.Time

	for _, entry := range c.entries {
		// Track oldest/newest
		if oldestTime == nil || entry.CreatedAt.Before(*oldestTime) {
			t := entry.CreatedAt
			oldestTime = &t
		}
		if newestTime == nil || entry.CreatedAt.After(*newestTime) {
			t := entry.CreatedAt
			newestTime = &t
		}

		// Estimate memory usage (rough)
		stats.MemoryUsageBytes += int64(len(entry.Response)) + 200 // 200 for overhead

		// Per-function stats
		fs, exists := stats.PerFunction[entry.FunctionName]
		if !exists {
			fs = &FunctionCacheStats{}
			stats.PerFunction[entry.FunctionName] = fs
		}
		fs.Entries++
		fs.Hits += entry.HitCount
		fs.TotalSize += int64(len(entry.Response))
		fs.AvgTTL += entry.TTL.Seconds()
	}

	stats.OldestEntry = oldestTime
	stats.NewestEntry = newestTime

	// Calculate averages and hit rates for per-function stats
	for funcName, fs := range stats.PerFunction {
		if fs.Entries > 0 {
			fs.AvgTTL /= float64(fs.Entries)
		}
		// Get function-specific misses from index
		if keys, exists := c.functionIndex[funcName]; exists {
			total := fs.Hits + int64(len(keys))
			if total > 0 {
				fs.HitRate = float64(fs.Hits) / float64(total)
			}
		}
	}

	return stats
}

// List returns all cache entries, optionally filtered by function name.
func (c *Cache) List(functionName string, limit int) []*CacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var entries []*CacheEntry

	if functionName != "" {
		// Filter by function
		if keys, exists := c.functionIndex[functionName]; exists {
			for key := range keys {
				if entry, ok := c.entries[key]; ok {
					entries = append(entries, entry)
					if limit > 0 && len(entries) >= limit {
						break
					}
				}
			}
		}
	} else {
		// Return all entries
		for _, entry := range c.entries {
			entries = append(entries, entry)
			if limit > 0 && len(entries) >= limit {
				break
			}
		}
	}

	return entries
}

// GetEntry returns a specific cache entry by key without updating stats.
func (c *Cache) GetEntry(key string) (*CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	return entry, exists
}

// GetAllConfigs returns all function cache configurations.
func (c *Cache) GetAllConfigs() map[string]CacheConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	configs := make(map[string]CacheConfig)
	for name, config := range c.configs {
		configs[name] = config
	}
	return configs
}

// GetDefaultConfig returns the default cache configuration.
func (c *Cache) GetDefaultConfig() CacheConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.defaultConfig
}

// SetDefaultConfig sets the default cache configuration.
func (c *Cache) SetDefaultConfig(config CacheConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.defaultConfig = config
}

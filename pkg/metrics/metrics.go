package metrics

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Collector aggregates metrics for the lambda service.
type Collector struct {
	mu sync.RWMutex

	// Counters
	invocationsTotal   map[string]*atomic.Int64 // by function name
	invocationsSuccess map[string]*atomic.Int64
	invocationsFailed  map[string]*atomic.Int64
	invocationsTimeout map[string]*atomic.Int64

	// Gauges
	invocationsInFlight map[string]*atomic.Int64

	// Histograms (duration tracking)
	durations map[string]*DurationHistogram

	// System metrics
	startTime time.Time
}

// DurationHistogram tracks duration statistics.
type DurationHistogram struct {
	mu      sync.Mutex
	count   int64
	sum     float64
	min     float64
	max     float64
	buckets map[float64]*atomic.Int64 // bucket upper bound -> count
}

// Default bucket boundaries in milliseconds
var defaultBuckets = []float64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000}

// NewDurationHistogram creates a new duration histogram.
func NewDurationHistogram() *DurationHistogram {
	buckets := make(map[float64]*atomic.Int64)
	for _, b := range defaultBuckets {
		buckets[b] = &atomic.Int64{}
	}
	return &DurationHistogram{
		min:     -1,
		buckets: buckets,
	}
}

// Observe records a duration observation.
func (h *DurationHistogram) Observe(durationMs float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.count++
	h.sum += durationMs

	if h.min < 0 || durationMs < h.min {
		h.min = durationMs
	}
	if durationMs > h.max {
		h.max = durationMs
	}

	for _, bound := range defaultBuckets {
		if durationMs <= bound {
			h.buckets[bound].Add(1)
		}
	}
}

// Stats returns current histogram statistics.
func (h *DurationHistogram) Stats() DurationStats {
	h.mu.Lock()
	defer h.mu.Unlock()

	stats := DurationStats{
		Count: h.count,
		Sum:   h.sum,
		Min:   h.min,
		Max:   h.max,
	}

	if h.count > 0 {
		stats.Avg = h.sum / float64(h.count)
	}

	stats.Buckets = make(map[float64]int64)
	for bound, count := range h.buckets {
		stats.Buckets[bound] = count.Load()
	}

	return stats
}

// DurationStats represents duration histogram statistics.
type DurationStats struct {
	Count   int64             `json:"count"`
	Sum     float64           `json:"sum_ms"`
	Avg     float64           `json:"avg_ms"`
	Min     float64           `json:"min_ms"`
	Max     float64           `json:"max_ms"`
	Buckets map[float64]int64 `json:"buckets"`
}

// New creates a new metrics collector.
func New() *Collector {
	return &Collector{
		invocationsTotal:    make(map[string]*atomic.Int64),
		invocationsSuccess:  make(map[string]*atomic.Int64),
		invocationsFailed:   make(map[string]*atomic.Int64),
		invocationsTimeout:  make(map[string]*atomic.Int64),
		invocationsInFlight: make(map[string]*atomic.Int64),
		durations:           make(map[string]*DurationHistogram),
		startTime:           time.Now(),
	}
}

// Default is the global metrics collector.
var Default = New()

func (c *Collector) getOrCreateCounter(m map[string]*atomic.Int64, key string) *atomic.Int64 {
	c.mu.RLock()
	counter, exists := m[key]
	c.mu.RUnlock()

	if exists {
		return counter
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if counter, exists = m[key]; exists {
		return counter
	}

	counter = &atomic.Int64{}
	m[key] = counter
	return counter
}

func (c *Collector) getOrCreateHistogram(key string) *DurationHistogram {
	c.mu.RLock()
	hist, exists := c.durations[key]
	c.mu.RUnlock()

	if exists {
		return hist
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if hist, exists = c.durations[key]; exists {
		return hist
	}

	hist = NewDurationHistogram()
	c.durations[key] = hist
	return hist
}

// InvocationStarted records the start of a function invocation.
func (c *Collector) InvocationStarted(functionName string) {
	c.getOrCreateCounter(c.invocationsTotal, functionName).Add(1)
	c.getOrCreateCounter(c.invocationsInFlight, functionName).Add(1)
}

// InvocationCompleted records the successful completion of a function invocation.
func (c *Collector) InvocationCompleted(functionName string, durationMs float64) {
	c.getOrCreateCounter(c.invocationsSuccess, functionName).Add(1)
	c.getOrCreateCounter(c.invocationsInFlight, functionName).Add(-1)
	c.getOrCreateHistogram(functionName).Observe(durationMs)
}

// InvocationFailed records a failed function invocation.
func (c *Collector) InvocationFailed(functionName string, durationMs float64) {
	c.getOrCreateCounter(c.invocationsFailed, functionName).Add(1)
	c.getOrCreateCounter(c.invocationsInFlight, functionName).Add(-1)
	c.getOrCreateHistogram(functionName).Observe(durationMs)
}

// InvocationTimeout records a timed-out function invocation.
func (c *Collector) InvocationTimeout(functionName string, durationMs float64) {
	c.getOrCreateCounter(c.invocationsTimeout, functionName).Add(1)
	c.getOrCreateCounter(c.invocationsInFlight, functionName).Add(-1)
	c.getOrCreateHistogram(functionName).Observe(durationMs)
}

// FunctionMetrics represents metrics for a single function.
type FunctionMetrics struct {
	Name     string        `json:"name"`
	Total    int64         `json:"invocations_total"`
	Success  int64         `json:"invocations_success"`
	Failed   int64         `json:"invocations_failed"`
	Timeout  int64         `json:"invocations_timeout"`
	InFlight int64         `json:"invocations_in_flight"`
	Duration DurationStats `json:"duration"`
}

// Snapshot represents a point-in-time snapshot of all metrics.
type Snapshot struct {
	Timestamp  string            `json:"timestamp"`
	Uptime     string            `json:"uptime"`
	UptimeSecs float64           `json:"uptime_seconds"`
	Functions  []FunctionMetrics `json:"functions"`
	Totals     TotalMetrics      `json:"totals"`
}

// TotalMetrics represents aggregate metrics across all functions.
type TotalMetrics struct {
	Invocations int64 `json:"invocations_total"`
	Success     int64 `json:"invocations_success"`
	Failed      int64 `json:"invocations_failed"`
	Timeout     int64 `json:"invocations_timeout"`
	InFlight    int64 `json:"invocations_in_flight"`
}

// Snapshot returns a point-in-time snapshot of all metrics.
func (c *Collector) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	uptime := time.Since(c.startTime)

	snapshot := Snapshot{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Uptime:     uptime.String(),
		UptimeSecs: uptime.Seconds(),
		Functions:  make([]FunctionMetrics, 0),
	}

	// Collect unique function names
	functions := make(map[string]struct{})
	for name := range c.invocationsTotal {
		functions[name] = struct{}{}
	}

	// Build function metrics
	for name := range functions {
		fm := FunctionMetrics{Name: name}

		if counter, ok := c.invocationsTotal[name]; ok {
			fm.Total = counter.Load()
			snapshot.Totals.Invocations += fm.Total
		}
		if counter, ok := c.invocationsSuccess[name]; ok {
			fm.Success = counter.Load()
			snapshot.Totals.Success += fm.Success
		}
		if counter, ok := c.invocationsFailed[name]; ok {
			fm.Failed = counter.Load()
			snapshot.Totals.Failed += fm.Failed
		}
		if counter, ok := c.invocationsTimeout[name]; ok {
			fm.Timeout = counter.Load()
			snapshot.Totals.Timeout += fm.Timeout
		}
		if counter, ok := c.invocationsInFlight[name]; ok {
			fm.InFlight = counter.Load()
			snapshot.Totals.InFlight += fm.InFlight
		}
		if hist, ok := c.durations[name]; ok {
			fm.Duration = hist.Stats()
		}

		snapshot.Functions = append(snapshot.Functions, fm)
	}

	// Sort functions by name
	sort.Slice(snapshot.Functions, func(i, j int) bool {
		return snapshot.Functions[i].Name < snapshot.Functions[j].Name
	})

	return snapshot
}

// Reset clears all metrics.
func (c *Collector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.invocationsTotal = make(map[string]*atomic.Int64)
	c.invocationsSuccess = make(map[string]*atomic.Int64)
	c.invocationsFailed = make(map[string]*atomic.Int64)
	c.invocationsTimeout = make(map[string]*atomic.Int64)
	c.invocationsInFlight = make(map[string]*atomic.Int64)
	c.durations = make(map[string]*DurationHistogram)
	c.startTime = time.Now()
}

// Handler returns an HTTP handler for the metrics endpoint.
func (c *Collector) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c.Snapshot())
	}
}

// Package-level convenience functions using the default collector

// InvocationStarted records the start of a function invocation.
func InvocationStarted(functionName string) {
	Default.InvocationStarted(functionName)
}

// InvocationCompleted records the successful completion of a function invocation.
func InvocationCompleted(functionName string, durationMs float64) {
	Default.InvocationCompleted(functionName, durationMs)
}

// InvocationFailed records a failed function invocation.
func InvocationFailed(functionName string, durationMs float64) {
	Default.InvocationFailed(functionName, durationMs)
}

// InvocationTimeout records a timed-out function invocation.
func InvocationTimeout(functionName string, durationMs float64) {
	Default.InvocationTimeout(functionName, durationMs)
}

// Snapshot returns a point-in-time snapshot of all metrics.
func Snapshot() Snapshot {
	return Default.Snapshot()
}

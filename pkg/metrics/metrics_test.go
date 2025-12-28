package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewDurationHistogram(t *testing.T) {
	h := NewDurationHistogram()

	if h == nil {
		t.Fatal("NewDurationHistogram() returned nil")
	}
	if h.min != -1 {
		t.Errorf("Initial min = %v, want -1", h.min)
	}
	if len(h.buckets) != len(defaultBuckets) {
		t.Errorf("Buckets count = %v, want %v", len(h.buckets), len(defaultBuckets))
	}
}

func TestDurationHistogram_Observe(t *testing.T) {
	h := NewDurationHistogram()

	h.Observe(100)
	h.Observe(200)
	h.Observe(50)

	stats := h.Stats()

	if stats.Count != 3 {
		t.Errorf("Count = %v, want 3", stats.Count)
	}
	if stats.Sum != 350 {
		t.Errorf("Sum = %v, want 350", stats.Sum)
	}
	if stats.Min != 50 {
		t.Errorf("Min = %v, want 50", stats.Min)
	}
	if stats.Max != 200 {
		t.Errorf("Max = %v, want 200", stats.Max)
	}
	if stats.Avg != 350.0/3.0 {
		t.Errorf("Avg = %v, want %v", stats.Avg, 350.0/3.0)
	}
}

func TestDurationHistogram_Buckets(t *testing.T) {
	h := NewDurationHistogram()

	// Observe values in different buckets
	h.Observe(5)   // <= 10
	h.Observe(20)  // <= 25
	h.Observe(100) // <= 100

	stats := h.Stats()

	// Value of 5 should increment all buckets from 10 onwards
	if stats.Buckets[10] != 1 {
		t.Errorf("Bucket[10] = %v, want 1", stats.Buckets[10])
	}
	// Value of 20 should increment all buckets from 25 onwards
	if stats.Buckets[25] != 2 {
		t.Errorf("Bucket[25] = %v, want 2", stats.Buckets[25])
	}
}

func TestNew(t *testing.T) {
	c := New()

	if c == nil {
		t.Fatal("New() returned nil")
	}
	if c.invocationsTotal == nil {
		t.Error("invocationsTotal should be initialized")
	}
}

func TestCollector_InvocationStarted(t *testing.T) {
	c := New()

	c.InvocationStarted("test-func")
	c.InvocationStarted("test-func")
	c.InvocationStarted("other-func")

	snapshot := c.Snapshot()

	var testFunc FunctionMetrics
	for _, fm := range snapshot.Functions {
		if fm.Name == "test-func" {
			testFunc = fm
			break
		}
	}

	if testFunc.Total != 2 {
		t.Errorf("test-func Total = %v, want 2", testFunc.Total)
	}
	if testFunc.InFlight != 2 {
		t.Errorf("test-func InFlight = %v, want 2", testFunc.InFlight)
	}
}

func TestCollector_InvocationCompleted(t *testing.T) {
	c := New()

	c.InvocationStarted("test-func")
	c.InvocationCompleted("test-func", 150.0)

	snapshot := c.Snapshot()

	var testFunc FunctionMetrics
	for _, fm := range snapshot.Functions {
		if fm.Name == "test-func" {
			testFunc = fm
			break
		}
	}

	if testFunc.Success != 1 {
		t.Errorf("Success = %v, want 1", testFunc.Success)
	}
	if testFunc.InFlight != 0 {
		t.Errorf("InFlight = %v, want 0", testFunc.InFlight)
	}
	if testFunc.Duration.Count != 1 {
		t.Errorf("Duration.Count = %v, want 1", testFunc.Duration.Count)
	}
}

func TestCollector_InvocationFailed(t *testing.T) {
	c := New()

	c.InvocationStarted("test-func")
	c.InvocationFailed("test-func", 100.0)

	snapshot := c.Snapshot()

	var testFunc FunctionMetrics
	for _, fm := range snapshot.Functions {
		if fm.Name == "test-func" {
			testFunc = fm
			break
		}
	}

	if testFunc.Failed != 1 {
		t.Errorf("Failed = %v, want 1", testFunc.Failed)
	}
}

func TestCollector_InvocationTimeout(t *testing.T) {
	c := New()

	c.InvocationStarted("test-func")
	c.InvocationTimeout("test-func", 5000.0)

	snapshot := c.Snapshot()

	var testFunc FunctionMetrics
	for _, fm := range snapshot.Functions {
		if fm.Name == "test-func" {
			testFunc = fm
			break
		}
	}

	if testFunc.Timeout != 1 {
		t.Errorf("Timeout = %v, want 1", testFunc.Timeout)
	}
}

func TestCollector_Snapshot(t *testing.T) {
	c := New()

	c.InvocationStarted("func-a")
	c.InvocationCompleted("func-a", 100.0)
	c.InvocationStarted("func-b")
	c.InvocationFailed("func-b", 50.0)

	snapshot := c.Snapshot()

	if snapshot.Timestamp == "" {
		t.Error("Timestamp should be set")
	}
	if snapshot.Uptime == "" {
		t.Error("Uptime should be set")
	}
	if len(snapshot.Functions) != 2 {
		t.Errorf("Functions count = %v, want 2", len(snapshot.Functions))
	}

	// Totals should be aggregated
	if snapshot.Totals.Invocations != 2 {
		t.Errorf("Totals.Invocations = %v, want 2", snapshot.Totals.Invocations)
	}
	if snapshot.Totals.Success != 1 {
		t.Errorf("Totals.Success = %v, want 1", snapshot.Totals.Success)
	}
	if snapshot.Totals.Failed != 1 {
		t.Errorf("Totals.Failed = %v, want 1", snapshot.Totals.Failed)
	}
}

func TestCollector_Snapshot_Sorted(t *testing.T) {
	c := New()

	c.InvocationStarted("zebra")
	c.InvocationStarted("alpha")
	c.InvocationStarted("middle")

	snapshot := c.Snapshot()

	if len(snapshot.Functions) != 3 {
		t.Fatalf("Functions count = %v, want 3", len(snapshot.Functions))
	}

	// Should be sorted alphabetically
	if snapshot.Functions[0].Name != "alpha" {
		t.Errorf("First function = %v, want alpha", snapshot.Functions[0].Name)
	}
	if snapshot.Functions[1].Name != "middle" {
		t.Errorf("Second function = %v, want middle", snapshot.Functions[1].Name)
	}
	if snapshot.Functions[2].Name != "zebra" {
		t.Errorf("Third function = %v, want zebra", snapshot.Functions[2].Name)
	}
}

func TestCollector_Reset(t *testing.T) {
	c := New()

	c.InvocationStarted("test-func")
	c.InvocationCompleted("test-func", 100.0)

	c.Reset()

	snapshot := c.Snapshot()
	if len(snapshot.Functions) != 0 {
		t.Errorf("After reset, Functions count = %v, want 0", len(snapshot.Functions))
	}
}

func TestCollector_Handler(t *testing.T) {
	c := New()
	c.InvocationStarted("test-func")
	c.InvocationCompleted("test-func", 100.0)

	handler := c.Handler()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status code = %v, want 200", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %v, want application/json", contentType)
	}

	var snapshot Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(snapshot.Functions) != 1 {
		t.Errorf("Response Functions count = %v, want 1", len(snapshot.Functions))
	}
}

// Test package-level functions
func TestPackageLevel_InvocationStarted(t *testing.T) {
	originalDefault := Default
	defer func() { Default = originalDefault }()

	Default = New()
	InvocationStarted("pkg-test")

	snapshot := GetSnapshot()
	if snapshot.Totals.Invocations != 1 {
		t.Errorf("Package-level InvocationStarted didn't work")
	}
}

func TestPackageLevel_InvocationCompleted(t *testing.T) {
	originalDefault := Default
	defer func() { Default = originalDefault }()

	Default = New()
	InvocationStarted("pkg-test")
	InvocationCompleted("pkg-test", 100.0)

	snapshot := GetSnapshot()
	if snapshot.Totals.Success != 1 {
		t.Errorf("Package-level InvocationCompleted didn't work")
	}
}

func TestPackageLevel_InvocationFailed(t *testing.T) {
	originalDefault := Default
	defer func() { Default = originalDefault }()

	Default = New()
	InvocationStarted("pkg-test")
	InvocationFailed("pkg-test", 100.0)

	snapshot := GetSnapshot()
	if snapshot.Totals.Failed != 1 {
		t.Errorf("Package-level InvocationFailed didn't work")
	}
}

func TestPackageLevel_InvocationTimeout(t *testing.T) {
	originalDefault := Default
	defer func() { Default = originalDefault }()

	Default = New()
	InvocationStarted("pkg-test")
	InvocationTimeout("pkg-test", 100.0)

	snapshot := GetSnapshot()
	if snapshot.Totals.Timeout != 1 {
		t.Errorf("Package-level InvocationTimeout didn't work")
	}
}

func TestCollector_Concurrent(t *testing.T) {
	c := New()
	done := make(chan bool)

	// Concurrent invocations
	for i := 0; i < 100; i++ {
		go func(n int) {
			funcName := "func"
			if n%2 == 0 {
				funcName = "func-even"
			}
			c.InvocationStarted(funcName)
			if n%3 == 0 {
				c.InvocationFailed(funcName, float64(n))
			} else {
				c.InvocationCompleted(funcName, float64(n))
			}
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	snapshot := c.Snapshot()
	if snapshot.Totals.Invocations != 100 {
		t.Errorf("Concurrent invocations count = %v, want 100", snapshot.Totals.Invocations)
	}
}

func TestDurationStats_Empty(t *testing.T) {
	h := NewDurationHistogram()
	stats := h.Stats()

	if stats.Count != 0 {
		t.Errorf("Empty histogram Count = %v, want 0", stats.Count)
	}
	if stats.Avg != 0 {
		t.Errorf("Empty histogram Avg = %v, want 0", stats.Avg)
	}
}

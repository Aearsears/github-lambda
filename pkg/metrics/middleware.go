package metrics

import (
	"net/http"
	"sync/atomic"
	"time"
)

// HTTPMetrics tracks HTTP-level metrics.
type HTTPMetrics struct {
	requestsTotal     atomic.Int64
	requestsInFlight  atomic.Int64
	requestDurations  *DurationHistogram
	responsesByStatus map[int]*atomic.Int64
}

// NewHTTPMetrics creates a new HTTP metrics tracker.
func NewHTTPMetrics() *HTTPMetrics {
	return &HTTPMetrics{
		requestDurations:  NewDurationHistogram(),
		responsesByStatus: make(map[int]*atomic.Int64),
	}
}

// DefaultHTTPMetrics is the global HTTP metrics tracker.
var DefaultHTTPMetrics = NewHTTPMetrics()

// ResponseWriter wraps http.ResponseWriter to capture status code.
type ResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader captures the status code.
func (rw *ResponseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

// Write writes the response body.
func (rw *ResponseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.statusCode = http.StatusOK
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}

// Middleware returns an HTTP middleware that tracks request metrics.
func (m *HTTPMetrics) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		m.requestsTotal.Add(1)
		m.requestsInFlight.Add(1)
		defer m.requestsInFlight.Add(-1)

		// Wrap response writer to capture status
		wrapped := &ResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		// Record duration
		durationMs := float64(time.Since(start).Milliseconds())
		m.requestDurations.Observe(durationMs)

		// Record status code
		statusBucket := (wrapped.statusCode / 100) * 100 // 200, 300, 400, 500
		if counter, ok := m.responsesByStatus[statusBucket]; ok {
			counter.Add(1)
		} else {
			counter := &atomic.Int64{}
			counter.Add(1)
			m.responsesByStatus[statusBucket] = counter
		}
	})
}

// HTTPSnapshot represents HTTP metrics snapshot.
type HTTPSnapshot struct {
	RequestsTotal    int64            `json:"requests_total"`
	RequestsInFlight int64            `json:"requests_in_flight"`
	Duration         DurationStats    `json:"duration"`
	ResponseCodes    map[string]int64 `json:"response_codes"`
}

// Snapshot returns current HTTP metrics.
func (m *HTTPMetrics) Snapshot() HTTPSnapshot {
	codes := make(map[string]int64)
	for status, counter := range m.responsesByStatus {
		switch status {
		case 200:
			codes["2xx"] = counter.Load()
		case 300:
			codes["3xx"] = counter.Load()
		case 400:
			codes["4xx"] = counter.Load()
		case 500:
			codes["5xx"] = counter.Load()
		}
	}

	return HTTPSnapshot{
		RequestsTotal:    m.requestsTotal.Load(),
		RequestsInFlight: m.requestsInFlight.Load(),
		Duration:         m.requestDurations.Stats(),
		ResponseCodes:    codes,
	}
}

// Middleware returns the default HTTP middleware.
func Middleware(next http.Handler) http.Handler {
	return DefaultHTTPMetrics.Middleware(next)
}

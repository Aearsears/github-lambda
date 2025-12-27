package dlq

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/github-lambda/pkg/logging"
)

// ErrorType categorizes errors as retriable or permanent.
type ErrorType string

const (
	// ErrorTypeRetriable indicates the error may succeed on retry.
	ErrorTypeRetriable ErrorType = "retriable"
	// ErrorTypePermanent indicates the error will not succeed on retry.
	ErrorTypePermanent ErrorType = "permanent"
	// ErrorTypeUnknown indicates the error type could not be determined.
	ErrorTypeUnknown ErrorType = "unknown"
)

// FailureReason provides detailed categorization of failures.
type FailureReason string

const (
	ReasonTimeout           FailureReason = "timeout"
	ReasonRateLimited       FailureReason = "rate_limited"
	ReasonServiceError      FailureReason = "service_error"
	ReasonInvalidPayload    FailureReason = "invalid_payload"
	ReasonFunctionNotFound  FailureReason = "function_not_found"
	ReasonPermissionDenied  FailureReason = "permission_denied"
	ReasonResourceExhausted FailureReason = "resource_exhausted"
	ReasonNetworkError      FailureReason = "network_error"
	ReasonFunctionError     FailureReason = "function_error"
	ReasonUnknown           FailureReason = "unknown"
)

// GetErrorType returns the error type for a failure reason.
func (r FailureReason) GetErrorType() ErrorType {
	switch r {
	case ReasonTimeout, ReasonRateLimited, ReasonServiceError, ReasonNetworkError, ReasonResourceExhausted:
		return ErrorTypeRetriable
	case ReasonInvalidPayload, ReasonFunctionNotFound, ReasonPermissionDenied:
		return ErrorTypePermanent
	case ReasonFunctionError:
		// Function errors might be retriable depending on the error
		return ErrorTypeUnknown
	default:
		return ErrorTypeUnknown
	}
}

// FailedEvent represents an event that failed after all retry attempts.
type FailedEvent struct {
	ID           string            `json:"id"`
	InvocationID string            `json:"invocation_id"`
	FunctionName string            `json:"function_name"`
	Version      int               `json:"version,omitempty"`
	Alias        string            `json:"alias,omitempty"`
	Payload      json.RawMessage   `json:"payload"`
	Headers      map[string]string `json:"headers,omitempty"`

	// Error information
	ErrorMessage  string        `json:"error_message"`
	ErrorType     ErrorType     `json:"error_type"`
	FailureReason FailureReason `json:"failure_reason"`

	// Retry information
	RetryAttempts int            `json:"retry_attempts"`
	MaxRetries    int            `json:"max_retries"`
	RetryHistory  []RetryAttempt `json:"retry_history,omitempty"`

	// Timestamps
	OriginalTime time.Time  `json:"original_time"`
	FailedTime   time.Time  `json:"failed_time"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`

	// Metadata
	Source   string            `json:"source,omitempty"` // e.g., "http", "schedule", "webhook"
	SourceID string            `json:"source_id,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`

	// Replay information
	ReplayedAt   *time.Time `json:"replayed_at,omitempty"`
	ReplayCount  int        `json:"replay_count"`
	ReplayStatus string     `json:"replay_status,omitempty"` // pending, success, failed
}

// RetryAttempt records details of a single retry attempt.
type RetryAttempt struct {
	Attempt      int       `json:"attempt"`
	AttemptedAt  time.Time `json:"attempted_at"`
	ErrorMessage string    `json:"error_message"`
	DurationMs   int64     `json:"duration_ms"`
}

// Queue represents a dead letter queue for a function or globally.
type Queue struct {
	mu            sync.RWMutex
	events        map[string]*FailedEvent
	byFunction    map[string][]string // functionName -> event IDs
	maxSize       int
	retentionDays int
	logger        *logging.Logger
}

// QueueConfig configures a DLQ.
type QueueConfig struct {
	MaxSize       int `json:"max_size"`       // Maximum events to store (0 = unlimited)
	RetentionDays int `json:"retention_days"` // Days to retain events (0 = forever)
}

// DefaultConfig returns default DLQ configuration.
func DefaultConfig() QueueConfig {
	return QueueConfig{
		MaxSize:       10000,
		RetentionDays: 14,
	}
}

// NewQueue creates a new dead letter queue.
func NewQueue(config QueueConfig) *Queue {
	q := &Queue{
		events:        make(map[string]*FailedEvent),
		byFunction:    make(map[string][]string),
		maxSize:       config.MaxSize,
		retentionDays: config.RetentionDays,
		logger:        logging.New("dlq"),
	}

	// Start cleanup goroutine if retention is configured
	if config.RetentionDays > 0 {
		go q.cleanupLoop()
	}

	return q
}

// Add adds a failed event to the queue.
func (q *Queue) Add(event *FailedEvent) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Generate ID if not set
	if event.ID == "" {
		event.ID = fmt.Sprintf("dlq-%d", time.Now().UnixNano())
	}

	// Set expiration if retention is configured
	if q.retentionDays > 0 {
		expires := time.Now().AddDate(0, 0, q.retentionDays)
		event.ExpiresAt = &expires
	}

	// Check if queue is full
	if q.maxSize > 0 && len(q.events) >= q.maxSize {
		// Remove oldest event
		q.removeOldest()
	}

	q.events[event.ID] = event
	q.byFunction[event.FunctionName] = append(q.byFunction[event.FunctionName], event.ID)

	q.logger.Info("event added to DLQ", logging.Fields{
		"event_id":      event.ID,
		"function_name": event.FunctionName,
		"error_type":    string(event.ErrorType),
		"reason":        string(event.FailureReason),
		"retries":       event.RetryAttempts,
	})

	return nil
}

// Get retrieves a failed event by ID.
func (q *Queue) Get(id string) (*FailedEvent, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	event, ok := q.events[id]
	if !ok {
		return nil, fmt.Errorf("event not found: %s", id)
	}

	return event, nil
}

// List lists failed events with optional filters.
func (q *Queue) List(filter ListFilter) []*FailedEvent {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var result []*FailedEvent

	for _, event := range q.events {
		if q.matchesFilter(event, filter) {
			result = append(result, event)
		}
	}

	// Sort by failed time descending
	sort.Slice(result, func(i, j int) bool {
		return result[i].FailedTime.After(result[j].FailedTime)
	})

	// Apply limit
	if filter.Limit > 0 && len(result) > filter.Limit {
		result = result[:filter.Limit]
	}

	return result
}

// ListFilter defines filters for listing DLQ events.
type ListFilter struct {
	FunctionName    string
	ErrorType       ErrorType
	FailureReason   FailureReason
	Since           *time.Time
	Until           *time.Time
	Limit           int
	IncludeReplayed bool
}

func (q *Queue) matchesFilter(event *FailedEvent, filter ListFilter) bool {
	if filter.FunctionName != "" && event.FunctionName != filter.FunctionName {
		return false
	}
	if filter.ErrorType != "" && event.ErrorType != filter.ErrorType {
		return false
	}
	if filter.FailureReason != "" && event.FailureReason != filter.FailureReason {
		return false
	}
	if filter.Since != nil && event.FailedTime.Before(*filter.Since) {
		return false
	}
	if filter.Until != nil && event.FailedTime.After(*filter.Until) {
		return false
	}
	if !filter.IncludeReplayed && event.ReplayedAt != nil {
		return false
	}
	return true
}

// Delete removes a failed event from the queue.
func (q *Queue) Delete(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	event, ok := q.events[id]
	if !ok {
		return fmt.Errorf("event not found: %s", id)
	}

	delete(q.events, id)
	q.removeFromFunctionIndex(event.FunctionName, id)

	q.logger.Info("event removed from DLQ", logging.Fields{
		"event_id":      id,
		"function_name": event.FunctionName,
	})

	return nil
}

// MarkReplayed marks an event as replayed.
func (q *Queue) MarkReplayed(id string, status string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	event, ok := q.events[id]
	if !ok {
		return fmt.Errorf("event not found: %s", id)
	}

	now := time.Now()
	event.ReplayedAt = &now
	event.ReplayCount++
	event.ReplayStatus = status

	return nil
}

// Stats returns statistics about the DLQ.
func (q *Queue) Stats() QueueStats {
	q.mu.RLock()
	defer q.mu.RUnlock()

	stats := QueueStats{
		TotalEvents:     len(q.events),
		ByFunction:      make(map[string]int),
		ByErrorType:     make(map[ErrorType]int),
		ByFailureReason: make(map[FailureReason]int),
	}

	for _, event := range q.events {
		stats.ByFunction[event.FunctionName]++
		stats.ByErrorType[event.ErrorType]++
		stats.ByFailureReason[event.FailureReason]++

		if event.ReplayedAt != nil {
			stats.ReplayedEvents++
		} else {
			stats.PendingEvents++
		}
	}

	return stats
}

// QueueStats represents DLQ statistics.
type QueueStats struct {
	TotalEvents     int                   `json:"total_events"`
	PendingEvents   int                   `json:"pending_events"`
	ReplayedEvents  int                   `json:"replayed_events"`
	ByFunction      map[string]int        `json:"by_function"`
	ByErrorType     map[ErrorType]int     `json:"by_error_type"`
	ByFailureReason map[FailureReason]int `json:"by_failure_reason"`
}

// Purge removes all events matching the filter.
func (q *Queue) Purge(filter ListFilter) int {
	q.mu.Lock()
	defer q.mu.Unlock()

	var toDelete []string
	for id, event := range q.events {
		if q.matchesFilter(event, filter) {
			toDelete = append(toDelete, id)
		}
	}

	for _, id := range toDelete {
		event := q.events[id]
		delete(q.events, id)
		q.removeFromFunctionIndex(event.FunctionName, id)
	}

	q.logger.Info("purged events from DLQ", logging.Fields{
		"count": len(toDelete),
	})

	return len(toDelete)
}

func (q *Queue) removeOldest() {
	var oldest *FailedEvent
	var oldestID string

	for id, event := range q.events {
		if oldest == nil || event.FailedTime.Before(oldest.FailedTime) {
			oldest = event
			oldestID = id
		}
	}

	if oldestID != "" {
		delete(q.events, oldestID)
		q.removeFromFunctionIndex(oldest.FunctionName, oldestID)
	}
}

func (q *Queue) removeFromFunctionIndex(functionName, eventID string) {
	ids := q.byFunction[functionName]
	for i, id := range ids {
		if id == eventID {
			q.byFunction[functionName] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
}

func (q *Queue) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		q.cleanup()
	}
}

func (q *Queue) cleanup() {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	var toDelete []string

	for id, event := range q.events {
		if event.ExpiresAt != nil && now.After(*event.ExpiresAt) {
			toDelete = append(toDelete, id)
		}
	}

	for _, id := range toDelete {
		event := q.events[id]
		delete(q.events, id)
		q.removeFromFunctionIndex(event.FunctionName, id)
	}

	if len(toDelete) > 0 {
		q.logger.Info("cleaned up expired DLQ events", logging.Fields{
			"count": len(toDelete),
		})
	}
}

// SaveToFile saves the DLQ state to a JSON file.
func (q *Queue) SaveToFile(path string) error {
	q.mu.RLock()
	defer q.mu.RUnlock()

	data, err := json.MarshalIndent(q.events, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal DLQ: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write DLQ file: %w", err)
	}

	return nil
}

// LoadFromFile loads the DLQ state from a JSON file.
func (q *Queue) LoadFromFile(path string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read DLQ file: %w", err)
	}

	var events map[string]*FailedEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return fmt.Errorf("failed to unmarshal DLQ: %w", err)
	}

	q.events = events
	q.byFunction = make(map[string][]string)

	for id, event := range events {
		q.byFunction[event.FunctionName] = append(q.byFunction[event.FunctionName], id)
	}

	q.logger.Info("loaded DLQ state", logging.Fields{
		"path":   path,
		"events": len(events),
	})

	return nil
}

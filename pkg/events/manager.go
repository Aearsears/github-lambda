package events

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/github-lambda/internal/dispatcher"
	"github.com/github-lambda/pkg/logging"
)

// EventType represents the type of event source.
type EventType string

const (
	EventTypeHTTP     EventType = "http"
	EventTypeSchedule EventType = "schedule"
	EventTypeGitHub   EventType = "github"
	EventTypeWebhook  EventType = "webhook"
)

// EventSource represents a configured event source that triggers functions.
type EventSource struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Type          EventType       `json:"type"`
	FunctionName  string          `json:"function_name"`
	Enabled       bool            `json:"enabled"`
	Config        json.RawMessage `json:"config"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	LastTriggered *time.Time      `json:"last_triggered,omitempty"`
	TriggerCount  int64           `json:"trigger_count"`
}

// Event represents an event that triggers a function.
type Event struct {
	ID           string            `json:"id"`
	SourceID     string            `json:"source_id"`
	SourceType   EventType         `json:"source_type"`
	FunctionName string            `json:"function_name"`
	Payload      json.RawMessage   `json:"payload"`
	Headers      map[string]string `json:"headers,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	ReceivedAt   time.Time         `json:"received_at"`
}

// Manager manages event sources and dispatches events to functions.
type Manager struct {
	mu         sync.RWMutex
	sources    map[string]*EventSource
	dispatcher *dispatcher.Dispatcher
	scheduler  *Scheduler
	logger     *logging.Logger

	// Event handlers by type
	handlers map[EventType]EventHandler
}

// EventHandler processes events of a specific type.
type EventHandler interface {
	Handle(ctx context.Context, event *Event) error
	Validate(config json.RawMessage) error
}

// NewManager creates a new event source manager.
func NewManager(d *dispatcher.Dispatcher) *Manager {
	m := &Manager{
		sources:    make(map[string]*EventSource),
		dispatcher: d,
		logger:     logging.New("events"),
		handlers:   make(map[EventType]EventHandler),
	}

	// Initialize scheduler
	m.scheduler = NewScheduler(m)

	return m
}

// RegisterHandler registers a handler for an event type.
func (m *Manager) RegisterHandler(eventType EventType, handler EventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[eventType] = handler
}

// CreateSource creates a new event source.
func (m *Manager) CreateSource(source *EventSource) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate configuration based on type
	if handler, ok := m.handlers[source.Type]; ok {
		if err := handler.Validate(source.Config); err != nil {
			return fmt.Errorf("invalid configuration: %w", err)
		}
	}

	if source.ID == "" {
		source.ID = generateID()
	}
	source.CreatedAt = time.Now()
	source.UpdatedAt = time.Now()
	source.Enabled = true

	m.sources[source.ID] = source

	// If it's a scheduled source, register with scheduler
	if source.Type == EventTypeSchedule && source.Enabled {
		if err := m.scheduler.Add(source); err != nil {
			delete(m.sources, source.ID)
			return fmt.Errorf("failed to schedule: %w", err)
		}
	}

	m.logger.Info("event source created", logging.Fields{
		"source_id":     source.ID,
		"name":          source.Name,
		"type":          source.Type,
		"function_name": source.FunctionName,
	})

	return nil
}

// UpdateSource updates an existing event source.
func (m *Manager) UpdateSource(id string, updates *EventSource) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	source, exists := m.sources[id]
	if !exists {
		return fmt.Errorf("event source not found: %s", id)
	}

	// Update fields
	if updates.Name != "" {
		source.Name = updates.Name
	}
	if updates.FunctionName != "" {
		source.FunctionName = updates.FunctionName
	}
	if updates.Config != nil {
		if handler, ok := m.handlers[source.Type]; ok {
			if err := handler.Validate(updates.Config); err != nil {
				return fmt.Errorf("invalid configuration: %w", err)
			}
		}
		source.Config = updates.Config
	}
	source.UpdatedAt = time.Now()

	// Update scheduler if needed
	if source.Type == EventTypeSchedule {
		m.scheduler.Remove(source.ID)
		if source.Enabled {
			if err := m.scheduler.Add(source); err != nil {
				return fmt.Errorf("failed to reschedule: %w", err)
			}
		}
	}

	m.logger.Info("event source updated", logging.Fields{
		"source_id": id,
	})

	return nil
}

// DeleteSource deletes an event source.
func (m *Manager) DeleteSource(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	source, exists := m.sources[id]
	if !exists {
		return fmt.Errorf("event source not found: %s", id)
	}

	// Remove from scheduler if applicable
	if source.Type == EventTypeSchedule {
		m.scheduler.Remove(id)
	}

	delete(m.sources, id)

	m.logger.Info("event source deleted", logging.Fields{
		"source_id": id,
	})

	return nil
}

// EnableSource enables an event source.
func (m *Manager) EnableSource(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	source, exists := m.sources[id]
	if !exists {
		return fmt.Errorf("event source not found: %s", id)
	}

	source.Enabled = true
	source.UpdatedAt = time.Now()

	if source.Type == EventTypeSchedule {
		if err := m.scheduler.Add(source); err != nil {
			return err
		}
	}

	return nil
}

// DisableSource disables an event source.
func (m *Manager) DisableSource(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	source, exists := m.sources[id]
	if !exists {
		return fmt.Errorf("event source not found: %s", id)
	}

	source.Enabled = false
	source.UpdatedAt = time.Now()

	if source.Type == EventTypeSchedule {
		m.scheduler.Remove(id)
	}

	return nil
}

// GetSource retrieves an event source by ID.
func (m *Manager) GetSource(id string) (*EventSource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	source, exists := m.sources[id]
	if !exists {
		return nil, fmt.Errorf("event source not found: %s", id)
	}

	return source, nil
}

// ListSources lists all event sources.
func (m *Manager) ListSources() []*EventSource {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sources := make([]*EventSource, 0, len(m.sources))
	for _, source := range m.sources {
		sources = append(sources, source)
	}
	return sources
}

// ListSourcesByType lists event sources of a specific type.
func (m *Manager) ListSourcesByType(eventType EventType) []*EventSource {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sources := make([]*EventSource, 0)
	for _, source := range m.sources {
		if source.Type == eventType {
			sources = append(sources, source)
		}
	}
	return sources
}

// ListSourcesByFunction lists event sources for a specific function.
func (m *Manager) ListSourcesByFunction(functionName string) []*EventSource {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sources := make([]*EventSource, 0)
	for _, source := range m.sources {
		if source.FunctionName == functionName {
			sources = append(sources, source)
		}
	}
	return sources
}

// ProcessEvent processes an incoming event.
func (m *Manager) ProcessEvent(ctx context.Context, event *Event) (*dispatcher.Execution, error) {
	m.mu.RLock()
	source, exists := m.sources[event.SourceID]
	m.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("event source not found: %s", event.SourceID)
	}

	if !source.Enabled {
		return nil, fmt.Errorf("event source is disabled: %s", event.SourceID)
	}

	// Update trigger stats
	m.mu.Lock()
	now := time.Now()
	source.LastTriggered = &now
	source.TriggerCount++
	m.mu.Unlock()

	m.logger.Info("processing event", logging.Fields{
		"event_id":      event.ID,
		"source_id":     event.SourceID,
		"source_type":   event.SourceType,
		"function_name": event.FunctionName,
	})

	// Dispatch to function asynchronously
	req := dispatcher.InvokeRequest{
		FunctionName: event.FunctionName,
		Payload:      event.Payload,
	}

	return m.dispatcher.Invoke(ctx, req)
}

// StartScheduler starts the scheduler.
func (m *Manager) StartScheduler() {
	m.scheduler.Start()
	m.logger.Info("scheduler started")
}

// StopScheduler stops the scheduler.
func (m *Manager) StopScheduler() {
	m.scheduler.Stop()
	m.logger.Info("scheduler stopped")
}

// Start starts the event manager (scheduler, etc.)
func (m *Manager) Start() {
	m.scheduler.Start()
	m.logger.Info("event manager started")
}

// Stop stops the event manager.
func (m *Manager) Stop() {
	m.scheduler.Stop()
	m.logger.Info("event manager stopped")
}

// generateID creates a unique ID.
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

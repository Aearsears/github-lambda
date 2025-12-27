package events

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/github-lambda/pkg/logging"
)

// ScheduleConfig represents configuration for a scheduled event source.
type ScheduleConfig struct {
	// Cron expression (e.g., "0 * * * *" for every hour)
	Cron string `json:"cron,omitempty"`

	// Rate expression (e.g., "5m" for every 5 minutes)
	Rate string `json:"rate,omitempty"`

	// Timezone for cron expressions (default: UTC)
	Timezone string `json:"timezone,omitempty"`

	// Payload to send with each invocation
	Payload json.RawMessage `json:"payload,omitempty"`

	// Enabled days of week (0=Sunday, 6=Saturday). Empty means all days.
	EnabledDays []int `json:"enabled_days,omitempty"`

	// Start and end times for the schedule (optional)
	StartTime string `json:"start_time,omitempty"` // HH:MM format
	EndTime   string `json:"end_time,omitempty"`   // HH:MM format
}

// Scheduler handles scheduled event sources.
type Scheduler struct {
	mu      sync.RWMutex
	manager *Manager
	jobs    map[string]*scheduledJob
	running bool
	stopCh  chan struct{}
	logger  *logging.Logger
}

type scheduledJob struct {
	source  *EventSource
	config  ScheduleConfig
	nextRun time.Time
	stopCh  chan struct{}
	running bool
}

// NewScheduler creates a new scheduler.
func NewScheduler(manager *Manager) *Scheduler {
	return &Scheduler{
		manager: manager,
		jobs:    make(map[string]*scheduledJob),
		logger:  logging.New("scheduler"),
	}
}

// Add adds a scheduled event source.
func (s *Scheduler) Add(source *EventSource) error {
	var config ScheduleConfig
	if err := json.Unmarshal(source.Config, &config); err != nil {
		return fmt.Errorf("invalid schedule config: %w", err)
	}

	if config.Cron == "" && config.Rate == "" {
		return fmt.Errorf("either cron or rate must be specified")
	}

	job := &scheduledJob{
		source: source,
		config: config,
		stopCh: make(chan struct{}),
	}

	// Calculate next run time
	if err := job.calculateNextRun(); err != nil {
		return err
	}

	s.mu.Lock()
	s.jobs[source.ID] = job
	s.mu.Unlock()

	// Start the job if scheduler is running
	if s.running {
		go s.runJob(job)
	}

	s.logger.Info("scheduled job added", logging.Fields{
		"source_id":     source.ID,
		"function_name": source.FunctionName,
		"next_run":      job.nextRun.Format(time.RFC3339),
	})

	return nil
}

// Remove removes a scheduled job.
func (s *Scheduler) Remove(sourceID string) {
	s.mu.Lock()
	job, exists := s.jobs[sourceID]
	if exists {
		close(job.stopCh)
		delete(s.jobs, sourceID)
	}
	s.mu.Unlock()

	if exists {
		s.logger.Info("scheduled job removed", logging.Fields{
			"source_id": sourceID,
		})
	}
}

// Start starts the scheduler.
func (s *Scheduler) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	// Start all existing jobs
	s.mu.RLock()
	for _, job := range s.jobs {
		go s.runJob(job)
	}
	s.mu.RUnlock()

	s.logger.Info("scheduler started")
}

// Stop stops the scheduler.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)

	// Stop all jobs
	for _, job := range s.jobs {
		close(job.stopCh)
	}
	s.mu.Unlock()

	s.logger.Info("scheduler stopped")
}

// runJob runs a scheduled job.
func (s *Scheduler) runJob(job *scheduledJob) {
	job.running = true
	defer func() { job.running = false }()

	for {
		// Calculate time until next run
		now := time.Now()
		if job.nextRun.Before(now) {
			job.calculateNextRun()
		}

		waitDuration := time.Until(job.nextRun)
		if waitDuration < 0 {
			waitDuration = time.Second
		}

		timer := time.NewTimer(waitDuration)

		select {
		case <-job.stopCh:
			timer.Stop()
			return
		case <-s.stopCh:
			timer.Stop()
			return
		case <-timer.C:
			// Check if within allowed time window
			if s.isWithinTimeWindow(job) {
				s.triggerJob(job)
			}
			job.calculateNextRun()
		}
	}
}

// isWithinTimeWindow checks if current time is within the job's allowed time window.
func (s *Scheduler) isWithinTimeWindow(job *scheduledJob) bool {
	now := time.Now()

	// Check enabled days
	if len(job.config.EnabledDays) > 0 {
		currentDay := int(now.Weekday())
		enabled := false
		for _, day := range job.config.EnabledDays {
			if day == currentDay {
				enabled = true
				break
			}
		}
		if !enabled {
			return false
		}
	}

	// Check time window
	if job.config.StartTime != "" && job.config.EndTime != "" {
		currentTime := now.Format("15:04")
		if currentTime < job.config.StartTime || currentTime > job.config.EndTime {
			return false
		}
	}

	return true
}

// triggerJob triggers a scheduled job.
func (s *Scheduler) triggerJob(job *scheduledJob) {
	event := &Event{
		ID:           generateID(),
		SourceID:     job.source.ID,
		SourceType:   EventTypeSchedule,
		FunctionName: job.source.FunctionName,
		Payload:      job.config.Payload,
		Metadata: map[string]string{
			"schedule_type": "cron",
			"scheduled_at":  job.nextRun.Format(time.RFC3339),
		},
		ReceivedAt: time.Now(),
	}

	if job.config.Payload == nil {
		event.Payload = json.RawMessage(`{}`)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	exec, err := s.manager.ProcessEvent(ctx, event)
	if err != nil {
		s.logger.Error("failed to trigger scheduled job", logging.Fields{
			"source_id":     job.source.ID,
			"function_name": job.source.FunctionName,
			"error":         err.Error(),
		})
		return
	}

	s.logger.Info("scheduled job triggered", logging.Fields{
		"source_id":     job.source.ID,
		"function_name": job.source.FunctionName,
		"invocation_id": exec.ID,
	})
}

// calculateNextRun calculates the next run time for a job.
func (job *scheduledJob) calculateNextRun() error {
	now := time.Now()

	if job.config.Rate != "" {
		// Parse rate duration
		duration, err := time.ParseDuration(job.config.Rate)
		if err != nil {
			return fmt.Errorf("invalid rate: %w", err)
		}
		job.nextRun = now.Add(duration)
		return nil
	}

	if job.config.Cron != "" {
		// Parse cron expression
		next, err := parseCronExpression(job.config.Cron, now)
		if err != nil {
			return fmt.Errorf("invalid cron expression: %w", err)
		}
		job.nextRun = next
		return nil
	}

	return fmt.Errorf("no schedule configured")
}

// parseCronExpression parses a simple cron expression and returns the next run time.
// Supports: minute hour day-of-month month day-of-week
// Special values: * (any), */n (every n)
func parseCronExpression(expr string, after time.Time) (time.Time, error) {
	fields := splitFields(expr)
	if len(fields) != 5 {
		return time.Time{}, fmt.Errorf("cron expression must have 5 fields")
	}

	// Parse each field
	minutes, err := parseCronField(fields[0], 0, 59)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid minute field: %w", err)
	}

	hours, err := parseCronField(fields[1], 0, 23)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid hour field: %w", err)
	}

	days, err := parseCronField(fields[2], 1, 31)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid day field: %w", err)
	}

	months, err := parseCronField(fields[3], 1, 12)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid month field: %w", err)
	}

	weekdays, err := parseCronField(fields[4], 0, 6)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid weekday field: %w", err)
	}

	// Find next matching time
	t := after.Add(time.Minute).Truncate(time.Minute)

	// Search for up to a year
	maxIterations := 366 * 24 * 60
	for i := 0; i < maxIterations; i++ {
		if contains(months, int(t.Month())) &&
			contains(days, t.Day()) &&
			contains(weekdays, int(t.Weekday())) &&
			contains(hours, t.Hour()) &&
			contains(minutes, t.Minute()) {
			return t, nil
		}
		t = t.Add(time.Minute)
	}

	return time.Time{}, fmt.Errorf("no matching time found within a year")
}

// parseCronField parses a single cron field.
func parseCronField(field string, min, max int) ([]int, error) {
	if field == "*" {
		result := make([]int, max-min+1)
		for i := range result {
			result[i] = min + i
		}
		return result, nil
	}

	// Handle */n (every n)
	if len(field) > 2 && field[:2] == "*/" {
		var step int
		_, err := fmt.Sscanf(field, "*/%d", &step)
		if err != nil || step <= 0 {
			return nil, fmt.Errorf("invalid step: %s", field)
		}
		var result []int
		for i := min; i <= max; i += step {
			result = append(result, i)
		}
		return result, nil
	}

	// Handle single value
	var val int
	_, err := fmt.Sscanf(field, "%d", &val)
	if err == nil {
		if val < min || val > max {
			return nil, fmt.Errorf("value %d out of range [%d, %d]", val, min, max)
		}
		return []int{val}, nil
	}

	return nil, fmt.Errorf("invalid field: %s", field)
}

func splitFields(s string) []string {
	var fields []string
	current := ""
	for _, c := range s {
		if c == ' ' || c == '\t' {
			if current != "" {
				fields = append(fields, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		fields = append(fields, current)
	}
	return fields
}

func contains(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

// ScheduleHandler handles schedule events.
type ScheduleHandler struct{}

// Handle processes a schedule event.
func (h *ScheduleHandler) Handle(ctx context.Context, event *Event) error {
	return nil // Processing handled by scheduler
}

// Validate validates schedule configuration.
func (h *ScheduleHandler) Validate(config json.RawMessage) error {
	var cfg ScheduleConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return err
	}

	if cfg.Cron == "" && cfg.Rate == "" {
		return fmt.Errorf("either cron or rate must be specified")
	}

	if cfg.Rate != "" {
		if _, err := time.ParseDuration(cfg.Rate); err != nil {
			return fmt.Errorf("invalid rate duration: %w", err)
		}
	}

	if cfg.Cron != "" {
		_, err := parseCronExpression(cfg.Cron, time.Now())
		if err != nil {
			return fmt.Errorf("invalid cron expression: %w", err)
		}
	}

	return nil
}

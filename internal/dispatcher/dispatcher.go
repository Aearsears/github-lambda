package dispatcher

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/github-lambda/pkg/logging"
	"github.com/github-lambda/pkg/metrics"
	"github.com/google/go-github/v57/github"
	"golang.org/x/oauth2"
)

// Dispatcher handles triggering GitHub Actions workflows.
type Dispatcher struct {
	client     *github.Client
	owner      string
	repo       string
	mu         sync.RWMutex
	executions map[string]*Execution
	logger     *logging.Logger
}

// Execution represents a running or completed function execution.
type Execution struct {
	ID           string          `json:"id"`
	FunctionName string          `json:"function_name"`
	Status       ExecutionStatus `json:"status"`
	RunID        int64           `json:"run_id,omitempty"`
	StartedAt    time.Time       `json:"started_at"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
	Error        string          `json:"error,omitempty"`
}

// ExecutionStatus represents the status of an execution.
type ExecutionStatus string

const (
	StatusPending   ExecutionStatus = "pending"
	StatusRunning   ExecutionStatus = "running"
	StatusCompleted ExecutionStatus = "completed"
	StatusFailed    ExecutionStatus = "failed"
)

// New creates a new Dispatcher.
func New(token, owner, repo string) *Dispatcher {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
logger := logging.New("dispatcher")

	return &Dispatcher{
		client:     github.NewClient(tc),
		owner:      owner,
		repo:       repo,
		executions: make(map[string]*Execution),
		logger:     logger,
		executions: make(map[string]*Execution),
	}
}

// InvokeRequest represents a request to invoke a function.
type InvokeRequest struct {
	FunctionName string          `json:"function_name"`
	Payload      json.RawMessage `json:"payload"`
	Timeout      time.Duration   `json:"timeout,omitempty"`
}

// Invoke triggers a workflow and waits for completion.
func (d *Dispatcher) Invoke(ctx context.Context, req InvokeRequest) (*Execution, error) {
	exec, err := d.InvokeAsync(ctx, req)
	if err != nil {
	logger := d.logger.WithInvocation(exec.ID, req.FunctionName)

	// Poll for completion
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeout := req.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		select {
		case <-timeoutCtx.Done():
			durationMs := float64(time.Since(exec.StartedAt).Milliseconds())
			metrics.InvocationTimeout(req.FunctionName, durationMs)
			logger.Warn("invocation timed out", logging.Fields{
				"duration_ms": int64(durationMs),
			})
			return nil, fmt.Errorf("execution timed out")
		case <-ticker.C:
			exec, err = d.GetExecution(exec.ID)
			if err != nil {
				return nil, err
			}
			if exec.Status == StatusCompleted || exec.Status == StatusFailed {
				durationMs := float64(time.Since(exec.StartedAt).Milliseconds())
				if exec.Status == StatusCompleted {
					metrics.InvocationCompleted(req.FunctionName, durationMs)
					logger.Info("invocation completed", logging.Fields{
						"duration_ms": int64(durationMs),
					})
	logger := d.logger.WithInvocation(invocationID, req.FunctionName)
	logger.Info("starting invocation")

	// Track metrics
	metrics.InvocationStarted(req.FunctionName)

	exec := &Execution{
		ID:           invocationID,
		FunctionName: req.FunctionName,
		Status:       StatusPending,
		StartedAt:    time.Now(),
	}

	d.mu.Lock()
	d.executions[invocationID] = exec
	d.mu.Unlock()

	// Trigger workflow_dispatch event
	payload, _ := json.Marshal(map[string]string{
		"function_name": req.FunctionName,
		"invocation_id": invocationID,
		"payload":       string(req.Payload),
	})

	_, _, err := d.client.Repositories.CreateRepositoryDispatch(
		ctx,
		d.owner,
		d.repo,
		github.DispatchRequestOptions{
			EventType:     "lambda-invoke",
			ClientPayload: (*json.RawMessage)(&payload),
		},
	)
	if err != nil {
		exec.Status = StatusFailed
		exec.Error = err.Error()
		durationMs := float64(time.Since(exec.StartedAt).Milliseconds())
		metrics.InvocationFailed(req.FunctionName, durationMs)
		logger.Error("failed to dispatch workflow", logging.Fields{
			"error":       err.Error(),
			"duration_ms": int64(durationMs),
		})
		return exec, fmt.Errorf("failed to dispatch workflow: %w", err)
	}

	exec.Status = StatusRunning
	logger.Debug("workflow dispatched successfully", logging.Fields{
		"function_name": req.FunctionName,
		"invocation_id": invocationID,
		"payload":       string(req.Payload),
	})

	_, _, err := d.client.Repositories.CreateRepositoryDispatch(
		ctx,
		d.owner,
		d.repo,
		github.DispatchRequestOptions{
			EventType:     "lambda-invoke",
			ClientPayload: (*json.RawMessage)(&payload),
		},
	)
	if err != nil {
		exec.Status = StatusFailed
		exec.Error = err.Error()
		return exec, fmt.Errorf("failed to dispatch workflow: %w", err)
	}

	exec.Status = StatusRunning
	return exec, nil
}

// GetExecution retrieves an execution by ID.
func (d *Dispatcher) GetExecution(id string) (*Execution, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	exec, exists := d.executions[id]
	if !exists {
		return nil, fmt.Errorf("execution not found: %s", id)
	}

	return exec, nil
}

// UpdateExecution updates an execution's status.
func (d *Dispatcher) UpdateExecution(id string, status ExecutionStatus, result json.RawMessage, errMsg string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	exec, exists := d.executions[id]
	if !exists {
		return fmt.Errorf("execution not found: %s", id)
	}

	exec.Status = status
	exec.Result = result
	exec.Error = errMsg
	if status == StatusCompleted || status == StatusFailed {
		now := time.Now()
		exec.CompletedAt = &now
	}

	return nil
}

// generateID creates a unique invocation ID.
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

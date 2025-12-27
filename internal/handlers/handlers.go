package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/github-lambda/internal/dispatcher"
	"github.com/github-lambda/pkg/auth"
	"github.com/github-lambda/pkg/cache"
	"github.com/github-lambda/pkg/config"
	"github.com/github-lambda/pkg/dlq"
	"github.com/github-lambda/pkg/logging"
	"github.com/github-lambda/pkg/metrics"
	"github.com/github-lambda/pkg/ratelimit"
	"github.com/github-lambda/pkg/versioning"
)

var logger = logging.New("handlers")

// InvokeHandler handles synchronous function invocations.
func InvokeHandler(d *dispatcher.Dispatcher, limiter *ratelimit.Limiter, resolver *versioning.Resolver, retryer *dlq.Retryer, dlqQueue *dlq.Queue, resultCache *cache.Cache) http.HandlerFunc {
	return InvokeHandlerWithConfig(d, limiter, resolver, retryer, dlqQueue, resultCache, nil)
}

// InvokeHandlerWithConfig handles synchronous function invocations with configuration injection.
func InvokeHandlerWithConfig(d *dispatcher.Dispatcher, limiter *ratelimit.Limiter, resolver *versioning.Resolver, retryer *dlq.Retryer, dlqQueue *dlq.Queue, resultCache *cache.Cache, configManager *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		startTime := time.Now()
		var req dispatcher.InvokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn("invalid request body", logging.Fields{"error": err.Error()})
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.FunctionName == "" {
			http.Error(w, "function_name is required", http.StatusBadRequest)
			return
		}

		originalFunctionName := req.FunctionName

		// Resolve version/alias if resolver is provided
		var resolvedVersion int
		var resolvedAlias string
		if resolver != nil {
			resolved, err := resolver.Resolve(req.FunctionName)
			if err != nil {
				logger.Warn("failed to resolve function version", logging.Fields{
					"function_name": req.FunctionName,
					"error":         err.Error(),
				})
				http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusNotFound)
				return
			}
			req.FunctionName = resolved.FunctionName
			resolvedVersion = resolved.Version
			resolvedAlias = resolved.Alias
		}

		// Check function-level access
		if err := auth.RequireFunctionAccess(req.FunctionName, r); err != nil {
			logger.Warn("function access denied", logging.Fields{
				"function_name": req.FunctionName,
				"error":         err.Error(),
			})
			http.Error(w, `{"error": "access denied for function"}`, http.StatusForbidden)
			return
		}

		// Check function-specific rate limit and concurrency
		if err := limiter.AcquireFunction(r.Context(), req.FunctionName); err != nil {
			logger.Warn("function rate/concurrency limit exceeded", logging.Fields{
				"function_name": req.FunctionName,
				"error":         err.Error(),
			})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}
		defer limiter.ReleaseFunction(req.FunctionName)

		// Check cache for existing result (skip if no-cache header is set)
		skipCache := r.Header.Get("Cache-Control") == "no-cache" || r.Header.Get("X-Skip-Cache") == "true"

		if resultCache != nil && !skipCache {
			if cachedEntry, err := resultCache.Get(req.FunctionName, resolvedVersion, req.Payload); err == nil {
				logger.Info("cache hit", logging.Fields{
					"function_name": req.FunctionName,
					"version":       resolvedVersion,
					"cache_key":     cachedEntry.Key,
					"hit_count":     cachedEntry.HitCount,
				})

				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Cache", "HIT")
				w.Header().Set("X-Cache-Key", cachedEntry.Key)
				w.Header().Set("X-Cache-Age", fmt.Sprintf("%.0f", time.Since(cachedEntry.CreatedAt).Seconds()))
				w.WriteHeader(cachedEntry.StatusCode)
				w.Write(cachedEntry.Response)
				return
			}
		}

		logger.Info("handling sync invocation", logging.Fields{
			"function_name": req.FunctionName,
			"version":       resolvedVersion,
			"alias":         resolvedAlias,
		})

		// Set version in request for dispatcher
		req.Version = resolvedVersion

		// Inject environment variables from configuration if manager is available
		if configManager != nil {
			envVars, err := configManager.GetEnvVars(r.Context(), req.FunctionName)
			if err != nil {
				logger.Debug("no env vars configured for function", logging.Fields{
					"function_name": req.FunctionName,
				})
			} else if len(envVars) > 0 {
				req.EnvVars = envVars
				logger.Debug("injected env vars", logging.Fields{
					"function_name": req.FunctionName,
					"env_var_count": len(envVars),
				})
			}
		}

		// Execute with retry support if retryer is provided
		var exec *dispatcher.Execution
		var finalErr error

		if retryer != nil {
			result := retryer.ExecuteWithRetry(r.Context(), req.FunctionName, func(ctx context.Context) (interface{}, error) {
				return d.Invoke(ctx, req)
			}, dlq.ClassifyError)

			if result.Success {
				exec = result.Result.(*dispatcher.Execution)
			} else {
				finalErr = result.FinalError

				// Send to DLQ on failure
				if dlqQueue != nil {
					failedEvent := &dlq.FailedEvent{
						InvocationID:  fmt.Sprintf("invoke-%d", time.Now().UnixNano()),
						FunctionName:  req.FunctionName,
						Version:       resolvedVersion,
						Alias:         resolvedAlias,
						Payload:       req.Payload,
						ErrorMessage:  finalErr.Error(),
						ErrorType:     dlq.ClassifyError(finalErr).GetErrorType(),
						FailureReason: dlq.ClassifyError(finalErr),
						RetryAttempts: result.Attempts,
						MaxRetries:    retryer.GetPolicy(req.FunctionName).MaxRetries,
						RetryHistory:  result.RetryHistory,
						OriginalTime:  startTime,
						FailedTime:    time.Now(),
						Source:        "http",
						Metadata: map[string]string{
							"original_function": originalFunctionName,
							"remote_addr":       r.RemoteAddr,
						},
					}
					if err := dlqQueue.Add(failedEvent); err != nil {
						logger.Error("failed to add event to DLQ", logging.Fields{"error": err.Error()})
					}
				}
			}
		} else {
			exec, finalErr = d.Invoke(r.Context(), req)
		}

		if finalErr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": finalErr.Error(),
			})
			return
		}

		// Serialize response for caching
		responseBytes, err := json.Marshal(exec)
		if err != nil {
			logger.Error("failed to serialize response", logging.Fields{"error": err.Error()})
		}

		// Cache successful responses
		if resultCache != nil && err == nil {
			cacheEntry, cacheErr := resultCache.Set(
				req.FunctionName,
				resolvedVersion,
				req.Payload,
				responseBytes,
				http.StatusOK,
				map[string]string{
					"original_function": originalFunctionName,
					"alias":             resolvedAlias,
				},
			)
			if cacheErr != nil && cacheErr != cache.ErrCacheDisabled {
				logger.Warn("failed to cache response", logging.Fields{"error": cacheErr.Error()})
			} else if cacheEntry != nil {
				w.Header().Set("X-Cache", "MISS")
				w.Header().Set("X-Cache-Key", cacheEntry.Key)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(responseBytes)
	}
}

// AsyncInvokeHandler handles asynchronous function invocations.
func AsyncInvokeHandler(d *dispatcher.Dispatcher, limiter *ratelimit.Limiter, resolver *versioning.Resolver, retryer *dlq.Retryer, dlqQueue *dlq.Queue) http.HandlerFunc {
	return AsyncInvokeHandlerWithConfig(d, limiter, resolver, retryer, dlqQueue, nil)
}

// AsyncInvokeHandlerWithConfig handles asynchronous function invocations with configuration injection.
func AsyncInvokeHandlerWithConfig(d *dispatcher.Dispatcher, limiter *ratelimit.Limiter, resolver *versioning.Resolver, retryer *dlq.Retryer, dlqQueue *dlq.Queue, configManager *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req dispatcher.InvokeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.Warn("invalid request body", logging.Fields{"error": err.Error()})
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.FunctionName == "" {
			http.Error(w, "function_name is required", http.StatusBadRequest)
			return
		}

		// Resolve version/alias if resolver is provided
		var resolvedVersion int
		var resolvedAlias string
		if resolver != nil {
			resolved, err := resolver.Resolve(req.FunctionName)
			if err != nil {
				logger.Warn("failed to resolve function version", logging.Fields{
					"function_name": req.FunctionName,
					"error":         err.Error(),
				})
				http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusNotFound)
				return
			}
			req.FunctionName = resolved.FunctionName
			resolvedVersion = resolved.Version
			resolvedAlias = resolved.Alias
		}

		// Check function-level access
		if err := auth.RequireFunctionAccess(req.FunctionName, r); err != nil {
			logger.Warn("function access denied", logging.Fields{
				"function_name": req.FunctionName,
				"error":         err.Error(),
			})
			http.Error(w, `{"error": "access denied for function"}`, http.StatusForbidden)
			return
		}

		// Check function-specific rate limit (but not concurrency for async)
		clientKey := getClientKey(r)
		if err := limiter.Allow(clientKey, req.FunctionName); err != nil {
			logger.Warn("function rate limit exceeded", logging.Fields{
				"function_name": req.FunctionName,
				"error":         err.Error(),
			})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}

		logger.Info("handling async invocation", logging.Fields{
			"function_name": req.FunctionName,
			"version":       resolvedVersion,
			"alias":         resolvedAlias,
		})

		// Set version in request for dispatcher
		req.Version = resolvedVersion

		// Inject environment variables from configuration if manager is available
		if configManager != nil {
			envVars, err := configManager.GetEnvVars(r.Context(), req.FunctionName)
			if err != nil {
				logger.Debug("no env vars configured for function", logging.Fields{
					"function_name": req.FunctionName,
				})
			} else if len(envVars) > 0 {
				req.EnvVars = envVars
				logger.Debug("injected env vars", logging.Fields{
					"function_name": req.FunctionName,
					"env_var_count": len(envVars),
				})
			}
		}

		exec, err := d.InvokeAsync(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(exec)
	}
}

// getClientKey extracts a unique key for rate limiting from the request.
func getClientKey(r *http.Request) string {
	if apiKey := auth.GetAPIKey(r.Context()); apiKey != nil {
		return "key:" + apiKey.ID
	}

	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		if idx := strings.Index(ip, ","); idx != -1 {
			ip = strings.TrimSpace(ip[:idx])
		}
	} else {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
	}

	return "ip:" + ip
}

// StatusHandler handles execution status queries.
func StatusHandler(d *dispatcher.Dispatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract execution ID from path: /status/{id}
		id := strings.TrimPrefix(r.URL.Path, "/status/")
		if id == "" {
			http.Error(w, "execution ID is required", http.StatusBadRequest)
			return
		}

		exec, err := d.GetExecution(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(exec)
	}
}

// HealthHandler handles health check requests.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// CallbackHandler handles workflow completion callbacks.
func CallbackHandler(d *dispatcher.Dispatcher, authMiddleware *auth.Middleware) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read the body for signature verification
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// Verify callback signature if configured
		if !authMiddleware.VerifyCallbackSignature(r, body) {
			logger.Warn("invalid callback signature", logging.Fields{
				"ip": r.RemoteAddr,
			})
			http.Error(w, `{"error": "invalid signature"}`, http.StatusUnauthorized)
			return
		}

		var callback struct {
			InvocationID string          `json:"invocation_id"`
			FunctionName string          `json:"function_name"`
			Status       string          `json:"status"`
			Result       json.RawMessage `json:"result,omitempty"`
			Error        string          `json:"error,omitempty"`
			DurationMs   float64         `json:"duration_ms,omitempty"`
		}

		if err := json.Unmarshal(body, &callback); err != nil {
			logger.Warn("invalid callback request", logging.Fields{"error": err.Error()})
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		logger.Info("received callback", logging.Fields{
			"invocation_id": callback.InvocationID,
			"function_name": callback.FunctionName,
			"status":        callback.Status,
		})

		status := dispatcher.StatusCompleted
		if callback.Status == "failed" {
			status = dispatcher.StatusFailed
			metrics.InvocationFailed(callback.FunctionName, callback.DurationMs)
		} else {
			metrics.InvocationCompleted(callback.FunctionName, callback.DurationMs)
		}

		if err := d.UpdateExecution(callback.InvocationID, status, callback.Result, callback.Error); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

package main

import (
	"context"
	"net/http"
	"os"
	"strconv"

	"github.com/github-lambda/internal/dispatcher"
	"github.com/github-lambda/internal/handlers"
	"github.com/github-lambda/pkg/auth"
	"github.com/github-lambda/pkg/dlq"
	"github.com/github-lambda/pkg/events"
	"github.com/github-lambda/pkg/logging"
	"github.com/github-lambda/pkg/metrics"
	"github.com/github-lambda/pkg/ratelimit"
	"github.com/github-lambda/pkg/versioning"
)

func main() {
	logger := logging.New("server")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		logger.Error("GITHUB_TOKEN environment variable is required")
		os.Exit(1)
	}

	repoOwner := os.Getenv("GITHUB_OWNER")
	repoName := os.Getenv("GITHUB_REPO")
	if repoOwner == "" || repoName == "" {
		logger.Error("GITHUB_OWNER and GITHUB_REPO environment variables are required")
		os.Exit(1)
	}

	// Initialize the key store
	keyStore := auth.NewKeyStore()

	// Load existing keys from file if configured
	if keysFile := os.Getenv("API_KEYS_FILE"); keysFile != "" {
		if err := keyStore.LoadFromFile(keysFile); err != nil {
			logger.Warn("failed to load API keys file", logging.Fields{"error": err.Error()})
		}
	}

	// Generate a bootstrap admin key if none exist and BOOTSTRAP_ADMIN_KEY is set
	if os.Getenv("BOOTSTRAP_ADMIN_KEY") == "true" && len(keyStore.ListKeys()) == 0 {
		key, keyInfo, err := keyStore.GenerateAPIKey(
			"bootstrap-admin",
			[]auth.Permission{auth.PermAll},
			nil,
			nil,
		)
		if err != nil {
			logger.Error("failed to generate bootstrap admin key", logging.Fields{"error": err.Error()})
		} else {
			logger.Info("generated bootstrap admin key - save this, it won't be shown again", logging.Fields{
				"key":    key,
				"key_id": keyInfo.ID,
			})
		}
	}

	// Initialize auth middleware
	authMiddleware := auth.NewMiddleware(keyStore)
	authMiddleware.SetSkipPaths("/health", "/metrics", "/ratelimit/stats")

	// Initialize rate limiter with configuration from environment
	rateLimitConfig := ratelimit.DefaultConfig()
	if rps := os.Getenv("RATE_LIMIT_RPS"); rps != "" {
		if v, err := strconv.ParseFloat(rps, 64); err == nil {
			rateLimitConfig.RequestsPerSecond = v
		}
	}
	if burst := os.Getenv("RATE_LIMIT_BURST"); burst != "" {
		if v, err := strconv.Atoi(burst); err == nil {
			rateLimitConfig.BurstSize = v
		}
	}
	if maxConcurrent := os.Getenv("RATE_LIMIT_MAX_CONCURRENT"); maxConcurrent != "" {
		if v, err := strconv.Atoi(maxConcurrent); err == nil {
			rateLimitConfig.MaxConcurrent = v
		}
	}
	if queueSize := os.Getenv("RATE_LIMIT_QUEUE_SIZE"); queueSize != "" {
		if v, err := strconv.Atoi(queueSize); err == nil {
			rateLimitConfig.MaxQueueSize = v
		}
	}

	limiter := ratelimit.New(rateLimitConfig)
	rateLimitMiddleware := ratelimit.NewMiddleware(limiter)

	logger.Info("rate limiter configured", logging.Fields{
		"rps":            rateLimitConfig.RequestsPerSecond,
		"burst":          rateLimitConfig.BurstSize,
		"max_concurrent": rateLimitConfig.MaxConcurrent,
		"queue_size":     rateLimitConfig.MaxQueueSize,
	})

	// Initialize the dispatcher with logging
	d := dispatcher.New(githubToken, repoOwner, repoName)

	// Initialize event source manager
	eventManager := events.NewManager(d)

	// Initialize event HTTP handler
	eventHandler := events.NewHTTPHandler(eventManager)

	// Start scheduler if not disabled
	if os.Getenv("SCHEDULER_DISABLED") != "true" {
		eventManager.StartScheduler()
		logger.Info("event scheduler started")
	}

	// Initialize versioning manager
	versionManager := versioning.NewManager()

	// Load versioning state from file if configured
	if versionFile := os.Getenv("VERSIONS_FILE"); versionFile != "" {
		if err := versionManager.LoadFromFile(versionFile); err != nil {
			logger.Warn("failed to load versions file", logging.Fields{"error": err.Error()})
		}
	}

	// Initialize version resolver
	versionResolver := versioning.NewResolver(versionManager)

	// Initialize versioning HTTP handler
	versioningHandler := versioning.NewHTTPHandler(versionManager)

	// Initialize Dead Letter Queue
	dlqConfig := dlq.DefaultConfig()
	if maxSize := os.Getenv("DLQ_MAX_SIZE"); maxSize != "" {
		if v, err := strconv.Atoi(maxSize); err == nil {
			dlqConfig.MaxSize = v
		}
	}
	if retention := os.Getenv("DLQ_RETENTION_DAYS"); retention != "" {
		if v, err := strconv.Atoi(retention); err == nil {
			dlqConfig.RetentionDays = v
		}
	}

	dlqQueue := dlq.NewQueue(dlqConfig)

	// Load DLQ state from file if configured
	if dlqFile := os.Getenv("DLQ_FILE"); dlqFile != "" {
		if err := dlqQueue.LoadFromFile(dlqFile); err != nil {
			logger.Warn("failed to load DLQ file", logging.Fields{"error": err.Error()})
		}
	}

	// Initialize retryer with default policy
	retryPolicy := dlq.DefaultRetryPolicy()
	if maxRetries := os.Getenv("DLQ_MAX_RETRIES"); maxRetries != "" {
		if v, err := strconv.Atoi(maxRetries); err == nil {
			retryPolicy.MaxRetries = v
		}
	}

	retryer := dlq.NewRetryer(dlqQueue, retryPolicy)

	// Initialize DLQ HTTP handler
	dlqHandler := dlq.NewHTTPHandler(dlqQueue, retryer)

	// Set up replay function
	dlqHandler.SetReplayFunc(func(event *dlq.FailedEvent) error {
		req := dispatcher.InvokeRequest{
			FunctionName: event.FunctionName,
			Version:      event.Version,
			Payload:      event.Payload,
		}
		_, err := d.InvokeAsync(context.Background(), req)
		return err
	})

	logger.Info("DLQ configured", logging.Fields{
		"max_size":       dlqConfig.MaxSize,
		"retention_days": dlqConfig.RetentionDays,
		"max_retries":    retryPolicy.MaxRetries,
	})

	// Initialize admin handler
	adminHandler := auth.NewAdminHandler(keyStore)

	// Set up HTTP routes
	mux := http.NewServeMux()

	// Public routes (no auth required)
	mux.HandleFunc("/health", handlers.HealthHandler)
	mux.HandleFunc("/metrics", metrics.Default.Handler())
	mux.HandleFunc("/ratelimit/stats", rateLimitMiddleware.Handler())

	// Protected routes
	mux.HandleFunc("/invoke", handlers.InvokeHandler(d, limiter, versionResolver, retryer, dlqQueue))
	mux.HandleFunc("/invoke/async", handlers.AsyncInvokeHandler(d, limiter, versionResolver, retryer, dlqQueue))
	mux.HandleFunc("/status/", handlers.StatusHandler(d))
	mux.HandleFunc("/callback", handlers.CallbackHandler(d, authMiddleware))

	// Admin routes (require admin permission)
	adminHandler.RegisterRoutes(mux)

	// Event source routes
	eventHandler.RegisterRoutes(mux)

	// Versioning routes (require admin permission)
	versioningHandler.RegisterRoutes(mux)

	// DLQ routes
	dlqHandler.RegisterRoutes(mux)

	// Determine if auth is enabled
	authEnabled := os.Getenv("AUTH_DISABLED") != "true"
	rateLimitEnabled := os.Getenv("RATE_LIMIT_DISABLED") != "true"

	var handler http.Handler = mux

	// Apply rate limiting middleware if enabled (before auth so we can rate limit unauthenticated requests)
	if rateLimitEnabled {
		handler = rateLimitMiddleware.RateLimit(handler)
		logger.Info("rate limiting enabled")
	} else {
		logger.Warn("rate limiting DISABLED - not recommended for production")
	}

	// Apply authentication middleware if enabled
	if authEnabled {
		handler = authMiddleware.RequireAuth(handler)
		logger.Info("authentication enabled")
	} else {
		logger.Warn("authentication DISABLED - not recommended for production")
	}

	// Apply metrics middleware (outermost)
	handler = metrics.Middleware(handler)

	logger.Info("server starting", logging.Fields{
		"port":               port,
		"owner":              repoOwner,
		"repo":               repoName,
		"auth_enabled":       authEnabled,
		"rate_limit_enabled": rateLimitEnabled,
	})

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		logger.Error("server failed to start", logging.Fields{"error": err})
		os.Exit(1)
	}
}

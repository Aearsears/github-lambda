package main

import (
	"net/http"
	"os"

	"github.com/github-lambda/internal/dispatcher"
	"github.com/github-lambda/internal/handlers"
	"github.com/github-lambda/pkg/auth"
	"github.com/github-lambda/pkg/logging"
	"github.com/github-lambda/pkg/metrics"
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
	authMiddleware.SetSkipPaths("/health", "/metrics")

	// Initialize the dispatcher with logging
	d := dispatcher.New(githubToken, repoOwner, repoName)

	// Initialize admin handler
	adminHandler := auth.NewAdminHandler(keyStore)

	// Set up HTTP routes
	mux := http.NewServeMux()

	// Public routes (no auth required)
	mux.HandleFunc("/health", handlers.HealthHandler)
	mux.HandleFunc("/metrics", metrics.Default.Handler())

	// Protected routes
	mux.HandleFunc("/invoke", handlers.InvokeHandler(d))
	mux.HandleFunc("/invoke/async", handlers.AsyncInvokeHandler(d))
	mux.HandleFunc("/status/", handlers.StatusHandler(d))
	mux.HandleFunc("/callback", handlers.CallbackHandler(d, authMiddleware))

	// Admin routes (require admin permission)
	adminHandler.RegisterRoutes(mux)

	// Determine if auth is enabled
	authEnabled := os.Getenv("AUTH_DISABLED") != "true"

	var handler http.Handler = mux

	// Apply authentication middleware if enabled
	if authEnabled {
		handler = authMiddleware.RequireAuth(mux)
		logger.Info("authentication enabled")
	} else {
		logger.Warn("authentication DISABLED - not recommended for production")
	}

	// Apply metrics middleware (outermost)
	handler = metrics.Middleware(handler)

	logger.Info("server starting", logging.Fields{
		"port":         port,
		"owner":        repoOwner,
		"repo":         repoName,
		"auth_enabled": authEnabled,
	})

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		logger.Error("server failed to start", logging.Fields{"error": err})
		os.Exit(1)
	}
}

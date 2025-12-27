package main

import (
	"net/http"
	"os"

	"github.com/github-lambda/internal/dispatcher"
	"github.com/github-lambda/internal/handlers"
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

	// Initialize the dispatcher with logging
	d := dispatcher.New(githubToken, repoOwner, repoName)

	// Set up HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/invoke", handlers.InvokeHandler(d))
	mux.HandleFunc("/invoke/async", handlers.AsyncInvokeHandler(d))
	mux.HandleFunc("/status/", handlers.StatusHandler(d))
	mux.HandleFunc("/health", handlers.HealthHandler)
	mux.HandleFunc("/metrics", metrics.Default.Handler())
	mux.HandleFunc("/callback", handlers.CallbackHandler(d))

	// Wrap with metrics middleware
	handler := metrics.Middleware(mux)

	logger.Info("server starting", logging.Fields{
		"port":  port,
		"owner": repoOwner,
		"repo":  repoName,
	})

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		logger.Error("server failed to start", logging.Fields{"error": err})
		os.Exit(1)
	}
}

package main

import (
	"log"
	"net/http"
	"os"

	"github.com/github-lambda/internal/dispatcher"
	"github.com/github-lambda/internal/handlers"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		log.Fatal("GITHUB_TOKEN environment variable is required")
	}

	repoOwner := os.Getenv("GITHUB_OWNER")
	repoName := os.Getenv("GITHUB_REPO")
	if repoOwner == "" || repoName == "" {
		log.Fatal("GITHUB_OWNER and GITHUB_REPO environment variables are required")
	}

	// Initialize the dispatcher
	d := dispatcher.New(githubToken, repoOwner, repoName)

	// Set up HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/invoke", handlers.InvokeHandler(d))
	mux.HandleFunc("/invoke/async", handlers.AsyncInvokeHandler(d))
	mux.HandleFunc("/status/", handlers.StatusHandler(d))
	mux.HandleFunc("/health", handlers.HealthHandler)

	log.Printf("github-lambda server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

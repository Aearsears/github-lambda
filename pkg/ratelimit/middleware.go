package ratelimit

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/github-lambda/pkg/auth"
	"github.com/github-lambda/pkg/logging"
)

// Middleware provides HTTP middleware for rate limiting.
type Middleware struct {
	limiter *Limiter
	logger  *logging.Logger
}

// NewMiddleware creates new rate limiting middleware.
func NewMiddleware(limiter *Limiter) *Middleware {
	return &Middleware{
		limiter: limiter,
		logger:  logging.New("ratelimit"),
	}
}

// getClientKey extracts a unique key for rate limiting from the request.
func (m *Middleware) getClientKey(r *http.Request) string {
	// First, try to use API key ID if authenticated
	if apiKey := auth.GetAPIKey(r.Context()); apiKey != nil {
		return "key:" + apiKey.ID
	}

	// Fall back to IP address
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		// Take the first IP in the chain
		if idx := strings.Index(ip, ","); idx != -1 {
			ip = strings.TrimSpace(ip[:idx])
		}
	} else {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = r.RemoteAddr
		// Remove port if present
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
	}

	return "ip:" + ip
}

// RateLimit returns middleware that applies rate limiting.
func (m *Middleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientKey := m.getClientKey(r)

		// Check rate limit (without function context for general endpoints)
		if err := m.limiter.Allow(clientKey, ""); err != nil {
			m.logger.Warn("rate limit exceeded", logging.Fields{
				"client_key": clientKey,
				"path":       r.URL.Path,
				"error":      err.Error(),
			})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}

		// Acquire concurrency slot
		if err := m.limiter.Acquire(r.Context()); err != nil {
			m.logger.Warn("concurrency limit exceeded", logging.Fields{
				"client_key": clientKey,
				"path":       r.URL.Path,
				"error":      err.Error(),
			})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}
		defer m.limiter.Release()

		next.ServeHTTP(w, r)
	})
}

// RateLimitFunc returns middleware that applies function-specific rate limiting.
// This is meant to wrap individual function invoke handlers.
func (m *Middleware) RateLimitFunc(functionName string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientKey := m.getClientKey(r)

		// Check function-specific rate limit
		if err := m.limiter.Allow(clientKey, functionName); err != nil {
			m.logger.Warn("function rate limit exceeded", logging.Fields{
				"client_key": clientKey,
				"function":   functionName,
				"error":      err.Error(),
			})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}

		// Check function concurrency limit
		if err := m.limiter.AcquireFunction(r.Context(), functionName); err != nil {
			m.logger.Warn("function concurrency limit exceeded", logging.Fields{
				"client_key": clientKey,
				"function":   functionName,
				"error":      err.Error(),
			})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}
		defer m.limiter.ReleaseFunction(functionName)

		next.ServeHTTP(w, r)
	})
}

// Handler returns an HTTP handler for rate limit stats endpoint.
func (m *Middleware) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m.limiter.Stats())
	}
}

// CheckFunctionLimit checks if a function invocation is allowed.
// This can be called directly from handlers before invoking.
func CheckFunctionLimit(r *http.Request, functionName string) error {
	// Get client key from request
	clientKey := ""
	if apiKey := auth.GetAPIKey(r.Context()); apiKey != nil {
		clientKey = "key:" + apiKey.ID
	} else {
		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
		clientKey = "ip:" + ip
	}

	// Check rate limit
	if err := Default.Allow(clientKey, functionName); err != nil {
		return err
	}

	// Check concurrency
	if err := Default.AcquireFunction(r.Context(), functionName); err != nil {
		return err
	}

	return nil
}

// ReleaseFunctionLimit releases the function concurrency slot.
func ReleaseFunctionLimit(functionName string) {
	Default.ReleaseFunction(functionName)
}

package warmpool

import (
	"context"
	"net/http"

	"github.com/github-lambda/pkg/logging"
)

// ColdStartMiddleware injects cold start optimization into requests.
type ColdStartMiddleware struct {
	manager     *Manager
	prebuildMgr *PrebuildManager
	logger      *logging.Logger
}

// NewColdStartMiddleware creates middleware for cold start optimization.
func NewColdStartMiddleware(manager *Manager, prebuildMgr *PrebuildManager) *ColdStartMiddleware {
	return &ColdStartMiddleware{
		manager:     manager,
		prebuildMgr: prebuildMgr,
		logger:      logging.New("coldstart-middleware"),
	}
}

// ContextKey for warm pool context values.
type ContextKey string

const (
	// ContextKeyWarmPool is the context key for warm pool manager.
	ContextKeyWarmPool ContextKey = "warmpool_manager"

	// ContextKeyPrebuild is the context key for prebuild manager.
	ContextKeyPrebuild ContextKey = "prebuild_manager"

	// ContextKeyCacheConfig is the context key for cache configuration.
	ContextKeyCacheConfig ContextKey = "cache_config"

	// ContextKeyWarmInstance is the context key for warm instance.
	ContextKeyWarmInstance ContextKey = "warm_instance"
)

// Middleware wraps an HTTP handler with cold start optimization.
func (m *ColdStartMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Inject managers into context
		ctx = context.WithValue(ctx, ContextKeyWarmPool, m.manager)
		ctx = context.WithValue(ctx, ContextKeyPrebuild, m.prebuildMgr)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// WarmInstanceMiddleware attempts to use warm instances for function invocations.
func (m *ColdStartMiddleware) WarmInstanceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Extract function name from request (implementation depends on your routing)
		functionName := r.Header.Get("X-Function-Name")
		if functionName == "" {
			functionName = r.URL.Query().Get("function")
		}

		if functionName != "" {
			// Try to get a warm instance
			instance, err := m.manager.GetWarmInstance(functionName)
			if err == nil {
				ctx = context.WithValue(ctx, ContextKeyWarmInstance, instance)

				m.logger.Debug("using warm instance", logging.Fields{
					"function_name": functionName,
					"instance_id":   instance.ID,
				})

				// Release instance after request
				defer func() {
					if err := m.manager.ReleaseInstance(instance.ID); err != nil {
						m.logger.Warn("failed to release instance", logging.Fields{
							"instance_id": instance.ID,
							"error":       err.Error(),
						})
					}
				}()
			} else {
				m.logger.Debug("no warm instance available", logging.Fields{
					"function_name": functionName,
					"error":         err.Error(),
				})
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CacheConfigMiddleware injects cache configuration for functions.
func (m *ColdStartMiddleware) CacheConfigMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		functionName := r.Header.Get("X-Function-Name")
		if functionName == "" {
			functionName = r.URL.Query().Get("function")
		}

		if functionName != "" {
			config, err := m.manager.GetGitHubCacheConfig(functionName)
			if err == nil {
				ctx = context.WithValue(ctx, ContextKeyCacheConfig, config)

				m.logger.Debug("cache config injected", logging.Fields{
					"function_name": functionName,
					"cache_paths":   len(config.CachePaths),
				})
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AutoPrebuildMiddleware triggers prebuilds when dependencies change.
func (m *ColdStartMiddleware) AutoPrebuildMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle webhook events that might trigger prebuilds
		if r.Header.Get("X-GitHub-Event") == "push" {
			// Check if any registered prebuild should be triggered
			m.prebuildMgr.mu.RLock()
			for _, spec := range m.prebuildMgr.specs {
				if spec.Enabled && spec.TriggerOnPush {
					go func(s *PrebuildSpec) {
						_, err := m.prebuildMgr.TriggerBuild(context.Background(), s.FunctionName, BuildTriggerWebhook)
						if err != nil {
							m.logger.Warn("failed to trigger auto prebuild", logging.Fields{
								"function_name": s.FunctionName,
								"error":         err.Error(),
							})
						}
					}(spec)
				}
			}
			m.prebuildMgr.mu.RUnlock()
		}

		next.ServeHTTP(w, r)
	})
}

// GetWarmPoolFromContext retrieves the warm pool manager from context.
func GetWarmPoolFromContext(ctx context.Context) *Manager {
	if manager, ok := ctx.Value(ContextKeyWarmPool).(*Manager); ok {
		return manager
	}
	return nil
}

// GetPrebuildFromContext retrieves the prebuild manager from context.
func GetPrebuildFromContext(ctx context.Context) *PrebuildManager {
	if manager, ok := ctx.Value(ContextKeyPrebuild).(*PrebuildManager); ok {
		return manager
	}
	return nil
}

// GetCacheConfigFromContext retrieves the cache config from context.
func GetCacheConfigFromContext(ctx context.Context) *GitHubCacheConfig {
	if config, ok := ctx.Value(ContextKeyCacheConfig).(*GitHubCacheConfig); ok {
		return config
	}
	return nil
}

// GetWarmInstanceFromContext retrieves the warm instance from context.
func GetWarmInstanceFromContext(ctx context.Context) *WarmInstance {
	if instance, ok := ctx.Value(ContextKeyWarmInstance).(*WarmInstance); ok {
		return instance
	}
	return nil
}

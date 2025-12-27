package config

import (
	"context"
	"net/http"
	"sync"

	"github.com/github-lambda/pkg/logging"
)

var middlewareLogger = logging.New("config-middleware")

// contextKey is used for storing config in context.
type contextKey string

const (
	// EnvVarsContextKey is the key for storing resolved env vars in context.
	EnvVarsContextKey contextKey = "config_env_vars"
	// FunctionConfigContextKey is the key for storing function config in context.
	FunctionConfigContextKey contextKey = "function_config"
)

// Middleware injects configuration into requests.
type Middleware struct {
	manager      *Manager
	mu           sync.RWMutex
	resolveOnce  map[string]*sync.Once
	resolvedVars map[string]map[string]string
}

// NewMiddleware creates a new configuration middleware.
func NewMiddleware(manager *Manager) *Middleware {
	return &Middleware{
		manager:      manager,
		resolveOnce:  make(map[string]*sync.Once),
		resolvedVars: make(map[string]map[string]string),
	}
}

// InjectConfig returns middleware that injects configuration for a function.
func (m *Middleware) InjectConfig(functionName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Resolve env vars for the function
			envVars, err := m.manager.GetEnvVars(ctx, functionName)
			if err != nil {
				middlewareLogger.Error("failed to resolve env vars", logging.Fields{
					"function_name": functionName,
					"error":         err.Error(),
				})
				// Continue without env vars rather than failing
				envVars = make(map[string]string)
			}

			// Add env vars to context
			ctx = context.WithValue(ctx, EnvVarsContextKey, envVars)

			// Add function config to context if it exists
			if config, err := m.manager.GetFunctionConfig(functionName); err == nil {
				ctx = context.WithValue(ctx, FunctionConfigContextKey, config)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetEnvVarsFromContext retrieves resolved env vars from context.
func GetEnvVarsFromContext(ctx context.Context) map[string]string {
	if envVars, ok := ctx.Value(EnvVarsContextKey).(map[string]string); ok {
		return envVars
	}
	return nil
}

// GetFunctionConfigFromContext retrieves function config from context.
func GetFunctionConfigFromContext(ctx context.Context) *FunctionConfig {
	if config, ok := ctx.Value(FunctionConfigContextKey).(*FunctionConfig); ok {
		return config
	}
	return nil
}

// GetEnvVar retrieves a single env var from context with a default fallback.
func GetEnvVar(ctx context.Context, key, defaultValue string) string {
	envVars := GetEnvVarsFromContext(ctx)
	if envVars == nil {
		return defaultValue
	}
	if val, ok := envVars[key]; ok {
		return val
	}
	return defaultValue
}

// MustGetEnvVar retrieves a single env var from context, panicking if not found.
func MustGetEnvVar(ctx context.Context, key string) string {
	envVars := GetEnvVarsFromContext(ctx)
	if envVars == nil {
		panic("env vars not found in context")
	}
	if val, ok := envVars[key]; ok {
		return val
	}
	panic("required env var not found: " + key)
}

// FunctionEnvProvider provides environment variables to a specific function execution.
type FunctionEnvProvider struct {
	manager      *Manager
	functionName string
	cache        map[string]string
	cacheMu      sync.RWMutex
	resolved     bool
}

// NewFunctionEnvProvider creates a new function-specific env provider.
func NewFunctionEnvProvider(manager *Manager, functionName string) *FunctionEnvProvider {
	return &FunctionEnvProvider{
		manager:      manager,
		functionName: functionName,
		cache:        make(map[string]string),
	}
}

// Resolve resolves all env vars for the function and caches them.
func (p *FunctionEnvProvider) Resolve(ctx context.Context) error {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()

	if p.resolved {
		return nil
	}

	envVars, err := p.manager.GetEnvVars(ctx, p.functionName)
	if err != nil {
		return err
	}

	p.cache = envVars
	p.resolved = true

	return nil
}

// Get retrieves an env var, resolving if necessary.
func (p *FunctionEnvProvider) Get(ctx context.Context, key string) (string, error) {
	if err := p.Resolve(ctx); err != nil {
		return "", err
	}

	p.cacheMu.RLock()
	defer p.cacheMu.RUnlock()

	if val, ok := p.cache[key]; ok {
		return val, nil
	}

	return "", ErrConfigNotFound
}

// GetWithDefault retrieves an env var with a default fallback.
func (p *FunctionEnvProvider) GetWithDefault(ctx context.Context, key, defaultValue string) string {
	val, err := p.Get(ctx, key)
	if err != nil {
		return defaultValue
	}
	return val
}

// GetAll returns all resolved env vars.
func (p *FunctionEnvProvider) GetAll(ctx context.Context) (map[string]string, error) {
	if err := p.Resolve(ctx); err != nil {
		return nil, err
	}

	p.cacheMu.RLock()
	defer p.cacheMu.RUnlock()

	result := make(map[string]string, len(p.cache))
	for k, v := range p.cache {
		result[k] = v
	}
	return result, nil
}

// Invalidate clears the cached env vars.
func (p *FunctionEnvProvider) Invalidate() {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	p.cache = make(map[string]string)
	p.resolved = false
}

// ConfigAwareHandler wraps a handler with configuration injection.
type ConfigAwareHandler struct {
	manager *Manager
	handler http.Handler
}

// NewConfigAwareHandler creates a new config-aware handler wrapper.
func NewConfigAwareHandler(manager *Manager, handler http.Handler) *ConfigAwareHandler {
	return &ConfigAwareHandler{
		manager: manager,
		handler: handler,
	}
}

// ServeHTTP implements http.Handler with automatic config injection.
func (h *ConfigAwareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Try to extract function name from the request
	functionName := extractFunctionName(r)
	if functionName == "" {
		h.handler.ServeHTTP(w, r)
		return
	}

	ctx := r.Context()

	// Resolve env vars for the function
	envVars, err := h.manager.GetEnvVars(ctx, functionName)
	if err != nil {
		middlewareLogger.Debug("no config for function", logging.Fields{
			"function_name": functionName,
		})
		envVars = make(map[string]string)
	}

	// Add to context
	ctx = context.WithValue(ctx, EnvVarsContextKey, envVars)

	if config, err := h.manager.GetFunctionConfig(functionName); err == nil {
		ctx = context.WithValue(ctx, FunctionConfigContextKey, config)
	}

	h.handler.ServeHTTP(w, r.WithContext(ctx))
}

// extractFunctionName attempts to extract the function name from the request.
func extractFunctionName(r *http.Request) string {
	// Try query parameter
	if fn := r.URL.Query().Get("function"); fn != "" {
		return fn
	}
	if fn := r.URL.Query().Get("function_name"); fn != "" {
		return fn
	}

	// Try header
	if fn := r.Header.Get("X-Function-Name"); fn != "" {
		return fn
	}

	return ""
}

// RuntimeEnvInjector injects resolved env vars into the actual process environment.
// This is useful when running lambda functions as subprocesses.
type RuntimeEnvInjector struct {
	manager *Manager
}

// NewRuntimeEnvInjector creates a new runtime env injector.
func NewRuntimeEnvInjector(manager *Manager) *RuntimeEnvInjector {
	return &RuntimeEnvInjector{manager: manager}
}

// GetEnvForFunction returns environment variables formatted for subprocess execution.
func (i *RuntimeEnvInjector) GetEnvForFunction(ctx context.Context, functionName string, baseEnv []string) ([]string, error) {
	envVars, err := i.manager.GetEnvVars(ctx, functionName)
	if err != nil {
		return nil, err
	}

	// Start with base environment
	result := make([]string, len(baseEnv))
	copy(result, baseEnv)

	// Add function-specific env vars
	for k, v := range envVars {
		result = append(result, k+"="+v)
	}

	return result, nil
}

// ToEnvSlice converts a map of env vars to a slice of "KEY=VALUE" strings.
func ToEnvSlice(envVars map[string]string) []string {
	result := make([]string, 0, len(envVars))
	for k, v := range envVars {
		result = append(result, k+"="+v)
	}
	return result
}

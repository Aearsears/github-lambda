package lambda

import (
	"fmt"
	"sync"
)

// Registry manages registered lambda functions.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// NewRegistry creates a new function registry.
func NewRegistry() *Registry {
	return &Registry{
		handlers: make(map[string]Handler),
	}
}

// DefaultRegistry is the global default registry.
var DefaultRegistry = NewRegistry()

// Register adds a handler to the registry.
func (r *Registry) Register(name string, handler Handler) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.handlers[name]; exists {
		return fmt.Errorf("handler already registered: %s", name)
	}

	r.handlers[name] = handler
	return nil
}

// RegisterFunc adds a handler function to the registry.
func (r *Registry) RegisterFunc(name string, fn HandlerFunc) error {
	return r.Register(name, fn)
}

// Get retrieves a handler by name.
func (r *Registry) Get(name string) (Handler, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	handler, exists := r.handlers[name]
	if !exists {
		return nil, fmt.Errorf("handler not found: %s", name)
	}

	return handler, nil
}

// List returns all registered handler names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.handlers))
	for name := range r.handlers {
		names = append(names, name)
	}
	return names
}

// Register adds a handler to the default registry.
func Register(name string, handler Handler) error {
	return DefaultRegistry.Register(name, handler)
}

// RegisterFunc adds a handler function to the default registry.
func RegisterFunc(name string, fn HandlerFunc) error {
	return DefaultRegistry.RegisterFunc(name, fn)
}

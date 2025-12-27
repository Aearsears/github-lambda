package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/github-lambda/pkg/logging"
)

var (
	ErrInvalidAPIKey     = errors.New("invalid API key")
	ErrMissingAPIKey     = errors.New("missing API key")
	ErrExpiredAPIKey     = errors.New("API key has expired")
	ErrInsufficientPerms = errors.New("insufficient permissions")
	ErrInvalidSignature  = errors.New("invalid signature")
)

// Permission represents an action that can be performed.
type Permission string

const (
	PermInvoke      Permission = "invoke"
	PermInvokeAsync Permission = "invoke:async"
	PermStatus      Permission = "status"
	PermMetrics     Permission = "metrics"
	PermAdmin       Permission = "admin"
	PermAll         Permission = "*"
)

// APIKey represents an API key with associated permissions.
type APIKey struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	KeyHash     string       `json:"key_hash"` // SHA256 hash of the key
	Permissions []Permission `json:"permissions"`
	Functions   []string     `json:"functions,omitempty"` // Empty means all functions
	CreatedAt   time.Time    `json:"created_at"`
	ExpiresAt   *time.Time   `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time   `json:"last_used_at,omitempty"`
	Enabled     bool         `json:"enabled"`
}

// HasPermission checks if the API key has the given permission.
func (k *APIKey) HasPermission(perm Permission) bool {
	for _, p := range k.Permissions {
		if p == PermAll || p == perm {
			return true
		}
	}
	return false
}

// CanAccessFunction checks if the API key can access the given function.
func (k *APIKey) CanAccessFunction(functionName string) bool {
	if len(k.Functions) == 0 {
		return true // Empty means all functions
	}
	for _, f := range k.Functions {
		if f == "*" || f == functionName {
			return true
		}
		// Support wildcard patterns like "hello-*"
		if strings.HasSuffix(f, "*") {
			prefix := strings.TrimSuffix(f, "*")
			if strings.HasPrefix(functionName, prefix) {
				return true
			}
		}
	}
	return false
}

// IsValid checks if the API key is valid (enabled and not expired).
func (k *APIKey) IsValid() error {
	if !k.Enabled {
		return ErrInvalidAPIKey
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return ErrExpiredAPIKey
	}
	return nil
}

// KeyStore manages API keys.
type KeyStore struct {
	mu     sync.RWMutex
	keys   map[string]*APIKey // Keyed by hash
	logger *logging.Logger
}

// NewKeyStore creates a new key store.
func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys:   make(map[string]*APIKey),
		logger: logging.New("auth"),
	}
}

// GenerateAPIKey creates a new API key with the given parameters.
func (s *KeyStore) GenerateAPIKey(name string, permissions []Permission, functions []string, ttl *time.Duration) (string, *APIKey, error) {
	// Generate a random 32-byte key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create the key string with a prefix for easy identification
	keyString := "ghl_" + hex.EncodeToString(keyBytes)

	// Hash the key for storage
	hash := sha256.Sum256([]byte(keyString))
	keyHash := hex.EncodeToString(hash[:])

	// Generate a short ID
	idBytes := make([]byte, 8)
	rand.Read(idBytes)
	id := hex.EncodeToString(idBytes)

	key := &APIKey{
		ID:          id,
		Name:        name,
		KeyHash:     keyHash,
		Permissions: permissions,
		Functions:   functions,
		CreatedAt:   time.Now(),
		Enabled:     true,
	}

	if ttl != nil {
		expiresAt := time.Now().Add(*ttl)
		key.ExpiresAt = &expiresAt
	}

	s.mu.Lock()
	s.keys[keyHash] = key
	s.mu.Unlock()

	s.logger.Info("API key generated", logging.Fields{
		"key_id": id,
		"name":   name,
	})

	return keyString, key, nil
}

// ValidateKey validates an API key and returns the key object if valid.
func (s *KeyStore) ValidateKey(keyString string) (*APIKey, error) {
	hash := sha256.Sum256([]byte(keyString))
	keyHash := hex.EncodeToString(hash[:])

	s.mu.RLock()
	key, exists := s.keys[keyHash]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrInvalidAPIKey
	}

	if err := key.IsValid(); err != nil {
		return nil, err
	}

	// Update last used time
	s.mu.Lock()
	now := time.Now()
	key.LastUsedAt = &now
	s.mu.Unlock()

	return key, nil
}

// RevokeKey revokes an API key by ID.
func (s *KeyStore) RevokeKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, key := range s.keys {
		if key.ID == id {
			key.Enabled = false
			s.logger.Info("API key revoked", logging.Fields{"key_id": id})
			return nil
		}
	}

	return fmt.Errorf("key not found: %s", id)
}

// DeleteKey permanently deletes an API key by ID.
func (s *KeyStore) DeleteKey(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for hash, key := range s.keys {
		if key.ID == id {
			delete(s.keys, hash)
			s.logger.Info("API key deleted", logging.Fields{"key_id": id})
			return nil
		}
	}

	return fmt.Errorf("key not found: %s", id)
}

// ListKeys returns all API keys (without the actual key values).
func (s *KeyStore) ListKeys() []*APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]*APIKey, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, key)
	}
	return keys
}

// LoadFromFile loads API keys from a JSON file.
func (s *KeyStore) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, start fresh
		}
		return err
	}

	var keys []*APIKey
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}

	s.mu.Lock()
	for _, key := range keys {
		s.keys[key.KeyHash] = key
	}
	s.mu.Unlock()

	s.logger.Info("loaded API keys from file", logging.Fields{
		"path":  path,
		"count": len(keys),
	})

	return nil
}

// SaveToFile saves API keys to a JSON file.
func (s *KeyStore) SaveToFile(path string) error {
	s.mu.RLock()
	keys := make([]*APIKey, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, key)
	}
	s.mu.RUnlock()

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// DefaultKeyStore is the global key store.
var DefaultKeyStore = NewKeyStore()

// Context key for authenticated key
type contextKey string

const authKeyContextKey contextKey = "auth_key"

// GetAPIKey retrieves the authenticated API key from context.
func GetAPIKey(ctx context.Context) *APIKey {
	if key, ok := ctx.Value(authKeyContextKey).(*APIKey); ok {
		return key
	}
	return nil
}

// WithAPIKey adds an API key to the context.
func WithAPIKey(ctx context.Context, key *APIKey) context.Context {
	return context.WithValue(ctx, authKeyContextKey, key)
}

// Middleware provides authentication middleware.
type Middleware struct {
	keyStore       *KeyStore
	logger         *logging.Logger
	skipPaths      map[string]bool
	callbackSecret string
}

// NewMiddleware creates a new authentication middleware.
func NewMiddleware(keyStore *KeyStore) *Middleware {
	return &Middleware{
		keyStore: keyStore,
		logger:   logging.New("auth"),
		skipPaths: map[string]bool{
			"/health": true,
		},
		callbackSecret: os.Getenv("CALLBACK_SECRET"),
	}
}

// extractAPIKey extracts the API key from the request.
func (m *Middleware) extractAPIKey(r *http.Request) string {
	// Check Authorization header first
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// Check X-API-Key header
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}

	// Check query parameter (less secure, but useful for some use cases)
	if key := r.URL.Query().Get("api_key"); key != "" {
		return key
	}

	return ""
}

// RequireAuth returns middleware that requires authentication.
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for certain paths
		if m.skipPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		keyString := m.extractAPIKey(r)
		if keyString == "" {
			m.logger.Warn("missing API key", logging.Fields{
				"path":   r.URL.Path,
				"method": r.Method,
				"ip":     r.RemoteAddr,
			})
			http.Error(w, `{"error": "missing API key"}`, http.StatusUnauthorized)
			return
		}

		key, err := m.keyStore.ValidateKey(keyString)
		if err != nil {
			m.logger.Warn("invalid API key", logging.Fields{
				"path":   r.URL.Path,
				"method": r.Method,
				"ip":     r.RemoteAddr,
				"error":  err.Error(),
			})
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusUnauthorized)
			return
		}

		// Add key to context
		ctx := WithAPIKey(r.Context(), key)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission returns middleware that checks for a specific permission.
func RequirePermission(perm Permission) func(http.Handler) http.Handler {
	logger := logging.New("auth")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := GetAPIKey(r.Context())
			if key == nil {
				http.Error(w, `{"error": "not authenticated"}`, http.StatusUnauthorized)
				return
			}

			if !key.HasPermission(perm) {
				logger.Warn("insufficient permissions", logging.Fields{
					"key_id":   key.ID,
					"required": perm,
					"granted":  key.Permissions,
				})
				http.Error(w, `{"error": "insufficient permissions"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireFunctionAccess checks if the authenticated key can access the given function.
func RequireFunctionAccess(functionName string, r *http.Request) error {
	key := GetAPIKey(r.Context())
	if key == nil {
		return ErrMissingAPIKey
	}

	if !key.CanAccessFunction(functionName) {
		return ErrInsufficientPerms
	}

	return nil
}

// VerifyCallbackSignature verifies the HMAC signature of a callback request.
func (m *Middleware) VerifyCallbackSignature(r *http.Request, body []byte) bool {
	if m.callbackSecret == "" {
		// No secret configured, skip verification (not recommended for production)
		return true
	}

	signature := r.Header.Get("X-Lambda-Signature")
	if signature == "" {
		return false
	}

	// Expected format: sha256=<hex-encoded-signature>
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	providedSig, err := hex.DecodeString(strings.TrimPrefix(signature, "sha256="))
	if err != nil {
		return false
	}

	// Compute expected signature
	mac := hmac.New(sha256.New, []byte(m.callbackSecret))
	mac.Write(body)
	expectedSig := mac.Sum(nil)

	return hmac.Equal(providedSig, expectedSig)
}

// GenerateCallbackSignature generates an HMAC signature for callback data.
func GenerateCallbackSignature(secret string, data []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// ConstantTimeCompare performs a constant-time comparison of two strings.
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// SetSkipPaths sets paths that should skip authentication.
func (m *Middleware) SetSkipPaths(paths ...string) {
	m.skipPaths = make(map[string]bool)
	for _, p := range paths {
		m.skipPaths[p] = true
	}
}

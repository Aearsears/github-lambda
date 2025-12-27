package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/github-lambda/pkg/logging"
)

var logger = logging.New("config")

// Common errors
var (
	ErrConfigNotFound      = errors.New("configuration not found")
	ErrSecretNotFound      = errors.New("secret not found")
	ErrInvalidEncryption   = errors.New("invalid encryption")
	ErrEncryptionRequired  = errors.New("encryption key required for secrets")
	ErrFunctionNotFound    = errors.New("function not found")
	ErrInvalidSecretSource = errors.New("invalid secret source")
)

// SecretSource represents where a secret is stored.
type SecretSource string

const (
	// SecretSourceLocal indicates secrets stored locally (encrypted).
	SecretSourceLocal SecretSource = "local"
	// SecretSourceEnv indicates secrets from environment variables.
	SecretSourceEnv SecretSource = "env"
	// SecretSourceVault indicates secrets from HashiCorp Vault.
	SecretSourceVault SecretSource = "vault"
	// SecretSourceAWS indicates secrets from AWS Secrets Manager.
	SecretSourceAWS SecretSource = "aws"
	// SecretSourceGCP indicates secrets from GCP Secret Manager.
	SecretSourceGCP SecretSource = "gcp"
	// SecretSourceAzure indicates secrets from Azure Key Vault.
	SecretSourceAzure SecretSource = "azure"
)

// EnvVar represents an environment variable for a function.
type EnvVar struct {
	// Name is the environment variable name.
	Name string `json:"name"`

	// Value is the plaintext value (only for non-secret vars).
	Value string `json:"value,omitempty"`

	// IsSecret indicates if this is a secret value.
	IsSecret bool `json:"is_secret"`

	// SecretRef is the reference to the secret (if IsSecret is true).
	SecretRef *SecretReference `json:"secret_ref,omitempty"`

	// Description provides context for this variable.
	Description string `json:"description,omitempty"`

	// Required indicates if the function requires this variable.
	Required bool `json:"required"`

	// Sensitive indicates the value should be masked in logs.
	Sensitive bool `json:"sensitive"`
}

// SecretReference points to a secret in a secret store.
type SecretReference struct {
	// Source is where the secret is stored.
	Source SecretSource `json:"source"`

	// Key is the key/path to the secret in the source.
	Key string `json:"key"`

	// Version is the specific version of the secret (optional).
	Version string `json:"version,omitempty"`

	// Field is the specific field within the secret (for JSON secrets).
	Field string `json:"field,omitempty"`
}

// FunctionConfig holds all configuration for a single function.
type FunctionConfig struct {
	// FunctionName is the name of the function.
	FunctionName string `json:"function_name"`

	// EnvVars contains the environment variables for this function.
	EnvVars map[string]*EnvVar `json:"env_vars"`

	// Secrets contains encrypted secret values stored locally.
	Secrets map[string]*EncryptedSecret `json:"secrets,omitempty"`

	// Inherit specifies parent configs to inherit from.
	Inherit []string `json:"inherit,omitempty"`

	// CreatedAt is when this config was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this config was last updated.
	UpdatedAt time.Time `json:"updated_at"`

	// Version tracks configuration changes.
	Version int `json:"version"`
}

// EncryptedSecret represents an encrypted secret value.
type EncryptedSecret struct {
	// Ciphertext is the encrypted value (base64 encoded).
	Ciphertext string `json:"ciphertext"`

	// Nonce is the encryption nonce (base64 encoded).
	Nonce string `json:"nonce"`

	// Algorithm is the encryption algorithm used.
	Algorithm string `json:"algorithm"`

	// KeyID identifies the encryption key used.
	KeyID string `json:"key_id"`

	// CreatedAt is when the secret was stored.
	CreatedAt time.Time `json:"created_at"`

	// RotatedAt is when the secret was last rotated.
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
}

// GlobalConfig holds configuration shared across all functions.
type GlobalConfig struct {
	// EnvVars are environment variables available to all functions.
	EnvVars map[string]*EnvVar `json:"env_vars"`

	// DefaultSecretSource is the default source for secrets.
	DefaultSecretSource SecretSource `json:"default_secret_source"`

	// SecretProviderConfigs holds configs for each secret provider.
	SecretProviderConfigs map[SecretSource]*SecretProviderConfig `json:"secret_provider_configs,omitempty"`
}

// SecretProviderConfig configures a secret provider.
type SecretProviderConfig struct {
	// Enabled indicates if this provider is enabled.
	Enabled bool `json:"enabled"`

	// Endpoint is the provider endpoint (for Vault, etc.).
	Endpoint string `json:"endpoint,omitempty"`

	// Region is the cloud region (for AWS, GCP, Azure).
	Region string `json:"region,omitempty"`

	// Namespace is the namespace/project for the secrets.
	Namespace string `json:"namespace,omitempty"`

	// AuthMethod specifies how to authenticate with the provider.
	AuthMethod string `json:"auth_method,omitempty"`

	// CacheTTL is how long to cache secrets from this provider.
	CacheTTL time.Duration `json:"cache_ttl,omitempty"`

	// Extra holds provider-specific configuration.
	Extra map[string]string `json:"extra,omitempty"`
}

// Manager manages function configurations and secrets.
type Manager struct {
	mu            sync.RWMutex
	configs       map[string]*FunctionConfig
	globalConfig  *GlobalConfig
	encryptionKey []byte
	secretCache   map[string]*cachedSecret
	cacheMu       sync.RWMutex
	providers     map[SecretSource]SecretProvider
	configFile    string
	autoSave      bool
	logger        *logging.Logger
}

// cachedSecret represents a cached secret value.
type cachedSecret struct {
	value     string
	expiresAt time.Time
}

// SecretProvider is the interface for secret management backends.
type SecretProvider interface {
	// GetSecret retrieves a secret from the provider.
	GetSecret(ctx Context, ref *SecretReference) (string, error)

	// SetSecret stores a secret in the provider.
	SetSecret(ctx Context, key, value string) error

	// DeleteSecret removes a secret from the provider.
	DeleteSecret(ctx Context, key string) error

	// ListSecrets lists available secrets.
	ListSecrets(ctx Context) ([]string, error)

	// RotateSecret rotates a secret to a new value.
	RotateSecret(ctx Context, key string) (string, error)
}

// Context for secret operations
type Context interface {
	Deadline() (deadline time.Time, ok bool)
	Done() <-chan struct{}
	Err() error
	Value(key any) any
}

// ManagerOptions configures the Manager.
type ManagerOptions struct {
	// EncryptionKey is the master key for encrypting local secrets.
	EncryptionKey string

	// ConfigFile is the path to persist configurations.
	ConfigFile string

	// AutoSave enables automatic persistence of changes.
	AutoSave bool

	// DefaultSecretSource is the default secret provider.
	DefaultSecretSource SecretSource

	// SecretCacheTTL is the default TTL for cached secrets.
	SecretCacheTTL time.Duration
}

// DefaultManagerOptions returns default manager options.
func DefaultManagerOptions() ManagerOptions {
	return ManagerOptions{
		DefaultSecretSource: SecretSourceLocal,
		SecretCacheTTL:      5 * time.Minute,
		AutoSave:            true,
	}
}

// NewManager creates a new configuration manager.
func NewManager(opts ManagerOptions) (*Manager, error) {
	m := &Manager{
		configs:     make(map[string]*FunctionConfig),
		secretCache: make(map[string]*cachedSecret),
		providers:   make(map[SecretSource]SecretProvider),
		configFile:  opts.ConfigFile,
		autoSave:    opts.AutoSave,
		logger:      logging.New("config"),
		globalConfig: &GlobalConfig{
			EnvVars:               make(map[string]*EnvVar),
			DefaultSecretSource:   opts.DefaultSecretSource,
			SecretProviderConfigs: make(map[SecretSource]*SecretProviderConfig),
		},
	}

	// Derive encryption key if provided
	if opts.EncryptionKey != "" {
		hash := sha256.Sum256([]byte(opts.EncryptionKey))
		m.encryptionKey = hash[:]
	}

	// Register built-in providers
	m.providers[SecretSourceEnv] = &envSecretProvider{}
	m.providers[SecretSourceLocal] = &localSecretProvider{manager: m}

	// Load config file if specified
	if opts.ConfigFile != "" {
		if err := m.LoadFromFile(opts.ConfigFile); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}

	return m, nil
}

// SetEncryptionKey sets the encryption key for secrets.
func (m *Manager) SetEncryptionKey(key string) {
	hash := sha256.Sum256([]byte(key))
	m.mu.Lock()
	m.encryptionKey = hash[:]
	m.mu.Unlock()
}

// RegisterProvider registers a secret provider.
func (m *Manager) RegisterProvider(source SecretSource, provider SecretProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[source] = provider
}

// SetGlobalEnvVar sets a global environment variable.
func (m *Manager) SetGlobalEnvVar(name, value string, opts ...EnvVarOption) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	envVar := &EnvVar{
		Name:  name,
		Value: value,
	}

	for _, opt := range opts {
		opt(envVar)
	}

	m.globalConfig.EnvVars[name] = envVar

	m.logger.Info("global env var set", logging.Fields{
		"name":      name,
		"is_secret": envVar.IsSecret,
	})

	if m.autoSave && m.configFile != "" {
		return m.SaveToFile(m.configFile)
	}
	return nil
}

// GetFunctionConfig retrieves or creates a function's configuration.
func (m *Manager) GetFunctionConfig(functionName string) (*FunctionConfig, error) {
	m.mu.RLock()
	config, exists := m.configs[functionName]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrFunctionNotFound
	}

	return config, nil
}

// CreateFunctionConfig creates a new function configuration.
func (m *Manager) CreateFunctionConfig(functionName string) *FunctionConfig {
	m.mu.Lock()
	defer m.mu.Unlock()

	config := &FunctionConfig{
		FunctionName: functionName,
		EnvVars:      make(map[string]*EnvVar),
		Secrets:      make(map[string]*EncryptedSecret),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Version:      1,
	}

	m.configs[functionName] = config

	m.logger.Info("function config created", logging.Fields{
		"function_name": functionName,
	})

	return config
}

// SetEnvVar sets an environment variable for a function.
func (m *Manager) SetEnvVar(functionName, name, value string, opts ...EnvVarOption) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	config, exists := m.configs[functionName]
	if !exists {
		config = &FunctionConfig{
			FunctionName: functionName,
			EnvVars:      make(map[string]*EnvVar),
			Secrets:      make(map[string]*EncryptedSecret),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			Version:      1,
		}
		m.configs[functionName] = config
	}

	envVar := &EnvVar{
		Name:  name,
		Value: value,
	}

	for _, opt := range opts {
		opt(envVar)
	}

	config.EnvVars[name] = envVar
	config.UpdatedAt = time.Now()
	config.Version++

	m.logger.Info("env var set", logging.Fields{
		"function_name": functionName,
		"name":          name,
		"is_secret":     envVar.IsSecret,
	})

	if m.autoSave && m.configFile != "" {
		return m.saveToFileUnlocked(m.configFile)
	}
	return nil
}

// SetSecret stores a secret for a function.
func (m *Manager) SetSecret(functionName, name, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.encryptionKey == nil {
		return ErrEncryptionRequired
	}

	config, exists := m.configs[functionName]
	if !exists {
		config = &FunctionConfig{
			FunctionName: functionName,
			EnvVars:      make(map[string]*EnvVar),
			Secrets:      make(map[string]*EncryptedSecret),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			Version:      1,
		}
		m.configs[functionName] = config
	}

	// Encrypt the secret
	encrypted, err := m.encrypt(value)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	config.Secrets[name] = encrypted
	config.EnvVars[name] = &EnvVar{
		Name:     name,
		IsSecret: true,
		SecretRef: &SecretReference{
			Source: SecretSourceLocal,
			Key:    name,
		},
		Sensitive: true,
	}
	config.UpdatedAt = time.Now()
	config.Version++

	m.logger.Info("secret stored", logging.Fields{
		"function_name": functionName,
		"secret_name":   name,
	})

	if m.autoSave && m.configFile != "" {
		return m.saveToFileUnlocked(m.configFile)
	}
	return nil
}

// SetSecretRef sets a reference to an external secret.
func (m *Manager) SetSecretRef(functionName, name string, ref *SecretReference) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	config, exists := m.configs[functionName]
	if !exists {
		config = &FunctionConfig{
			FunctionName: functionName,
			EnvVars:      make(map[string]*EnvVar),
			Secrets:      make(map[string]*EncryptedSecret),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			Version:      1,
		}
		m.configs[functionName] = config
	}

	config.EnvVars[name] = &EnvVar{
		Name:      name,
		IsSecret:  true,
		SecretRef: ref,
		Sensitive: true,
	}
	config.UpdatedAt = time.Now()
	config.Version++

	m.logger.Info("secret reference set", logging.Fields{
		"function_name": functionName,
		"secret_name":   name,
		"source":        ref.Source,
		"key":           ref.Key,
	})

	if m.autoSave && m.configFile != "" {
		return m.saveToFileUnlocked(m.configFile)
	}
	return nil
}

// GetEnvVars returns all environment variables for a function, with secrets resolved.
// Environment variables are resolved in the following order (later overrides earlier):
// 1. Global environment variables
// 2. Inherited configuration (in order specified)
// 3. Function-specific environment variables
func (m *Manager) GetEnvVars(ctx Context, functionName string) (map[string]string, error) {
	m.mu.RLock()
	config, exists := m.configs[functionName]
	globalConfig := m.globalConfig
	m.mu.RUnlock()

	result := make(map[string]string)

	// Step 1: Start with global env vars
	for name, envVar := range globalConfig.EnvVars {
		val, err := m.resolveEnvVar(ctx, functionName, envVar)
		if err != nil {
			if envVar.Required {
				return nil, fmt.Errorf("failed to resolve required global env var %s: %w", name, err)
			}
			continue
		}
		result[name] = val
	}

	if !exists {
		return result, nil
	}

	// Step 2: Handle inheritance (with cycle detection)
	visited := make(map[string]bool)
	if err := m.resolveInheritedEnvVars(ctx, config, result, visited); err != nil {
		return nil, err
	}

	// Step 3: Apply function-specific env vars (override inherited)
	for name, envVar := range config.EnvVars {
		val, err := m.resolveEnvVar(ctx, functionName, envVar)
		if err != nil {
			if envVar.Required {
				return nil, fmt.Errorf("failed to resolve required env var %s: %w", name, err)
			}
			continue
		}
		result[name] = val
	}

	return result, nil
}

// resolveInheritedEnvVars recursively resolves inherited environment variables.
func (m *Manager) resolveInheritedEnvVars(ctx Context, config *FunctionConfig, result map[string]string, visited map[string]bool) error {
	if visited[config.FunctionName] {
		return fmt.Errorf("circular inheritance detected at %s", config.FunctionName)
	}
	visited[config.FunctionName] = true

	for _, parentName := range config.Inherit {
		m.mu.RLock()
		parentConfig, exists := m.configs[parentName]
		m.mu.RUnlock()

		if !exists {
			return fmt.Errorf("inherited config %s not found", parentName)
		}

		// Recursively resolve parent's inherited configs first
		if err := m.resolveInheritedEnvVars(ctx, parentConfig, result, visited); err != nil {
			return err
		}

		// Then apply parent's own env vars
		for name, envVar := range parentConfig.EnvVars {
			val, err := m.resolveEnvVar(ctx, parentName, envVar)
			if err != nil {
				if envVar.Required {
					return fmt.Errorf("failed to resolve required env var %s from %s: %w", name, parentName, err)
				}
				continue
			}
			result[name] = val
		}
	}

	return nil
}

// GetGlobalConfig returns the global configuration.
func (m *Manager) GetGlobalConfig() *GlobalConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.globalConfig
}

// SetInheritance sets the inheritance chain for a function.
func (m *Manager) SetInheritance(functionName string, parents []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	config, exists := m.configs[functionName]
	if !exists {
		return ErrFunctionNotFound
	}

	// Validate that all parents exist
	for _, parent := range parents {
		if _, parentExists := m.configs[parent]; !parentExists {
			return fmt.Errorf("parent config %s not found", parent)
		}
	}

	// Check for circular inheritance
	if err := m.checkCircularInheritance(functionName, parents); err != nil {
		return err
	}

	config.Inherit = parents
	config.UpdatedAt = time.Now()
	config.Version++

	m.logger.Info("inheritance set", logging.Fields{
		"function_name": functionName,
		"parents":       parents,
	})

	if m.autoSave && m.configFile != "" {
		return m.saveToFileUnlocked(m.configFile)
	}
	return nil
}

// checkCircularInheritance checks if adding the given parents would create a cycle.
func (m *Manager) checkCircularInheritance(functionName string, newParents []string) error {
	visited := make(map[string]bool)

	var check func(name string) error
	check = func(name string) error {
		if name == functionName {
			return fmt.Errorf("circular inheritance detected: %s would create a cycle", name)
		}
		if visited[name] {
			return nil
		}
		visited[name] = true

		config, exists := m.configs[name]
		if !exists {
			return nil
		}

		for _, parent := range config.Inherit {
			if err := check(parent); err != nil {
				return err
			}
		}
		return nil
	}

	for _, parent := range newParents {
		if err := check(parent); err != nil {
			return err
		}
	}

	return nil
}

// GetInheritanceChain returns the full inheritance chain for a function.
func (m *Manager) GetInheritanceChain(functionName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	config, exists := m.configs[functionName]
	if !exists {
		return nil, ErrFunctionNotFound
	}

	chain := []string{"global"}
	visited := make(map[string]bool)
	m.buildInheritanceChainRecursive(config, &chain, visited)
	chain = append(chain, functionName)

	return chain, nil
}

func (m *Manager) buildInheritanceChainRecursive(config *FunctionConfig, chain *[]string, visited map[string]bool) {
	if visited[config.FunctionName] {
		return
	}
	visited[config.FunctionName] = true

	for _, parentName := range config.Inherit {
		parentConfig, exists := m.configs[parentName]
		if !exists {
			continue
		}
		m.buildInheritanceChainRecursive(parentConfig, chain, visited)
		*chain = append(*chain, parentName)
	}
}

// GetSecret retrieves a specific secret value.
func (m *Manager) GetSecret(ctx Context, functionName, secretName string) (string, error) {
	m.mu.RLock()
	config, exists := m.configs[functionName]
	m.mu.RUnlock()

	if !exists {
		return "", ErrFunctionNotFound
	}

	envVar, exists := config.EnvVars[secretName]
	if !exists || !envVar.IsSecret {
		return "", ErrSecretNotFound
	}

	return m.resolveSecret(ctx, functionName, envVar)
}

// resolveEnvVar resolves an environment variable's value.
func (m *Manager) resolveEnvVar(ctx Context, functionName string, envVar *EnvVar) (string, error) {
	if !envVar.IsSecret {
		return envVar.Value, nil
	}

	return m.resolveSecret(ctx, functionName, envVar)
}

// resolveSecret resolves a secret reference to its actual value.
func (m *Manager) resolveSecret(ctx Context, functionName string, envVar *EnvVar) (string, error) {
	if envVar.SecretRef == nil {
		return "", ErrSecretNotFound
	}

	ref := envVar.SecretRef

	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s:%s", ref.Source, ref.Key, ref.Version)
	m.cacheMu.RLock()
	cached, exists := m.secretCache[cacheKey]
	m.cacheMu.RUnlock()

	if exists && time.Now().Before(cached.expiresAt) {
		return cached.value, nil
	}

	// Resolve based on source
	m.mu.RLock()
	provider, hasProvider := m.providers[ref.Source]
	config := m.configs[functionName]
	m.mu.RUnlock()

	if !hasProvider {
		return "", fmt.Errorf("%w: %s", ErrInvalidSecretSource, ref.Source)
	}

	// For local secrets, we need to decrypt
	if ref.Source == SecretSourceLocal && config != nil {
		if encrypted, ok := config.Secrets[ref.Key]; ok {
			return m.decrypt(encrypted)
		}
	}

	// Use the provider to get the secret
	value, err := provider.GetSecret(ctx, ref)
	if err != nil {
		return "", err
	}

	// Handle field extraction for JSON secrets
	if ref.Field != "" {
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(value), &data); err == nil {
			if fieldVal, ok := data[ref.Field]; ok {
				value = fmt.Sprintf("%v", fieldVal)
			}
		}
	}

	// Cache the result
	m.cacheMu.Lock()
	m.secretCache[cacheKey] = &cachedSecret{
		value:     value,
		expiresAt: time.Now().Add(5 * time.Minute),
	}
	m.cacheMu.Unlock()

	return value, nil
}

// encrypt encrypts a plaintext value.
func (m *Manager) encrypt(plaintext string) (*EncryptedSecret, error) {
	if m.encryptionKey == nil {
		return nil, ErrEncryptionRequired
	}

	block, err := aes.NewCipher(m.encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	return &EncryptedSecret{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Algorithm:  "AES-256-GCM",
		KeyID:      "master",
		CreatedAt:  time.Now(),
	}, nil
}

// decrypt decrypts an encrypted secret.
func (m *Manager) decrypt(secret *EncryptedSecret) (string, error) {
	if m.encryptionKey == nil {
		return "", ErrEncryptionRequired
	}

	ciphertext, err := base64.StdEncoding.DecodeString(secret.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext encoding: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(secret.Nonce)
	if err != nil {
		return "", fmt.Errorf("invalid nonce encoding: %w", err)
	}

	block, err := aes.NewCipher(m.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrInvalidEncryption
	}

	return string(plaintext), nil
}

// DeleteEnvVar removes an environment variable from a function.
func (m *Manager) DeleteEnvVar(functionName, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	config, exists := m.configs[functionName]
	if !exists {
		return ErrFunctionNotFound
	}

	delete(config.EnvVars, name)
	delete(config.Secrets, name)
	config.UpdatedAt = time.Now()
	config.Version++

	m.logger.Info("env var deleted", logging.Fields{
		"function_name": functionName,
		"name":          name,
	})

	if m.autoSave && m.configFile != "" {
		return m.saveToFileUnlocked(m.configFile)
	}
	return nil
}

// DeleteFunctionConfig removes a function's configuration.
func (m *Manager) DeleteFunctionConfig(functionName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.configs[functionName]; !exists {
		return ErrFunctionNotFound
	}

	delete(m.configs, functionName)

	m.logger.Info("function config deleted", logging.Fields{
		"function_name": functionName,
	})

	if m.autoSave && m.configFile != "" {
		return m.saveToFileUnlocked(m.configFile)
	}
	return nil
}

// ListFunctions returns all configured function names.
func (m *Manager) ListFunctions() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.configs))
	for name := range m.configs {
		names = append(names, name)
	}
	return names
}

// ListEnvVars returns all environment variable names for a function.
func (m *Manager) ListEnvVars(functionName string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	config, exists := m.configs[functionName]
	if !exists {
		return nil, ErrFunctionNotFound
	}

	names := make([]string, 0, len(config.EnvVars))
	for name := range config.EnvVars {
		names = append(names, name)
	}
	return names, nil
}

// Export exports the configuration (with secrets redacted).
func (m *Manager) Export() *ExportedConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	exported := &ExportedConfig{
		GlobalConfig: &ExportedGlobalConfig{
			EnvVars:             make(map[string]*ExportedEnvVar),
			DefaultSecretSource: m.globalConfig.DefaultSecretSource,
		},
		Functions: make(map[string]*ExportedFunctionConfig),
	}

	for name, envVar := range m.globalConfig.EnvVars {
		exported.GlobalConfig.EnvVars[name] = exportEnvVar(envVar)
	}

	for name, config := range m.configs {
		exported.Functions[name] = &ExportedFunctionConfig{
			FunctionName: config.FunctionName,
			EnvVars:      make(map[string]*ExportedEnvVar),
			Inherit:      config.Inherit,
			CreatedAt:    config.CreatedAt,
			UpdatedAt:    config.UpdatedAt,
			Version:      config.Version,
		}
		for envName, envVar := range config.EnvVars {
			exported.Functions[name].EnvVars[envName] = exportEnvVar(envVar)
		}
	}

	return exported
}

func exportEnvVar(envVar *EnvVar) *ExportedEnvVar {
	exp := &ExportedEnvVar{
		Name:        envVar.Name,
		IsSecret:    envVar.IsSecret,
		Description: envVar.Description,
		Required:    envVar.Required,
		Sensitive:   envVar.Sensitive,
	}
	if !envVar.IsSecret && !envVar.Sensitive {
		exp.Value = envVar.Value
	} else {
		exp.Value = "[REDACTED]"
	}
	if envVar.SecretRef != nil {
		exp.SecretSource = string(envVar.SecretRef.Source)
		exp.SecretKey = envVar.SecretRef.Key
	}
	return exp
}

// ExportedConfig represents a sanitized configuration export.
type ExportedConfig struct {
	GlobalConfig *ExportedGlobalConfig              `json:"global_config"`
	Functions    map[string]*ExportedFunctionConfig `json:"functions"`
}

// ExportedGlobalConfig represents exported global configuration.
type ExportedGlobalConfig struct {
	EnvVars             map[string]*ExportedEnvVar `json:"env_vars"`
	DefaultSecretSource SecretSource               `json:"default_secret_source"`
}

// ExportedFunctionConfig represents a sanitized function config export.
type ExportedFunctionConfig struct {
	FunctionName string                     `json:"function_name"`
	EnvVars      map[string]*ExportedEnvVar `json:"env_vars"`
	Inherit      []string                   `json:"inherit,omitempty"`
	CreatedAt    time.Time                  `json:"created_at"`
	UpdatedAt    time.Time                  `json:"updated_at"`
	Version      int                        `json:"version"`
}

// ExportedEnvVar represents a sanitized environment variable.
type ExportedEnvVar struct {
	Name         string `json:"name"`
	Value        string `json:"value"` // Will be "[REDACTED]" for secrets
	IsSecret     bool   `json:"is_secret"`
	SecretSource string `json:"secret_source,omitempty"`
	SecretKey    string `json:"secret_key,omitempty"`
	Description  string `json:"description,omitempty"`
	Required     bool   `json:"required"`
	Sensitive    bool   `json:"sensitive"`
}

// EnvVarOption is a functional option for configuring an EnvVar.
type EnvVarOption func(*EnvVar)

// WithDescription sets the description for an env var.
func WithDescription(desc string) EnvVarOption {
	return func(e *EnvVar) {
		e.Description = desc
	}
}

// WithRequired marks an env var as required.
func WithRequired() EnvVarOption {
	return func(e *EnvVar) {
		e.Required = true
	}
}

// WithSensitive marks an env var as sensitive (masked in logs).
func WithSensitive() EnvVarOption {
	return func(e *EnvVar) {
		e.Sensitive = true
	}
}

// persistenceData is the structure for persisting configurations.
type persistenceData struct {
	GlobalConfig *GlobalConfig              `json:"global_config"`
	Functions    map[string]*FunctionConfig `json:"functions"`
	Version      string                     `json:"version"`
	SavedAt      time.Time                  `json:"saved_at"`
}

// SaveToFile persists the configuration to a file.
func (m *Manager) SaveToFile(path string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.saveToFileUnlocked(path)
}

func (m *Manager) saveToFileUnlocked(path string) error {
	data := &persistenceData{
		GlobalConfig: m.globalConfig,
		Functions:    m.configs,
		Version:      "1.0",
		SavedAt:      time.Now(),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	m.logger.Info("configuration saved", logging.Fields{
		"path":      path,
		"functions": len(m.configs),
	})

	return nil
}

// LoadFromFile loads configuration from a file.
func (m *Manager) LoadFromFile(path string) error {
	jsonData, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var data persistenceData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if data.GlobalConfig != nil {
		m.globalConfig = data.GlobalConfig
	}
	if data.Functions != nil {
		m.configs = data.Functions
	}

	m.logger.Info("configuration loaded", logging.Fields{
		"path":      path,
		"functions": len(m.configs),
		"saved_at":  data.SavedAt,
	})

	return nil
}

// ClearSecretCache clears the secret cache.
func (m *Manager) ClearSecretCache() {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()
	m.secretCache = make(map[string]*cachedSecret)
}

// ValidateConfig validates a function's configuration.
func (m *Manager) ValidateConfig(functionName string) []string {
	m.mu.RLock()
	config, exists := m.configs[functionName]
	m.mu.RUnlock()

	var errors []string

	if !exists {
		return []string{"function configuration not found"}
	}

	for name, envVar := range config.EnvVars {
		if envVar.Required {
			if envVar.IsSecret {
				if envVar.SecretRef == nil {
					errors = append(errors, fmt.Sprintf("required secret %s has no reference", name))
				}
			} else if envVar.Value == "" {
				errors = append(errors, fmt.Sprintf("required env var %s has no value", name))
			}
		}
	}

	// Validate inheritance
	for _, parentName := range config.Inherit {
		if _, err := m.GetFunctionConfig(parentName); err != nil {
			errors = append(errors, fmt.Sprintf("inherited config %s not found", parentName))
		}
	}

	return errors
}

// envSecretProvider retrieves secrets from environment variables.
type envSecretProvider struct{}

func (p *envSecretProvider) GetSecret(ctx Context, ref *SecretReference) (string, error) {
	value := os.Getenv(ref.Key)
	if value == "" {
		// Try with common prefixes
		for _, prefix := range []string{"", "SECRET_", "LAMBDA_"} {
			if v := os.Getenv(prefix + ref.Key); v != "" {
				return v, nil
			}
		}
		return "", ErrSecretNotFound
	}
	return value, nil
}

func (p *envSecretProvider) SetSecret(ctx Context, key, value string) error {
	return os.Setenv(key, value)
}

func (p *envSecretProvider) DeleteSecret(ctx Context, key string) error {
	return os.Unsetenv(key)
}

func (p *envSecretProvider) ListSecrets(ctx Context) ([]string, error) {
	var secrets []string
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && (strings.HasPrefix(parts[0], "SECRET_") || strings.HasPrefix(parts[0], "LAMBDA_")) {
			secrets = append(secrets, parts[0])
		}
	}
	return secrets, nil
}

func (p *envSecretProvider) RotateSecret(ctx Context, key string) (string, error) {
	return "", errors.New("rotation not supported for environment variables")
}

// localSecretProvider handles locally encrypted secrets.
type localSecretProvider struct {
	manager *Manager
}

func (p *localSecretProvider) GetSecret(ctx Context, ref *SecretReference) (string, error) {
	// The actual decryption happens in resolveSecret
	return "", ErrSecretNotFound
}

func (p *localSecretProvider) SetSecret(ctx Context, key, value string) error {
	return errors.New("use Manager.SetSecret instead")
}

func (p *localSecretProvider) DeleteSecret(ctx Context, key string) error {
	return errors.New("use Manager.DeleteEnvVar instead")
}

func (p *localSecretProvider) ListSecrets(ctx Context) ([]string, error) {
	p.manager.mu.RLock()
	defer p.manager.mu.RUnlock()

	var secrets []string
	for _, config := range p.manager.configs {
		for name := range config.Secrets {
			secrets = append(secrets, fmt.Sprintf("%s/%s", config.FunctionName, name))
		}
	}
	return secrets, nil
}

func (p *localSecretProvider) RotateSecret(ctx Context, key string) (string, error) {
	return "", errors.New("rotation must be done via Manager.SetSecret")
}

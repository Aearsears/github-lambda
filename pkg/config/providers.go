package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/github-lambda/pkg/logging"
)

var providerLogger = logging.New("secret-providers")

// VaultProvider implements SecretProvider for HashiCorp Vault.
type VaultProvider struct {
	endpoint   string
	token      string
	namespace  string
	mountPath  string
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]*cachedSecret
	cacheTTL   time.Duration
}

// VaultProviderConfig configures the Vault provider.
type VaultProviderConfig struct {
	// Endpoint is the Vault server address.
	Endpoint string

	// Token is the Vault authentication token.
	Token string

	// Namespace is the Vault namespace (enterprise feature).
	Namespace string

	// MountPath is the secrets engine mount path (default: "secret").
	MountPath string

	// CacheTTL is how long to cache secrets.
	CacheTTL time.Duration
}

// NewVaultProvider creates a new Vault secret provider.
func NewVaultProvider(config VaultProviderConfig) *VaultProvider {
	if config.MountPath == "" {
		config.MountPath = "secret"
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}

	return &VaultProvider{
		endpoint:  strings.TrimSuffix(config.Endpoint, "/"),
		token:     config.Token,
		namespace: config.Namespace,
		mountPath: config.MountPath,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:    make(map[string]*cachedSecret),
		cacheTTL: config.CacheTTL,
	}
}

// NewVaultProviderFromEnv creates a Vault provider from environment variables.
func NewVaultProviderFromEnv() (*VaultProvider, error) {
	endpoint := os.Getenv("VAULT_ADDR")
	if endpoint == "" {
		return nil, errors.New("VAULT_ADDR environment variable required")
	}

	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		return nil, errors.New("VAULT_TOKEN environment variable required")
	}

	return NewVaultProvider(VaultProviderConfig{
		Endpoint:  endpoint,
		Token:     token,
		Namespace: os.Getenv("VAULT_NAMESPACE"),
		MountPath: os.Getenv("VAULT_MOUNT_PATH"),
	}), nil
}

// GetSecret retrieves a secret from Vault.
func (p *VaultProvider) GetSecret(ctx Context, ref *SecretReference) (string, error) {
	cacheKey := p.getCacheKey(ref)

	// Check cache
	p.mu.RLock()
	if cached, ok := p.cache[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
		p.mu.RUnlock()
		return cached.value, nil
	}
	p.mu.RUnlock()

	// Build the URL
	url := fmt.Sprintf("%s/v1/%s/data/%s", p.endpoint, p.mountPath, ref.Key)
	if ref.Version != "" {
		url = fmt.Sprintf("%s?version=%s", url, ref.Version)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", p.token)
	if p.namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.namespace)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", ErrSecretNotFound
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("vault returned status %d: %s", resp.StatusCode, string(body))
	}

	var vaultResp struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vaultResp); err != nil {
		return "", fmt.Errorf("failed to decode vault response: %w", err)
	}

	// Extract the specific field or return the whole secret as JSON
	var value string
	if ref.Field != "" {
		if fieldVal, ok := vaultResp.Data.Data[ref.Field]; ok {
			value = fmt.Sprintf("%v", fieldVal)
		} else {
			return "", fmt.Errorf("field %s not found in secret", ref.Field)
		}
	} else {
		// Return all data as JSON
		data, _ := json.Marshal(vaultResp.Data.Data)
		value = string(data)
	}

	// Cache the result
	p.mu.Lock()
	p.cache[cacheKey] = &cachedSecret{
		value:     value,
		expiresAt: time.Now().Add(p.cacheTTL),
	}
	p.mu.Unlock()

	providerLogger.Debug("vault secret retrieved", logging.Fields{
		"key": ref.Key,
	})

	return value, nil
}

// SetSecret stores a secret in Vault.
func (p *VaultProvider) SetSecret(ctx Context, key, value string) error {
	url := fmt.Sprintf("%s/v1/%s/data/%s", p.endpoint, p.mountPath, key)

	// Wrap the value in the Vault KV v2 format
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"value": value,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", p.token)
	req.Header.Set("Content-Type", "application/json")
	if p.namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.namespace)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Invalidate cache
	p.mu.Lock()
	delete(p.cache, key)
	p.mu.Unlock()

	providerLogger.Info("vault secret stored", logging.Fields{
		"key": key,
	})

	return nil
}

// DeleteSecret removes a secret from Vault.
func (p *VaultProvider) DeleteSecret(ctx Context, key string) error {
	url := fmt.Sprintf("%s/v1/%s/metadata/%s", p.endpoint, p.mountPath, key)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", p.token)
	if p.namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.namespace)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault returned status %d: %s", resp.StatusCode, string(body))
	}

	// Invalidate cache
	p.mu.Lock()
	delete(p.cache, key)
	p.mu.Unlock()

	providerLogger.Info("vault secret deleted", logging.Fields{
		"key": key,
	})

	return nil
}

// ListSecrets lists secrets at a path in Vault.
func (p *VaultProvider) ListSecrets(ctx Context) ([]string, error) {
	url := fmt.Sprintf("%s/v1/%s/metadata?list=true", p.endpoint, p.mountPath)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", p.token)
	if p.namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.namespace)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []string{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vault returned status %d: %s", resp.StatusCode, string(body))
	}

	var listResp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("failed to decode vault response: %w", err)
	}

	return listResp.Data.Keys, nil
}

// RotateSecret rotates a secret in Vault.
func (p *VaultProvider) RotateSecret(ctx Context, key string) (string, error) {
	// For Vault, rotation is typically handled by the application
	// This is a placeholder that could be extended to use Vault's
	// dynamic secrets or other rotation mechanisms
	return "", errors.New("vault secret rotation should be handled by Vault policies or dynamic secrets")
}

func (p *VaultProvider) getCacheKey(ref *SecretReference) string {
	return fmt.Sprintf("%s:%s:%s", ref.Key, ref.Version, ref.Field)
}

// AWSSecretsManagerProvider implements SecretProvider for AWS Secrets Manager.
// Note: This is a simplified implementation. In production, use the AWS SDK.
type AWSSecretsManagerProvider struct {
	region     string
	endpoint   string
	accessKey  string
	secretKey  string
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]*cachedSecret
	cacheTTL   time.Duration
}

// AWSSecretsManagerConfig configures the AWS Secrets Manager provider.
type AWSSecretsManagerConfig struct {
	Region    string
	Endpoint  string // For LocalStack or custom endpoints
	AccessKey string
	SecretKey string
	CacheTTL  time.Duration
}

// NewAWSSecretsManagerProvider creates a new AWS Secrets Manager provider.
func NewAWSSecretsManagerProvider(config AWSSecretsManagerConfig) *AWSSecretsManagerProvider {
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}

	return &AWSSecretsManagerProvider{
		region:    config.Region,
		endpoint:  config.Endpoint,
		accessKey: config.AccessKey,
		secretKey: config.SecretKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:    make(map[string]*cachedSecret),
		cacheTTL: config.CacheTTL,
	}
}

// NewAWSSecretsManagerProviderFromEnv creates an AWS provider from environment variables.
func NewAWSSecretsManagerProviderFromEnv() (*AWSSecretsManagerProvider, error) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		return nil, errors.New("AWS_REGION environment variable required")
	}

	return NewAWSSecretsManagerProvider(AWSSecretsManagerConfig{
		Region:    region,
		Endpoint:  os.Getenv("AWS_SECRETS_MANAGER_ENDPOINT"),
		AccessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
	}), nil
}

// GetSecret retrieves a secret from AWS Secrets Manager.
// Note: This is a simplified implementation. Use the AWS SDK for production.
func (p *AWSSecretsManagerProvider) GetSecret(ctx Context, ref *SecretReference) (string, error) {
	cacheKey := p.getCacheKey(ref)

	// Check cache
	p.mu.RLock()
	if cached, ok := p.cache[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
		p.mu.RUnlock()
		return cached.value, nil
	}
	p.mu.RUnlock()

	// In a real implementation, you would use the AWS SDK here
	// This is a placeholder that demonstrates the interface
	providerLogger.Warn("AWS Secrets Manager provider requires AWS SDK for full functionality", logging.Fields{
		"key": ref.Key,
	})

	return "", errors.New("AWS Secrets Manager provider requires AWS SDK - use environment variables or implement with AWS SDK")
}

// SetSecret stores a secret in AWS Secrets Manager.
func (p *AWSSecretsManagerProvider) SetSecret(ctx Context, key, value string) error {
	return errors.New("AWS Secrets Manager SetSecret requires AWS SDK")
}

// DeleteSecret removes a secret from AWS Secrets Manager.
func (p *AWSSecretsManagerProvider) DeleteSecret(ctx Context, key string) error {
	return errors.New("AWS Secrets Manager DeleteSecret requires AWS SDK")
}

// ListSecrets lists secrets in AWS Secrets Manager.
func (p *AWSSecretsManagerProvider) ListSecrets(ctx Context) ([]string, error) {
	return nil, errors.New("AWS Secrets Manager ListSecrets requires AWS SDK")
}

// RotateSecret rotates a secret in AWS Secrets Manager.
func (p *AWSSecretsManagerProvider) RotateSecret(ctx Context, key string) (string, error) {
	return "", errors.New("AWS Secrets Manager RotateSecret requires AWS SDK")
}

func (p *AWSSecretsManagerProvider) getCacheKey(ref *SecretReference) string {
	return fmt.Sprintf("%s:%s", ref.Key, ref.Version)
}

// GCPSecretManagerProvider implements SecretProvider for GCP Secret Manager.
// Note: This is a simplified implementation. In production, use the GCP SDK.
type GCPSecretManagerProvider struct {
	projectID  string
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]*cachedSecret
	cacheTTL   time.Duration
}

// GCPSecretManagerConfig configures the GCP Secret Manager provider.
type GCPSecretManagerConfig struct {
	ProjectID string
	CacheTTL  time.Duration
}

// NewGCPSecretManagerProvider creates a new GCP Secret Manager provider.
func NewGCPSecretManagerProvider(config GCPSecretManagerConfig) *GCPSecretManagerProvider {
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}

	return &GCPSecretManagerProvider{
		projectID: config.ProjectID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:    make(map[string]*cachedSecret),
		cacheTTL: config.CacheTTL,
	}
}

// NewGCPSecretManagerProviderFromEnv creates a GCP provider from environment variables.
func NewGCPSecretManagerProviderFromEnv() (*GCPSecretManagerProvider, error) {
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}
	if projectID == "" {
		return nil, errors.New("GCP_PROJECT_ID environment variable required")
	}

	return NewGCPSecretManagerProvider(GCPSecretManagerConfig{
		ProjectID: projectID,
	}), nil
}

// GetSecret retrieves a secret from GCP Secret Manager.
func (p *GCPSecretManagerProvider) GetSecret(ctx Context, ref *SecretReference) (string, error) {
	providerLogger.Warn("GCP Secret Manager provider requires GCP SDK for full functionality", logging.Fields{
		"key": ref.Key,
	})
	return "", errors.New("GCP Secret Manager provider requires GCP SDK - use environment variables or implement with GCP SDK")
}

// SetSecret stores a secret in GCP Secret Manager.
func (p *GCPSecretManagerProvider) SetSecret(ctx Context, key, value string) error {
	return errors.New("GCP Secret Manager SetSecret requires GCP SDK")
}

// DeleteSecret removes a secret from GCP Secret Manager.
func (p *GCPSecretManagerProvider) DeleteSecret(ctx Context, key string) error {
	return errors.New("GCP Secret Manager DeleteSecret requires GCP SDK")
}

// ListSecrets lists secrets in GCP Secret Manager.
func (p *GCPSecretManagerProvider) ListSecrets(ctx Context) ([]string, error) {
	return nil, errors.New("GCP Secret Manager ListSecrets requires GCP SDK")
}

// RotateSecret rotates a secret in GCP Secret Manager.
func (p *GCPSecretManagerProvider) RotateSecret(ctx Context, key string) (string, error) {
	return "", errors.New("GCP Secret Manager RotateSecret requires GCP SDK")
}

// AzureKeyVaultProvider implements SecretProvider for Azure Key Vault.
// Note: This is a simplified implementation. In production, use the Azure SDK.
type AzureKeyVaultProvider struct {
	vaultURL   string
	tenantID   string
	clientID   string
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]*cachedSecret
	cacheTTL   time.Duration
}

// AzureKeyVaultConfig configures the Azure Key Vault provider.
type AzureKeyVaultConfig struct {
	VaultURL string
	TenantID string
	ClientID string
	CacheTTL time.Duration
}

// NewAzureKeyVaultProvider creates a new Azure Key Vault provider.
func NewAzureKeyVaultProvider(config AzureKeyVaultConfig) *AzureKeyVaultProvider {
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}

	return &AzureKeyVaultProvider{
		vaultURL: config.VaultURL,
		tenantID: config.TenantID,
		clientID: config.ClientID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:    make(map[string]*cachedSecret),
		cacheTTL: config.CacheTTL,
	}
}

// NewAzureKeyVaultProviderFromEnv creates an Azure provider from environment variables.
func NewAzureKeyVaultProviderFromEnv() (*AzureKeyVaultProvider, error) {
	vaultURL := os.Getenv("AZURE_KEY_VAULT_URL")
	if vaultURL == "" {
		return nil, errors.New("AZURE_KEY_VAULT_URL environment variable required")
	}

	return NewAzureKeyVaultProvider(AzureKeyVaultConfig{
		VaultURL: vaultURL,
		TenantID: os.Getenv("AZURE_TENANT_ID"),
		ClientID: os.Getenv("AZURE_CLIENT_ID"),
	}), nil
}

// GetSecret retrieves a secret from Azure Key Vault.
func (p *AzureKeyVaultProvider) GetSecret(ctx Context, ref *SecretReference) (string, error) {
	providerLogger.Warn("Azure Key Vault provider requires Azure SDK for full functionality", logging.Fields{
		"key": ref.Key,
	})
	return "", errors.New("Azure Key Vault provider requires Azure SDK - use environment variables or implement with Azure SDK")
}

// SetSecret stores a secret in Azure Key Vault.
func (p *AzureKeyVaultProvider) SetSecret(ctx Context, key, value string) error {
	return errors.New("Azure Key Vault SetSecret requires Azure SDK")
}

// DeleteSecret removes a secret from Azure Key Vault.
func (p *AzureKeyVaultProvider) DeleteSecret(ctx Context, key string) error {
	return errors.New("Azure Key Vault DeleteSecret requires Azure SDK")
}

// ListSecrets lists secrets in Azure Key Vault.
func (p *AzureKeyVaultProvider) ListSecrets(ctx Context) ([]string, error) {
	return nil, errors.New("Azure Key Vault ListSecrets requires Azure SDK")
}

// RotateSecret rotates a secret in Azure Key Vault.
func (p *AzureKeyVaultProvider) RotateSecret(ctx Context, key string) (string, error) {
	return "", errors.New("Azure Key Vault RotateSecret requires Azure SDK")
}

// GitHubSecretsProvider implements SecretProvider for GitHub Actions Secrets.
type GitHubSecretsProvider struct {
	token      string
	owner      string
	repo       string
	httpClient *http.Client
	mu         sync.RWMutex
	cache      map[string]*cachedSecret
	cacheTTL   time.Duration
}

// GitHubSecretsConfig configures the GitHub Secrets provider.
type GitHubSecretsConfig struct {
	Token    string
	Owner    string
	Repo     string
	CacheTTL time.Duration
}

// NewGitHubSecretsProvider creates a new GitHub Secrets provider.
func NewGitHubSecretsProvider(config GitHubSecretsConfig) *GitHubSecretsProvider {
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}

	return &GitHubSecretsProvider{
		token: config.Token,
		owner: config.Owner,
		repo:  config.Repo,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:    make(map[string]*cachedSecret),
		cacheTTL: config.CacheTTL,
	}
}

// NewGitHubSecretsProviderFromEnv creates a GitHub provider from environment variables.
func NewGitHubSecretsProviderFromEnv() (*GitHubSecretsProvider, error) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, errors.New("GITHUB_TOKEN environment variable required")
	}

	owner := os.Getenv("GITHUB_OWNER")
	repo := os.Getenv("GITHUB_REPO")

	return NewGitHubSecretsProvider(GitHubSecretsConfig{
		Token: token,
		Owner: owner,
		Repo:  repo,
	}), nil
}

// GetSecret retrieves a secret from GitHub.
// Note: GitHub secrets cannot be read via API, only written.
// This implementation looks for the secret in environment variables
// that GitHub Actions would have set.
func (p *GitHubSecretsProvider) GetSecret(ctx Context, ref *SecretReference) (string, error) {
	// GitHub secrets are typically passed as environment variables in Actions
	// Look for the secret in common patterns
	key := ref.Key
	envVars := []string{
		key,
		strings.ToUpper(key),
		"INPUT_" + strings.ToUpper(key),
		"GITHUB_" + strings.ToUpper(key),
	}

	for _, envVar := range envVars {
		if val := os.Getenv(envVar); val != "" {
			return val, nil
		}
	}

	return "", fmt.Errorf("GitHub secret %s not found in environment", ref.Key)
}

// SetSecret stores a secret in GitHub.
func (p *GitHubSecretsProvider) SetSecret(ctx Context, key, value string) error {
	// GitHub secrets require encryption with the repo's public key
	// This is a simplified implementation
	return errors.New("GitHub Secrets SetSecret requires GitHub API with sodium encryption")
}

// DeleteSecret removes a secret from GitHub.
func (p *GitHubSecretsProvider) DeleteSecret(ctx Context, key string) error {
	return errors.New("GitHub Secrets DeleteSecret requires GitHub API")
}

// ListSecrets lists secrets in GitHub.
func (p *GitHubSecretsProvider) ListSecrets(ctx Context) ([]string, error) {
	return nil, errors.New("GitHub Secrets ListSecrets requires GitHub API")
}

// RotateSecret rotates a secret in GitHub.
func (p *GitHubSecretsProvider) RotateSecret(ctx Context, key string) (string, error) {
	return "", errors.New("GitHub Secrets rotation not directly supported")
}

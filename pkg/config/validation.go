package config

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/github-lambda/pkg/logging"
)

var validationLogger = logging.New("config-validation")

// ValidationSeverity represents the severity of a validation issue.
type ValidationSeverity string

const (
	// SeverityError indicates a critical issue that will prevent deployment.
	SeverityError ValidationSeverity = "error"
	// SeverityWarning indicates an issue that should be addressed but won't block deployment.
	SeverityWarning ValidationSeverity = "warning"
	// SeverityInfo indicates informational feedback.
	SeverityInfo ValidationSeverity = "info"
)

// ValidationIssue represents a single validation problem.
type ValidationIssue struct {
	// Severity indicates how critical this issue is.
	Severity ValidationSeverity `json:"severity"`

	// Code is a unique identifier for this type of issue.
	Code string `json:"code"`

	// Message describes the issue.
	Message string `json:"message"`

	// Field identifies the configuration field with the issue.
	Field string `json:"field,omitempty"`

	// Value is the problematic value (redacted if sensitive).
	Value string `json:"value,omitempty"`

	// Suggestion provides guidance on how to fix the issue.
	Suggestion string `json:"suggestion,omitempty"`
}

// ValidationResult contains the complete validation output.
type ValidationResult struct {
	// Valid indicates if the configuration can be deployed.
	Valid bool `json:"valid"`

	// FunctionName is the function being validated.
	FunctionName string `json:"function_name"`

	// Issues contains all validation problems found.
	Issues []*ValidationIssue `json:"issues"`

	// ResolvedEnvVars shows all environment variables after inheritance resolution.
	ResolvedEnvVars map[string]*ResolvedEnvVar `json:"resolved_env_vars,omitempty"`

	// InheritanceChain shows the inheritance hierarchy.
	InheritanceChain []string `json:"inheritance_chain,omitempty"`

	// ValidatedAt is when the validation was performed.
	ValidatedAt time.Time `json:"validated_at"`

	// Summary provides counts of issues by severity.
	Summary *ValidationSummary `json:"summary"`
}

// ResolvedEnvVar represents an environment variable after inheritance resolution.
type ResolvedEnvVar struct {
	// Name is the variable name.
	Name string `json:"name"`

	// Value is the resolved value (redacted if sensitive).
	Value string `json:"value"`

	// Source indicates where this variable came from.
	Source string `json:"source"`

	// IsSecret indicates if this is a secret.
	IsSecret bool `json:"is_secret"`

	// Required indicates if this variable is required.
	Required bool `json:"required"`

	// OverriddenBy shows which config overrode a parent value.
	OverriddenBy string `json:"overridden_by,omitempty"`
}

// ValidationSummary provides counts of issues by severity.
type ValidationSummary struct {
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// ValidationOptions configures the validation behavior.
type ValidationOptions struct {
	// ValidateSecrets enables validation that secrets can be resolved.
	ValidateSecrets bool

	// ValidateInheritance enables validation of the inheritance chain.
	ValidateInheritance bool

	// ResolveEnvVars includes resolved environment variables in the result.
	ResolveEnvVars bool

	// StrictMode treats warnings as errors.
	StrictMode bool

	// AllowedEnvVarPatterns restricts env var names to specific patterns.
	AllowedEnvVarPatterns []string

	// RequiredEnvVars specifies env vars that must be present.
	RequiredEnvVars []string

	// ForbiddenEnvVars specifies env vars that must not be used.
	ForbiddenEnvVars []string
}

// DefaultValidationOptions returns default validation options.
func DefaultValidationOptions() ValidationOptions {
	return ValidationOptions{
		ValidateSecrets:     false, // Don't try to resolve secrets by default
		ValidateInheritance: true,
		ResolveEnvVars:      true,
		StrictMode:          false,
	}
}

// Validator performs configuration validation.
type Validator struct {
	manager *Manager
	rules   []ValidationRule
}

// ValidationRule is a function that validates configuration.
type ValidationRule func(ctx *ValidationContext) []*ValidationIssue

// ValidationContext provides context for validation rules.
type ValidationContext struct {
	Manager      *Manager
	FunctionName string
	Config       *FunctionConfig
	GlobalConfig *GlobalConfig
	Options      ValidationOptions
	Visited      map[string]bool // For cycle detection
}

// NewValidator creates a new configuration validator.
func NewValidator(manager *Manager) *Validator {
	v := &Validator{
		manager: manager,
		rules:   make([]ValidationRule, 0),
	}

	// Register default validation rules
	v.RegisterRule(validateRequiredEnvVars)
	v.RegisterRule(validateSecretReferences)
	v.RegisterRule(validateInheritanceChain)
	v.RegisterRule(validateEnvVarNames)
	v.RegisterRule(validateEnvVarValues)
	v.RegisterRule(validateCircularInheritance)
	v.RegisterRule(validateSecretProviders)

	return v
}

// RegisterRule adds a custom validation rule.
func (v *Validator) RegisterRule(rule ValidationRule) {
	v.rules = append(v.rules, rule)
}

// Validate performs comprehensive validation on a function's configuration.
func (v *Validator) Validate(functionName string, opts ValidationOptions) *ValidationResult {
	result := &ValidationResult{
		FunctionName:    functionName,
		Issues:          make([]*ValidationIssue, 0),
		ResolvedEnvVars: make(map[string]*ResolvedEnvVar),
		ValidatedAt:     time.Now(),
		Summary:         &ValidationSummary{},
	}

	v.manager.mu.RLock()
	config, exists := v.manager.configs[functionName]
	globalConfig := v.manager.globalConfig
	v.manager.mu.RUnlock()

	if !exists {
		result.Issues = append(result.Issues, &ValidationIssue{
			Severity:   SeverityError,
			Code:       "CONFIG_NOT_FOUND",
			Message:    fmt.Sprintf("configuration for function '%s' not found", functionName),
			Suggestion: "Create the function configuration first using the /config/function endpoint",
		})
		result.Valid = false
		result.Summary.Errors = 1
		result.Summary.Total = 1
		return result
	}

	// Create validation context
	ctx := &ValidationContext{
		Manager:      v.manager,
		FunctionName: functionName,
		Config:       config,
		GlobalConfig: globalConfig,
		Options:      opts,
		Visited:      make(map[string]bool),
	}

	// Run all validation rules
	for _, rule := range v.rules {
		issues := rule(ctx)
		result.Issues = append(result.Issues, issues...)
	}

	// Build inheritance chain
	result.InheritanceChain = v.buildInheritanceChain(functionName, make(map[string]bool))

	// Resolve environment variables if requested
	if opts.ResolveEnvVars {
		result.ResolvedEnvVars = v.resolveAllEnvVars(functionName, result.InheritanceChain)
	}

	// Check for required env vars from options
	for _, required := range opts.RequiredEnvVars {
		if _, ok := result.ResolvedEnvVars[required]; !ok {
			result.Issues = append(result.Issues, &ValidationIssue{
				Severity:   SeverityError,
				Code:       "MISSING_REQUIRED_VAR",
				Message:    fmt.Sprintf("required environment variable '%s' is not configured", required),
				Field:      required,
				Suggestion: "Add this environment variable to the function or global configuration",
			})
		}
	}

	// Check for forbidden env vars
	for _, forbidden := range opts.ForbiddenEnvVars {
		if _, ok := result.ResolvedEnvVars[forbidden]; ok {
			result.Issues = append(result.Issues, &ValidationIssue{
				Severity:   SeverityError,
				Code:       "FORBIDDEN_VAR",
				Message:    fmt.Sprintf("environment variable '%s' is not allowed", forbidden),
				Field:      forbidden,
				Suggestion: "Remove this environment variable from the configuration",
			})
		}
	}

	// Validate allowed patterns
	if len(opts.AllowedEnvVarPatterns) > 0 {
		for name := range result.ResolvedEnvVars {
			matched := false
			for _, pattern := range opts.AllowedEnvVarPatterns {
				if matched, _ = regexp.MatchString(pattern, name); matched {
					break
				}
			}
			if !matched {
				result.Issues = append(result.Issues, &ValidationIssue{
					Severity:   SeverityWarning,
					Code:       "PATTERN_MISMATCH",
					Message:    fmt.Sprintf("environment variable '%s' does not match allowed patterns", name),
					Field:      name,
					Suggestion: fmt.Sprintf("Rename the variable to match one of: %v", opts.AllowedEnvVarPatterns),
				})
			}
		}
	}

	// Calculate summary
	for _, issue := range result.Issues {
		switch issue.Severity {
		case SeverityError:
			result.Summary.Errors++
		case SeverityWarning:
			result.Summary.Warnings++
		case SeverityInfo:
			result.Summary.Info++
		}
		result.Summary.Total++
	}

	// Determine if valid
	if opts.StrictMode {
		result.Valid = result.Summary.Errors == 0 && result.Summary.Warnings == 0
	} else {
		result.Valid = result.Summary.Errors == 0
	}

	validationLogger.Info("validation completed", logging.Fields{
		"function_name": functionName,
		"valid":         result.Valid,
		"errors":        result.Summary.Errors,
		"warnings":      result.Summary.Warnings,
	})

	return result
}

// ValidateForDeployment performs strict validation suitable for pre-deployment checks.
func (v *Validator) ValidateForDeployment(functionName string) *ValidationResult {
	opts := ValidationOptions{
		ValidateSecrets:     true,
		ValidateInheritance: true,
		ResolveEnvVars:      true,
		StrictMode:          true,
	}
	return v.Validate(functionName, opts)
}

// ValidateAll validates all configured functions.
func (v *Validator) ValidateAll(opts ValidationOptions) map[string]*ValidationResult {
	results := make(map[string]*ValidationResult)

	for _, functionName := range v.manager.ListFunctions() {
		results[functionName] = v.Validate(functionName, opts)
	}

	return results
}

// buildInheritanceChain builds the full inheritance chain for a function.
func (v *Validator) buildInheritanceChain(functionName string, visited map[string]bool) []string {
	if visited[functionName] {
		return nil // Cycle detected
	}
	visited[functionName] = true

	chain := []string{"global"}

	v.manager.mu.RLock()
	config, exists := v.manager.configs[functionName]
	v.manager.mu.RUnlock()

	if !exists {
		return chain
	}

	// Add inherited configs
	for _, parentName := range config.Inherit {
		parentChain := v.buildInheritanceChain(parentName, visited)
		chain = append(chain, parentChain...)
	}

	chain = append(chain, functionName)
	return chain
}

// resolveAllEnvVars resolves all environment variables with source tracking.
func (v *Validator) resolveAllEnvVars(functionName string, chain []string) map[string]*ResolvedEnvVar {
	resolved := make(map[string]*ResolvedEnvVar)

	// Start with global config
	v.manager.mu.RLock()
	globalConfig := v.manager.globalConfig
	v.manager.mu.RUnlock()

	for name, envVar := range globalConfig.EnvVars {
		resolved[name] = &ResolvedEnvVar{
			Name:     name,
			Value:    redactIfSensitive(envVar),
			Source:   "global",
			IsSecret: envVar.IsSecret,
			Required: envVar.Required,
		}
	}

	// Process inheritance chain (excluding global which we already processed)
	for _, configName := range chain {
		if configName == "global" {
			continue
		}

		v.manager.mu.RLock()
		config, exists := v.manager.configs[configName]
		v.manager.mu.RUnlock()

		if !exists {
			continue
		}

		for name, envVar := range config.EnvVars {
			existing, wasSet := resolved[name]
			resolved[name] = &ResolvedEnvVar{
				Name:     name,
				Value:    redactIfSensitive(envVar),
				Source:   configName,
				IsSecret: envVar.IsSecret,
				Required: envVar.Required,
			}
			if wasSet && existing.Source != configName {
				resolved[name].OverriddenBy = configName
			}
		}
	}

	return resolved
}

func redactIfSensitive(envVar *EnvVar) string {
	if envVar.IsSecret || envVar.Sensitive {
		return "[REDACTED]"
	}
	return envVar.Value
}

// Built-in validation rules

func validateRequiredEnvVars(ctx *ValidationContext) []*ValidationIssue {
	var issues []*ValidationIssue

	for name, envVar := range ctx.Config.EnvVars {
		if envVar.Required {
			if envVar.IsSecret {
				if envVar.SecretRef == nil {
					issues = append(issues, &ValidationIssue{
						Severity:   SeverityError,
						Code:       "MISSING_SECRET_REF",
						Message:    fmt.Sprintf("required secret '%s' has no reference configured", name),
						Field:      name,
						Suggestion: "Set a secret reference using /config/secret/ref endpoint",
					})
				}
			} else if envVar.Value == "" {
				issues = append(issues, &ValidationIssue{
					Severity:   SeverityError,
					Code:       "MISSING_REQUIRED_VALUE",
					Message:    fmt.Sprintf("required environment variable '%s' has no value", name),
					Field:      name,
					Suggestion: "Set a value for this environment variable",
				})
			}
		}
	}

	return issues
}

func validateSecretReferences(ctx *ValidationContext) []*ValidationIssue {
	var issues []*ValidationIssue

	for name, envVar := range ctx.Config.EnvVars {
		if envVar.IsSecret && envVar.SecretRef != nil {
			ref := envVar.SecretRef

			// Validate source is known
			ctx.Manager.mu.RLock()
			_, hasProvider := ctx.Manager.providers[ref.Source]
			ctx.Manager.mu.RUnlock()

			if !hasProvider {
				issues = append(issues, &ValidationIssue{
					Severity:   SeverityError,
					Code:       "INVALID_SECRET_SOURCE",
					Message:    fmt.Sprintf("secret '%s' references unknown source '%s'", name, ref.Source),
					Field:      name,
					Value:      string(ref.Source),
					Suggestion: "Use a valid secret source: local, env, vault, aws, gcp, azure",
				})
			}

			// Validate key is not empty
			if ref.Key == "" {
				issues = append(issues, &ValidationIssue{
					Severity:   SeverityError,
					Code:       "EMPTY_SECRET_KEY",
					Message:    fmt.Sprintf("secret '%s' has empty key reference", name),
					Field:      name,
					Suggestion: "Provide the key/path to the secret in the secret store",
				})
			}

			// Validate secret can be resolved if option is set
			if ctx.Options.ValidateSecrets {
				ctx.Manager.mu.RLock()
				config := ctx.Manager.configs[ctx.FunctionName]
				ctx.Manager.mu.RUnlock()

				if ref.Source == SecretSourceLocal {
					if config.Secrets == nil || config.Secrets[ref.Key] == nil {
						issues = append(issues, &ValidationIssue{
							Severity:   SeverityError,
							Code:       "SECRET_NOT_FOUND",
							Message:    fmt.Sprintf("local secret '%s' (key: %s) not found", name, ref.Key),
							Field:      name,
							Suggestion: "Store the secret using /config/secret endpoint",
						})
					}
				}
			}
		}
	}

	return issues
}

func validateInheritanceChain(ctx *ValidationContext) []*ValidationIssue {
	var issues []*ValidationIssue

	if !ctx.Options.ValidateInheritance {
		return issues
	}

	for _, parentName := range ctx.Config.Inherit {
		ctx.Manager.mu.RLock()
		_, exists := ctx.Manager.configs[parentName]
		ctx.Manager.mu.RUnlock()

		if !exists {
			issues = append(issues, &ValidationIssue{
				Severity:   SeverityError,
				Code:       "MISSING_PARENT_CONFIG",
				Message:    fmt.Sprintf("inherited configuration '%s' does not exist", parentName),
				Field:      "inherit",
				Value:      parentName,
				Suggestion: fmt.Sprintf("Create the '%s' configuration first, or remove it from inheritance", parentName),
			})
		}
	}

	return issues
}

func validateEnvVarNames(ctx *ValidationContext) []*ValidationIssue {
	var issues []*ValidationIssue

	// Valid env var name pattern (POSIX-compliant)
	validName := regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

	for name := range ctx.Config.EnvVars {
		if !validName.MatchString(name) {
			issues = append(issues, &ValidationIssue{
				Severity:   SeverityError,
				Code:       "INVALID_VAR_NAME",
				Message:    fmt.Sprintf("environment variable name '%s' is not valid", name),
				Field:      name,
				Suggestion: "Use only letters, numbers, and underscores. Must start with letter or underscore.",
			})
		}

		// Warn about reserved prefixes
		reservedPrefixes := []string{"GITHUB_", "ACTIONS_", "RUNNER_", "CI", "PATH", "HOME"}
		for _, prefix := range reservedPrefixes {
			if strings.HasPrefix(name, prefix) {
				issues = append(issues, &ValidationIssue{
					Severity:   SeverityWarning,
					Code:       "RESERVED_PREFIX",
					Message:    fmt.Sprintf("environment variable '%s' uses a reserved prefix", name),
					Field:      name,
					Suggestion: fmt.Sprintf("Consider renaming to avoid conflicts with %s* variables", prefix),
				})
				break
			}
		}
	}

	return issues
}

func validateEnvVarValues(ctx *ValidationContext) []*ValidationIssue {
	var issues []*ValidationIssue

	for name, envVar := range ctx.Config.EnvVars {
		if envVar.IsSecret {
			continue // Don't validate secret values
		}

		// Check for empty non-required values (informational)
		if envVar.Value == "" && !envVar.Required {
			issues = append(issues, &ValidationIssue{
				Severity:   SeverityInfo,
				Code:       "EMPTY_VALUE",
				Message:    fmt.Sprintf("environment variable '%s' has an empty value", name),
				Field:      name,
				Suggestion: "Consider setting a value or marking as required if needed",
			})
		}

		// Check for potentially sensitive values in non-secret vars
		sensitivePatterns := []string{"password", "secret", "key", "token", "credential", "auth"}
		lowerName := strings.ToLower(name)
		for _, pattern := range sensitivePatterns {
			if strings.Contains(lowerName, pattern) && !envVar.IsSecret && !envVar.Sensitive {
				issues = append(issues, &ValidationIssue{
					Severity:   SeverityWarning,
					Code:       "POTENTIALLY_SENSITIVE",
					Message:    fmt.Sprintf("environment variable '%s' may contain sensitive data but is not marked as secret", name),
					Field:      name,
					Suggestion: "Mark this variable as a secret or set sensitive=true",
				})
				break
			}
		}

		// Check for overly long values
		if len(envVar.Value) > 32768 {
			issues = append(issues, &ValidationIssue{
				Severity:   SeverityWarning,
				Code:       "VALUE_TOO_LONG",
				Message:    fmt.Sprintf("environment variable '%s' has a very long value (%d bytes)", name, len(envVar.Value)),
				Field:      name,
				Suggestion: "Consider storing large values in files or external storage",
			})
		}
	}

	return issues
}

func validateCircularInheritance(ctx *ValidationContext) []*ValidationIssue {
	var issues []*ValidationIssue

	// Check for circular inheritance
	visited := make(map[string]bool)
	path := make([]string, 0)

	var checkCycle func(name string) bool
	checkCycle = func(name string) bool {
		if visited[name] {
			// Found a cycle
			cycleStart := -1
			for i, p := range path {
				if p == name {
					cycleStart = i
					break
				}
			}
			if cycleStart >= 0 {
				cycle := append(path[cycleStart:], name)
				issues = append(issues, &ValidationIssue{
					Severity:   SeverityError,
					Code:       "CIRCULAR_INHERITANCE",
					Message:    fmt.Sprintf("circular inheritance detected: %s", strings.Join(cycle, " -> ")),
					Field:      "inherit",
					Suggestion: "Remove one of the inheritance relationships to break the cycle",
				})
			}
			return true
		}

		visited[name] = true
		path = append(path, name)

		ctx.Manager.mu.RLock()
		config, exists := ctx.Manager.configs[name]
		ctx.Manager.mu.RUnlock()

		if exists {
			for _, parent := range config.Inherit {
				if checkCycle(parent) {
					return true
				}
			}
		}

		path = path[:len(path)-1]
		return false
	}

	checkCycle(ctx.FunctionName)

	return issues
}

func validateSecretProviders(ctx *ValidationContext) []*ValidationIssue {
	var issues []*ValidationIssue

	// Check that used secret providers are configured
	usedSources := make(map[SecretSource]bool)

	for _, envVar := range ctx.Config.EnvVars {
		if envVar.IsSecret && envVar.SecretRef != nil {
			usedSources[envVar.SecretRef.Source] = true
		}
	}

	ctx.Manager.mu.RLock()
	providerConfigs := ctx.GlobalConfig.SecretProviderConfigs
	ctx.Manager.mu.RUnlock()

	for source := range usedSources {
		if source == SecretSourceLocal || source == SecretSourceEnv {
			continue // Built-in providers
		}

		if providerConfigs == nil || providerConfigs[source] == nil || !providerConfigs[source].Enabled {
			issues = append(issues, &ValidationIssue{
				Severity:   SeverityWarning,
				Code:       "PROVIDER_NOT_CONFIGURED",
				Message:    fmt.Sprintf("secret provider '%s' is used but not configured", source),
				Field:      string(source),
				Suggestion: fmt.Sprintf("Configure the %s secret provider in global settings", source),
			})
		}
	}

	return issues
}

// DeploymentReadiness represents the deployment readiness status.
type DeploymentReadiness struct {
	// Ready indicates if the function can be deployed.
	Ready bool `json:"ready"`

	// FunctionName is the function being checked.
	FunctionName string `json:"function_name"`

	// Blockers are issues preventing deployment.
	Blockers []*ValidationIssue `json:"blockers,omitempty"`

	// Warnings are non-blocking issues.
	Warnings []*ValidationIssue `json:"warnings,omitempty"`

	// CheckedAt is when the check was performed.
	CheckedAt time.Time `json:"checked_at"`

	// ResolvedConfig shows the final resolved configuration.
	ResolvedConfig map[string]string `json:"resolved_config,omitempty"`
}

// CheckDeploymentReadiness performs a comprehensive check for deployment.
func (v *Validator) CheckDeploymentReadiness(ctx Context, functionName string) *DeploymentReadiness {
	readiness := &DeploymentReadiness{
		FunctionName: functionName,
		Blockers:     make([]*ValidationIssue, 0),
		Warnings:     make([]*ValidationIssue, 0),
		CheckedAt:    time.Now(),
	}

	// Run validation
	result := v.ValidateForDeployment(functionName)

	for _, issue := range result.Issues {
		if issue.Severity == SeverityError {
			readiness.Blockers = append(readiness.Blockers, issue)
		} else if issue.Severity == SeverityWarning {
			readiness.Warnings = append(readiness.Warnings, issue)
		}
	}

	// Try to resolve all env vars
	resolvedVars, err := v.manager.GetEnvVars(ctx, functionName)
	if err != nil {
		readiness.Blockers = append(readiness.Blockers, &ValidationIssue{
			Severity:   SeverityError,
			Code:       "RESOLUTION_FAILED",
			Message:    fmt.Sprintf("failed to resolve environment variables: %s", err.Error()),
			Suggestion: "Fix the underlying configuration issues",
		})
	} else {
		// Redact sensitive values
		readiness.ResolvedConfig = make(map[string]string)
		for name, value := range resolvedVars {
			v.manager.mu.RLock()
			config, exists := v.manager.configs[functionName]
			v.manager.mu.RUnlock()

			isSensitive := false
			if exists {
				if envVar, ok := config.EnvVars[name]; ok {
					isSensitive = envVar.IsSecret || envVar.Sensitive
				}
			}

			if isSensitive {
				readiness.ResolvedConfig[name] = "[REDACTED]"
			} else {
				readiness.ResolvedConfig[name] = value
			}
		}
	}

	readiness.Ready = len(readiness.Blockers) == 0

	validationLogger.Info("deployment readiness checked", logging.Fields{
		"function_name": functionName,
		"ready":         readiness.Ready,
		"blockers":      len(readiness.Blockers),
		"warnings":      len(readiness.Warnings),
	})

	return readiness
}

// MarshalJSON implements custom JSON marshaling for ValidationResult.
func (r *ValidationResult) MarshalJSON() ([]byte, error) {
	type Alias ValidationResult
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(r),
	})
}

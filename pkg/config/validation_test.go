package config

import (
	"testing"
)

func TestValidator_BasicValidation(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.EncryptionKey = "test-encryption-key-32-chars!!"
	manager, _ := NewManager(opts)
	validator := NewValidator(manager)

	// Create function with valid config
	manager.CreateFunctionConfig(&FunctionConfig{
		Name: "valid-func",
		EnvVars: map[string]*EnvVar{
			"VALID_VAR": {Name: "VALID_VAR", Value: "value"},
		},
	})

	result := validator.Validate("valid-func", nil)

	if !result.Valid {
		t.Errorf("Valid config should pass validation, got issues: %v", result.Issues)
	}
}

func TestValidator_RequiredFields(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.EncryptionKey = "test-encryption-key-32-chars!!"
	manager, _ := NewManager(opts)
	validator := NewValidator(manager)

	// Create function with missing required variable
	manager.CreateFunctionConfig(&FunctionConfig{
		Name: "missing-required",
		EnvVars: map[string]*EnvVar{
			"REQUIRED_VAR": {Name: "REQUIRED_VAR", Value: "", Required: true},
		},
	})

	result := validator.Validate("missing-required", nil)

	if result.Valid {
		t.Error("Missing required field should fail validation")
	}

	// Check for required field issue
	hasRequiredIssue := false
	for _, issue := range result.Issues {
		if issue.Rule == "required_fields" {
			hasRequiredIssue = true
			break
		}
	}
	if !hasRequiredIssue {
		t.Error("Should have required_fields issue")
	}
}

func TestValidator_EnvVarNaming(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.EncryptionKey = "test-encryption-key-32-chars!!"
	manager, _ := NewManager(opts)
	validator := NewValidator(manager)

	tests := []struct {
		name    string
		varName string
		valid   bool
	}{
		{"valid uppercase", "MY_VAR", true},
		{"valid with numbers", "VAR_123", true},
		{"starts with number", "123_VAR", false},
		{"lowercase", "my_var", false},
		{"mixed case", "My_Var", false},
		{"has dash", "MY-VAR", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			funcName := "test-func-" + tt.name
			manager.CreateFunctionConfig(&FunctionConfig{
				Name: funcName,
				EnvVars: map[string]*EnvVar{
					tt.varName: {Name: tt.varName, Value: "value"},
				},
			})

			result := validator.Validate(funcName, nil)

			hasNamingIssue := false
			for _, issue := range result.Issues {
				if issue.Rule == "env_var_naming" {
					hasNamingIssue = true
					break
				}
			}

			if tt.valid && hasNamingIssue {
				t.Errorf("Valid var name %q flagged as invalid", tt.varName)
			}
			if !tt.valid && !hasNamingIssue {
				t.Errorf("Invalid var name %q not flagged", tt.varName)
			}
		})
	}
}

func TestValidator_SecretDetection(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.EncryptionKey = "test-encryption-key-32-chars!!"
	manager, _ := NewManager(opts)
	validator := NewValidator(manager)

	// Create function with sensitive-looking value not marked as secret
	manager.CreateFunctionConfig(&FunctionConfig{
		Name: "secret-detection",
		EnvVars: map[string]*EnvVar{
			"API_KEY":     {Name: "API_KEY", Value: "sk_live_abcd1234", IsSecret: false},
			"NORMAL_VAR":  {Name: "NORMAL_VAR", Value: "normal-value", IsSecret: false},
			"DB_PASSWORD": {Name: "DB_PASSWORD", Value: "password123", IsSecret: false},
		},
	})

	result := validator.Validate("secret-detection", nil)

	hasSecretIssue := false
	for _, issue := range result.Issues {
		if issue.Rule == "secret_detection" {
			hasSecretIssue = true
			break
		}
	}

	if !hasSecretIssue {
		t.Error("Should detect potential secrets in non-secret variables")
	}
}

func TestValidator_SecretResolution(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.EncryptionKey = "test-encryption-key-32-chars!!"
	manager, _ := NewManager(opts)
	validator := NewValidator(manager)

	// Create function with invalid secret reference
	manager.CreateFunctionConfig(&FunctionConfig{
		Name: "bad-secret-ref",
		EnvVars: map[string]*EnvVar{
			"SECRET_VAR": {
				Name:     "SECRET_VAR",
				IsSecret: true,
				SecretRef: &SecretReference{
					Source: SecretSource("invalid-source"),
					Key:    "some-key",
				},
			},
		},
	})

	valOpts := &ValidationOptions{
		ValidateSecrets: true,
	}
	result := validator.Validate("bad-secret-ref", valOpts)

	hasSecretResolutionIssue := false
	for _, issue := range result.Issues {
		if issue.Rule == "secret_resolution" {
			hasSecretResolutionIssue = true
			break
		}
	}

	if !hasSecretResolutionIssue {
		t.Error("Should have secret_resolution issue for invalid source")
	}
}

func TestValidator_InheritanceResolution(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.EncryptionKey = "test-encryption-key-32-chars!!"
	manager, _ := NewManager(opts)
	validator := NewValidator(manager)

	// Create function with non-existent parent
	manager.CreateFunctionConfig(&FunctionConfig{
		Name:    "bad-inherit",
		Inherit: []string{"non-existent-parent"},
	})

	result := validator.Validate("bad-inherit", nil)

	hasInheritanceIssue := false
	for _, issue := range result.Issues {
		if issue.Rule == "inheritance_resolution" {
			hasInheritanceIssue = true
			break
		}
	}

	if !hasInheritanceIssue {
		t.Error("Should have inheritance_resolution issue for non-existent parent")
	}
}

func TestValidator_CustomRule(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.EncryptionKey = "test-encryption-key-32-chars!!"
	manager, _ := NewManager(opts)
	validator := NewValidator(manager)

	// Register custom rule
	validator.RegisterRule("custom_check", func(ctx *ValidationContext) []ValidationIssue {
		var issues []ValidationIssue
		if ctx.Config.Description == "" {
			issues = append(issues, ValidationIssue{
				Level:   ValidationLevelWarning,
				Rule:    "custom_check",
				Field:   "description",
				Message: "Description is recommended",
			})
		}
		return issues
	})

	// Create function without description
	manager.CreateFunctionConfig(&FunctionConfig{
		Name:        "no-description",
		Description: "",
	})

	result := validator.Validate("no-description", nil)

	hasCustomIssue := false
	for _, issue := range result.Issues {
		if issue.Rule == "custom_check" {
			hasCustomIssue = true
			break
		}
	}

	if !hasCustomIssue {
		t.Error("Custom rule should have been triggered")
	}
}

func TestValidator_ValidateAll(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.EncryptionKey = "test-encryption-key-32-chars!!"
	manager, _ := NewManager(opts)
	validator := NewValidator(manager)

	// Create multiple functions
	manager.CreateFunctionConfig(&FunctionConfig{
		Name: "func1",
		EnvVars: map[string]*EnvVar{
			"VAR1": {Name: "VAR1", Value: "value1"},
		},
	})
	manager.CreateFunctionConfig(&FunctionConfig{
		Name: "func2",
		EnvVars: map[string]*EnvVar{
			"VAR2": {Name: "VAR2", Value: "", Required: true}, // Will fail
		},
	})

	results := validator.ValidateAll(nil)

	if len(results) != 2 {
		t.Errorf("ValidateAll() returned %v results, want 2", len(results))
	}

	// Check that func2 has errors
	if result, ok := results["func2"]; ok {
		if result.Valid {
			t.Error("func2 should be invalid")
		}
	} else {
		t.Error("func2 not in results")
	}
}

func TestValidator_CheckDeploymentReadiness(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.EncryptionKey = "test-encryption-key-32-chars!!"
	manager, _ := NewManager(opts)
	validator := NewValidator(manager)

	// Create ready function
	manager.CreateFunctionConfig(&FunctionConfig{
		Name: "ready-func",
		EnvVars: map[string]*EnvVar{
			"VAR1": {Name: "VAR1", Value: "value1"},
		},
	})

	// Create not-ready function (missing required)
	manager.CreateFunctionConfig(&FunctionConfig{
		Name: "not-ready-func",
		EnvVars: map[string]*EnvVar{
			"REQUIRED": {Name: "REQUIRED", Value: "", Required: true},
		},
	})

	readiness := validator.CheckDeploymentReadiness([]string{"ready-func", "not-ready-func"})

	if readiness.Ready {
		t.Error("Deployment should not be ready with invalid function")
	}
	if readiness.ReadyCount != 1 {
		t.Errorf("ReadyCount = %v, want 1", readiness.ReadyCount)
	}
	if readiness.NotReadyCount != 1 {
		t.Errorf("NotReadyCount = %v, want 1", readiness.NotReadyCount)
	}
}

func TestValidationResult_Helpers(t *testing.T) {
	result := &ValidationResult{
		FunctionName: "test-func",
		Valid:        false,
		Issues: []ValidationIssue{
			{Level: ValidationLevelError, Rule: "rule1", Message: "Error 1"},
			{Level: ValidationLevelError, Rule: "rule2", Message: "Error 2"},
			{Level: ValidationLevelWarning, Rule: "rule3", Message: "Warning 1"},
			{Level: ValidationLevelInfo, Rule: "rule4", Message: "Info 1"},
		},
	}

	errors := result.Errors()
	if len(errors) != 2 {
		t.Errorf("Errors() count = %v, want 2", len(errors))
	}

	warnings := result.Warnings()
	if len(warnings) != 1 {
		t.Errorf("Warnings() count = %v, want 1", len(warnings))
	}

	if result.ErrorCount() != 2 {
		t.Errorf("ErrorCount() = %v, want 2", result.ErrorCount())
	}

	if result.WarningCount() != 1 {
		t.Errorf("WarningCount() = %v, want 1", result.WarningCount())
	}
}

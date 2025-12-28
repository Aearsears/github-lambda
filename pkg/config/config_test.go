package config

import (
	"context"
	"testing"
	"time"
)

// newTestManager creates a manager for testing
func newTestManager() (*Manager, error) {
	return NewManager(DefaultManagerOptions())
}

func TestNewManager(t *testing.T) {
	m, err := newTestManager()
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if m == nil {
		t.Fatal("NewManager() returned nil")
	}
}

func TestManager_CreateFunctionConfig(t *testing.T) {
	m, _ := newTestManager()

	config := m.CreateFunctionConfig("test-func")
	if config == nil {
		t.Fatal("CreateFunctionConfig() returned nil")
	}
	if config.FunctionName != "test-func" {
		t.Errorf("FunctionName = %v, want test-func", config.FunctionName)
	}
	if config.EnvVars == nil {
		t.Error("EnvVars map should be initialized")
	}
}

func TestManager_GetFunctionConfig(t *testing.T) {
	m, _ := newTestManager()
	m.CreateFunctionConfig("test-func")

	config, err := m.GetFunctionConfig("test-func")
	if err != nil {
		t.Fatalf("GetFunctionConfig() error = %v", err)
	}
	if config.FunctionName != "test-func" {
		t.Errorf("FunctionName = %v, want test-func", config.FunctionName)
	}
}

func TestManager_GetFunctionConfig_NotFound(t *testing.T) {
	m, _ := newTestManager()

	_, err := m.GetFunctionConfig("non-existent")
	if err == nil {
		t.Error("GetFunctionConfig() should return error for non-existent function")
	}
}

func TestManager_SetEnvVar(t *testing.T) {
	m, _ := newTestManager()
	m.CreateFunctionConfig("test-func")

	err := m.SetEnvVar("test-func", "MY_VAR", "my-value")
	if err != nil {
		t.Fatalf("SetEnvVar() error = %v", err)
	}

	config, _ := m.GetFunctionConfig("test-func")
	if config.EnvVars["MY_VAR"] == nil {
		t.Fatal("EnvVar should be set")
	}
	if config.EnvVars["MY_VAR"].Value != "my-value" {
		t.Errorf("EnvVar value = %v, want my-value", config.EnvVars["MY_VAR"].Value)
	}
}

func TestManager_SetEnvVar_WithDescription(t *testing.T) {
	m, _ := newTestManager()
	m.CreateFunctionConfig("test-func")

	err := m.SetEnvVar("test-func", "MY_VAR", "my-value", WithDescription("Test variable"))
	if err != nil {
		t.Fatalf("SetEnvVar() error = %v", err)
	}

	config, _ := m.GetFunctionConfig("test-func")
	if config.EnvVars["MY_VAR"].Description != "Test variable" {
		t.Errorf("Description = %v, want Test variable", config.EnvVars["MY_VAR"].Description)
	}
}

func TestManager_SetEnvVar_Required(t *testing.T) {
	m, _ := newTestManager()
	m.CreateFunctionConfig("test-func")

	err := m.SetEnvVar("test-func", "MY_VAR", "my-value", WithRequired(true))
	if err != nil {
		t.Fatalf("SetEnvVar() error = %v", err)
	}

	config, _ := m.GetFunctionConfig("test-func")
	if !config.EnvVars["MY_VAR"].Required {
		t.Error("EnvVar should be required")
	}
}

func TestManager_DeleteEnvVar(t *testing.T) {
	m, _ := newTestManager()
	m.CreateFunctionConfig("test-func")
	m.SetEnvVar("test-func", "MY_VAR", "my-value")

	err := m.DeleteEnvVar("test-func", "MY_VAR")
	if err != nil {
		t.Fatalf("DeleteEnvVar() error = %v", err)
	}

	config, _ := m.GetFunctionConfig("test-func")
	if config.EnvVars["MY_VAR"] != nil {
		t.Error("EnvVar should be deleted")
	}
}

func TestManager_SetGlobalEnvVar(t *testing.T) {
	m, _ := newTestManager()

	err := m.SetGlobalEnvVar("GLOBAL_VAR", "global-value")
	if err != nil {
		t.Fatalf("SetGlobalEnvVar() error = %v", err)
	}

	global := m.GetGlobalConfig()
	if global.EnvVars["GLOBAL_VAR"] == nil {
		t.Fatal("Global EnvVar should be set")
	}
	if global.EnvVars["GLOBAL_VAR"].Value != "global-value" {
		t.Errorf("Global EnvVar value = %v, want global-value", global.EnvVars["GLOBAL_VAR"].Value)
	}
}

func TestManager_GetEnvVars(t *testing.T) {
	m, _ := newTestManager()
	m.CreateFunctionConfig("test-func")
	m.SetEnvVar("test-func", "VAR1", "value1")
	m.SetEnvVar("test-func", "VAR2", "value2")

	vars, err := m.GetEnvVars(context.Background(), "test-func")
	if err != nil {
		t.Fatalf("GetEnvVars() error = %v", err)
	}

	if vars["VAR1"] != "value1" {
		t.Errorf("VAR1 = %v, want value1", vars["VAR1"])
	}
	if vars["VAR2"] != "value2" {
		t.Errorf("VAR2 = %v, want value2", vars["VAR2"])
	}
}

func TestManager_Inheritance_Basic(t *testing.T) {
	m, _ := newTestManager()
	m.CreateFunctionConfig("parent")
	m.SetEnvVar("parent", "PARENT_VAR", "parent-value")

	m.CreateFunctionConfig("child")
	m.SetEnvVar("child", "CHILD_VAR", "child-value")
	m.SetInheritance("child", []string{"parent"})

	vars, err := m.GetEnvVars(context.Background(), "child")
	if err != nil {
		t.Fatalf("GetEnvVars() error = %v", err)
	}

	if vars["PARENT_VAR"] != "parent-value" {
		t.Errorf("PARENT_VAR = %v, want parent-value", vars["PARENT_VAR"])
	}
	if vars["CHILD_VAR"] != "child-value" {
		t.Errorf("CHILD_VAR = %v, want child-value", vars["CHILD_VAR"])
	}
}

func TestManager_Inheritance_Override(t *testing.T) {
	m, _ := newTestManager()
	m.CreateFunctionConfig("parent")
	m.SetEnvVar("parent", "VAR", "parent-value")

	m.CreateFunctionConfig("child")
	m.SetEnvVar("child", "VAR", "child-value")
	m.SetInheritance("child", []string{"parent"})

	vars, err := m.GetEnvVars(context.Background(), "child")
	if err != nil {
		t.Fatalf("GetEnvVars() error = %v", err)
	}

	// Child value should override parent
	if vars["VAR"] != "child-value" {
		t.Errorf("VAR = %v, want child-value (override)", vars["VAR"])
	}
}

func TestManager_Inheritance_MultiLevel(t *testing.T) {
	m, _ := newTestManager()
	m.CreateFunctionConfig("grandparent")
	m.SetEnvVar("grandparent", "GP_VAR", "gp-value")

	m.CreateFunctionConfig("parent")
	m.SetEnvVar("parent", "P_VAR", "p-value")
	m.SetInheritance("parent", []string{"grandparent"})

	m.CreateFunctionConfig("child")
	m.SetEnvVar("child", "C_VAR", "c-value")
	m.SetInheritance("child", []string{"parent"})

	vars, err := m.GetEnvVars(context.Background(), "child")
	if err != nil {
		t.Fatalf("GetEnvVars() error = %v", err)
	}

	if vars["GP_VAR"] != "gp-value" {
		t.Errorf("GP_VAR = %v, want gp-value", vars["GP_VAR"])
	}
	if vars["P_VAR"] != "p-value" {
		t.Errorf("P_VAR = %v, want p-value", vars["P_VAR"])
	}
	if vars["C_VAR"] != "c-value" {
		t.Errorf("C_VAR = %v, want c-value", vars["C_VAR"])
	}
}

func TestManager_Inheritance_Circular_Prevention(t *testing.T) {
	m, _ := newTestManager()
	m.CreateFunctionConfig("a")
	m.CreateFunctionConfig("b")

	m.SetInheritance("a", []string{"b"})
	err := m.SetInheritance("b", []string{"a"})
	if err == nil {
		t.Error("SetInheritance() should prevent circular inheritance")
	}
}

func TestManager_GetInheritanceChain(t *testing.T) {
	m, _ := newTestManager()
	m.CreateFunctionConfig("base")
	m.CreateFunctionConfig("middle")
	m.SetInheritance("middle", []string{"base"})
	m.CreateFunctionConfig("top")
	m.SetInheritance("top", []string{"middle"})

	chain, err := m.GetInheritanceChain("top")
	if err != nil {
		t.Fatalf("GetInheritanceChain() error = %v", err)
	}

	if len(chain) != 3 {
		t.Errorf("Chain length = %v, want 3", len(chain))
	}
}

func TestManager_SetSecret_WithEncryptionKey(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.EncryptionKey = "32-byte-key-for-aes-256-gcm!!!"
	m, _ := NewManager(opts)
	m.CreateFunctionConfig("test-func")

	err := m.SetSecret("test-func", "MY_SECRET", "secret-value")
	if err != nil {
		t.Fatalf("SetSecret() error = %v", err)
	}

	config, _ := m.GetFunctionConfig("test-func")
	if config.Secrets["MY_SECRET"] == nil {
		t.Fatal("Secret should be stored")
	}
	if config.Secrets["MY_SECRET"].Ciphertext == "" {
		t.Error("Secret should be encrypted")
	}
}

func TestManager_SetSecret_NoEncryptionKey(t *testing.T) {
	m, _ := newTestManager()
	m.CreateFunctionConfig("test-func")

	err := m.SetSecret("test-func", "MY_SECRET", "secret-value")
	if err == nil {
		t.Error("SetSecret() should fail without encryption key")
	}
}

func TestManager_GetSecret(t *testing.T) {
	opts := DefaultManagerOptions()
	opts.EncryptionKey = "32-byte-key-for-aes-256-gcm!!!"
	m, _ := NewManager(opts)
	m.CreateFunctionConfig("test-func")
	m.SetSecret("test-func", "MY_SECRET", "secret-value")

	value, err := m.GetSecret(context.Background(), "test-func", "MY_SECRET")
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}

	if value != "secret-value" {
		t.Errorf("GetSecret() = %v, want secret-value", value)
	}
}

func TestFunctionConfig_Version(t *testing.T) {
	m, _ := newTestManager()
	config := m.CreateFunctionConfig("test-func")

	initialVersion := config.Version

	m.SetEnvVar("test-func", "VAR1", "value1")
	config, _ = m.GetFunctionConfig("test-func")

	if config.Version <= initialVersion {
		t.Error("Version should increment on changes")
	}
}

func TestFunctionConfig_Timestamps(t *testing.T) {
	m, _ := newTestManager()

	before := time.Now()
	config := m.CreateFunctionConfig("test-func")
	after := time.Now()

	if config.CreatedAt.Before(before) || config.CreatedAt.After(after) {
		t.Error("CreatedAt should be set to current time")
	}
}

func TestEnvVar_Validation(t *testing.T) {
	tests := []struct {
		name     string
		envVar   EnvVar
		hasError bool
	}{
		{
			name: "valid plain value",
			envVar: EnvVar{
				Name:     "TEST",
				Value:    "value",
				Required: true,
			},
			hasError: false,
		},
		{
			name: "missing name",
			envVar: EnvVar{
				Value: "value",
			},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.envVar.Validate()
			if (err != nil) != tt.hasError {
				t.Errorf("Validate() error = %v, wantError %v", err, tt.hasError)
			}
		})
	}
}

func TestManager_GlobalAndFunctionVars(t *testing.T) {
	m, _ := newTestManager()
	m.SetGlobalEnvVar("GLOBAL_VAR", "global")
	m.CreateFunctionConfig("test-func")
	m.SetEnvVar("test-func", "LOCAL_VAR", "local")

	vars, err := m.GetEnvVars(context.Background(), "test-func")
	if err != nil {
		t.Fatalf("GetEnvVars() error = %v", err)
	}

	if vars["GLOBAL_VAR"] != "global" {
		t.Errorf("GLOBAL_VAR = %v, want global", vars["GLOBAL_VAR"])
	}
	if vars["LOCAL_VAR"] != "local" {
		t.Errorf("LOCAL_VAR = %v, want local", vars["LOCAL_VAR"])
	}
}

func TestManager_FunctionOverridesGlobal(t *testing.T) {
	m, _ := newTestManager()
	m.SetGlobalEnvVar("MY_VAR", "global")
	m.CreateFunctionConfig("test-func")
	m.SetEnvVar("test-func", "MY_VAR", "local")

	vars, err := m.GetEnvVars(context.Background(), "test-func")
	if err != nil {
		t.Fatalf("GetEnvVars() error = %v", err)
	}

	if vars["MY_VAR"] != "local" {
		t.Errorf("MY_VAR = %v, want local (override)", vars["MY_VAR"])
	}
}

func TestDefaultManagerOptions(t *testing.T) {
	opts := DefaultManagerOptions()

	if opts.DefaultSecretSource != SecretSourceLocal {
		t.Errorf("DefaultSecretSource = %v, want SecretSourceLocal", opts.DefaultSecretSource)
	}
	if opts.SecretCacheTTL != 5*time.Minute {
		t.Errorf("SecretCacheTTL = %v, want 5m", opts.SecretCacheTTL)
	}
	if !opts.AutoSave {
		t.Error("AutoSave should be true by default")
	}
}

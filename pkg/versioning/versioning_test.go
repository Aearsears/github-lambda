package versioning

import (
	"testing"
	"time"
)

func TestVersion_VersionID(t *testing.T) {
	v := &Version{
		FunctionName: "test-func",
		Version:      5,
	}

	if v.VersionID() != "test-func:5" {
		t.Errorf("VersionID() = %v, want test-func:5", v.VersionID())
	}
}

func TestAlias_AliasID(t *testing.T) {
	a := &Alias{
		FunctionName: "test-func",
		Name:         "prod",
	}

	if a.AliasID() != "test-func:prod" {
		t.Errorf("AliasID() = %v, want test-func:prod", a.AliasID())
	}
}

func TestNewManager(t *testing.T) {
	m := NewManager()

	if m == nil {
		t.Fatal("NewManager() returned nil")
	}
	if m.functions == nil {
		t.Error("functions map should be initialized")
	}
	if m.versions == nil {
		t.Error("versions map should be initialized")
	}
	if m.aliases == nil {
		t.Error("aliases map should be initialized")
	}
}

func TestManager_CreateFunction(t *testing.T) {
	m := NewManager()

	config := &FunctionConfig{
		Name:        "test-func",
		Description: "Test function",
		Runtime:     "go1.21",
		Handler:     "main",
		Timeout:     30,
		MemorySize:  128,
	}

	err := m.CreateFunction(config)
	if err != nil {
		t.Fatalf("CreateFunction() error = %v", err)
	}

	// Verify function was created
	retrieved, err := m.GetFunction("test-func")
	if err != nil {
		t.Fatalf("GetFunction() error = %v", err)
	}

	if retrieved.Name != "test-func" {
		t.Errorf("Name = %v, want test-func", retrieved.Name)
	}
	if retrieved.LatestVersion != 0 {
		t.Errorf("LatestVersion = %v, want 0", retrieved.LatestVersion)
	}
}

func TestManager_CreateFunction_EmptyName(t *testing.T) {
	m := NewManager()

	err := m.CreateFunction(&FunctionConfig{Name: ""})
	if err == nil {
		t.Error("CreateFunction() should return error for empty name")
	}
}

func TestManager_CreateFunction_Update(t *testing.T) {
	m := NewManager()

	m.CreateFunction(&FunctionConfig{
		Name:        "test-func",
		Description: "Original",
	})

	m.CreateFunction(&FunctionConfig{
		Name:        "test-func",
		Description: "Updated",
	})

	config, _ := m.GetFunction("test-func")
	if config.Description != "Updated" {
		t.Errorf("Description = %v, want Updated", config.Description)
	}
}

func TestManager_PublishVersion(t *testing.T) {
	m := NewManager()

	m.CreateFunction(&FunctionConfig{
		Name:    "test-func",
		Runtime: "go1.21",
	})

	version, err := m.PublishVersion("test-func", "First release", "abc123", "user1")
	if err != nil {
		t.Fatalf("PublishVersion() error = %v", err)
	}

	if version.Version != 1 {
		t.Errorf("Version = %v, want 1", version.Version)
	}
	if version.FunctionName != "test-func" {
		t.Errorf("FunctionName = %v, want test-func", version.FunctionName)
	}
	if version.CodeHash != "abc123" {
		t.Errorf("CodeHash = %v, want abc123", version.CodeHash)
	}
	if version.CreatedBy != "user1" {
		t.Errorf("CreatedBy = %v, want user1", version.CreatedBy)
	}
}

func TestManager_PublishVersion_Multiple(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})

	v1, _ := m.PublishVersion("test-func", "v1", "hash1", "user")
	v2, _ := m.PublishVersion("test-func", "v2", "hash2", "user")
	v3, _ := m.PublishVersion("test-func", "v3", "hash3", "user")

	if v1.Version != 1 || v2.Version != 2 || v3.Version != 3 {
		t.Error("Version numbers should increment")
	}

	// Latest version should be 3
	config, _ := m.GetFunction("test-func")
	if config.LatestVersion != 3 {
		t.Errorf("LatestVersion = %v, want 3", config.LatestVersion)
	}
}

func TestManager_PublishVersion_FunctionNotFound(t *testing.T) {
	m := NewManager()

	_, err := m.PublishVersion("non-existent", "desc", "hash", "user")
	if err == nil {
		t.Error("PublishVersion() should return error for non-existent function")
	}
}

func TestManager_GetVersion(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})
	m.PublishVersion("test-func", "v1", "hash1", "user")

	version, err := m.GetVersion("test-func", 1)
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}

	if version.Version != 1 {
		t.Errorf("Version = %v, want 1", version.Version)
	}
}

func TestManager_GetVersion_NotFound(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})

	_, err := m.GetVersion("test-func", 999)
	if err == nil {
		t.Error("GetVersion() should return error for non-existent version")
	}
}

func TestManager_ListVersions(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})
	m.PublishVersion("test-func", "v1", "hash1", "user")
	m.PublishVersion("test-func", "v2", "hash2", "user")
	m.PublishVersion("test-func", "v3", "hash3", "user")

	versions, err := m.ListVersions("test-func")
	if err != nil {
		t.Fatalf("ListVersions() error = %v", err)
	}

	if len(versions) != 3 {
		t.Errorf("ListVersions() returned %v versions, want 3", len(versions))
	}

	// Should be sorted by version descending
	if versions[0].Version != 3 {
		t.Error("Versions should be sorted descending")
	}
}

func TestManager_CreateAlias(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})
	m.PublishVersion("test-func", "v1", "hash", "user")

	alias, err := m.CreateAlias("test-func", "prod", "Production", 1, nil)
	if err != nil {
		t.Fatalf("CreateAlias() error = %v", err)
	}

	if alias.Name != "prod" {
		t.Errorf("Name = %v, want prod", alias.Name)
	}
	if alias.FunctionVersion != 1 {
		t.Errorf("FunctionVersion = %v, want 1", alias.FunctionVersion)
	}
}

func TestManager_CreateAlias_InvalidVersion(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})

	_, err := m.CreateAlias("test-func", "prod", "Production", 999, nil)
	if err == nil {
		t.Error("CreateAlias() should return error for non-existent version")
	}
}

func TestManager_UpdateAlias(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})
	m.PublishVersion("test-func", "v1", "hash1", "user")
	m.PublishVersion("test-func", "v2", "hash2", "user")
	m.CreateAlias("test-func", "prod", "Production", 1, nil)

	newVersion := 2
	alias, err := m.UpdateAlias("test-func", "prod", &newVersion, nil, nil)
	if err != nil {
		t.Fatalf("UpdateAlias() error = %v", err)
	}

	if alias.FunctionVersion != 2 {
		t.Errorf("FunctionVersion = %v, want 2", alias.FunctionVersion)
	}
}

func TestManager_GetAlias(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})
	m.PublishVersion("test-func", "v1", "hash", "user")
	m.CreateAlias("test-func", "prod", "Production", 1, nil)

	alias, err := m.GetAlias("test-func", "prod")
	if err != nil {
		t.Fatalf("GetAlias() error = %v", err)
	}

	if alias.Name != "prod" {
		t.Errorf("Name = %v, want prod", alias.Name)
	}
}

func TestManager_ListAliases(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})
	m.PublishVersion("test-func", "v1", "hash", "user")
	m.CreateAlias("test-func", "prod", "Production", 1, nil)
	m.CreateAlias("test-func", "staging", "Staging", 1, nil)

	aliases, err := m.ListAliases("test-func")
	if err != nil {
		t.Fatalf("ListAliases() error = %v", err)
	}

	if len(aliases) != 2 {
		t.Errorf("ListAliases() returned %v aliases, want 2", len(aliases))
	}
}

func TestManager_DeleteAlias(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})
	m.PublishVersion("test-func", "v1", "hash", "user")
	m.CreateAlias("test-func", "prod", "Production", 1, nil)

	err := m.DeleteAlias("test-func", "prod")
	if err != nil {
		t.Fatalf("DeleteAlias() error = %v", err)
	}

	_, err = m.GetAlias("test-func", "prod")
	if err == nil {
		t.Error("GetAlias() should return error after delete")
	}
}

// Test QualifiedName parsing
func TestParseQualifiedName(t *testing.T) {
	tests := []struct {
		input        string
		expectedFunc string
		expectedQual string
	}{
		{"myFunction", "myFunction", ""},
		{"myFunction:1", "myFunction", "1"},
		{"myFunction:prod", "myFunction", "prod"},
		{"myFunction:$LATEST", "myFunction", "$LATEST"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			qn := ParseQualifiedName(tt.input)
			if qn.FunctionName != tt.expectedFunc {
				t.Errorf("FunctionName = %v, want %v", qn.FunctionName, tt.expectedFunc)
			}
			if qn.Qualifier != tt.expectedQual {
				t.Errorf("Qualifier = %v, want %v", qn.Qualifier, tt.expectedQual)
			}
		})
	}
}

func TestQualifiedName_String(t *testing.T) {
	qn := QualifiedName{FunctionName: "myFunc", Qualifier: "prod"}
	if qn.String() != "myFunc:prod" {
		t.Errorf("String() = %v, want myFunc:prod", qn.String())
	}

	qn = QualifiedName{FunctionName: "myFunc"}
	if qn.String() != "myFunc" {
		t.Errorf("String() = %v, want myFunc", qn.String())
	}
}

func TestQualifiedName_IsVersion(t *testing.T) {
	tests := []struct {
		qualifier string
		expected  bool
	}{
		{"1", true},
		{"42", true},
		{"prod", false},
		{"$LATEST", false},
		{"", false},
	}

	for _, tt := range tests {
		qn := QualifiedName{FunctionName: "func", Qualifier: tt.qualifier}
		if qn.IsVersion() != tt.expected {
			t.Errorf("IsVersion(%v) = %v, want %v", tt.qualifier, qn.IsVersion(), tt.expected)
		}
	}
}

func TestQualifiedName_IsAlias(t *testing.T) {
	tests := []struct {
		qualifier string
		expected  bool
	}{
		{"prod", true},
		{"staging", true},
		{"1", false},
		{"$LATEST", false},
		{"", false},
	}

	for _, tt := range tests {
		qn := QualifiedName{FunctionName: "func", Qualifier: tt.qualifier}
		if qn.IsAlias() != tt.expected {
			t.Errorf("IsAlias(%v) = %v, want %v", tt.qualifier, qn.IsAlias(), tt.expected)
		}
	}
}

func TestQualifiedName_IsLatest(t *testing.T) {
	tests := []struct {
		qualifier string
		expected  bool
	}{
		{"", true},
		{"$LATEST", true},
		{"1", false},
		{"prod", false},
	}

	for _, tt := range tests {
		qn := QualifiedName{FunctionName: "func", Qualifier: tt.qualifier}
		if qn.IsLatest() != tt.expected {
			t.Errorf("IsLatest(%v) = %v, want %v", tt.qualifier, qn.IsLatest(), tt.expected)
		}
	}
}

func TestQualifiedName_Version(t *testing.T) {
	qn := QualifiedName{FunctionName: "func", Qualifier: "42"}
	v, ok := qn.Version()
	if !ok || v != 42 {
		t.Errorf("Version() = (%v, %v), want (42, true)", v, ok)
	}

	qn = QualifiedName{FunctionName: "func", Qualifier: "prod"}
	_, ok = qn.Version()
	if ok {
		t.Error("Version() should return false for alias")
	}
}

// Test Resolver
func TestResolver_Resolve_Latest(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})
	m.PublishVersion("test-func", "v1", "hash", "user")

	r := NewResolver(m)

	resolved, err := r.Resolve("test-func")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if resolved.Version != 1 {
		t.Errorf("Version = %v, want 1", resolved.Version)
	}
	if !resolved.IsLatest {
		t.Error("IsLatest should be true")
	}
}

func TestResolver_Resolve_Version(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})
	m.PublishVersion("test-func", "v1", "hash", "user")
	m.PublishVersion("test-func", "v2", "hash", "user")

	r := NewResolver(m)

	resolved, err := r.Resolve("test-func:1")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if resolved.Version != 1 {
		t.Errorf("Version = %v, want 1", resolved.Version)
	}
	if resolved.IsLatest {
		t.Error("IsLatest should be false")
	}
}

func TestResolver_Resolve_Alias(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})
	m.PublishVersion("test-func", "v1", "hash", "user")
	m.CreateAlias("test-func", "prod", "Production", 1, nil)

	r := NewResolver(m)

	resolved, err := r.Resolve("test-func:prod")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if resolved.Version != 1 {
		t.Errorf("Version = %v, want 1", resolved.Version)
	}
	if resolved.Alias != "prod" {
		t.Errorf("Alias = %v, want prod", resolved.Alias)
	}
}

func TestResolver_Resolve_UnknownFunction(t *testing.T) {
	m := NewManager()
	r := NewResolver(m)

	// Should return successfully for backward compatibility
	resolved, err := r.Resolve("unknown-func")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if resolved.FunctionName != "unknown-func" {
		t.Errorf("FunctionName = %v, want unknown-func", resolved.FunctionName)
	}
	if resolved.Version != 0 {
		t.Errorf("Version = %v, want 0", resolved.Version)
	}
}

func TestManager_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/versions.json"

	m1 := NewManager()
	m1.CreateFunction(&FunctionConfig{
		Name:    "test-func",
		Runtime: "go1.21",
	})
	m1.PublishVersion("test-func", "v1", "hash1", "user")
	m1.CreateAlias("test-func", "prod", "Production", 1, nil)

	err := m1.SaveToFile(path)
	if err != nil {
		t.Fatalf("SaveToFile() error = %v", err)
	}

	m2 := NewManager()
	err = m2.LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	// Verify data was loaded
	config, _ := m2.GetFunction("test-func")
	if config.Runtime != "go1.21" {
		t.Errorf("Runtime = %v, want go1.21", config.Runtime)
	}

	version, _ := m2.GetVersion("test-func", 1)
	if version.CodeHash != "hash1" {
		t.Errorf("CodeHash = %v, want hash1", version.CodeHash)
	}

	alias, _ := m2.GetAlias("test-func", "prod")
	if alias.FunctionVersion != 1 {
		t.Errorf("FunctionVersion = %v, want 1", alias.FunctionVersion)
	}
}

func TestVersion_Timestamps(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})

	before := time.Now()
	version, _ := m.PublishVersion("test-func", "desc", "hash", "user")
	after := time.Now()

	if version.CreatedAt.Before(before) || version.CreatedAt.After(after) {
		t.Error("CreatedAt should be set to current time")
	}
}

func TestAlias_UpdateTimestamps(t *testing.T) {
	m := NewManager()
	m.CreateFunction(&FunctionConfig{Name: "test-func"})
	m.PublishVersion("test-func", "v1", "hash", "user")
	m.PublishVersion("test-func", "v2", "hash", "user")

	alias, _ := m.CreateAlias("test-func", "prod", "Production", 1, nil)
	createTime := alias.CreatedAt

	time.Sleep(1 * time.Millisecond)

	newVersion := 2
	alias, _ = m.UpdateAlias("test-func", "prod", &newVersion, nil, nil)

	if !alias.UpdatedAt.After(createTime) {
		t.Error("UpdatedAt should be updated")
	}
}

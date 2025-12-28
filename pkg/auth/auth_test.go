package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAPIKey_HasPermission(t *testing.T) {
	tests := []struct {
		name        string
		permissions []Permission
		check       Permission
		expected    bool
	}{
		{
			name:        "has exact permission",
			permissions: []Permission{PermInvoke, PermStatus},
			check:       PermInvoke,
			expected:    true,
		},
		{
			name:        "does not have permission",
			permissions: []Permission{PermInvoke},
			check:       PermAdmin,
			expected:    false,
		},
		{
			name:        "wildcard permission",
			permissions: []Permission{PermAll},
			check:       PermAdmin,
			expected:    true,
		},
		{
			name:        "empty permissions",
			permissions: []Permission{},
			check:       PermInvoke,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{Permissions: tt.permissions}
			if got := key.HasPermission(tt.check); got != tt.expected {
				t.Errorf("HasPermission() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAPIKey_CanAccessFunction(t *testing.T) {
	tests := []struct {
		name         string
		functions    []string
		functionName string
		expected     bool
	}{
		{
			name:         "empty means all",
			functions:    []string{},
			functionName: "any-function",
			expected:     true,
		},
		{
			name:         "exact match",
			functions:    []string{"hello", "world"},
			functionName: "hello",
			expected:     true,
		},
		{
			name:         "no match",
			functions:    []string{"hello"},
			functionName: "goodbye",
			expected:     false,
		},
		{
			name:         "wildcard all",
			functions:    []string{"*"},
			functionName: "anything",
			expected:     true,
		},
		{
			name:         "prefix wildcard match",
			functions:    []string{"hello-*"},
			functionName: "hello-world",
			expected:     true,
		},
		{
			name:         "prefix wildcard no match",
			functions:    []string{"hello-*"},
			functionName: "goodbye-world",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{Functions: tt.functions}
			if got := key.CanAccessFunction(tt.functionName); got != tt.expected {
				t.Errorf("CanAccessFunction() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAPIKey_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		key       *APIKey
		wantError bool
	}{
		{
			name: "valid key",
			key: &APIKey{
				Enabled: true,
			},
			wantError: false,
		},
		{
			name: "disabled key",
			key: &APIKey{
				Enabled: false,
			},
			wantError: true,
		},
		{
			name: "expired key",
			key: &APIKey{
				Enabled:   true,
				ExpiresAt: func() *time.Time { t := time.Now().Add(-time.Hour); return &t }(),
			},
			wantError: true,
		},
		{
			name: "not expired",
			key: &APIKey{
				Enabled:   true,
				ExpiresAt: func() *time.Time { t := time.Now().Add(time.Hour); return &t }(),
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.key.IsValid()
			if (err != nil) != tt.wantError {
				t.Errorf("IsValid() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestNewKeyStore(t *testing.T) {
	store := NewKeyStore()
	if store == nil {
		t.Fatal("NewKeyStore() returned nil")
	}
}

func TestKeyStore_GenerateAPIKey(t *testing.T) {
	store := NewKeyStore()

	keyString, keyInfo, err := store.GenerateAPIKey("test-key", []Permission{PermInvoke}, nil, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey() error = %v", err)
	}

	if keyString == "" {
		t.Error("GenerateAPIKey() returned empty key string")
	}
	if keyInfo == nil {
		t.Fatal("GenerateAPIKey() returned nil key info")
	}
	if keyInfo.Name != "test-key" {
		t.Errorf("Name = %v, want test-key", keyInfo.Name)
	}
	if !keyInfo.HasPermission(PermInvoke) {
		t.Error("Key should have invoke permission")
	}
	if !keyInfo.Enabled {
		t.Error("Key should be enabled by default")
	}
}

func TestKeyStore_GenerateAPIKey_WithTTL(t *testing.T) {
	store := NewKeyStore()

	ttl := time.Hour
	_, keyInfo, err := store.GenerateAPIKey("test-key", []Permission{PermInvoke}, nil, &ttl)
	if err != nil {
		t.Fatalf("GenerateAPIKey() error = %v", err)
	}

	if keyInfo.ExpiresAt == nil {
		t.Error("ExpiresAt should be set when TTL provided")
	}
}

func TestKeyStore_ValidateKey(t *testing.T) {
	store := NewKeyStore()

	keyString, keyInfo, _ := store.GenerateAPIKey("test", []Permission{PermInvoke}, nil, nil)

	validated, err := store.ValidateKey(keyString)
	if err != nil {
		t.Fatalf("ValidateKey() error = %v", err)
	}
	if validated.ID != keyInfo.ID {
		t.Errorf("Validated ID = %v, want %v", validated.ID, keyInfo.ID)
	}
}

func TestKeyStore_ValidateKey_Invalid(t *testing.T) {
	store := NewKeyStore()

	_, err := store.ValidateKey("invalid-key")
	if err != ErrInvalidAPIKey {
		t.Errorf("ValidateKey() error = %v, want ErrInvalidAPIKey", err)
	}
}

func TestKeyStore_RevokeKey(t *testing.T) {
	store := NewKeyStore()

	keyString, keyInfo, _ := store.GenerateAPIKey("test", []Permission{PermInvoke}, nil, nil)

	err := store.RevokeKey(keyInfo.ID)
	if err != nil {
		t.Fatalf("RevokeKey() error = %v", err)
	}

	// Validate should now fail
	_, err = store.ValidateKey(keyString)
	if err != ErrInvalidAPIKey {
		t.Errorf("ValidateKey() after revoke error = %v, want ErrInvalidAPIKey", err)
	}
}

func TestKeyStore_DeleteKey(t *testing.T) {
	store := NewKeyStore()

	_, keyInfo, _ := store.GenerateAPIKey("test", []Permission{PermInvoke}, nil, nil)

	err := store.DeleteKey(keyInfo.ID)
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	// List should now be empty
	keys := store.ListKeys()
	if len(keys) != 0 {
		t.Errorf("ListKeys() count = %v, want 0", len(keys))
	}
}

func TestKeyStore_ListKeys(t *testing.T) {
	store := NewKeyStore()

	store.GenerateAPIKey("key1", []Permission{PermInvoke}, nil, nil)
	store.GenerateAPIKey("key2", []Permission{PermAdmin}, nil, nil)

	keys := store.ListKeys()
	if len(keys) != 2 {
		t.Errorf("ListKeys() count = %v, want 2", len(keys))
	}
}

func TestMiddleware_RequireAuth(t *testing.T) {
	store := NewKeyStore()
	keyString, _, _ := store.GenerateAPIKey("test", []Permission{PermInvoke}, nil, nil)

	middleware := NewMiddleware(store)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "valid bearer token",
			authHeader: "Bearer " + keyString,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing auth",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid auth scheme",
			authHeader: "Basic " + keyString,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid key",
			authHeader: "Bearer invalid-key",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()

			middleware.RequireAuth(handler).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("Status = %v, want %v", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestMiddleware_SkipPaths(t *testing.T) {
	store := NewKeyStore()
	middleware := NewMiddleware(store)
	middleware.SetSkipPaths("/health", "/metrics")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Request to skip path without auth should succeed
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	middleware.RequireAuth(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Skip path status = %v, want %v", rec.Code, http.StatusOK)
	}
}

func TestMiddleware_X_API_Key_Header(t *testing.T) {
	store := NewKeyStore()
	keyString, _, _ := store.GenerateAPIKey("test", []Permission{PermInvoke}, nil, nil)

	middleware := NewMiddleware(store)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-API-Key", keyString)
	rec := httptest.NewRecorder()

	middleware.RequireAuth(handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("X-API-Key status = %v, want %v", rec.Code, http.StatusOK)
	}
}

func TestMiddleware_RequirePermission(t *testing.T) {
	store := NewKeyStore()
	invokeKey, _, _ := store.GenerateAPIKey("invoke", []Permission{PermInvoke}, nil, nil)
	adminKey, _, _ := store.GenerateAPIKey("admin", []Permission{PermAdmin}, nil, nil)

	middleware := NewMiddleware(store)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		key        string
		permission Permission
		wantStatus int
	}{
		{
			name:       "has required permission",
			key:        invokeKey,
			permission: PermInvoke,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing permission",
			key:        invokeKey,
			permission: PermAdmin,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "admin has admin",
			key:        adminKey,
			permission: PermAdmin,
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Bearer "+tt.key)
			rec := httptest.NewRecorder()

			middleware.RequireAuth(
				RequirePermission(tt.permission)(handler),
			).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("Status = %v, want %v", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestGenerateCallbackSignature(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{"test": "data"}`)

	signature := GenerateCallbackSignature(secret, payload)
	if signature == "" {
		t.Error("GenerateCallbackSignature() returned empty string")
	}

	// Should start with sha256=
	if len(signature) < 7 || signature[:7] != "sha256=" {
		t.Error("Signature should start with 'sha256='")
	}
}

func TestGetAPIKeyFromContext(t *testing.T) {
	store := NewKeyStore()
	keyString, keyInfo, _ := store.GenerateAPIKey("test", []Permission{PermInvoke}, nil, nil)

	middleware := NewMiddleware(store)

	var contextKey *APIKey

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextKey = GetAPIKey(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+keyString)
	rec := httptest.NewRecorder()

	middleware.RequireAuth(handler).ServeHTTP(rec, req)

	if contextKey == nil {
		t.Fatal("GetAPIKeyFromContext() returned nil")
	}
	if contextKey.ID != keyInfo.ID {
		t.Errorf("Context key ID = %v, want %v", contextKey.ID, keyInfo.ID)
	}
}

func TestConstantTimeCompare(t *testing.T) {
	tests := []struct {
		a        string
		b        string
		expected bool
	}{
		{"same", "same", true},
		{"different", "strings", false},
		{"", "", true},
		{"a", "", false},
	}

	for _, tt := range tests {
		if got := ConstantTimeCompare(tt.a, tt.b); got != tt.expected {
			t.Errorf("ConstantTimeCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expected)
		}
	}
}

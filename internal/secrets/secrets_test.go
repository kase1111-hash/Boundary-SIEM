package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestEnvProvider tests the environment variable provider.
func TestEnvProvider(t *testing.T) {
	provider := NewEnvProvider(nil)

	ctx := context.Background()

	t.Run("get existing env var", func(t *testing.T) {
		os.Setenv("BOUNDARY_TEST_SECRET", "test-value")
		defer os.Unsetenv("BOUNDARY_TEST_SECRET")

		secret, err := provider.Get(ctx, "TEST_SECRET")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if secret.Value != "test-value" {
			t.Errorf("expected value 'test-value', got %q", secret.Value)
		}
	})

	t.Run("get with normalization", func(t *testing.T) {
		os.Setenv("BOUNDARY_DATABASE_PASSWORD", "db-pass")
		defer os.Unsetenv("BOUNDARY_DATABASE_PASSWORD")

		secret, err := provider.Get(ctx, "database.password")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if secret.Value != "db-pass" {
			t.Errorf("expected value 'db-pass', got %q", secret.Value)
		}
	})

	t.Run("get non-existent secret", func(t *testing.T) {
		_, err := provider.Get(ctx, "NONEXISTENT_SECRET")
		if err != ErrSecretNotFound {
			t.Errorf("expected ErrSecretNotFound, got %v", err)
		}
	})

	t.Run("set not supported", func(t *testing.T) {
		err := provider.Set(ctx, "TEST", "value")
		if err != ErrNotSupported {
			t.Errorf("expected ErrNotSupported, got %v", err)
		}
	})
}

// TestFileProvider tests the file-based provider.
func TestFileProvider(t *testing.T) {
	tmpDir := t.TempDir()
	provider := NewFileProvider(tmpDir, nil)

	ctx := context.Background()

	t.Run("set and get secret", func(t *testing.T) {
		err := provider.Set(ctx, "test_secret", "file-value")
		if err != nil {
			t.Fatalf("failed to set secret: %v", err)
		}

		secret, err := provider.Get(ctx, "test_secret")
		if err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		if secret.Value != "file-value" {
			t.Errorf("expected value 'file-value', got %q", secret.Value)
		}
	})

	t.Run("get non-existent secret", func(t *testing.T) {
		_, err := provider.Get(ctx, "nonexistent")
		if err != ErrSecretNotFound {
			t.Errorf("expected ErrSecretNotFound, got %v", err)
		}
	})

	t.Run("delete secret", func(t *testing.T) {
		provider.Set(ctx, "to_delete", "value")

		err := provider.Delete(ctx, "to_delete")
		if err != nil {
			t.Fatalf("failed to delete secret: %v", err)
		}

		_, err = provider.Get(ctx, "to_delete")
		if err != ErrSecretNotFound {
			t.Errorf("expected secret to be deleted, got error: %v", err)
		}
	})

	t.Run("health check", func(t *testing.T) {
		err := provider.HealthCheck(ctx)
		if err != nil {
			t.Errorf("health check failed: %v", err)
		}
	})

	t.Run("key to filename conversion", func(t *testing.T) {
		tests := []struct {
			key      string
			expected string
		}{
			{"simple", "simple"},
			{"database/password", "database_password"},
			{"app.api.key", "app_api_key"},
			{"UPPER_CASE", "upper_case"},
		}

		for _, tt := range tests {
			result := provider.keyToFilename(tt.key)
			if result != tt.expected {
				t.Errorf("keyToFilename(%q) = %q, expected %q", tt.key, result, tt.expected)
			}
		}
	})
}

// TestManager tests the secrets manager.
func TestManager(t *testing.T) {
	cfg := &Config{
		EnableVault: false,
		EnableEnv:   true,
		EnableFile:  true,
		CacheTTL:    100 * time.Millisecond,
	}

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer manager.Close()

	ctx := context.Background()

	t.Run("get from env provider", func(t *testing.T) {
		os.Setenv("BOUNDARY_ENV_TEST", "env-value")
		defer os.Unsetenv("BOUNDARY_ENV_TEST")

		value, err := manager.Get(ctx, "ENV_TEST")
		if err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		if value != "env-value" {
			t.Errorf("expected 'env-value', got %q", value)
		}
	})

	t.Run("get with default", func(t *testing.T) {
		value := manager.GetWithDefault(ctx, "NONEXISTENT", "default-value")
		if value != "default-value" {
			t.Errorf("expected 'default-value', got %q", value)
		}
	})

	t.Run("cache functionality", func(t *testing.T) {
		os.Setenv("BOUNDARY_CACHE_TEST", "cached-value")
		defer os.Unsetenv("BOUNDARY_CACHE_TEST")

		// First get - should fetch and cache
		value1, err := manager.Get(ctx, "CACHE_TEST")
		if err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		// Change env var
		os.Setenv("BOUNDARY_CACHE_TEST", "new-value")

		// Second get - should return cached value
		value2, err := manager.Get(ctx, "CACHE_TEST")
		if err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		if value1 != value2 {
			t.Error("expected cached value to be returned")
		}

		// Wait for cache to expire
		time.Sleep(150 * time.Millisecond)

		// Third get - should fetch new value
		value3, err := manager.Get(ctx, "CACHE_TEST")
		if err != nil {
			t.Fatalf("failed to get secret: %v", err)
		}

		if value3 != "new-value" {
			t.Errorf("expected 'new-value' after cache expiry, got %q", value3)
		}
	})

	t.Run("clear cache", func(t *testing.T) {
		os.Setenv("BOUNDARY_CLEAR_TEST", "value1")
		defer os.Unsetenv("BOUNDARY_CLEAR_TEST")

		// Get and cache
		manager.Get(ctx, "CLEAR_TEST")

		// Clear cache
		manager.ClearCache()

		// Change value
		os.Setenv("BOUNDARY_CLEAR_TEST", "value2")

		// Should get new value
		value, _ := manager.Get(ctx, "CLEAR_TEST")
		if value != "value2" {
			t.Errorf("expected 'value2' after cache clear, got %q", value)
		}
	})

	t.Run("health check", func(t *testing.T) {
		err := manager.HealthCheck(ctx)
		if err != nil {
			t.Errorf("health check failed: %v", err)
		}
	})
}

// TestParseSecretRef tests secret reference parsing.
func TestParseSecretRef(t *testing.T) {
	tests := []struct {
		ref              string
		expectedProvider string
		expectedKey      string
	}{
		{"literal_value", "literal", "literal_value"},
		{"env:VAR_NAME", "env", "VAR_NAME"},
		{"vault:secret/path/to/secret", "vault", "secret/path/to/secret"},
		{"file:/etc/secrets/password", "file", "/etc/secrets/password"},
	}

	for _, tt := range tests {
		provider, key := ParseSecretRef(tt.ref)
		if provider != tt.expectedProvider {
			t.Errorf("ParseSecretRef(%q) provider = %q, expected %q", tt.ref, provider, tt.expectedProvider)
		}
		if key != tt.expectedKey {
			t.Errorf("ParseSecretRef(%q) key = %q, expected %q", tt.ref, key, tt.expectedKey)
		}
	}
}

// TestResolveSecret tests secret resolution.
func TestResolveSecret(t *testing.T) {
	cfg := &Config{
		EnableVault: false,
		EnableEnv:   true,
		EnableFile:  false,
		CacheTTL:    time.Minute,
	}

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer manager.Close()

	ctx := context.Background()

	t.Run("resolve literal", func(t *testing.T) {
		value, err := manager.ResolveSecret(ctx, "literal_value")
		if err != nil {
			t.Fatalf("failed to resolve: %v", err)
		}

		if value != "literal_value" {
			t.Errorf("expected 'literal_value', got %q", value)
		}
	})

	t.Run("resolve env reference", func(t *testing.T) {
		os.Setenv("BOUNDARY_RESOLVE_TEST", "resolved-value")
		defer os.Unsetenv("BOUNDARY_RESOLVE_TEST")

		value, err := manager.ResolveSecret(ctx, "env:RESOLVE_TEST")
		if err != nil {
			t.Fatalf("failed to resolve: %v", err)
		}

		if value != "resolved-value" {
			t.Errorf("expected 'resolved-value', got %q", value)
		}
	})
}

// TestNormalizeEnvKey tests environment key normalization.
func TestNormalizeEnvKey(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"admin_password", "BOUNDARY_ADMIN_PASSWORD"},
		{"ADMIN_PASSWORD", "BOUNDARY_ADMIN_PASSWORD"},
		{"BOUNDARY_ADMIN_PASSWORD", "BOUNDARY_ADMIN_PASSWORD"},
		{"database.password", "BOUNDARY_DATABASE_PASSWORD"},
		{"app-name.api-key", "BOUNDARY_APP_NAME_API_KEY"},
	}

	for _, tt := range tests {
		result := normalizeEnvKey(tt.input)
		if result != tt.expected {
			t.Errorf("normalizeEnvKey(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

// TestProviderFallback tests fallback between providers.
func TestProviderFallback(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		EnableVault: false,
		EnableEnv:   true,
		EnableFile:  true,
		CacheTTL:    time.Minute,
	}

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Override file provider to use temp dir
	for i, p := range manager.providers {
		if p.Name() == "file" {
			manager.providers[i] = NewFileProvider(tmpDir, nil)
		}
	}

	defer manager.Close()

	ctx := context.Background()

	// Set secret in file provider only
	fileProvider := NewFileProvider(tmpDir, nil)
	fileProvider.Set(ctx, "fallback_test", "file-value")

	// Get should fall back to file provider
	value, err := manager.Get(ctx, "fallback_test")
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	if value != "file-value" {
		t.Errorf("expected 'file-value', got %q", value)
	}
}

// TestFileProviderWithNewlines tests that file provider handles newlines.
func TestFileProviderWithNewlines(t *testing.T) {
	tmpDir := t.TempDir()
	provider := NewFileProvider(tmpDir, nil)

	ctx := context.Background()

	// Write secret with trailing newline (common in Docker/K8s)
	secretPath := filepath.Join(tmpDir, "test_newline")
	os.WriteFile(secretPath, []byte("value-with-newline\n"), 0600)

	secret, err := provider.Get(ctx, "test_newline")
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	// Should have newline trimmed
	if secret.Value != "value-with-newline" {
		t.Errorf("expected newline to be trimmed, got %q", secret.Value)
	}
}

// BenchmarkManagerGet benchmarks secret retrieval.
func BenchmarkManagerGet(b *testing.B) {
	os.Setenv("BOUNDARY_BENCH_SECRET", "bench-value")
	defer os.Unsetenv("BOUNDARY_BENCH_SECRET")

	cfg := &Config{
		EnableVault: false,
		EnableEnv:   true,
		EnableFile:  false,
		CacheTTL:    time.Minute,
	}

	manager, _ := NewManager(cfg)
	defer manager.Close()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Get(ctx, "BENCH_SECRET")
	}
}

// BenchmarkManagerGetCached benchmarks cached secret retrieval.
func BenchmarkManagerGetCached(b *testing.B) {
	os.Setenv("BOUNDARY_BENCH_CACHED", "cached-value")
	defer os.Unsetenv("BOUNDARY_BENCH_CACHED")

	cfg := &Config{
		EnableVault: false,
		EnableEnv:   true,
		EnableFile:  false,
		CacheTTL:    time.Hour, // Long TTL for benchmark
	}

	manager, _ := NewManager(cfg)
	defer manager.Close()

	ctx := context.Background()

	// Warm up cache
	manager.Get(ctx, "BENCH_CACHED")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.Get(ctx, "BENCH_CACHED")
	}
}

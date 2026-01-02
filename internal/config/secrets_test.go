package config

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestNewSecretsManager tests creating a secrets manager from config.
func TestNewSecretsManager(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Secrets.EnableEnv = true
	cfg.Secrets.EnableVault = false
	cfg.Secrets.EnableFile = false

	mgr, err := cfg.NewSecretsManager()
	if err != nil {
		t.Fatalf("failed to create secrets manager: %v", err)
	}
	defer mgr.Close()

	if mgr == nil {
		t.Fatal("expected non-nil secrets manager")
	}
}

// TestLoadAuthFromSecrets tests loading auth config from secrets manager.
func TestLoadAuthFromSecrets(t *testing.T) {
	// Set environment variables for testing
	os.Setenv("BOUNDARY_ADMIN_USERNAME", "test-admin")
	os.Setenv("BOUNDARY_ADMIN_PASSWORD", "TestPassword123!")
	os.Setenv("BOUNDARY_ADMIN_EMAIL", "admin@example.com")
	defer func() {
		os.Unsetenv("BOUNDARY_ADMIN_USERNAME")
		os.Unsetenv("BOUNDARY_ADMIN_PASSWORD")
		os.Unsetenv("BOUNDARY_ADMIN_EMAIL")
	}()

	cfg := DefaultConfig()
	cfg.Secrets.EnableEnv = true
	cfg.Secrets.EnableVault = false
	cfg.Secrets.EnableFile = false

	mgr, err := cfg.NewSecretsManager()
	if err != nil {
		t.Fatalf("failed to create secrets manager: %v", err)
	}
	defer mgr.Close()

	ctx := context.Background()
	err = cfg.LoadAuthFromSecrets(ctx, mgr)
	if err != nil {
		t.Fatalf("failed to load auth from secrets: %v", err)
	}

	// Verify the auth config was loaded
	if cfg.Auth.DefaultAdminUsername != "test-admin" {
		t.Errorf("expected username 'test-admin', got %q", cfg.Auth.DefaultAdminUsername)
	}

	if cfg.Auth.DefaultAdminPassword != "TestPassword123!" {
		t.Errorf("expected password to be loaded")
	}

	if cfg.Auth.DefaultAdminEmail != "admin@example.com" {
		t.Errorf("expected email 'admin@example.com', got %q", cfg.Auth.DefaultAdminEmail)
	}
}

// TestGetSecret tests retrieving a secret from config.
func TestGetSecret(t *testing.T) {
	os.Setenv("BOUNDARY_TEST_SECRET", "secret-value")
	defer os.Unsetenv("BOUNDARY_TEST_SECRET")

	cfg := DefaultConfig()
	cfg.Secrets.EnableEnv = true
	cfg.Secrets.EnableVault = false
	cfg.Secrets.EnableFile = false

	ctx := context.Background()
	value, err := cfg.GetSecret(ctx, "TEST_SECRET")
	if err != nil {
		t.Fatalf("failed to get secret: %v", err)
	}

	if value != "secret-value" {
		t.Errorf("expected 'secret-value', got %q", value)
	}
}

// TestGetSecretWithDefault tests retrieving a secret with default fallback.
func TestGetSecretWithDefault(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Secrets.EnableEnv = true
	cfg.Secrets.EnableVault = false
	cfg.Secrets.EnableFile = false

	ctx := context.Background()

	// Test with non-existent secret
	value := cfg.GetSecretWithDefault(ctx, "NONEXISTENT_SECRET", "default-value")
	if value != "default-value" {
		t.Errorf("expected 'default-value', got %q", value)
	}

	// Test with existing secret
	os.Setenv("BOUNDARY_EXISTING_SECRET", "actual-value")
	defer os.Unsetenv("BOUNDARY_EXISTING_SECRET")

	value = cfg.GetSecretWithDefault(ctx, "EXISTING_SECRET", "default-value")
	if value != "actual-value" {
		t.Errorf("expected 'actual-value', got %q", value)
	}
}

// TestSecretsConfigEnvOverrides tests environment variable overrides for secrets config.
func TestSecretsConfigEnvOverrides(t *testing.T) {
	// Set environment variables
	os.Setenv("SIEM_SECRETS_VAULT_ENABLED", "true")
	os.Setenv("VAULT_ADDR", "https://vault.example.com:8200")
	os.Setenv("VAULT_TOKEN", "test-token")
	os.Setenv("VAULT_PATH", "secret/test")
	os.Setenv("SIEM_SECRETS_FILE_ENABLED", "true")
	os.Setenv("SIEM_SECRETS_DIR", "/custom/secrets")
	defer func() {
		os.Unsetenv("SIEM_SECRETS_VAULT_ENABLED")
		os.Unsetenv("VAULT_ADDR")
		os.Unsetenv("VAULT_TOKEN")
		os.Unsetenv("VAULT_PATH")
		os.Unsetenv("SIEM_SECRETS_FILE_ENABLED")
		os.Unsetenv("SIEM_SECRETS_DIR")
	}()

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if !cfg.Secrets.EnableVault {
		t.Error("expected Vault to be enabled")
	}

	if cfg.Secrets.VaultAddress != "https://vault.example.com:8200" {
		t.Errorf("expected Vault address 'https://vault.example.com:8200', got %q", cfg.Secrets.VaultAddress)
	}

	if cfg.Secrets.VaultToken != "test-token" {
		t.Errorf("expected Vault token 'test-token', got %q", cfg.Secrets.VaultToken)
	}

	if cfg.Secrets.VaultPath != "secret/test" {
		t.Errorf("expected Vault path 'secret/test', got %q", cfg.Secrets.VaultPath)
	}

	if !cfg.Secrets.EnableFile {
		t.Error("expected file secrets to be enabled")
	}

	if cfg.Secrets.FileSecretsDir != "/custom/secrets" {
		t.Errorf("expected file secrets dir '/custom/secrets', got %q", cfg.Secrets.FileSecretsDir)
	}
}

// TestSecretsConfigDefaults tests default secrets configuration.
func TestSecretsConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Secrets.EnableVault {
		t.Error("expected Vault to be disabled by default")
	}

	if !cfg.Secrets.EnableEnv {
		t.Error("expected environment variables to be enabled by default")
	}

	if cfg.Secrets.EnableFile {
		t.Error("expected file secrets to be disabled by default")
	}

	if cfg.Secrets.VaultPath != "secret/boundary-siem" {
		t.Errorf("expected default Vault path 'secret/boundary-siem', got %q", cfg.Secrets.VaultPath)
	}

	if cfg.Secrets.VaultTimeout != 10*time.Second {
		t.Errorf("expected default Vault timeout 10s, got %v", cfg.Secrets.VaultTimeout)
	}

	if cfg.Secrets.FileSecretsDir != "/etc/secrets" {
		t.Errorf("expected default file secrets dir '/etc/secrets', got %q", cfg.Secrets.FileSecretsDir)
	}

	if cfg.Secrets.CacheTTL != 5*time.Minute {
		t.Errorf("expected default cache TTL 5m, got %v", cfg.Secrets.CacheTTL)
	}
}

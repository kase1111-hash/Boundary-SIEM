package config

import (
	"context"
	"encoding/base64"
	"os"
	"testing"

	"boundary-siem/internal/encryption"
)

// TestNewEncryptionEngine tests creating an encryption engine from config.
func TestNewEncryptionEngine(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		setup   func() *Config
		cleanup func()
		wantErr bool
	}{
		{
			name: "disabled_encryption",
			setup: func() *Config {
				cfg := DefaultConfig()
				cfg.Encryption.Enabled = false
				return cfg
			},
			cleanup: func() {},
			wantErr: false,
		},
		{
			name: "env_key_source",
			setup: func() *Config {
				// Generate and set a test key
				key, _ := encryption.GenerateKeyBase64()
				os.Setenv("BOUNDARY_ENCRYPTION_KEY", key)

				cfg := DefaultConfig()
				cfg.Encryption.Enabled = true
				cfg.Encryption.KeySource = "env"
				cfg.Encryption.KeyName = "BOUNDARY_ENCRYPTION_KEY"
				return cfg
			},
			cleanup: func() {
				os.Unsetenv("BOUNDARY_ENCRYPTION_KEY")
			},
			wantErr: false,
		},
		{
			name: "env_key_missing",
			setup: func() *Config {
				cfg := DefaultConfig()
				cfg.Encryption.Enabled = true
				cfg.Encryption.KeySource = "env"
				cfg.Encryption.KeyName = "MISSING_KEY"
				return cfg
			},
			cleanup: func() {},
			wantErr: true,
		},
		{
			name: "secret_key_source",
			setup: func() *Config {
				// Set up environment for secrets manager
				key, _ := encryption.GenerateKeyBase64()
				os.Setenv("BOUNDARY_ENCRYPTION_KEY", key)

				cfg := DefaultConfig()
				cfg.Encryption.Enabled = true
				cfg.Encryption.KeySource = "secret"
				cfg.Encryption.KeyName = "ENCRYPTION_KEY"
				cfg.Secrets.EnableEnv = true
				return cfg
			},
			cleanup: func() {
				os.Unsetenv("BOUNDARY_ENCRYPTION_KEY")
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.setup()
			defer tt.cleanup()

			engine, err := cfg.NewEncryptionEngine(ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEncryptionEngine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && engine == nil {
				t.Error("expected non-nil engine")
			}
		})
	}
}

// TestEncryptionConfigDefaults tests default encryption configuration.
func TestEncryptionConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Encryption.Enabled {
		t.Error("expected encryption to be disabled by default")
	}

	if cfg.Encryption.KeySource != "env" {
		t.Errorf("expected default key source 'env', got %q", cfg.Encryption.KeySource)
	}

	if cfg.Encryption.KeyName != "BOUNDARY_ENCRYPTION_KEY" {
		t.Errorf("expected default key name 'BOUNDARY_ENCRYPTION_KEY', got %q", cfg.Encryption.KeyName)
	}

	if cfg.Encryption.KeyVersion != 1 {
		t.Errorf("expected default key version 1, got %d", cfg.Encryption.KeyVersion)
	}

	if !cfg.Encryption.EncryptSessionData {
		t.Error("expected session data encryption to be enabled by default")
	}

	if !cfg.Encryption.EncryptUserData {
		t.Error("expected user data encryption to be enabled by default")
	}

	if !cfg.Encryption.EncryptAPIKeys {
		t.Error("expected API key encryption to be enabled by default")
	}
}

// TestEncryptionConfigEnvOverrides tests environment variable overrides.
func TestEncryptionConfigEnvOverrides(t *testing.T) {
	os.Setenv("SIEM_ENCRYPTION_ENABLED", "true")
	os.Setenv("SIEM_ENCRYPTION_KEY_SOURCE", "secret")
	os.Setenv("SIEM_ENCRYPTION_KEY_NAME", "MY_CUSTOM_KEY")
	os.Setenv("SIEM_ENCRYPTION_KEY_VERSION", "2")
	defer func() {
		os.Unsetenv("SIEM_ENCRYPTION_ENABLED")
		os.Unsetenv("SIEM_ENCRYPTION_KEY_SOURCE")
		os.Unsetenv("SIEM_ENCRYPTION_KEY_NAME")
		os.Unsetenv("SIEM_ENCRYPTION_KEY_VERSION")
	}()

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if !cfg.Encryption.Enabled {
		t.Error("expected encryption to be enabled")
	}

	if cfg.Encryption.KeySource != "secret" {
		t.Errorf("expected key source 'secret', got %q", cfg.Encryption.KeySource)
	}

	if cfg.Encryption.KeyName != "MY_CUSTOM_KEY" {
		t.Errorf("expected key name 'MY_CUSTOM_KEY', got %q", cfg.Encryption.KeyName)
	}

	if cfg.Encryption.KeyVersion != 2 {
		t.Errorf("expected key version 2, got %d", cfg.Encryption.KeyVersion)
	}
}

// TestGenerateEncryptionKey tests key generation helper.
func TestGenerateEncryptionKey(t *testing.T) {
	key, err := GenerateEncryptionKey()
	if err != nil {
		t.Fatalf("GenerateEncryptionKey() error = %v", err)
	}

	// Decode and verify it's a valid base64 key
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatalf("failed to decode generated key: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(decoded))
	}
}

// TestEncryptionEngineWithRawKey tests engine creation with non-base64 key.
func TestEncryptionEngineWithRawKey(t *testing.T) {
	ctx := context.Background()

	// Set a raw key (not base64)
	rawKey := "this-is-a-raw-key-for-testing-32B"
	os.Setenv("BOUNDARY_ENCRYPTION_KEY", rawKey)
	defer os.Unsetenv("BOUNDARY_ENCRYPTION_KEY")

	cfg := DefaultConfig()
	cfg.Encryption.Enabled = true
	cfg.Encryption.KeySource = "env"

	engine, err := cfg.NewEncryptionEngine(ctx)
	if err != nil {
		t.Fatalf("NewEncryptionEngine() error = %v", err)
	}

	if engine == nil {
		t.Fatal("expected non-nil engine")
	}

	// Test encryption/decryption works
	plaintext := "test-data"
	ciphertext, err := engine.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}

	decrypted, err := engine.DecryptString(ciphertext)
	if err != nil {
		t.Fatalf("DecryptString() error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

// TestEncryptionEngineWithSecretsManager tests integration with secrets manager.
func TestEncryptionEngineWithSecretsManager(t *testing.T) {
	ctx := context.Background()

	// Generate key and store in environment (secrets manager will read from env)
	key, err := encryption.GenerateKeyBase64()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	os.Setenv("BOUNDARY_ENCRYPTION_KEY", key)
	defer os.Unsetenv("BOUNDARY_ENCRYPTION_KEY")

	cfg := DefaultConfig()
	cfg.Encryption.Enabled = true
	cfg.Encryption.KeySource = "secret"
	cfg.Encryption.KeyName = "ENCRYPTION_KEY"
	cfg.Secrets.EnableEnv = true

	engine, err := cfg.NewEncryptionEngine(ctx)
	if err != nil {
		t.Fatalf("NewEncryptionEngine() error = %v", err)
	}

	if engine == nil {
		t.Fatal("expected non-nil engine")
	}

	// Test encryption/decryption works
	plaintext := "sensitive-data"
	ciphertext, err := engine.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString() error = %v", err)
	}

	decrypted, err := engine.DecryptString(ciphertext)
	if err != nil {
		t.Fatalf("DecryptString() error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

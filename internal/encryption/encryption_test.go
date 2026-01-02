package encryption

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// TestNewEngine tests creating a new encryption engine.
func TestNewEngine(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid_config_enabled",
			cfg: &Config{
				Enabled:    true,
				MasterKey:  []byte("test-master-key-32-bytes-long!!"),
				KeyVersion: 1,
				Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
			},
			wantErr: false,
		},
		{
			name: "valid_config_disabled",
			cfg: &Config{
				Enabled: false,
				Logger:  slog.New(slog.NewTextHandler(os.Stdout, nil)),
			},
			wantErr: false,
		},
		{
			name: "nil_config",
			cfg:  nil,
			wantErr: true,
		},
		{
			name: "enabled_without_key",
			cfg: &Config{
				Enabled: true,
				Logger:  slog.New(slog.NewTextHandler(os.Stdout, nil)),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := NewEngine(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEngine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && engine == nil {
				t.Error("expected non-nil engine")
			}
		})
	}
}

// TestEncryptDecrypt tests basic encryption and decryption.
func TestEncryptDecrypt(t *testing.T) {
	engine, err := NewEngine(&Config{
		Enabled:    true,
		MasterKey:  []byte("test-master-key-32-bytes-long!!"),
		KeyVersion: 1,
		Logger:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "simple_text",
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "empty_string",
			plaintext: []byte(""),
		},
		{
			name:      "long_text",
			plaintext: []byte(strings.Repeat("A", 1000)),
		},
		{
			name:      "binary_data",
			plaintext: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
		{
			name:      "unicode",
			plaintext: []byte("Hello 世界 🌍"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := engine.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Verify ciphertext is different from plaintext
			if len(tt.plaintext) > 0 && ciphertext == string(tt.plaintext) {
				t.Error("ciphertext should differ from plaintext")
			}

			// Decrypt
			decrypted, err := engine.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			// Verify decrypted matches original
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("decrypted = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

// TestEncryptString tests string encryption.
func TestEncryptString(t *testing.T) {
	engine, err := NewEngine(&Config{
		Enabled:    true,
		MasterKey:  []byte("test-master-key-32-bytes-long!!"),
		KeyVersion: 1,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	plaintext := "sensitive-password"
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

// TestEncryptionDisabled tests that encryption is optional.
func TestEncryptionDisabled(t *testing.T) {
	engine, err := NewEngine(&Config{
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	if engine.Enabled() {
		t.Error("expected encryption to be disabled")
	}

	plaintext := []byte("test-data")
	ciphertext, err := engine.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// When disabled, ciphertext should be base64 of plaintext
	decoded, _ := base64.StdEncoding.DecodeString(ciphertext)
	if !bytes.Equal(decoded, plaintext) {
		t.Error("expected plaintext to be base64-encoded when encryption disabled")
	}

	decrypted, err := engine.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %v, want %v", decrypted, plaintext)
	}
}

// TestInvalidCiphertext tests decryption of invalid data.
func TestInvalidCiphertext(t *testing.T) {
	engine, err := NewEngine(&Config{
		Enabled:    true,
		MasterKey:  []byte("test-master-key-32-bytes-long!!"),
		KeyVersion: 1,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	tests := []struct {
		name       string
		ciphertext string
	}{
		{
			name:       "invalid_base64",
			ciphertext: "not-valid-base64!@#$",
		},
		{
			name:       "too_short",
			ciphertext: base64.StdEncoding.EncodeToString([]byte{0x01}),
		},
		{
			name:       "corrupted_data",
			ciphertext: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("X", 50))),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := engine.Decrypt(tt.ciphertext)
			if err == nil {
				t.Error("expected error decrypting invalid ciphertext")
			}
		})
	}
}

// TestKeyRotation tests key rotation functionality.
func TestKeyRotation(t *testing.T) {
	// Create engine with initial key
	oldKey := []byte("old-master-key-32-bytes-long!!!")
	engine, err := NewEngine(&Config{
		Enabled:    true,
		MasterKey:  oldKey,
		KeyVersion: 1,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	// Encrypt with old key
	plaintext := "sensitive-data"
	oldCiphertext, err := engine.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Rotate to new key
	newKey := []byte("new-master-key-32-bytes-long!!!")
	if err := engine.RotateKey(newKey, 2); err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}

	// Encrypt with new key
	newCiphertext, err := engine.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Verify new ciphertext differs from old
	if oldCiphertext == newCiphertext {
		t.Error("new ciphertext should differ from old after key rotation")
	}

	// Note: Old ciphertext can't be decrypted with new key in this simple implementation
	// In production, you'd need to maintain old keys or re-encrypt data
}

// TestEncryptedField tests field-level encryption with metadata.
func TestEncryptedField(t *testing.T) {
	engine, err := NewEngine(&Config{
		Enabled:    true,
		MasterKey:  []byte("test-master-key-32-bytes-long!!"),
		KeyVersion: 1,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	plaintext := "secret-value"

	// Encrypt field
	field, err := engine.EncryptField(plaintext)
	if err != nil {
		t.Fatalf("EncryptField() error = %v", err)
	}

	if field.KeyVersion != 1 {
		t.Errorf("KeyVersion = %d, want 1", field.KeyVersion)
	}

	if field.Algorithm != "AES-256-GCM" {
		t.Errorf("Algorithm = %s, want AES-256-GCM", field.Algorithm)
	}

	if field.EncryptedAt == 0 {
		t.Error("EncryptedAt should be set")
	}

	// Decrypt field
	decrypted, err := engine.DecryptField(field)
	if err != nil {
		t.Fatalf("DecryptField() error = %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

// TestGenerateKey tests key generation.
func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	// Generate another key and verify they're different
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if bytes.Equal(key, key2) {
		t.Error("generated keys should be unique")
	}
}

// TestGenerateKeyBase64 tests base64 key generation.
func TestGenerateKeyBase64(t *testing.T) {
	keyStr, err := GenerateKeyBase64()
	if err != nil {
		t.Fatalf("GenerateKeyBase64() error = %v", err)
	}

	// Decode and verify length
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		t.Fatalf("failed to decode key: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
}

// TestConcurrentEncryption tests concurrent encryption/decryption.
func TestConcurrentEncryption(t *testing.T) {
	engine, err := NewEngine(&Config{
		Enabled:    true,
		MasterKey:  []byte("test-master-key-32-bytes-long!!"),
		KeyVersion: 1,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	const numGoroutines = 100
	const numOperations = 10

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				plaintext := []byte("concurrent-test-data")

				ciphertext, err := engine.Encrypt(plaintext)
				if err != nil {
					t.Errorf("Encrypt() error = %v", err)
					done <- false
					return
				}

				decrypted, err := engine.Decrypt(ciphertext)
				if err != nil {
					t.Errorf("Decrypt() error = %v", err)
					done <- false
					return
				}

				if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("decrypted != plaintext")
					done <- false
					return
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		if !<-done {
			t.Fatal("concurrent encryption test failed")
		}
	}
}

// TestDeriveKey tests key derivation.
func TestDeriveKey(t *testing.T) {
	masterKey := []byte("test-master-key")

	key1 := deriveKey(masterKey)
	key2 := deriveKey(masterKey)

	// Same input should produce same output
	if !bytes.Equal(key1, key2) {
		t.Error("derived keys should be identical for same input")
	}

	// Key should be 32 bytes
	if len(key1) != 32 {
		t.Errorf("derived key length = %d, want 32", len(key1))
	}

	// Different input should produce different output
	differentKey := deriveKey([]byte("different-key"))
	if bytes.Equal(key1, differentKey) {
		t.Error("different inputs should produce different derived keys")
	}
}

// BenchmarkEncrypt benchmarks encryption.
func BenchmarkEncrypt(b *testing.B) {
	engine, _ := NewEngine(&Config{
		Enabled:    true,
		MasterKey:  []byte("test-master-key-32-bytes-long!!"),
		KeyVersion: 1,
	})

	plaintext := []byte("benchmark-test-data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Encrypt(plaintext)
	}
}

// BenchmarkDecrypt benchmarks decryption.
func BenchmarkDecrypt(b *testing.B) {
	engine, _ := NewEngine(&Config{
		Enabled:    true,
		MasterKey:  []byte("test-master-key-32-bytes-long!!"),
		KeyVersion: 1,
	})

	plaintext := []byte("benchmark-test-data")
	ciphertext, _ := engine.Encrypt(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Decrypt(ciphertext)
	}
}

// BenchmarkEncryptString benchmarks string encryption.
func BenchmarkEncryptString(b *testing.B) {
	engine, _ := NewEngine(&Config{
		Enabled:    true,
		MasterKey:  []byte("test-master-key-32-bytes-long!!"),
		KeyVersion: 1,
	})

	plaintext := "benchmark-test-string"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.EncryptString(plaintext)
	}
}

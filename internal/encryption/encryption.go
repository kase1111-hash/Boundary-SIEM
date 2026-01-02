// Package encryption provides AES-256-GCM encryption for data at rest.
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

var (
	// ErrInvalidKey is returned when the encryption key is invalid.
	ErrInvalidKey = errors.New("invalid encryption key")

	// ErrInvalidCiphertext is returned when the ciphertext is invalid.
	ErrInvalidCiphertext = errors.New("invalid ciphertext")

	// ErrEncryptionFailed is returned when encryption fails.
	ErrEncryptionFailed = errors.New("encryption failed")

	// ErrDecryptionFailed is returned when decryption fails.
	ErrDecryptionFailed = errors.New("decryption failed")
)

// Config holds encryption configuration.
type Config struct {
	// Enabled indicates if encryption is enabled.
	Enabled bool

	// MasterKey is the master encryption key (32 bytes for AES-256).
	// This should be retrieved from a secure key management system.
	MasterKey []byte

	// KeyVersion is the version of the encryption key.
	// Used for key rotation support.
	KeyVersion int

	// Logger for encryption operations.
	Logger *slog.Logger
}

// Engine provides encryption and decryption operations.
type Engine struct {
	enabled    bool
	masterKey  []byte
	keyVersion int
	logger     *slog.Logger
	mu         sync.RWMutex

	// Key rotation support: map of version to key for backward compatibility
	oldKeys    map[int][]byte
}

// NewEngine creates a new encryption engine.
func NewEngine(cfg *Config) (*Engine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if !cfg.Enabled {
		return &Engine{
			enabled: false,
			logger:  cfg.Logger,
		}, nil
	}

	// Validate master key
	if len(cfg.MasterKey) == 0 {
		return nil, fmt.Errorf("%w: master key is required when encryption is enabled", ErrInvalidKey)
	}

	// Derive a 32-byte key from the master key using SHA-256
	derivedKey := deriveKey(cfg.MasterKey)

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	logger.Info("encryption engine initialized",
		"enabled", true,
		"key_version", cfg.KeyVersion,
		"algorithm", "AES-256-GCM")

	return &Engine{
		enabled:    true,
		masterKey:  derivedKey,
		keyVersion: cfg.KeyVersion,
		logger:     logger,
		oldKeys:    make(map[int][]byte),
	}, nil
}

// deriveKey derives a 32-byte encryption key from the master key using SHA-256.
func deriveKey(masterKey []byte) []byte {
	hash := sha256.Sum256(masterKey)
	return hash[:]
}

// Enabled returns whether encryption is enabled.
func (e *Engine) Enabled() bool {
	return e.enabled
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns base64-encoded ciphertext with embedded nonce and key version.
func (e *Engine) Encrypt(plaintext []byte) (string, error) {
	if !e.enabled {
		// If encryption is disabled, return plaintext as base64
		return base64.StdEncoding.EncodeToString(plaintext), nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(plaintext) == 0 {
		return "", nil
	}

	// Create AES cipher block
	block, err := aes.NewCipher(e.masterKey)
	if err != nil {
		e.logger.Error("failed to create cipher block", "error", err)
		return "", fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		e.logger.Error("failed to create GCM", "error", err)
		return "", fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		e.logger.Error("failed to generate nonce", "error", err)
		return "", fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Encrypt plaintext
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Format: [version:1byte][nonce][ciphertext]
	// This allows for key rotation by storing the version
	data := make([]byte, 1+len(nonce)+len(ciphertext))
	data[0] = byte(e.keyVersion)
	copy(data[1:], nonce)
	copy(data[1+len(nonce):], ciphertext)

	// Return base64-encoded result
	return base64.StdEncoding.EncodeToString(data), nil
}

// Decrypt decrypts base64-encoded ciphertext using AES-256-GCM.
func (e *Engine) Decrypt(encodedCiphertext string) ([]byte, error) {
	if !e.enabled {
		// If encryption is disabled, decode from base64
		return base64.StdEncoding.DecodeString(encodedCiphertext)
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	if encodedCiphertext == "" {
		return nil, nil
	}

	// Decode from base64
	data, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base64: %v", ErrInvalidCiphertext, err)
	}

	// Check minimum length: version(1) + nonce(12) + ciphertext(>=0) + tag(16)
	if len(data) < 29 {
		return nil, fmt.Errorf("%w: data too short", ErrInvalidCiphertext)
	}

	// Extract version
	version := int(data[0])

	// Select appropriate key for decryption
	var decryptionKey []byte
	if version == e.keyVersion {
		decryptionKey = e.masterKey
	} else {
		// Try to use old key for backward compatibility
		if oldKey, exists := e.oldKeys[version]; exists {
			decryptionKey = oldKey
			e.logger.Debug("using old key for decryption",
				"stored_version", version,
				"current_version", e.keyVersion)
		} else {
			e.logger.Warn("key version mismatch - no old key available",
				"stored_version", version,
				"current_version", e.keyVersion,
				"available_old_versions", len(e.oldKeys))
			// Fall back to current key (may fail if data was encrypted with different key)
			decryptionKey = e.masterKey
		}
	}

	// Create AES cipher block with appropriate key
	block, err := aes.NewCipher(decryptionKey)
	if err != nil {
		e.logger.Error("failed to create cipher block", "error", err)
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		e.logger.Error("failed to create GCM", "error", err)
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(data) < 1+nonceSize {
		return nil, fmt.Errorf("%w: insufficient data for nonce", ErrInvalidCiphertext)
	}

	nonce := data[1 : 1+nonceSize]
	ciphertext := data[1+nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		e.logger.Error("failed to decrypt", "error", err)
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// EncryptString encrypts a string value.
func (e *Engine) EncryptString(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	return e.Encrypt([]byte(plaintext))
}

// DecryptString decrypts a string value.
func (e *Engine) DecryptString(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// RotateKey rotates the encryption key and stores the old key for backward compatibility.
// This allows existing encrypted data to be decrypted while new data uses the new key.
// Use ReEncrypt() to migrate existing data to the new key.
func (e *Engine) RotateKey(newMasterKey []byte, newVersion int) error {
	if !e.enabled {
		return fmt.Errorf("encryption is not enabled")
	}

	if len(newMasterKey) == 0 {
		return fmt.Errorf("%w: new master key is required", ErrInvalidKey)
	}

	if newVersion <= e.keyVersion {
		return fmt.Errorf("new version (%d) must be greater than current version (%d)", newVersion, e.keyVersion)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Store current key as old key for backward compatibility
	e.oldKeys[e.keyVersion] = e.masterKey

	// Derive new key
	derivedKey := deriveKey(newMasterKey)

	// Update to new key and version
	oldVersion := e.keyVersion
	e.masterKey = derivedKey
	e.keyVersion = newVersion

	e.logger.Info("encryption key rotated",
		"old_version", oldVersion,
		"new_version", newVersion,
		"old_keys_retained", len(e.oldKeys))

	return nil
}

// ReEncrypt decrypts data with any available key and re-encrypts it with the current key.
// This is used during key rotation to migrate data to the new encryption key.
// Returns the re-encrypted data and true if re-encryption was performed, or the original
// data and false if it was already encrypted with the current key version.
func (e *Engine) ReEncrypt(encodedCiphertext string) (string, bool, error) {
	if !e.enabled {
		return encodedCiphertext, false, nil
	}

	if encodedCiphertext == "" {
		return "", false, nil
	}

	// Decode to check version
	data, err := base64.StdEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return "", false, fmt.Errorf("%w: invalid base64: %v", ErrInvalidCiphertext, err)
	}

	if len(data) < 29 {
		return "", false, fmt.Errorf("%w: data too short", ErrInvalidCiphertext)
	}

	version := int(data[0])

	// Already using current key version - no re-encryption needed
	if version == e.keyVersion {
		return encodedCiphertext, false, nil
	}

	// Decrypt with old key
	plaintext, err := e.Decrypt(encodedCiphertext)
	if err != nil {
		return "", false, fmt.Errorf("failed to decrypt during re-encryption: %w", err)
	}

	// Re-encrypt with current key
	newCiphertext, err := e.Encrypt(plaintext)
	if err != nil {
		return "", false, fmt.Errorf("failed to encrypt during re-encryption: %w", err)
	}

	e.logger.Debug("re-encrypted data with new key",
		"old_version", version,
		"new_version", e.keyVersion)

	return newCiphertext, true, nil
}

// GetKeyVersion returns the current encryption key version.
func (e *Engine) GetKeyVersion() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.keyVersion
}

// GetOldKeyVersions returns the list of old key versions still available for decryption.
func (e *Engine) GetOldKeyVersions() []int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	versions := make([]int, 0, len(e.oldKeys))
	for v := range e.oldKeys {
		versions = append(versions, v)
	}
	return versions
}

// PurgeOldKeys removes old keys from memory. Use with caution - this will make
// data encrypted with old keys unrecoverable unless it has been re-encrypted.
func (e *Engine) PurgeOldKeys() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	count := len(e.oldKeys)
	e.oldKeys = make(map[int][]byte)

	e.logger.Warn("purged old encryption keys",
		"keys_removed", count,
		"current_version", e.keyVersion)

	return count
}

// EncryptedField represents an encrypted field with metadata.
type EncryptedField struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion int    `json:"key_version"`
	Algorithm  string `json:"algorithm"`
	EncryptedAt int64 `json:"encrypted_at"`
}

// EncryptField encrypts a field and returns metadata.
func (e *Engine) EncryptField(plaintext string) (*EncryptedField, error) {
	ciphertext, err := e.EncryptString(plaintext)
	if err != nil {
		return nil, err
	}

	return &EncryptedField{
		Ciphertext:  ciphertext,
		KeyVersion:  e.keyVersion,
		Algorithm:   "AES-256-GCM",
		EncryptedAt: int64(time.Now().Unix()),
	}, nil
}

// DecryptField decrypts an encrypted field.
func (e *Engine) DecryptField(field *EncryptedField) (string, error) {
	if field == nil {
		return "", nil
	}
	return e.DecryptString(field.Ciphertext)
}

// GenerateKey generates a random 32-byte encryption key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// GenerateKeyBase64 generates a random key and returns it as base64.
func GenerateKeyBase64() (string, error) {
	key, err := GenerateKey()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

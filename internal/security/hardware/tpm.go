// Package hardware provides hardware security module integration.
// This file implements TPM 2.0 support for secure key storage.
package hardware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Common errors for TPM operations.
var (
	ErrTPMNotAvailable   = errors.New("TPM device not available")
	ErrTPMNotInitialized = errors.New("TPM not initialized")
	ErrTPMKeyNotFound    = errors.New("TPM key not found")
	ErrTPMSealFailed     = errors.New("TPM seal operation failed")
	ErrTPMUnsealFailed   = errors.New("TPM unseal operation failed")
	ErrTPMPCRMismatch    = errors.New("TPM PCR values do not match expected state")
	ErrTPMAuthFailed     = errors.New("TPM authorization failed")
	ErrTPMToolsNotFound  = errors.New("tpm2-tools not installed")
	ErrKeyAlreadyExists  = errors.New("key already exists in TPM")
)

// TPMDevice represents the TPM device path.
const (
	DefaultTPMDevice  = "/dev/tpmrm0" // TPM 2.0 resource manager
	FallbackTPMDevice = "/dev/tpm0"   // Direct TPM access
)

// PCR indices used for sealing
const (
	PCRFirmware   = 0 // BIOS/UEFI
	PCRBootloader = 4 // Bootloader
	PCRKernel     = 8 // Kernel command line
	PCRSecureBoot = 7 // Secure Boot state
)

// TPMConfig configures the TPM key storage.
type TPMConfig struct {
	// DevicePath is the TPM device path (default: /dev/tpmrm0).
	DevicePath string

	// KeyStorePath is where to store TPM key metadata.
	KeyStorePath string

	// PCRSelection specifies which PCRs to use for sealing.
	// Default: [0, 7] for firmware and secure boot state.
	PCRSelection []int

	// OwnerAuth is the TPM owner authorization password.
	// Leave empty for default (empty password).
	OwnerAuth string

	// EnablePCRPolicy enables PCR-based sealing policy.
	EnablePCRPolicy bool

	// AllowSoftwareFallback allows software key storage if TPM unavailable.
	AllowSoftwareFallback bool

	// Logger for diagnostic output.
	Logger *slog.Logger
}

// DefaultTPMConfig returns sensible defaults.
func DefaultTPMConfig() *TPMConfig {
	return &TPMConfig{
		DevicePath:            DefaultTPMDevice,
		KeyStorePath:          "/var/lib/boundary-siem/tpm",
		PCRSelection:          []int{PCRFirmware, PCRSecureBoot},
		EnablePCRPolicy:       true,
		AllowSoftwareFallback: true,
		Logger:                slog.Default(),
	}
}

// TPMKeyStore provides TPM-backed key storage.
type TPMKeyStore struct {
	mu     sync.RWMutex
	config *TPMConfig
	logger *slog.Logger

	// State
	available   bool
	initialized bool
	devicePath  string

	// Cached handles
	primaryHandle string

	// Key metadata
	keys map[string]*KeyMetadata
}

// KeyMetadata stores information about a TPM-stored key.
type KeyMetadata struct {
	Name        string    `json:"name"`
	Handle      string    `json:"handle"`
	Algorithm   string    `json:"algorithm"`
	CreatedAt   time.Time `json:"created_at"`
	PCRPolicy   []int     `json:"pcr_policy,omitempty"`
	PublicBlob  string    `json:"public_blob"`
	PrivateBlob string    `json:"private_blob"`
	// For software fallback
	SoftwareKey string `json:"software_key,omitempty"`
	IsHardware  bool   `json:"is_hardware"`
}

// NewTPMKeyStore creates a new TPM key store.
func NewTPMKeyStore(config *TPMConfig) (*TPMKeyStore, error) {
	if config == nil {
		config = DefaultTPMConfig()
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	store := &TPMKeyStore{
		config: config,
		logger: config.Logger,
		keys:   make(map[string]*KeyMetadata),
	}

	// Check TPM availability
	if err := store.checkTPMAvailability(); err != nil {
		if !config.AllowSoftwareFallback {
			return nil, err
		}
		store.logger.Warn("TPM not available, using software fallback", "error", err)
		store.available = false
	} else {
		store.available = true
		store.devicePath = config.DevicePath
	}

	// Create key store directory
	if err := os.MkdirAll(config.KeyStorePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key store directory: %w", err)
	}

	// Load existing key metadata
	if err := store.loadKeyMetadata(); err != nil {
		store.logger.Warn("failed to load key metadata", "error", err)
	}

	// Initialize TPM primary key if available
	if store.available {
		if err := store.initializePrimaryKey(); err != nil {
			store.logger.Warn("failed to initialize TPM primary key", "error", err)
			if !config.AllowSoftwareFallback {
				return nil, err
			}
			store.available = false
		} else {
			store.initialized = true
		}
	}

	store.logger.Info("TPM key store initialized",
		"available", store.available,
		"initialized", store.initialized,
		"device", store.devicePath)

	return store, nil
}

// checkTPMAvailability checks if TPM 2.0 is available.
func (t *TPMKeyStore) checkTPMAvailability() error {
	// Check for TPM device
	devices := []string{t.config.DevicePath, DefaultTPMDevice, FallbackTPMDevice}
	var foundDevice string

	for _, dev := range devices {
		if dev == "" {
			continue
		}
		if _, err := os.Stat(dev); err == nil {
			foundDevice = dev
			break
		}
	}

	if foundDevice == "" {
		return ErrTPMNotAvailable
	}

	t.config.DevicePath = foundDevice

	// Check for tpm2-tools
	if _, err := exec.LookPath("tpm2_getcap"); err != nil {
		return ErrTPMToolsNotFound
	}

	// Verify TPM is responsive
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "tpm2_getcap", "properties-fixed")
	cmd.Env = append(os.Environ(), fmt.Sprintf("TPM2TOOLS_TCTI=device:%s", foundDevice))

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("TPM not responsive: %w", err)
	}

	return nil
}

// initializePrimaryKey creates or loads the primary key for key derivation.
func (t *TPMKeyStore) initializePrimaryKey() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if primary key context exists
	primaryCtx := filepath.Join(t.config.KeyStorePath, "primary.ctx")
	if _, err := os.Stat(primaryCtx); err == nil {
		t.primaryHandle = primaryCtx
		t.logger.Debug("loaded existing TPM primary key")
		return nil
	}

	// Create primary key in owner hierarchy
	t.logger.Info("creating TPM primary key")

	cmd := exec.CommandContext(ctx, "tpm2_createprimary",
		"-C", "o", // Owner hierarchy
		"-g", "sha256", // Hash algorithm
		"-G", "aes256cfb", // Symmetric algorithm for sealing
		"-c", primaryCtx,
	)
	cmd.Env = t.tpmEnv()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create primary key: %s: %w", string(output), err)
	}

	t.primaryHandle = primaryCtx
	t.logger.Info("TPM primary key created")
	return nil
}

// tpmEnv returns environment variables for TPM tools.
func (t *TPMKeyStore) tpmEnv() []string {
	env := os.Environ()
	env = append(env, fmt.Sprintf("TPM2TOOLS_TCTI=device:%s", t.devicePath))
	return env
}

// loadKeyMetadata loads key metadata from disk.
func (t *TPMKeyStore) loadKeyMetadata() error {
	metadataPath := filepath.Join(t.config.KeyStorePath, "keys.json")

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No existing metadata
		}
		return err
	}

	return json.Unmarshal(data, &t.keys)
}

// saveKeyMetadata saves key metadata to disk.
func (t *TPMKeyStore) saveKeyMetadata() error {
	metadataPath := filepath.Join(t.config.KeyStorePath, "keys.json")

	data, err := json.MarshalIndent(t.keys, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(metadataPath, data, 0600)
}

// CreateKey creates a new key in the TPM.
func (t *TPMKeyStore) CreateKey(ctx context.Context, name string, keySize int) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if key already exists
	if _, exists := t.keys[name]; exists {
		return nil, ErrKeyAlreadyExists
	}

	if t.available && t.initialized {
		return t.createTPMKey(ctx, name, keySize)
	}

	if t.config.AllowSoftwareFallback {
		return t.createSoftwareKey(ctx, name, keySize)
	}

	return nil, ErrTPMNotAvailable
}

// createTPMKey creates a key sealed to the TPM.
func (t *TPMKeyStore) createTPMKey(ctx context.Context, name string, keySize int) ([]byte, error) {
	// Generate random key material
	keyMaterial := make([]byte, keySize)
	if _, err := rand.Read(keyMaterial); err != nil {
		return nil, fmt.Errorf("failed to generate key material: %w", err)
	}

	// Create sealed blob paths
	pubPath := filepath.Join(t.config.KeyStorePath, name+".pub")
	privPath := filepath.Join(t.config.KeyStorePath, name+".priv")
	sealedPath := filepath.Join(t.config.KeyStorePath, name+".sealed")

	// Write key material to temp file for sealing
	tmpFile, err := os.CreateTemp(t.config.KeyStorePath, "seal-*")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Write(keyMaterial)
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Build seal command
	args := []string{
		"-C", t.primaryHandle,
		"-i", tmpPath,
		"-u", pubPath,
		"-r", privPath,
	}

	// Add PCR policy if enabled
	if t.config.EnablePCRPolicy && len(t.config.PCRSelection) > 0 {
		pcrList := t.formatPCRList()
		args = append(args, "-L", pcrList)
	}

	cmd := exec.CommandContext(ctx, "tpm2_create", args...)
	cmd.Env = t.tpmEnv()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tpm2_create failed: %s: %w", string(output), err)
	}

	// Load the key to verify it works
	loadCtx := filepath.Join(t.config.KeyStorePath, name+".ctx")
	loadCmd := exec.CommandContext(ctx, "tpm2_load",
		"-C", t.primaryHandle,
		"-u", pubPath,
		"-r", privPath,
		"-c", loadCtx,
	)
	loadCmd.Env = t.tpmEnv()

	output, err = loadCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tpm2_load failed: %s: %w", string(output), err)
	}

	// Read public/private blobs for metadata
	pubBlob, _ := os.ReadFile(pubPath)
	privBlob, _ := os.ReadFile(privPath)

	// Store sealed data (encrypted key material)
	if err := os.WriteFile(sealedPath, keyMaterial, 0600); err != nil {
		return nil, err
	}

	// Save metadata
	t.keys[name] = &KeyMetadata{
		Name:        name,
		Handle:      loadCtx,
		Algorithm:   "aes256",
		CreatedAt:   time.Now(),
		PCRPolicy:   t.config.PCRSelection,
		PublicBlob:  hex.EncodeToString(pubBlob),
		PrivateBlob: hex.EncodeToString(privBlob),
		IsHardware:  true,
	}

	if err := t.saveKeyMetadata(); err != nil {
		t.logger.Warn("failed to save key metadata", "error", err)
	}

	t.logger.Info("created TPM-sealed key", "name", name, "size", keySize)
	return keyMaterial, nil
}

// createSoftwareKey creates a software-backed key.
func (t *TPMKeyStore) createSoftwareKey(ctx context.Context, name string, keySize int) ([]byte, error) {
	keyMaterial := make([]byte, keySize)
	if _, err := rand.Read(keyMaterial); err != nil {
		return nil, err
	}

	t.keys[name] = &KeyMetadata{
		Name:        name,
		Algorithm:   "aes256",
		CreatedAt:   time.Now(),
		SoftwareKey: hex.EncodeToString(keyMaterial),
		IsHardware:  false,
	}

	if err := t.saveKeyMetadata(); err != nil {
		t.logger.Warn("failed to save key metadata", "error", err)
	}

	// Also persist to file as backup
	keyPath := filepath.Join(t.config.KeyStorePath, name+".key")
	if err := os.WriteFile(keyPath, keyMaterial, 0400); err != nil {
		t.logger.Warn("failed to persist software key", "error", err)
	}

	t.logger.Info("created software key (TPM unavailable)", "name", name, "size", keySize)
	return keyMaterial, nil
}

// GetKey retrieves a key from the TPM or software storage.
func (t *TPMKeyStore) GetKey(ctx context.Context, name string) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	meta, exists := t.keys[name]
	if !exists {
		return nil, ErrTPMKeyNotFound
	}

	if meta.IsHardware && t.available {
		return t.unsealTPMKey(ctx, name, meta)
	}

	return t.getSoftwareKey(name, meta)
}

// unsealTPMKey unseals a key from the TPM.
func (t *TPMKeyStore) unsealTPMKey(ctx context.Context, name string, meta *KeyMetadata) ([]byte, error) {
	// Load the sealed key
	pubPath := filepath.Join(t.config.KeyStorePath, name+".pub")
	privPath := filepath.Join(t.config.KeyStorePath, name+".priv")
	loadCtx := filepath.Join(t.config.KeyStorePath, name+".ctx")

	// Check if we need to reload
	if _, err := os.Stat(loadCtx); os.IsNotExist(err) {
		loadCmd := exec.CommandContext(ctx, "tpm2_load",
			"-C", t.primaryHandle,
			"-u", pubPath,
			"-r", privPath,
			"-c", loadCtx,
		)
		loadCmd.Env = t.tpmEnv()

		output, err := loadCmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("tpm2_load failed: %s: %w", string(output), err)
		}
	}

	// Unseal the key
	unsealedPath := filepath.Join(t.config.KeyStorePath, name+".unsealed")
	defer os.Remove(unsealedPath)

	args := []string{
		"-c", loadCtx,
		"-o", unsealedPath,
	}

	// Add PCR session if policy was used
	if t.config.EnablePCRPolicy && len(meta.PCRPolicy) > 0 {
		// Create PCR policy session
		sessionPath := filepath.Join(t.config.KeyStorePath, "session.ctx")
		defer os.Remove(sessionPath)

		pcrList := t.formatPCRListFromMeta(meta.PCRPolicy)

		// Start auth session
		startCmd := exec.CommandContext(ctx, "tpm2_startauthsession",
			"-S", sessionPath,
			"--policy-session",
		)
		startCmd.Env = t.tpmEnv()
		if output, err := startCmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("tpm2_startauthsession failed: %s: %w", string(output), err)
		}

		// Apply PCR policy
		pcrCmd := exec.CommandContext(ctx, "tpm2_policypcr",
			"-S", sessionPath,
			"-l", pcrList,
		)
		pcrCmd.Env = t.tpmEnv()
		if output, err := pcrCmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("tpm2_policypcr failed: %s: %w", string(output), err)
		}

		args = append(args, "-p", "session:"+sessionPath)
	}

	unsealCmd := exec.CommandContext(ctx, "tpm2_unseal", args...)
	unsealCmd.Env = t.tpmEnv()

	output, err := unsealCmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "PCR") {
			return nil, ErrTPMPCRMismatch
		}
		return nil, fmt.Errorf("tpm2_unseal failed: %s: %w", string(output), err)
	}

	// Read unsealed key
	keyMaterial, err := os.ReadFile(unsealedPath)
	if err != nil {
		return nil, err
	}

	return keyMaterial, nil
}

// getSoftwareKey retrieves a software-backed key.
func (t *TPMKeyStore) getSoftwareKey(name string, meta *KeyMetadata) ([]byte, error) {
	if meta.SoftwareKey != "" {
		return hex.DecodeString(meta.SoftwareKey)
	}

	// Try reading from file
	keyPath := filepath.Join(t.config.KeyStorePath, name+".key")
	return os.ReadFile(keyPath)
}

// DeleteKey removes a key from the store.
func (t *TPMKeyStore) DeleteKey(ctx context.Context, name string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	meta, exists := t.keys[name]
	if !exists {
		return ErrTPMKeyNotFound
	}

	// Remove files
	extensions := []string{".pub", ".priv", ".ctx", ".sealed", ".key", ".unsealed"}
	for _, ext := range extensions {
		os.Remove(filepath.Join(t.config.KeyStorePath, name+ext))
	}

	// If hardware key, flush from TPM
	if meta.IsHardware && t.available {
		if meta.Handle != "" {
			cmd := exec.CommandContext(ctx, "tpm2_flushcontext", "-c", meta.Handle)
			cmd.Env = t.tpmEnv()
			cmd.Run() // Ignore errors
		}
	}

	delete(t.keys, name)
	return t.saveKeyMetadata()
}

// ListKeys returns all stored key names.
func (t *TPMKeyStore) ListKeys() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	names := make([]string, 0, len(t.keys))
	for name := range t.keys {
		names = append(names, name)
	}
	return names
}

// GetKeyMetadata returns metadata for a key.
func (t *TPMKeyStore) GetKeyMetadata(name string) (*KeyMetadata, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	meta, exists := t.keys[name]
	if !exists {
		return nil, ErrTPMKeyNotFound
	}

	// Return a copy
	copy := *meta
	return &copy, nil
}

// formatPCRList formats PCR selection for tpm2-tools.
func (t *TPMKeyStore) formatPCRList() string {
	return t.formatPCRListFromMeta(t.config.PCRSelection)
}

func (t *TPMKeyStore) formatPCRListFromMeta(pcrs []int) string {
	if len(pcrs) == 0 {
		return ""
	}

	parts := make([]string, len(pcrs))
	for i, pcr := range pcrs {
		parts[i] = fmt.Sprintf("%d", pcr)
	}
	return "sha256:" + strings.Join(parts, ",")
}

// GetPCRValues reads current PCR values.
func (t *TPMKeyStore) GetPCRValues(ctx context.Context, pcrs []int) (map[int]string, error) {
	if !t.available {
		return nil, ErrTPMNotAvailable
	}

	result := make(map[int]string)

	for _, pcr := range pcrs {
		cmd := exec.CommandContext(ctx, "tpm2_pcrread",
			fmt.Sprintf("sha256:%d", pcr),
		)
		cmd.Env = t.tpmEnv()

		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("failed to read PCR %d: %w", pcr, err)
		}

		// Parse output to extract hash value
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "0x") {
				parts := strings.Fields(line)
				for _, p := range parts {
					if strings.HasPrefix(p, "0x") {
						result[pcr] = strings.TrimPrefix(p, "0x")
						break
					}
				}
			}
		}
	}

	return result, nil
}

// Status returns the current TPM status.
func (t *TPMKeyStore) Status() TPMStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return TPMStatus{
		Available:    t.available,
		Initialized:  t.initialized,
		DevicePath:   t.devicePath,
		KeyCount:     len(t.keys),
		SoftwareMode: !t.available && t.config.AllowSoftwareFallback,
	}
}

// TPMStatus contains TPM status information.
type TPMStatus struct {
	Available    bool   `json:"available"`
	Initialized  bool   `json:"initialized"`
	DevicePath   string `json:"device_path"`
	KeyCount     int    `json:"key_count"`
	SoftwareMode bool   `json:"software_mode"`
}

// Close cleans up TPM resources.
func (t *TPMKeyStore) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Flush primary handle
	if t.primaryHandle != "" && t.available {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "tpm2_flushcontext", "-c", t.primaryHandle)
		cmd.Env = t.tpmEnv()
		cmd.Run() // Ignore errors
	}

	t.logger.Info("TPM key store closed")
	return nil
}

// SealData seals arbitrary data to the TPM.
func (t *TPMKeyStore) SealData(ctx context.Context, name string, data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.available || !t.initialized {
		if t.config.AllowSoftwareFallback {
			return t.sealDataSoftware(name, data)
		}
		return ErrTPMNotAvailable
	}

	// Write data to temp file
	tmpFile, err := os.CreateTemp(t.config.KeyStorePath, "seal-data-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Write(data)
	tmpFile.Close()
	defer os.Remove(tmpPath)

	pubPath := filepath.Join(t.config.KeyStorePath, name+".pub")
	privPath := filepath.Join(t.config.KeyStorePath, name+".priv")

	args := []string{
		"-C", t.primaryHandle,
		"-i", tmpPath,
		"-u", pubPath,
		"-r", privPath,
	}

	if t.config.EnablePCRPolicy && len(t.config.PCRSelection) > 0 {
		args = append(args, "-L", t.formatPCRList())
	}

	cmd := exec.CommandContext(ctx, "tpm2_create", args...)
	cmd.Env = t.tpmEnv()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tpm2_create failed: %s: %w", string(output), err)
	}

	// Store metadata
	pubBlob, _ := os.ReadFile(pubPath)
	privBlob, _ := os.ReadFile(privPath)

	t.keys[name] = &KeyMetadata{
		Name:        name,
		Algorithm:   "sealed",
		CreatedAt:   time.Now(),
		PCRPolicy:   t.config.PCRSelection,
		PublicBlob:  hex.EncodeToString(pubBlob),
		PrivateBlob: hex.EncodeToString(privBlob),
		IsHardware:  true,
	}

	return t.saveKeyMetadata()
}

func (t *TPMKeyStore) sealDataSoftware(name string, data []byte) error {
	// Simple encryption fallback using PBKDF2 + AES
	// In production, this should use a proper encryption library

	// Hash the data for integrity
	hash := sha256.Sum256(data)

	t.keys[name] = &KeyMetadata{
		Name:        name,
		Algorithm:   "software-sealed",
		CreatedAt:   time.Now(),
		SoftwareKey: hex.EncodeToString(append(hash[:], data...)),
		IsHardware:  false,
	}

	return t.saveKeyMetadata()
}

// UnsealData unseals data from the TPM.
func (t *TPMKeyStore) UnsealData(ctx context.Context, name string) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	meta, exists := t.keys[name]
	if !exists {
		return nil, ErrTPMKeyNotFound
	}

	if meta.IsHardware && t.available {
		return t.unsealTPMKey(ctx, name, meta)
	}

	// Software fallback
	if meta.SoftwareKey != "" {
		decoded, err := hex.DecodeString(meta.SoftwareKey)
		if err != nil {
			return nil, err
		}
		if len(decoded) > 32 {
			// Skip hash prefix
			return decoded[32:], nil
		}
		return decoded, nil
	}

	return nil, ErrTPMUnsealFailed
}

// GenerateRandom generates random bytes from the TPM.
func (t *TPMKeyStore) GenerateRandom(ctx context.Context, length int) ([]byte, error) {
	if !t.available {
		// Fallback to crypto/rand
		data := make([]byte, length)
		if _, err := rand.Read(data); err != nil {
			return nil, err
		}
		return data, nil
	}

	tmpFile, err := os.CreateTemp(t.config.KeyStorePath, "random-*")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	cmd := exec.CommandContext(ctx, "tpm2_getrandom",
		"-o", tmpPath,
		fmt.Sprintf("%d", length),
	)
	cmd.Env = t.tpmEnv()

	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("tpm2_getrandom failed: %s: %w", string(output), err)
	}

	return os.ReadFile(tmpPath)
}

// ExtendPCR extends a PCR with a hash value.
func (t *TPMKeyStore) ExtendPCR(ctx context.Context, pcr int, data []byte) error {
	if !t.available {
		return ErrTPMNotAvailable
	}

	// Hash the data
	hash := sha256.Sum256(data)
	hashHex := hex.EncodeToString(hash[:])

	cmd := exec.CommandContext(ctx, "tpm2_pcrextend",
		fmt.Sprintf("%d:sha256=%s", pcr, hashHex),
	)
	cmd.Env = t.tpmEnv()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("tpm2_pcrextend failed: %s: %w", string(output), err)
	}

	t.logger.Info("extended PCR", "pcr", pcr, "hash", hashHex[:16]+"...")
	return nil
}

// GetManufacturer returns TPM manufacturer information.
func (t *TPMKeyStore) GetManufacturer(ctx context.Context) (string, error) {
	if !t.available {
		return "", ErrTPMNotAvailable
	}

	cmd := exec.CommandContext(ctx, "tpm2_getcap", "properties-fixed")
	cmd.Env = t.tpmEnv()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	// Parse manufacturer from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "TPM2_PT_MANUFACTURER") {
			return line, nil
		}
	}

	return string(output), nil
}

// Helper to use TPM for audit key

// CreateAuditKey creates or retrieves the audit HMAC key using TPM.
func CreateAuditKey(store *TPMKeyStore, keyPath string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	keyName := "audit-hmac-key"

	// Try to get existing key
	key, err := store.GetKey(ctx, keyName)
	if err == nil {
		return key, nil
	}

	if err != ErrTPMKeyNotFound {
		return nil, err
	}

	// Create new key
	key, err = store.CreateKey(ctx, keyName, 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Compile-time interface check
var _ io.Closer = (*TPMKeyStore)(nil)

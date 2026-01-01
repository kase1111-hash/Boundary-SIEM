package hardware

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func hasTPM() bool {
	// Check for TPM device
	devices := []string{"/dev/tpmrm0", "/dev/tpm0"}
	for _, dev := range devices {
		if _, err := os.Stat(dev); err == nil {
			// Also check for tpm2-tools
			if _, err := exec.LookPath("tpm2_getcap"); err == nil {
				return true
			}
		}
	}
	return false
}

func testConfig(t *testing.T) *TPMConfig {
	t.Helper()
	tmpDir := filepath.Join(os.TempDir(), "tpm-test-"+t.Name())
	os.RemoveAll(tmpDir)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	return &TPMConfig{
		DevicePath:            DefaultTPMDevice,
		KeyStorePath:          tmpDir,
		PCRSelection:          []int{0, 7},
		EnablePCRPolicy:       false, // Disable for testing
		AllowSoftwareFallback: true,
	}
}

func TestDefaultTPMConfig(t *testing.T) {
	config := DefaultTPMConfig()

	if config.DevicePath == "" {
		t.Error("DevicePath should have default value")
	}
	if config.KeyStorePath == "" {
		t.Error("KeyStorePath should have default value")
	}
	if len(config.PCRSelection) == 0 {
		t.Error("PCRSelection should have default values")
	}
	if !config.AllowSoftwareFallback {
		t.Error("AllowSoftwareFallback should be true by default")
	}
}

func TestNewTPMKeyStore_SoftwareFallback(t *testing.T) {
	config := testConfig(t)
	config.AllowSoftwareFallback = true

	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	status := store.Status()
	// Either TPM is available or we're in software mode
	if !status.Available && !status.SoftwareMode {
		t.Error("Should be in software mode when TPM unavailable")
	}
}

func TestNewTPMKeyStore_NoFallback(t *testing.T) {
	if hasTPM() {
		t.Skip("TPM available, skipping no-fallback test")
	}

	config := testConfig(t)
	config.DevicePath = "/dev/nonexistent-tpm"
	config.AllowSoftwareFallback = false

	_, err := NewTPMKeyStore(config)
	if err == nil {
		t.Error("Should fail without TPM when fallback disabled")
	}
}

func TestTPMKeyStore_CreateKey_Software(t *testing.T) {
	config := testConfig(t)
	config.AllowSoftwareFallback = true
	config.DevicePath = "/dev/nonexistent" // Force software mode

	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Create a key
	key, err := store.CreateKey(ctx, "test-key", 32)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Key length = %d, want 32", len(key))
	}

	// Verify key is stored
	keys := store.ListKeys()
	if len(keys) != 1 {
		t.Errorf("ListKeys() = %d keys, want 1", len(keys))
	}
	if keys[0] != "test-key" {
		t.Errorf("Key name = %s, want test-key", keys[0])
	}
}

func TestTPMKeyStore_GetKey_Software(t *testing.T) {
	config := testConfig(t)
	config.AllowSoftwareFallback = true
	config.DevicePath = "/dev/nonexistent"

	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Create key
	originalKey, err := store.CreateKey(ctx, "retrieve-test", 32)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	// Retrieve key
	retrievedKey, err := store.GetKey(ctx, "retrieve-test")
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	// Compare
	if len(retrievedKey) != len(originalKey) {
		t.Errorf("Retrieved key length = %d, want %d", len(retrievedKey), len(originalKey))
	}

	for i := range originalKey {
		if retrievedKey[i] != originalKey[i] {
			t.Errorf("Key mismatch at byte %d", i)
			break
		}
	}
}

func TestTPMKeyStore_GetKey_NotFound(t *testing.T) {
	config := testConfig(t)
	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	_, err = store.GetKey(ctx, "nonexistent-key")
	if err != ErrTPMKeyNotFound {
		t.Errorf("GetKey() error = %v, want ErrTPMKeyNotFound", err)
	}
}

func TestTPMKeyStore_CreateKey_Duplicate(t *testing.T) {
	config := testConfig(t)
	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Create first key
	_, err = store.CreateKey(ctx, "duplicate-test", 32)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	// Try to create duplicate
	_, err = store.CreateKey(ctx, "duplicate-test", 32)
	if err != ErrKeyAlreadyExists {
		t.Errorf("CreateKey() error = %v, want ErrKeyAlreadyExists", err)
	}
}

func TestTPMKeyStore_DeleteKey(t *testing.T) {
	config := testConfig(t)
	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Create key
	_, err = store.CreateKey(ctx, "delete-test", 32)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	// Delete key
	err = store.DeleteKey(ctx, "delete-test")
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	// Verify deleted
	_, err = store.GetKey(ctx, "delete-test")
	if err != ErrTPMKeyNotFound {
		t.Errorf("Key should be deleted, got error = %v", err)
	}
}

func TestTPMKeyStore_DeleteKey_NotFound(t *testing.T) {
	config := testConfig(t)
	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	err = store.DeleteKey(ctx, "nonexistent")
	if err != ErrTPMKeyNotFound {
		t.Errorf("DeleteKey() error = %v, want ErrTPMKeyNotFound", err)
	}
}

func TestTPMKeyStore_GetKeyMetadata(t *testing.T) {
	config := testConfig(t)
	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Create key
	_, err = store.CreateKey(ctx, "metadata-test", 32)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	// Get metadata
	meta, err := store.GetKeyMetadata("metadata-test")
	if err != nil {
		t.Fatalf("GetKeyMetadata() error = %v", err)
	}

	if meta.Name != "metadata-test" {
		t.Errorf("Metadata.Name = %s, want metadata-test", meta.Name)
	}
	if meta.CreatedAt.IsZero() {
		t.Error("Metadata.CreatedAt should not be zero")
	}
}

func TestTPMKeyStore_SealUnsealData_Software(t *testing.T) {
	config := testConfig(t)
	config.DevicePath = "/dev/nonexistent"
	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Seal data
	testData := []byte("secret configuration data")
	err = store.SealData(ctx, "sealed-config", testData)
	if err != nil {
		t.Fatalf("SealData() error = %v", err)
	}

	// Unseal data
	unsealed, err := store.UnsealData(ctx, "sealed-config")
	if err != nil {
		t.Fatalf("UnsealData() error = %v", err)
	}

	if string(unsealed) != string(testData) {
		t.Errorf("Unsealed data = %q, want %q", string(unsealed), string(testData))
	}
}

func TestTPMKeyStore_GenerateRandom(t *testing.T) {
	config := testConfig(t)
	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Generate random bytes
	random1, err := store.GenerateRandom(ctx, 32)
	if err != nil {
		t.Fatalf("GenerateRandom() error = %v", err)
	}

	if len(random1) != 32 {
		t.Errorf("Random length = %d, want 32", len(random1))
	}

	// Generate again, should be different
	random2, err := store.GenerateRandom(ctx, 32)
	if err != nil {
		t.Fatalf("GenerateRandom() second call error = %v", err)
	}

	// Extremely unlikely to be equal
	equal := true
	for i := range random1 {
		if random1[i] != random2[i] {
			equal = false
			break
		}
	}
	if equal {
		t.Error("Two random generations should not be equal")
	}
}

func TestTPMKeyStore_Status(t *testing.T) {
	config := testConfig(t)
	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	status := store.Status()

	// Basic status checks
	if status.KeyCount < 0 {
		t.Error("KeyCount should not be negative")
	}

	// If not available, should be in software mode (since fallback enabled)
	if !status.Available && !status.SoftwareMode {
		t.Error("Should be in software mode when TPM unavailable")
	}
}

func TestTPMKeyStore_Persistence(t *testing.T) {
	config := testConfig(t)
	config.DevicePath = "/dev/nonexistent"

	// Create store and key
	store1, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}

	ctx := context.Background()
	originalKey, err := store1.CreateKey(ctx, "persist-test", 32)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	store1.Close()

	// Create new store instance
	store2, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() second instance error = %v", err)
	}
	defer store2.Close()

	// Key should still exist
	retrievedKey, err := store2.GetKey(ctx, "persist-test")
	if err != nil {
		t.Fatalf("GetKey() after reload error = %v", err)
	}

	for i := range originalKey {
		if retrievedKey[i] != originalKey[i] {
			t.Errorf("Key mismatch after reload at byte %d", i)
			break
		}
	}
}

func TestTPMKeyStore_MultipleKeys(t *testing.T) {
	config := testConfig(t)
	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	// Create multiple keys
	keyNames := []string{"key1", "key2", "key3"}
	for _, name := range keyNames {
		_, err := store.CreateKey(ctx, name, 32)
		if err != nil {
			t.Fatalf("CreateKey(%s) error = %v", name, err)
		}
	}

	// List keys
	keys := store.ListKeys()
	if len(keys) != len(keyNames) {
		t.Errorf("ListKeys() = %d keys, want %d", len(keys), len(keyNames))
	}

	// All keys should be retrievable
	for _, name := range keyNames {
		_, err := store.GetKey(ctx, name)
		if err != nil {
			t.Errorf("GetKey(%s) error = %v", name, err)
		}
	}
}

func TestCreateAuditKey(t *testing.T) {
	config := testConfig(t)
	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	keyPath := filepath.Join(config.KeyStorePath, "audit.key")

	// Create audit key
	key1, err := CreateAuditKey(store, keyPath)
	if err != nil {
		t.Fatalf("CreateAuditKey() error = %v", err)
	}

	if len(key1) != 32 {
		t.Errorf("Audit key length = %d, want 32", len(key1))
	}

	// Second call should return same key
	key2, err := CreateAuditKey(store, keyPath)
	if err != nil {
		t.Fatalf("CreateAuditKey() second call error = %v", err)
	}

	for i := range key1 {
		if key1[i] != key2[i] {
			t.Error("Audit key should be same on second call")
			break
		}
	}
}

// TPM Hardware Tests (only run if TPM is available)

func TestTPMKeyStore_Hardware_CreateKey(t *testing.T) {
	if !hasTPM() {
		t.Skip("TPM not available")
	}

	config := testConfig(t)
	config.AllowSoftwareFallback = false
	config.EnablePCRPolicy = false // Disable for simpler test

	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	if !store.Status().Available {
		t.Skip("TPM not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create key
	key, err := store.CreateKey(ctx, "hw-test-key", 32)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Key length = %d, want 32", len(key))
	}

	// Verify it's marked as hardware
	meta, _ := store.GetKeyMetadata("hw-test-key")
	if meta != nil && !meta.IsHardware {
		t.Error("Key should be marked as hardware")
	}
}

func TestTPMKeyStore_Hardware_GetPCRValues(t *testing.T) {
	if !hasTPM() {
		t.Skip("TPM not available")
	}

	config := testConfig(t)
	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	if !store.Status().Available {
		t.Skip("TPM not initialized")
	}

	ctx := context.Background()

	pcrs, err := store.GetPCRValues(ctx, []int{0, 7})
	if err != nil {
		t.Fatalf("GetPCRValues() error = %v", err)
	}

	if len(pcrs) == 0 {
		t.Error("Should have at least one PCR value")
	}

	for pcr, value := range pcrs {
		t.Logf("PCR[%d] = %s", pcr, value)
		if value == "" {
			t.Errorf("PCR[%d] value should not be empty", pcr)
		}
	}
}

func TestTPMKeyStore_Hardware_GetManufacturer(t *testing.T) {
	if !hasTPM() {
		t.Skip("TPM not available")
	}

	config := testConfig(t)
	store, err := NewTPMKeyStore(config)
	if err != nil {
		t.Fatalf("NewTPMKeyStore() error = %v", err)
	}
	defer store.Close()

	if !store.Status().Available {
		t.Skip("TPM not initialized")
	}

	ctx := context.Background()

	mfr, err := store.GetManufacturer(ctx)
	if err != nil {
		t.Fatalf("GetManufacturer() error = %v", err)
	}

	if mfr == "" {
		t.Error("Manufacturer info should not be empty")
	}

	t.Logf("TPM Manufacturer: %s", mfr)
}

func TestFormatPCRList(t *testing.T) {
	store := &TPMKeyStore{
		config: &TPMConfig{
			PCRSelection: []int{0, 7, 8},
		},
	}

	result := store.formatPCRList()
	expected := "sha256:0,7,8"

	if result != expected {
		t.Errorf("formatPCRList() = %q, want %q", result, expected)
	}
}

func TestFormatPCRList_Empty(t *testing.T) {
	store := &TPMKeyStore{
		config: &TPMConfig{
			PCRSelection: []int{},
		},
	}

	result := store.formatPCRList()
	if result != "" {
		t.Errorf("formatPCRList() = %q, want empty string", result)
	}
}

func TestTPMStatus_Fields(t *testing.T) {
	status := TPMStatus{
		Available:    true,
		Initialized:  true,
		DevicePath:   "/dev/tpmrm0",
		KeyCount:     5,
		SoftwareMode: false,
	}

	if !status.Available {
		t.Error("Available should be true")
	}
	if !status.Initialized {
		t.Error("Initialized should be true")
	}
	if status.DevicePath != "/dev/tpmrm0" {
		t.Errorf("DevicePath = %s, want /dev/tpmrm0", status.DevicePath)
	}
	if status.KeyCount != 5 {
		t.Errorf("KeyCount = %d, want 5", status.KeyCount)
	}
	if status.SoftwareMode {
		t.Error("SoftwareMode should be false")
	}
}

func TestKeyMetadata_Fields(t *testing.T) {
	now := time.Now()
	meta := KeyMetadata{
		Name:        "test-key",
		Handle:      "0x81000000",
		Algorithm:   "aes256",
		CreatedAt:   now,
		PCRPolicy:   []int{0, 7},
		PublicBlob:  "abc123",
		PrivateBlob: "def456",
		IsHardware:  true,
	}

	if meta.Name != "test-key" {
		t.Errorf("Name = %s, want test-key", meta.Name)
	}
	if !meta.IsHardware {
		t.Error("IsHardware should be true")
	}
	if len(meta.PCRPolicy) != 2 {
		t.Errorf("PCRPolicy length = %d, want 2", len(meta.PCRPolicy))
	}
}

func TestTPMErrors(t *testing.T) {
	errors := []error{
		ErrTPMNotAvailable,
		ErrTPMNotInitialized,
		ErrTPMKeyNotFound,
		ErrTPMSealFailed,
		ErrTPMUnsealFailed,
		ErrTPMPCRMismatch,
		ErrTPMAuthFailed,
		ErrTPMToolsNotFound,
		ErrKeyAlreadyExists,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("Error should not be nil")
		}
		if err.Error() == "" {
			t.Error("Error message should not be empty")
		}
	}
}

func TestPCRConstants(t *testing.T) {
	if PCRFirmware != 0 {
		t.Errorf("PCRFirmware = %d, want 0", PCRFirmware)
	}
	if PCRBootloader != 4 {
		t.Errorf("PCRBootloader = %d, want 4", PCRBootloader)
	}
	if PCRSecureBoot != 7 {
		t.Errorf("PCRSecureBoot = %d, want 7", PCRSecureBoot)
	}
	if PCRKernel != 8 {
		t.Errorf("PCRKernel = %d, want 8", PCRKernel)
	}
}

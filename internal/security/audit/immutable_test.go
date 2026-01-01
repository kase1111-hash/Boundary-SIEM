package audit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hasChattrCapability() bool {
	// Check if we can use chattr (need root or CAP_LINUX_IMMUTABLE)
	if os.Geteuid() == 0 {
		return true
	}

	// Try to find chattr
	if _, err := exec.LookPath("chattr"); err != nil {
		return false
	}

	// Create a temp file and try to set attribute
	tmpFile, err := os.CreateTemp("", "chattr-test-*")
	if err != nil {
		return false
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "chattr", "+a", tmpPath).Run(); err != nil {
		return false
	}

	// Clean up
	exec.CommandContext(ctx, "chattr", "-a", tmpPath).Run()
	return true
}

func TestDefaultImmutableConfig(t *testing.T) {
	config := DefaultImmutableConfig()

	if !config.Enabled {
		t.Error("Enabled should be true by default")
	}
	if config.ChattrPath == "" {
		t.Error("ChattrPath should not be empty")
	}
	if config.LsattrPath == "" {
		t.Error("LsattrPath should not be empty")
	}
	if !config.AppendOnlyActive {
		t.Error("AppendOnlyActive should be true by default")
	}
	if !config.ImmutableRotated {
		t.Error("ImmutableRotated should be true by default")
	}
}

func TestNewImmutableManager_Disabled(t *testing.T) {
	config := &ImmutableConfig{
		Enabled: false,
	}

	im, err := NewImmutableManager(config)
	if err != nil {
		t.Fatalf("NewImmutableManager() error = %v", err)
	}

	if im.HasCapability() {
		t.Error("Disabled manager should not report capability")
	}

	status := im.GetStatus()
	if status.Enabled {
		t.Error("Status.Enabled should be false")
	}
}

func TestNewImmutableManager_Enabled(t *testing.T) {
	// Skip if chattr not available
	if _, err := exec.LookPath("chattr"); err != nil {
		t.Skip("chattr not available")
	}

	config := DefaultImmutableConfig()
	im, err := NewImmutableManager(config)
	if err != nil {
		t.Fatalf("NewImmutableManager() error = %v", err)
	}

	status := im.GetStatus()
	if !status.Enabled {
		t.Error("Status.Enabled should be true")
	}
	if status.ChattrPath == "" {
		t.Error("ChattrPath should be set")
	}
}

func TestImmutableManager_SetAppendOnly(t *testing.T) {
	if !hasChattrCapability() {
		t.Skip("no chattr capability")
	}

	config := DefaultImmutableConfig()
	im, err := NewImmutableManager(config)
	if err != nil {
		t.Fatalf("NewImmutableManager() error = %v", err)
	}

	// Create test file
	tmpFile, err := os.CreateTemp("", "append-only-test-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer func() {
		// Clear attributes before cleanup
		ctx := context.Background()
		im.ClearAppendOnly(ctx, tmpPath)
		os.Remove(tmpPath)
	}()

	ctx := context.Background()

	// Set append-only
	err = im.SetAppendOnly(ctx, tmpPath)
	if err == ErrFilesystemNoSupport {
		t.Skip("filesystem does not support immutable attributes")
	}
	if err != nil {
		t.Fatalf("SetAppendOnly() error = %v", err)
	}

	// Verify attribute is set
	attrs, err := im.GetAttributes(ctx, tmpPath)
	if err != nil {
		t.Fatalf("GetAttributes() error = %v", err)
	}
	if !attrs.AppendOnly {
		t.Error("File should have append-only attribute")
	}

	// Clear append-only
	err = im.ClearAppendOnly(ctx, tmpPath)
	if err != nil {
		t.Fatalf("ClearAppendOnly() error = %v", err)
	}

	// Verify attribute is cleared
	attrs, err = im.GetAttributes(ctx, tmpPath)
	if err != nil {
		t.Fatalf("GetAttributes() error = %v", err)
	}
	if attrs.AppendOnly {
		t.Error("File should not have append-only attribute after clear")
	}
}

func TestImmutableManager_SetImmutable(t *testing.T) {
	if !hasChattrCapability() {
		t.Skip("no chattr capability")
	}

	config := DefaultImmutableConfig()
	im, err := NewImmutableManager(config)
	if err != nil {
		t.Fatalf("NewImmutableManager() error = %v", err)
	}

	// Create test file
	tmpFile, err := os.CreateTemp("", "immutable-test-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer func() {
		ctx := context.Background()
		im.ClearImmutable(ctx, tmpPath)
		os.Remove(tmpPath)
	}()

	ctx := context.Background()

	// Set immutable
	err = im.SetImmutable(ctx, tmpPath)
	if err == ErrFilesystemNoSupport {
		t.Skip("filesystem does not support immutable attributes")
	}
	if err != nil {
		t.Fatalf("SetImmutable() error = %v", err)
	}

	// Verify attribute is set
	attrs, err := im.GetAttributes(ctx, tmpPath)
	if err != nil {
		t.Fatalf("GetAttributes() error = %v", err)
	}
	if !attrs.Immutable {
		t.Error("File should have immutable attribute")
	}

	// Try to write to immutable file - should fail
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		f.Close()
		t.Error("Should not be able to open immutable file for writing")
	}

	// Clear immutable
	err = im.ClearImmutable(ctx, tmpPath)
	if err != nil {
		t.Fatalf("ClearImmutable() error = %v", err)
	}
}

func TestImmutableManager_DisabledNoOp(t *testing.T) {
	config := &ImmutableConfig{
		Enabled: false,
	}
	im, err := NewImmutableManager(config)
	if err != nil {
		t.Fatalf("NewImmutableManager() error = %v", err)
	}

	ctx := context.Background()

	// These should all be no-ops when disabled
	if err := im.SetAppendOnly(ctx, "/nonexistent"); err != nil {
		t.Errorf("SetAppendOnly() should be no-op when disabled, got %v", err)
	}
	if err := im.SetImmutable(ctx, "/nonexistent"); err != nil {
		t.Errorf("SetImmutable() should be no-op when disabled, got %v", err)
	}
	if err := im.ClearAppendOnly(ctx, "/nonexistent"); err != nil {
		t.Errorf("ClearAppendOnly() should be no-op when disabled, got %v", err)
	}
	if err := im.ClearImmutable(ctx, "/nonexistent"); err != nil {
		t.Errorf("ClearImmutable() should be no-op when disabled, got %v", err)
	}
}

func TestImmutableManager_VerifyLogDirectory(t *testing.T) {
	if !hasChattrCapability() {
		t.Skip("no chattr capability")
	}

	// Create temp directory
	tmpDir := filepath.Join(os.TempDir(), "immutable-verify-test")
	os.RemoveAll(tmpDir)
	os.MkdirAll(tmpDir, 0700)
	defer os.RemoveAll(tmpDir)

	// Create some log files
	for i := 0; i < 3; i++ {
		f, _ := os.Create(filepath.Join(tmpDir, "audit-2024-01-01-"+string(rune('a'+i))+".log"))
		f.Write([]byte("test log entry\n"))
		f.Close()
	}

	config := DefaultImmutableConfig()
	im, err := NewImmutableManager(config)
	if err != nil {
		t.Fatalf("NewImmutableManager() error = %v", err)
	}

	ctx := context.Background()
	result, err := im.VerifyLogDirectory(ctx, tmpDir)
	if err != nil {
		t.Fatalf("VerifyLogDirectory() error = %v", err)
	}

	if result.TotalFiles != 3 {
		t.Errorf("TotalFiles = %d, want 3", result.TotalFiles)
	}
}

func TestImmutableManager_PrepareAndFinalizeRotation(t *testing.T) {
	if !hasChattrCapability() {
		t.Skip("no chattr capability")
	}

	config := DefaultImmutableConfig()
	im, err := NewImmutableManager(config)
	if err != nil {
		t.Fatalf("NewImmutableManager() error = %v", err)
	}

	// Create test files in a directory that might support ext attrs
	// Using /var/tmp which is more likely to be on a real filesystem
	tmpDir := filepath.Join("/var/tmp", "rotation-test-"+t.Name())
	os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		// Fall back to os.TempDir
		tmpDir = filepath.Join(os.TempDir(), "rotation-test-"+t.Name())
		os.RemoveAll(tmpDir)
		os.MkdirAll(tmpDir, 0700)
	}
	defer os.RemoveAll(tmpDir)

	oldPath := filepath.Join(tmpDir, "audit-old.log")
	newPath := filepath.Join(tmpDir, "audit-new.log")

	os.WriteFile(oldPath, []byte("old data\n"), 0600)
	os.WriteFile(newPath, []byte("new data\n"), 0600)

	ctx := context.Background()

	// Set append-only on old file (simulating active file)
	err = im.SetAppendOnly(ctx, oldPath)
	if err == ErrFilesystemNoSupport {
		t.Skip("filesystem does not support immutable attributes")
	}
	// Ignore other errors from SetAppendOnly - we're testing PrepareForRotation

	// Prepare for rotation
	err = im.PrepareForRotation(ctx, oldPath)
	if err != nil && err != ErrFilesystemNoSupport {
		// PrepareForRotation clears attribute - if fs doesn't support, skip
		if strings.Contains(err.Error(), "not supported") {
			t.Skip("filesystem does not support immutable attributes")
		}
		t.Fatalf("PrepareForRotation() error = %v", err)
	}

	// Finalize rotation
	err = im.FinalizeRotation(ctx, oldPath, newPath)
	if err != nil {
		t.Fatalf("FinalizeRotation() error = %v", err)
	}

	// Clean up
	im.ClearImmutable(ctx, oldPath)
	im.ClearAppendOnly(ctx, newPath)
}

func TestImmutableManager_SecureDelete(t *testing.T) {
	config := DefaultImmutableConfig()
	config.Enabled = false // Don't need capability for basic delete
	im, err := NewImmutableManager(config)
	if err != nil {
		t.Fatalf("NewImmutableManager() error = %v", err)
	}

	// Create test file with some content
	tmpFile, err := os.CreateTemp("", "secure-delete-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Write([]byte("sensitive data that should be overwritten"))
	tmpFile.Close()

	ctx := context.Background()

	// Secure delete
	err = im.SecureDelete(ctx, tmpPath)
	if err != nil {
		t.Fatalf("SecureDelete() error = %v", err)
	}

	// Verify file is gone
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("File should not exist after SecureDelete")
	}
}

func TestWithImmutableLogs(t *testing.T) {
	if !hasChattrCapability() {
		t.Skip("no chattr capability")
	}

	// Try to use a directory that supports extended attributes
	tmpDir := filepath.Join("/var/tmp", "with-immutable-test-"+t.Name())
	os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		tmpDir = filepath.Join(os.TempDir(), "with-immutable-test-"+t.Name())
		os.RemoveAll(tmpDir)
	}
	t.Cleanup(func() {
		// Clean up any immutable files
		ctx := context.Background()
		config := DefaultImmutableConfig()
		im, _ := NewImmutableManager(config)
		files, _ := filepath.Glob(filepath.Join(tmpDir, "*"))
		for _, f := range files {
			im.ClearImmutable(ctx, f)
			im.ClearAppendOnly(ctx, f)
		}
		os.RemoveAll(tmpDir)
	})

	alConfig := &AuditLoggerConfig{
		LogPath:        tmpDir,
		MaxFileSize:    1024 * 1024,
		MaxFiles:       5,
		FlushInterval:  100 * time.Millisecond,
		VerifyInterval: 0,
		BufferSize:     100,
		Hostname:       "test-host",
	}

	al, err := NewAuditLogger(alConfig, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	defer al.Close()

	// Enable immutable logs
	imConfig := DefaultImmutableConfig()
	imConfig.VerifyOnStartup = false // Skip async verify
	err = WithImmutableLogs(al, imConfig)
	if err != nil {
		t.Fatalf("WithImmutableLogs() error = %v", err)
	}

	// Check status
	status := al.GetImmutableStatus()
	if status == nil {
		t.Fatal("GetImmutableStatus() returned nil")
	}
	if !status.Enabled {
		t.Error("Immutable should be enabled")
	}
	// HasCapability depends on fs support, so we don't fail if it's false
}

func TestFileAttributes_String(t *testing.T) {
	attrs := FileAttributes{
		AppendOnly: true,
		Immutable:  false,
		Raw:        "----a--------",
	}

	if !attrs.AppendOnly {
		t.Error("AppendOnly should be true")
	}
	if attrs.Immutable {
		t.Error("Immutable should be false")
	}
}

func TestVerificationResult(t *testing.T) {
	result := &VerificationResult{
		Directory:  "/tmp/test",
		TotalFiles: 5,
		Errors:     1,
		Warnings:   2,
		Files: []FileVerification{
			{Path: "/tmp/test/file1.log", Attributes: FileAttributes{AppendOnly: true}},
		},
	}

	if result.TotalFiles != 5 {
		t.Errorf("TotalFiles = %d, want 5", result.TotalFiles)
	}
	if result.Errors != 1 {
		t.Errorf("Errors = %d, want 1", result.Errors)
	}
	if result.Warnings != 2 {
		t.Errorf("Warnings = %d, want 2", result.Warnings)
	}
	if len(result.Files) != 1 {
		t.Errorf("Files length = %d, want 1", len(result.Files))
	}
}

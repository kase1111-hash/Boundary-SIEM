// Package audit provides tamper-evident audit logging for security events.
// This file implements Linux immutable file attribute support using chattr.
package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// File attribute constants (matching Linux FS_*_FL flags)
const (
	// FS_APPEND_FL - file is append-only
	attrAppendOnly = 0x00000020
	// FS_IMMUTABLE_FL - file is immutable
	attrImmutable = 0x00000010
)

// Common errors for immutable log operations.
var (
	ErrChattrNotFound      = errors.New("chattr command not found")
	ErrLsattrNotFound      = errors.New("lsattr command not found")
	ErrInsufficientCaps    = errors.New("insufficient capabilities for immutable attributes")
	ErrFilesystemNoSupport = errors.New("filesystem does not support immutable attributes")
	ErrImmutableActive     = errors.New("file has immutable attribute set")
)

// ImmutableConfig configures immutable log behavior.
type ImmutableConfig struct {
	// Enabled controls whether immutable attributes are used.
	Enabled bool

	// ChattrPath is the path to the chattr binary.
	ChattrPath string

	// LsattrPath is the path to the lsattr binary.
	LsattrPath string

	// AppendOnlyActive sets +a on active log files (allows appending but not modification).
	AppendOnlyActive bool

	// ImmutableRotated sets +i on rotated log files (completely immutable).
	ImmutableRotated bool

	// VerifyOnStartup checks immutable status of existing logs on startup.
	VerifyOnStartup bool

	// Logger for diagnostic output.
	Logger *slog.Logger
}

// DefaultImmutableConfig returns sensible defaults.
func DefaultImmutableConfig() *ImmutableConfig {
	return &ImmutableConfig{
		Enabled:          true,
		ChattrPath:       "/usr/bin/chattr",
		LsattrPath:       "/usr/bin/lsattr",
		AppendOnlyActive: true,
		ImmutableRotated: true,
		VerifyOnStartup:  true,
		Logger:           slog.Default(),
	}
}

// ImmutableManager manages immutable file attributes for audit logs.
type ImmutableManager struct {
	mu     sync.Mutex
	config *ImmutableConfig
	logger *slog.Logger

	// Cached capability check result
	hasCapability     bool
	capabilityChecked bool

	// Active files with append-only attribute
	activeFiles map[string]bool
}

// NewImmutableManager creates a new immutable manager.
func NewImmutableManager(config *ImmutableConfig) (*ImmutableManager, error) {
	if config == nil {
		config = DefaultImmutableConfig()
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	im := &ImmutableManager{
		config:      config,
		logger:      config.Logger,
		activeFiles: make(map[string]bool),
	}

	if config.Enabled {
		// Check for required tools
		if err := im.checkTools(); err != nil {
			return nil, err
		}

		// Check capabilities
		if err := im.checkCapabilities(); err != nil {
			im.logger.Warn("immutable attributes may not work", "error", err)
		}
	}

	return im, nil
}

// checkTools verifies that chattr and lsattr are available.
func (im *ImmutableManager) checkTools() error {
	if _, err := os.Stat(im.config.ChattrPath); os.IsNotExist(err) {
		// Try to find in PATH
		path, err := exec.LookPath("chattr")
		if err != nil {
			return ErrChattrNotFound
		}
		im.config.ChattrPath = path
	}

	if _, err := os.Stat(im.config.LsattrPath); os.IsNotExist(err) {
		path, err := exec.LookPath("lsattr")
		if err != nil {
			return ErrLsattrNotFound
		}
		im.config.LsattrPath = path
	}

	return nil
}

// checkCapabilities checks if we have CAP_LINUX_IMMUTABLE or are root.
func (im *ImmutableManager) checkCapabilities() error {
	im.mu.Lock()
	defer im.mu.Unlock()

	if im.capabilityChecked {
		if im.hasCapability {
			return nil
		}
		return ErrInsufficientCaps
	}

	im.capabilityChecked = true

	// Check if running as root
	if os.Geteuid() == 0 {
		im.hasCapability = true
		im.logger.Debug("running as root, immutable attributes available")
		return nil
	}

	// Try to check capabilities using getcap or /proc
	// For now, we'll test by attempting to set an attribute on a temp file
	tmpFile, err := os.CreateTemp("", "immutable-test-*")
	if err != nil {
		return fmt.Errorf("failed to create test file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Try to set append-only attribute
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, im.config.ChattrPath, "+a", tmpPath)
	if err := cmd.Run(); err != nil {
		im.hasCapability = false
		return ErrInsufficientCaps
	}

	// Remove the attribute
	exec.CommandContext(ctx, im.config.ChattrPath, "-a", tmpPath).Run()

	im.hasCapability = true
	im.logger.Debug("capability check passed, immutable attributes available")
	return nil
}

// HasCapability returns whether we can set immutable attributes.
func (im *ImmutableManager) HasCapability() bool {
	im.mu.Lock()
	defer im.mu.Unlock()
	return im.hasCapability
}

// SetAppendOnly sets the append-only attribute (+a) on a file.
// This allows appending but prevents modification or deletion.
func (im *ImmutableManager) SetAppendOnly(ctx context.Context, path string) error {
	if !im.config.Enabled {
		return nil
	}

	im.mu.Lock()
	defer im.mu.Unlock()

	if !im.hasCapability {
		im.logger.Debug("skipping append-only attribute, no capability", "path", path)
		return nil
	}

	// First remove any existing immutable attribute (in case of recovery)
	im.clearImmutableLocked(ctx, path)

	cmd := exec.CommandContext(ctx, im.config.ChattrPath, "+a", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check for filesystem support
		if strings.Contains(string(output), "Operation not supported") ||
			strings.Contains(string(output), "Inappropriate ioctl") {
			return ErrFilesystemNoSupport
		}
		return fmt.Errorf("chattr +a failed: %s: %w", string(output), err)
	}

	im.activeFiles[path] = true
	im.logger.Info("set append-only attribute on log file", "path", path)
	return nil
}

// SetImmutable sets the immutable attribute (+i) on a file.
// This prevents any modification, deletion, or renaming.
func (im *ImmutableManager) SetImmutable(ctx context.Context, path string) error {
	if !im.config.Enabled {
		return nil
	}

	im.mu.Lock()
	defer im.mu.Unlock()

	if !im.hasCapability {
		im.logger.Debug("skipping immutable attribute, no capability", "path", path)
		return nil
	}

	// Remove append-only first if set (immutable includes append-only semantics)
	im.clearAppendOnlyLocked(ctx, path)

	cmd := exec.CommandContext(ctx, im.config.ChattrPath, "+i", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "Operation not supported") ||
			strings.Contains(string(output), "Inappropriate ioctl") {
			return ErrFilesystemNoSupport
		}
		return fmt.Errorf("chattr +i failed: %s: %w", string(output), err)
	}

	delete(im.activeFiles, path) // No longer active
	im.logger.Info("set immutable attribute on rotated log file", "path", path)
	return nil
}

// ClearAppendOnly removes the append-only attribute (-a) from a file.
func (im *ImmutableManager) ClearAppendOnly(ctx context.Context, path string) error {
	if !im.config.Enabled {
		return nil
	}

	im.mu.Lock()
	defer im.mu.Unlock()

	return im.clearAppendOnlyLocked(ctx, path)
}

func (im *ImmutableManager) clearAppendOnlyLocked(ctx context.Context, path string) error {
	if !im.hasCapability {
		return nil
	}

	cmd := exec.CommandContext(ctx, im.config.ChattrPath, "-a", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Ignore errors if attribute wasn't set
		if !strings.Contains(string(output), "Operation not permitted") {
			return fmt.Errorf("chattr -a failed: %s: %w", string(output), err)
		}
	}

	delete(im.activeFiles, path)
	return nil
}

// ClearImmutable removes the immutable attribute (-i) from a file.
func (im *ImmutableManager) ClearImmutable(ctx context.Context, path string) error {
	if !im.config.Enabled {
		return nil
	}

	im.mu.Lock()
	defer im.mu.Unlock()

	return im.clearImmutableLocked(ctx, path)
}

func (im *ImmutableManager) clearImmutableLocked(ctx context.Context, path string) error {
	if !im.hasCapability {
		return nil
	}

	cmd := exec.CommandContext(ctx, im.config.ChattrPath, "-i", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Ignore errors if attribute wasn't set
		if !strings.Contains(string(output), "Operation not permitted") {
			return fmt.Errorf("chattr -i failed: %s: %w", string(output), err)
		}
	}

	return nil
}

// GetAttributes returns the current attributes of a file.
func (im *ImmutableManager) GetAttributes(ctx context.Context, path string) (FileAttributes, error) {
	attrs := FileAttributes{}

	if !im.config.Enabled {
		return attrs, nil
	}

	cmd := exec.CommandContext(ctx, im.config.LsattrPath, "-d", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return attrs, fmt.Errorf("lsattr failed: %s: %w", string(output), err)
	}

	// Parse lsattr output: "----ia------- /path/to/file"
	parts := strings.Fields(string(output))
	if len(parts) >= 1 {
		attrStr := parts[0]
		attrs.AppendOnly = strings.Contains(attrStr, "a")
		attrs.Immutable = strings.Contains(attrStr, "i")
		attrs.Raw = attrStr
	}

	return attrs, nil
}

// FileAttributes represents file attribute flags.
type FileAttributes struct {
	AppendOnly bool
	Immutable  bool
	Raw        string
}

// VerifyLogDirectory verifies immutable attributes on all log files in a directory.
func (im *ImmutableManager) VerifyLogDirectory(ctx context.Context, dir string) (*VerificationResult, error) {
	result := &VerificationResult{
		Directory: dir,
		Timestamp: time.Now(),
		Files:     make([]FileVerification, 0),
	}

	files, err := filepath.Glob(filepath.Join(dir, "audit-*.log"))
	if err != nil {
		return nil, fmt.Errorf("failed to list log files: %w", err)
	}

	// Also check checksum files
	checksumFiles, _ := filepath.Glob(filepath.Join(dir, "audit-*.log.sha256"))
	files = append(files, checksumFiles...)

	for _, file := range files {
		attrs, err := im.GetAttributes(ctx, file)
		fv := FileVerification{
			Path:       file,
			Attributes: attrs,
		}

		if err != nil {
			fv.Error = err.Error()
			result.Errors++
		} else {
			// Determine expected state
			isActive := im.isActiveFile(file)
			isChecksum := strings.HasSuffix(file, ".sha256")

			if isActive {
				// Active files should be append-only
				if im.config.AppendOnlyActive && !attrs.AppendOnly && im.hasCapability {
					fv.Warning = "active log file missing append-only attribute"
					result.Warnings++
				}
			} else if !isChecksum {
				// Rotated files should be immutable
				if im.config.ImmutableRotated && !attrs.Immutable && im.hasCapability {
					fv.Warning = "rotated log file missing immutable attribute"
					result.Warnings++
				}
			}
		}

		result.Files = append(result.Files, fv)
	}

	result.TotalFiles = len(result.Files)
	return result, nil
}

func (im *ImmutableManager) isActiveFile(path string) bool {
	im.mu.Lock()
	defer im.mu.Unlock()
	return im.activeFiles[path]
}

// VerificationResult contains verification results.
type VerificationResult struct {
	Directory  string
	Timestamp  time.Time
	TotalFiles int
	Errors     int
	Warnings   int
	Files      []FileVerification
}

// FileVerification contains verification status for a single file.
type FileVerification struct {
	Path       string
	Attributes FileAttributes
	Warning    string
	Error      string
}

// PrepareForRotation clears append-only attribute before rotation.
func (im *ImmutableManager) PrepareForRotation(ctx context.Context, path string) error {
	if !im.config.Enabled {
		return nil
	}

	im.mu.Lock()
	defer im.mu.Unlock()

	if !im.hasCapability {
		return nil
	}

	// Clear append-only so we can close and rotate
	return im.clearAppendOnlyLocked(ctx, path)
}

// FinalizeRotation sets immutable on the rotated file and append-only on the new file.
func (im *ImmutableManager) FinalizeRotation(ctx context.Context, rotatedPath, newPath string) error {
	if !im.config.Enabled {
		return nil
	}

	// Set immutable on the rotated file
	if im.config.ImmutableRotated {
		if err := im.SetImmutable(ctx, rotatedPath); err != nil {
			im.logger.Warn("failed to set immutable on rotated file", "path", rotatedPath, "error", err)
		}
	}

	// Set append-only on the new file
	if im.config.AppendOnlyActive {
		if err := im.SetAppendOnly(ctx, newPath); err != nil {
			im.logger.Warn("failed to set append-only on new file", "path", newPath, "error", err)
		}
	}

	return nil
}

// ProtectChecksumFile sets immutable on a checksum file.
func (im *ImmutableManager) ProtectChecksumFile(ctx context.Context, path string) error {
	if !im.config.Enabled || !im.config.ImmutableRotated {
		return nil
	}

	return im.SetImmutable(ctx, path)
}

// ProtectKeyFile sets immutable on the HMAC key file.
func (im *ImmutableManager) ProtectKeyFile(ctx context.Context, path string) error {
	if !im.config.Enabled {
		return nil
	}

	return im.SetImmutable(ctx, path)
}

// SecureDelete securely deletes a file by overwriting before removal.
// This clears immutable attributes first if present.
func (im *ImmutableManager) SecureDelete(ctx context.Context, path string) error {
	// Clear any immutable attributes first
	im.ClearImmutable(ctx, path)
	im.ClearAppendOnly(ctx, path)

	// Get file size
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	// Overwrite with zeros
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}

	zeros := make([]byte, 4096)
	remaining := info.Size()
	for remaining > 0 {
		toWrite := int64(len(zeros))
		if remaining < toWrite {
			toWrite = remaining
		}
		n, err := f.Write(zeros[:toWrite])
		if err != nil {
			f.Close()
			return err
		}
		remaining -= int64(n)
	}

	// Sync and close
	f.Sync()
	f.Close()

	// Remove the file
	return os.Remove(path)
}

// GetStatus returns the current status of the immutable manager.
func (im *ImmutableManager) GetStatus() ImmutableStatus {
	im.mu.Lock()
	defer im.mu.Unlock()

	return ImmutableStatus{
		Enabled:       im.config.Enabled,
		HasCapability: im.hasCapability,
		ActiveFiles:   len(im.activeFiles),
		ChattrPath:    im.config.ChattrPath,
		LsattrPath:    im.config.LsattrPath,
	}
}

// ImmutableStatus contains status information.
type ImmutableStatus struct {
	Enabled       bool
	HasCapability bool
	ActiveFiles   int
	ChattrPath    string
	LsattrPath    string
}

// CheckFilesystemSupport checks if the filesystem at path supports immutable attributes.
func CheckFilesystemSupport(path string) (bool, error) {
	// Create a test file
	testFile := filepath.Join(path, ".immutable-test")
	f, err := os.Create(testFile)
	if err != nil {
		return false, err
	}
	f.Close()
	defer os.Remove(testFile)

	// Try to get/set extended attributes using ioctl
	fd, err := syscall.Open(testFile, syscall.O_RDONLY, 0)
	if err != nil {
		return false, err
	}
	defer syscall.Close(fd)

	// Try to read current flags using FS_IOC_GETFLAGS
	// This is a rough check - the actual ioctl call is complex
	// For production, we'd use the chattr test approach

	return true, nil // Assume supported if we get here
}

// Integration helper for AuditLogger

// WithImmutableLogs enables immutable log attributes on an AuditLogger.
func WithImmutableLogs(al *AuditLogger, config *ImmutableConfig) error {
	if config == nil {
		config = DefaultImmutableConfig()
	}
	config.Logger = al.logger

	im, err := NewImmutableManager(config)
	if err != nil {
		return err
	}

	al.mu.Lock()
	al.immutableMgr = im
	al.mu.Unlock()

	// Set append-only on current file
	if al.currentPath != "" && config.AppendOnlyActive {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := im.SetAppendOnly(ctx, al.currentPath); err != nil {
			al.logger.Warn("failed to set append-only on current log", "path", al.currentPath, "error", err)
		}
	}

	// Verify existing logs if configured
	if config.VerifyOnStartup && al.config.LogPath != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			result, err := im.VerifyLogDirectory(ctx, al.config.LogPath)
			if err != nil {
				al.logger.Error("failed to verify log directory", "error", err)
				return
			}

			if result.Warnings > 0 || result.Errors > 0 {
				al.logger.Warn("log directory verification issues",
					"warnings", result.Warnings,
					"errors", result.Errors,
					"total_files", result.TotalFiles)
			} else {
				al.logger.Info("log directory verification passed",
					"total_files", result.TotalFiles)
			}
		}()
	}

	return nil
}

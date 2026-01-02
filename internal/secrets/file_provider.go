package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// FileProvider retrieves secrets from files on disk.
// This is useful for Docker secrets, Kubernetes secrets mounted as files, etc.
type FileProvider struct {
	baseDir string
	logger  *slog.Logger
}

// NewFileProvider creates a new file-based secret provider.
// Secrets are read from files in the specified directory.
// Each file should contain a single secret value.
func NewFileProvider(baseDir string, logger *slog.Logger) *FileProvider {
	if logger == nil {
		logger = slog.Default()
	}

	return &FileProvider{
		baseDir: baseDir,
		logger:  logger,
	}
}

// Name returns the provider name.
func (f *FileProvider) Name() string {
	return "file"
}

// Get retrieves a secret from a file.
// The key is converted to a filename (e.g., "database/password" -> "database_password").
func (f *FileProvider) Get(ctx context.Context, key string) (*Secret, error) {
	// Convert key to filename
	filename := f.keyToFilename(key)
	fullPath := filepath.Join(f.baseDir, filename)

	// Check if file exists
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return nil, ErrSecretNotFound
	}

	// Read file content
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret file: %w", err)
	}

	// Trim trailing newline (common in Docker/K8s secrets)
	value := strings.TrimRight(string(data), "\n\r")

	return &Secret{
		Value:    value,
		Version:  1,
		Metadata: map[string]string{"source": "file", "path": fullPath},
	}, nil
}

// Set writes a secret to a file.
func (f *FileProvider) Set(ctx context.Context, key, value string) error {
	filename := f.keyToFilename(key)
	fullPath := filepath.Join(f.baseDir, filename)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(fullPath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file with restricted permissions
	if err := os.WriteFile(fullPath, []byte(value), 0600); err != nil {
		return fmt.Errorf("failed to write secret file: %w", err)
	}

	return nil
}

// Delete removes a secret file.
func (f *FileProvider) Delete(ctx context.Context, key string) error {
	filename := f.keyToFilename(key)
	fullPath := filepath.Join(f.baseDir, filename)

	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete secret file: %w", err)
	}

	return nil
}

// Close is a no-op for file provider.
func (f *FileProvider) Close() error {
	return nil
}

// HealthCheck verifies the base directory is accessible.
func (f *FileProvider) HealthCheck(ctx context.Context) error {
	// Check if base directory exists and is readable
	info, err := os.Stat(f.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Directory doesn't exist - create it
			if err := os.MkdirAll(f.baseDir, 0700); err != nil {
				return fmt.Errorf("cannot create secrets directory: %w", err)
			}
			return nil
		}
		return fmt.Errorf("cannot access secrets directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("secrets path is not a directory: %s", f.baseDir)
	}

	return nil
}

// keyToFilename converts a secret key to a safe filename.
// Examples:
//   - "admin_password" -> "admin_password"
//   - "database/password" -> "database_password"
//   - "app.api.key" -> "app_api_key"
func (f *FileProvider) keyToFilename(key string) string {
	// Replace slashes and dots with underscores
	filename := strings.ReplaceAll(key, "/", "_")
	filename = strings.ReplaceAll(filename, ".", "_")
	filename = strings.ReplaceAll(filename, "-", "_")

	// Convert to lowercase for consistency
	filename = strings.ToLower(filename)

	return filename
}

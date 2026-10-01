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
	// Convert key to a path inside the base directory
	fullPath, err := f.secretPath(key)
	if err != nil {
		return nil, err
	}

	// Check if file exists
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return nil, ErrSecretNotFound
	}

	// Read file content
	data, err := os.ReadFile(fullPath) // #nosec G304 -- secretPath confines fullPath to a single file name directly inside baseDir
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
	fullPath, err := f.secretPath(key)
	if err != nil {
		return err
	}

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
	fullPath, err := f.secretPath(key)
	if err != nil {
		return err
	}

	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete secret file: %w", err)
	}

	return nil
}

// Close is a no-op for file provider.
func (f *FileProvider) Close() error {
	return nil
}

// HealthCheck verifies the base directory is accessible. It never modifies
// the filesystem: a missing directory is not an error, because the provider
// then simply holds no secrets (Get returns ErrSecretNotFound and Set creates
// the directory on first write).
func (f *FileProvider) HealthCheck(ctx context.Context) error {
	info, err := os.Stat(f.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			f.logger.Debug("secrets directory does not exist, file provider holds no secrets",
				"dir", f.baseDir)
			return nil
		}
		return fmt.Errorf("cannot access secrets directory: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("secrets path is not a directory: %s", f.baseDir)
	}

	return nil
}

// secretPath returns the path of the file holding key. keyToFilename rewrites
// separators and dots, so a valid key maps to exactly one path element inside
// baseDir; anything else (an empty key, or a separator keyToFilename does not
// rewrite on this platform) is rejected so a key can never address baseDir
// itself or a path outside it.
func (f *FileProvider) secretPath(key string) (string, error) {
	filename := f.keyToFilename(key)
	if filename == "" || filename != filepath.Base(filename) {
		return "", fmt.Errorf("invalid secret key %q", key)
	}
	return filepath.Join(f.baseDir, filename), nil
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

package secrets

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// EnvProvider retrieves secrets from environment variables.
// This is the simplest and most portable provider.
type EnvProvider struct {
	logger *slog.Logger
}

// NewEnvProvider creates a new environment variable provider.
func NewEnvProvider(logger *slog.Logger) *EnvProvider {
	if logger == nil {
		logger = slog.Default()
	}

	return &EnvProvider{
		logger: logger,
	}
}

// Name returns the provider name.
func (e *EnvProvider) Name() string {
	return "environment"
}

// Get retrieves a secret from environment variables.
// The key is converted to uppercase and prefixed with "BOUNDARY_" if not already prefixed.
func (e *EnvProvider) Get(ctx context.Context, key string) (*Secret, error) {
	// Normalize key: uppercase and ensure BOUNDARY_ prefix
	envKey := normalizeEnvKey(key)

	value := os.Getenv(envKey)
	if value == "" {
		// Also try without prefix for backward compatibility
		value = os.Getenv(key)
		if value == "" {
			return nil, ErrSecretNotFound
		}
	}

	return &Secret{
		Value:    value,
		Version:  1,
		Metadata: map[string]string{"source": "environment"},
	}, nil
}

// Set is not supported for environment variables.
func (e *EnvProvider) Set(ctx context.Context, key, value string) error {
	return ErrNotSupported
}

// Delete is not supported for environment variables.
func (e *EnvProvider) Delete(ctx context.Context, key string) error {
	return ErrNotSupported
}

// Close is a no-op for environment variables.
func (e *EnvProvider) Close() error {
	return nil
}

// HealthCheck always returns nil as environment variables are always available.
func (e *EnvProvider) HealthCheck(ctx context.Context) error {
	return nil
}

// normalizeEnvKey converts a key to uppercase environment variable format.
// Examples:
//   - "admin_password" -> "BOUNDARY_ADMIN_PASSWORD"
//   - "ADMIN_PASSWORD" -> "BOUNDARY_ADMIN_PASSWORD"
//   - "BOUNDARY_ADMIN_PASSWORD" -> "BOUNDARY_ADMIN_PASSWORD"
//   - "database.password" -> "BOUNDARY_DATABASE_PASSWORD"
func normalizeEnvKey(key string) string {
	// Convert to uppercase
	upper := strings.ToUpper(key)

	// Replace dots and dashes with underscores
	normalized := strings.ReplaceAll(upper, ".", "_")
	normalized = strings.ReplaceAll(normalized, "-", "_")

	// Add BOUNDARY_ prefix if not present
	if !strings.HasPrefix(normalized, "BOUNDARY_") {
		normalized = "BOUNDARY_" + normalized
	}

	return normalized
}

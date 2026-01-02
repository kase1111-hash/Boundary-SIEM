// Package secrets provides secure secret management with multiple providers.
// It supports HashiCorp Vault, environment variables, and file-based secrets
// with automatic fallback and caching.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	// ErrSecretNotFound is returned when a secret is not found in any provider.
	ErrSecretNotFound = errors.New("secret not found")

	// ErrNoProvider is returned when no secret providers are configured.
	ErrNoProvider = errors.New("no secret provider configured")
)

// Secret represents a retrieved secret with metadata.
type Secret struct {
	Value     string            // The actual secret value
	Version   int               // Secret version (if supported by provider)
	Metadata  map[string]string // Additional metadata
	ExpiresAt *time.Time        // Expiration time (if applicable)
}

// Provider is the interface that secret providers must implement.
type Provider interface {
	// Name returns the provider name for logging/debugging.
	Name() string

	// Get retrieves a secret by key.
	Get(ctx context.Context, key string) (*Secret, error)

	// Set stores a secret (if supported by the provider).
	Set(ctx context.Context, key string, value string) error

	// Delete removes a secret (if supported by the provider).
	Delete(ctx context.Context, key string) error

	// Close gracefully shuts down the provider.
	Close() error

	// HealthCheck verifies the provider is accessible.
	HealthCheck(ctx context.Context) error
}

// Manager manages multiple secret providers with fallback and caching.
type Manager struct {
	providers []Provider
	cache     map[string]*cachedSecret
	cacheMu   sync.RWMutex
	cacheTTL  time.Duration
	logger    *slog.Logger
}

// cachedSecret represents a cached secret with expiration.
type cachedSecret struct {
	secret    *Secret
	fetchedAt time.Time
}

// Config holds configuration for the secrets manager.
type Config struct {
	// Providers to use (in priority order: Vault, Env, File)
	EnableVault bool
	EnableEnv   bool
	EnableFile  bool

	// Vault configuration
	VaultAddress string
	VaultToken   string
	VaultPath    string

	// Cache configuration
	CacheTTL time.Duration

	// Logger
	Logger *slog.Logger
}

// DefaultConfig returns default secrets manager configuration.
func DefaultConfig() *Config {
	return &Config{
		EnableVault: false, // Vault disabled by default
		EnableEnv:   true,  // Env vars enabled by default
		EnableFile:  false, // File-based disabled by default
		CacheTTL:    5 * time.Minute,
		Logger:      slog.Default(),
	}
}

// NewManager creates a new secrets manager with the given configuration.
func NewManager(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	m := &Manager{
		providers: make([]Provider, 0),
		cache:     make(map[string]*cachedSecret),
		cacheTTL:  cfg.CacheTTL,
		logger:    cfg.Logger,
	}

	// Initialize providers in priority order
	if cfg.EnableVault {
		vaultProvider, err := NewVaultProvider(VaultConfig{
			Address: cfg.VaultAddress,
			Token:   cfg.VaultToken,
			Path:    cfg.VaultPath,
			Logger:  cfg.Logger,
		})
		if err != nil {
			cfg.Logger.Warn("failed to initialize Vault provider, skipping", "error", err)
		} else {
			m.providers = append(m.providers, vaultProvider)
			cfg.Logger.Info("Vault secret provider initialized")
		}
	}

	if cfg.EnableEnv {
		m.providers = append(m.providers, NewEnvProvider(cfg.Logger))
		cfg.Logger.Info("environment variable secret provider initialized")
	}

	if cfg.EnableFile {
		m.providers = append(m.providers, NewFileProvider("/etc/secrets", cfg.Logger))
		cfg.Logger.Info("file-based secret provider initialized")
	}

	if len(m.providers) == 0 {
		return nil, ErrNoProvider
	}

	return m, nil
}

// Get retrieves a secret, trying each provider in order until found.
// Results are cached for the configured TTL.
func (m *Manager) Get(ctx context.Context, key string) (string, error) {
	// Check cache first
	if cached := m.getFromCache(key); cached != nil {
		return cached.Value, nil
	}

	// Try each provider in order
	var lastErr error
	for _, provider := range m.providers {
		secret, err := provider.Get(ctx, key)
		if err == nil && secret != nil {
			// Cache the result
			m.cacheSecret(key, secret)
			m.logger.Debug("secret retrieved",
				"key", key,
				"provider", provider.Name())
			return secret.Value, nil
		}

		// If not ErrSecretNotFound, log the error
		if err != nil && !errors.Is(err, ErrSecretNotFound) {
			m.logger.Warn("provider error",
				"provider", provider.Name(),
				"key", key,
				"error", err)
		}

		lastErr = err
	}

	if lastErr == nil {
		lastErr = ErrSecretNotFound
	}

	return "", fmt.Errorf("failed to get secret %q: %w", key, lastErr)
}

// GetWithDefault retrieves a secret, returning the default value if not found.
func (m *Manager) GetWithDefault(ctx context.Context, key, defaultValue string) string {
	value, err := m.Get(ctx, key)
	if err != nil {
		return defaultValue
	}
	return value
}

// MustGet retrieves a secret, panicking if not found.
// Use only for critical secrets required at startup.
func (m *Manager) MustGet(ctx context.Context, key string) string {
	value, err := m.Get(ctx, key)
	if err != nil {
		panic(fmt.Sprintf("required secret %q not found: %v", key, err))
	}
	return value
}

// Set stores a secret in the first provider that supports writing.
func (m *Manager) Set(ctx context.Context, key, value string) error {
	for _, provider := range m.providers {
		err := provider.Set(ctx, key, value)
		if err == nil {
			// Invalidate cache
			m.cacheMu.Lock()
			delete(m.cache, key)
			m.cacheMu.Unlock()

			m.logger.Info("secret stored",
				"key", key,
				"provider", provider.Name())
			return nil
		}

		// If not supported, try next provider
		if errors.Is(err, ErrNotSupported) {
			continue
		}

		// Other errors are failures
		return fmt.Errorf("failed to set secret %q: %w", key, err)
	}

	return ErrNotSupported
}

// Delete removes a secret from all providers.
func (m *Manager) Delete(ctx context.Context, key string) error {
	// Invalidate cache
	m.cacheMu.Lock()
	delete(m.cache, key)
	m.cacheMu.Unlock()

	var errs []error
	for _, provider := range m.providers {
		err := provider.Delete(ctx, key)
		if err != nil && !errors.Is(err, ErrNotSupported) {
			errs = append(errs, fmt.Errorf("%s: %w", provider.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors deleting secret: %v", errs)
	}

	return nil
}

// Close gracefully shuts down all providers and clears the cache.
func (m *Manager) Close() error {
	// Clear cache
	m.cacheMu.Lock()
	m.cache = make(map[string]*cachedSecret)
	m.cacheMu.Unlock()

	// Close all providers
	var errs []error
	for _, provider := range m.providers {
		if err := provider.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", provider.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing providers: %v", errs)
	}

	return nil
}

// HealthCheck verifies all providers are accessible.
func (m *Manager) HealthCheck(ctx context.Context) error {
	var errs []error
	for _, provider := range m.providers {
		if err := provider.HealthCheck(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", provider.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("provider health check failed: %v", errs)
	}

	return nil
}

// getFromCache retrieves a secret from cache if valid.
func (m *Manager) getFromCache(key string) *Secret {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()

	cached, exists := m.cache[key]
	if !exists {
		return nil
	}

	// Check if cache entry has expired
	if time.Since(cached.fetchedAt) > m.cacheTTL {
		return nil
	}

	// Check if secret itself has expired
	if cached.secret.ExpiresAt != nil && time.Now().After(*cached.secret.ExpiresAt) {
		return nil
	}

	return cached.secret
}

// cacheSecret stores a secret in the cache.
func (m *Manager) cacheSecret(key string, secret *Secret) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()

	m.cache[key] = &cachedSecret{
		secret:    secret,
		fetchedAt: time.Now(),
	}
}

// ClearCache clears all cached secrets.
func (m *Manager) ClearCache() {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()

	m.cache = make(map[string]*cachedSecret)
	m.logger.Debug("secret cache cleared")
}

// Common errors
var (
	ErrNotSupported = errors.New("operation not supported by this provider")
)

// GetEnv is a helper function to get an environment variable.
// Deprecated: Use Manager.Get() instead.
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// ParseSecretRef parses a secret reference string.
// Formats supported:
//   - "value" - literal value
//   - "env:VAR_NAME" - environment variable
//   - "vault:secret/path" - Vault secret
//   - "file:/path/to/secret" - file-based secret
func ParseSecretRef(ref string) (provider, key string) {
	parts := strings.SplitN(ref, ":", 2)
	if len(parts) == 1 {
		return "literal", parts[0]
	}
	return parts[0], parts[1]
}

// ResolveSecret resolves a secret reference using the manager.
// If the reference is a literal value, it's returned as-is.
// Otherwise, it's fetched from the appropriate provider.
func (m *Manager) ResolveSecret(ctx context.Context, ref string) (string, error) {
	provider, key := ParseSecretRef(ref)

	// Literal values are returned as-is
	if provider == "literal" {
		return key, nil
	}

	// For other providers, use Get
	return m.Get(ctx, key)
}

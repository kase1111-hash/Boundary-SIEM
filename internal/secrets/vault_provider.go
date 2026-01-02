package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// VaultProvider retrieves secrets from HashiCorp Vault.
type VaultProvider struct {
	address    string
	token      string
	basePath   string
	httpClient *http.Client
	logger     *slog.Logger
}

// VaultConfig holds configuration for the Vault provider.
type VaultConfig struct {
	Address string // Vault server address (e.g., "https://vault.example.com:8200")
	Token   string // Vault authentication token
	Path    string // Base path for secrets (e.g., "secret/data/boundary-siem")
	Timeout time.Duration
	Logger  *slog.Logger
}

// NewVaultProvider creates a new Vault secret provider.
func NewVaultProvider(cfg VaultConfig) (*VaultProvider, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault address is required")
	}

	if cfg.Token == "" {
		return nil, fmt.Errorf("vault token is required")
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Ensure base path doesn't have trailing slash
	basePath := strings.TrimSuffix(cfg.Path, "/")

	vp := &VaultProvider{
		address:  strings.TrimSuffix(cfg.Address, "/"),
		token:    cfg.Token,
		basePath: basePath,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		logger: cfg.Logger,
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	if err := vp.HealthCheck(ctx); err != nil {
		return nil, fmt.Errorf("vault health check failed: %w", err)
	}

	return vp, nil
}

// Name returns the provider name.
func (v *VaultProvider) Name() string {
	return "vault"
}

// Get retrieves a secret from Vault.
func (vp *VaultProvider) Get(ctx context.Context, key string) (*Secret, error) {
	// Construct full path
	path := vp.secretPath(key)

	// Make GET request to Vault
	req, err := http.NewRequestWithContext(ctx, "GET", vp.address+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", vp.token)

	resp, err := vp.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle 404 as secret not found
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrSecretNotFound
	}

	// Check for other errors
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vault returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var vaultResp vaultReadResponse
	if err := json.NewDecoder(resp.Body).Decode(&vaultResp); err != nil {
		return nil, fmt.Errorf("failed to decode vault response: %w", err)
	}

	// Extract secret value
	if vaultResp.Data.Data == nil {
		return nil, ErrSecretNotFound
	}

	value, ok := vaultResp.Data.Data["value"].(string)
	if !ok {
		// Try to get any field that looks like a value
		for k, val := range vaultResp.Data.Data {
			if str, ok := val.(string); ok {
				value = str
				vp.logger.Debug("using field as value", "field", k, "key", key)
				break
			}
		}

		if value == "" {
			return nil, fmt.Errorf("secret %q has no value field", key)
		}
	}

	return &Secret{
		Value:    value,
		Version:  vaultResp.Data.Metadata.Version,
		Metadata: vaultResp.Data.Metadata.CustomMetadata,
	}, nil
}

// Set stores a secret in Vault.
func (v *VaultProvider) Set(ctx context.Context, key, value string) error {
	path := v.secretPath(key)

	// Prepare request body
	data := map[string]interface{}{
		"data": map[string]string{
			"value": value,
		},
	}

	bodyJSON, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make POST request to Vault
	req, err := http.NewRequestWithContext(ctx, "POST", v.address+path, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Delete removes a secret from Vault.
func (v *VaultProvider) Delete(ctx context.Context, key string) error {
	path := v.secretPath(key)

	// Make DELETE request to Vault
	req, err := http.NewRequestWithContext(ctx, "DELETE", v.address+path, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", v.token)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Close closes the HTTP client.
func (v *VaultProvider) Close() error {
	v.httpClient.CloseIdleConnections()
	return nil
}

// HealthCheck verifies the Vault connection.
func (v *VaultProvider) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", v.address+"/v1/sys/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}
	defer resp.Body.Close()

	// Vault health endpoint returns various status codes based on state
	// 200 = initialized, unsealed, and active
	// 429 = unsealed and standby
	// 472 = data recovery mode replication secondary and active
	// 473 = performance standby
	// 501 = not initialized
	// 503 = sealed
	if resp.StatusCode == 200 || resp.StatusCode == 429 || resp.StatusCode == 472 || resp.StatusCode == 473 {
		return nil
	}

	return fmt.Errorf("vault unhealthy: status %d", resp.StatusCode)
}

// secretPath constructs the full Vault API path for a secret.
func (v *VaultProvider) secretPath(key string) string {
	// Vault KV v2 uses /data/ in the path
	if v.basePath == "" {
		return fmt.Sprintf("/v1/secret/data/%s", key)
	}

	// Ensure /data/ is in the path for KV v2
	if strings.Contains(v.basePath, "/data/") {
		return fmt.Sprintf("/v1/%s/%s", v.basePath, key)
	}

	// Insert /data/ for KV v2
	parts := strings.SplitN(v.basePath, "/", 2)
	if len(parts) == 2 {
		return fmt.Sprintf("/v1/%s/data/%s/%s", parts[0], parts[1], key)
	}

	return fmt.Sprintf("/v1/%s/data/%s", v.basePath, key)
}

// vaultReadResponse represents a Vault KV v2 read response.
type vaultReadResponse struct {
	Data struct {
		Data     map[string]interface{} `json:"data"`
		Metadata struct {
			Version        int               `json:"version"`
			CreatedTime    string            `json:"created_time"`
			CustomMetadata map[string]string `json:"custom_metadata"`
		} `json:"metadata"`
	} `json:"data"`
}

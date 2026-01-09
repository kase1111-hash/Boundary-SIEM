// Package memoryvault provides integration with the Memory Vault secure storage system.
// Memory Vault is a cryptographically-enforced storage system for AI agent memory.
package memoryvault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the Memory Vault API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the Memory Vault client.
type ClientConfig struct {
	BaseURL      string        `yaml:"base_url"`
	APIKey       string        `yaml:"api_key"`
	Timeout      time.Duration `yaml:"timeout"`
	MaxRetries   int           `yaml:"max_retries"`
	RetryBackoff time.Duration `yaml:"retry_backoff"`
}

// DefaultClientConfig returns the default client configuration.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		BaseURL:      "http://localhost:8500",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new Memory Vault client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// Memory represents a stored memory.
type Memory struct {
	ID             string                 `json:"id"`
	ProfileID      string                 `json:"profile_id"`
	Classification int                    `json:"classification"` // 0-5 security level
	CreatedAt      time.Time              `json:"created_at"`
	LastAccessedAt *time.Time             `json:"last_accessed_at,omitempty"`
	ExpiresAt      *time.Time             `json:"expires_at,omitempty"`
	ContentHash    string                 `json:"content_hash"`
	EncryptionType string                 `json:"encryption_type"`
	Tags           []string               `json:"tags,omitempty"`
	ChainAnchorID  string                 `json:"chain_anchor_id,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// AccessEvent represents a memory access event.
type AccessEvent struct {
	ID             string                 `json:"id"`
	Timestamp      time.Time              `json:"timestamp"`
	MemoryID       string                 `json:"memory_id"`
	ProfileID      string                 `json:"profile_id"`
	AccessType     string                 `json:"access_type"` // store, recall, update, delete
	Classification int                    `json:"classification"`
	Authorized     bool                   `json:"authorized"`
	DenialReason   string                 `json:"denial_reason,omitempty"`
	SourceIP       string                 `json:"source_ip,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// IntegrityEvent represents a chain integrity verification event.
type IntegrityEvent struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	ProfileID    string    `json:"profile_id"`
	CheckType    string    `json:"check_type"` // merkle, chain, signature
	Passed       bool      `json:"passed"`
	FailureCount int       `json:"failure_count,omitempty"`
	Details      string    `json:"details"`
}

// LockdownEvent represents an emergency lockdown event.
type LockdownEvent struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	ProfileID   string    `json:"profile_id"`
	TriggerType string    `json:"trigger_type"` // manual, breach_detection, dead_man_switch
	Active      bool      `json:"active"`
	Reason      string    `json:"reason"`
	InitiatedBy string    `json:"initiated_by"`
}

// SuccessionEvent represents a succession/heir access event.
type SuccessionEvent struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	ProfileID  string    `json:"profile_id"`
	HeirID     string    `json:"heir_id"`
	EventType  string    `json:"event_type"` // access_granted, access_denied, key_released
	Authorized bool      `json:"authorized"`
	Reason     string    `json:"reason,omitempty"`
}

// BackupEvent represents a backup/restore event.
type BackupEvent struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	ProfileID   string    `json:"profile_id"`
	EventType   string    `json:"event_type"` // backup_created, backup_verified, restore_initiated, restore_completed
	BackupID    string    `json:"backup_id"`
	Success     bool      `json:"success"`
	MemoryCount int       `json:"memory_count"`
	SizeBytes   int64     `json:"size_bytes"`
}

// PhysicalTokenEvent represents FIDO2/hardware token events.
type PhysicalTokenEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	ProfileID string    `json:"profile_id"`
	TokenType string    `json:"token_type"` // fido2, yubikey, totp
	EventType string    `json:"event_type"` // registered, verified, failed, revoked
	TokenID   string    `json:"token_id"`
	Success   bool      `json:"success"`
}

// VaultStats represents statistics about the vault.
type VaultStats struct {
	TotalMemories     int64     `json:"total_memories"`
	TotalProfiles     int       `json:"total_profiles"`
	HighClassMemories int64     `json:"high_class_memories"` // Level 4-5
	ChainIntegrity    bool      `json:"chain_integrity"`
	LastAccessTime    time.Time `json:"last_access_time"`
	LockdownActive    bool      `json:"lockdown_active"`
}

// HealthStatus represents the health of the Memory Vault service.
type HealthStatus struct {
	Status    string    `json:"status"`
	Ready     bool      `json:"ready"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// GetHealth checks the health of the Memory Vault service.
func (c *Client) GetHealth(ctx context.Context) (*HealthStatus, error) {
	resp, err := c.doRequest(ctx, "GET", "/health", nil)
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	var health HealthStatus
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, fmt.Errorf("failed to decode health response: %w", err)
	}
	health.Timestamp = time.Now().UTC()
	return &health, nil
}

// GetStats retrieves vault statistics.
func (c *Client) GetStats(ctx context.Context) (*VaultStats, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/stats", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}
	defer resp.Body.Close()

	var stats VaultStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode stats response: %w", err)
	}
	return &stats, nil
}

// GetAccessEvents retrieves memory access events.
func (c *Client) GetAccessEvents(ctx context.Context, since time.Time, limit int) ([]AccessEvent, error) {
	path := fmt.Sprintf("/api/v1/access/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get access events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []AccessEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode access events response: %w", err)
	}
	return result.Events, nil
}

// GetIntegrityEvents retrieves integrity verification events.
func (c *Client) GetIntegrityEvents(ctx context.Context, since time.Time, limit int) ([]IntegrityEvent, error) {
	path := fmt.Sprintf("/api/v1/integrity/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get integrity events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []IntegrityEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode integrity events response: %w", err)
	}
	return result.Events, nil
}

// GetLockdownEvents retrieves lockdown events.
func (c *Client) GetLockdownEvents(ctx context.Context, since time.Time, limit int) ([]LockdownEvent, error) {
	path := fmt.Sprintf("/api/v1/lockdown/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get lockdown events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []LockdownEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode lockdown events response: %w", err)
	}
	return result.Events, nil
}

// GetSuccessionEvents retrieves succession events.
func (c *Client) GetSuccessionEvents(ctx context.Context, since time.Time, limit int) ([]SuccessionEvent, error) {
	path := fmt.Sprintf("/api/v1/succession/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get succession events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []SuccessionEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode succession events response: %w", err)
	}
	return result.Events, nil
}

// GetBackupEvents retrieves backup events.
func (c *Client) GetBackupEvents(ctx context.Context, since time.Time, limit int) ([]BackupEvent, error) {
	path := fmt.Sprintf("/api/v1/backup/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []BackupEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode backup events response: %w", err)
	}
	return result.Events, nil
}

// GetPhysicalTokenEvents retrieves physical token events.
func (c *Client) GetPhysicalTokenEvents(ctx context.Context, since time.Time, limit int) ([]PhysicalTokenEvent, error) {
	path := fmt.Sprintf("/api/v1/tokens/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get physical token events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []PhysicalTokenEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode physical token events response: %w", err)
	}
	return result.Events, nil
}

// doRequest performs an HTTP request to the Memory Vault API.
func (c *Client) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	reqURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return resp, nil
}

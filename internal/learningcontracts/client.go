// Package learningcontracts provides integration with the Learning Contracts module.
// Learning Contracts define explicit consent frameworks for AI agent learning operations.
package learningcontracts

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the Learning Contracts API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the Learning Contracts client.
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
		BaseURL:      "http://localhost:8300",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new Learning Contracts client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// Contract represents a learning contract.
type Contract struct {
	ID              string                 `json:"id"`
	AgentID         string                 `json:"agent_id"`
	UserID          string                 `json:"user_id"`
	ContractType    string                 `json:"contract_type"` // observation, episodic, procedural, strategic, prohibited
	Status          string                 `json:"status"`        // draft, pending_review, active, revoked, expired
	CreatedAt       time.Time              `json:"created_at"`
	ActivatedAt     *time.Time             `json:"activated_at,omitempty"`
	ExpiresAt       *time.Time             `json:"expires_at,omitempty"`
	RevokedAt       *time.Time             `json:"revoked_at,omitempty"`
	RevokedBy       string                 `json:"revoked_by,omitempty"`
	RevokeReason    string                 `json:"revoke_reason,omitempty"`
	Scope           ContractScope          `json:"scope"`
	RetentionPolicy RetentionPolicy        `json:"retention_policy"`
	Signature       string                 `json:"signature"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ContractScope defines what the contract allows.
type ContractScope struct {
	Domains           []string `json:"domains"`
	AllowedOperations []string `json:"allowed_operations"`
	Restrictions      []string `json:"restrictions"`
	MaxRetention      string   `json:"max_retention"`
}

// RetentionPolicy defines data retention rules.
type RetentionPolicy struct {
	Duration       string `json:"duration"`
	AutoDelete     bool   `json:"auto_delete"`
	RequireConsent bool   `json:"require_consent"`
}

// EnforcementEvent represents an enforcement gate check.
type EnforcementEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	ContractID   string                 `json:"contract_id"`
	AgentID      string                 `json:"agent_id"`
	GateType     string                 `json:"gate_type"` // memory_creation, abstraction, recall, export
	Operation    string                 `json:"operation"`
	Allowed      bool                   `json:"allowed"`
	Reason       string                 `json:"reason"`
	DataHash     string                 `json:"data_hash,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ContractStateChange represents a contract state transition.
type ContractStateChange struct {
	ID           string    `json:"id"`
	ContractID   string    `json:"contract_id"`
	Timestamp    time.Time `json:"timestamp"`
	FromState    string    `json:"from_state"`
	ToState      string    `json:"to_state"`
	ChangedBy    string    `json:"changed_by"`
	Reason       string    `json:"reason"`
	AuditHash    string    `json:"audit_hash"`
}

// ViolationEvent represents a contract violation.
type ViolationEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	ContractID   string                 `json:"contract_id"`
	AgentID      string                 `json:"agent_id"`
	ViolationType string                `json:"violation_type"`
	Description  string                 `json:"description"`
	Severity     string                 `json:"severity"`
	Remediation  string                 `json:"remediation,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ModuleStats represents statistics about the Learning Contracts module.
type ModuleStats struct {
	TotalContracts   int64     `json:"total_contracts"`
	ActiveContracts  int64     `json:"active_contracts"`
	RevokedContracts int64     `json:"revoked_contracts"`
	EnforcementRate  float64   `json:"enforcement_rate"`
	ViolationCount   int64     `json:"violation_count"`
	LastActivityTime time.Time `json:"last_activity_time"`
}

// HealthStatus represents the health of the Learning Contracts service.
type HealthStatus struct {
	Status    string    `json:"status"`
	Ready     bool      `json:"ready"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// GetHealth checks the health of the Learning Contracts service.
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

// GetStats retrieves module statistics.
func (c *Client) GetStats(ctx context.Context) (*ModuleStats, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/stats", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}
	defer resp.Body.Close()

	var stats ModuleStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode stats response: %w", err)
	}
	return &stats, nil
}

// GetContracts retrieves contracts with optional filters.
func (c *Client) GetContracts(ctx context.Context, status string, since time.Time, limit int) ([]Contract, error) {
	path := fmt.Sprintf("/api/v1/contracts?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	if status != "" {
		path += "&status=" + url.QueryEscape(status)
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get contracts: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Contracts []Contract `json:"contracts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode contracts response: %w", err)
	}
	return result.Contracts, nil
}

// GetEnforcementEvents retrieves enforcement gate events.
func (c *Client) GetEnforcementEvents(ctx context.Context, since time.Time, limit int) ([]EnforcementEvent, error) {
	path := fmt.Sprintf("/api/v1/enforcement/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get enforcement events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []EnforcementEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode enforcement events response: %w", err)
	}
	return result.Events, nil
}

// GetStateChanges retrieves contract state changes.
func (c *Client) GetStateChanges(ctx context.Context, since time.Time, limit int) ([]ContractStateChange, error) {
	path := fmt.Sprintf("/api/v1/contracts/changes?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get state changes: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Changes []ContractStateChange `json:"changes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode state changes response: %w", err)
	}
	return result.Changes, nil
}

// GetViolations retrieves contract violations.
func (c *Client) GetViolations(ctx context.Context, since time.Time, limit int) ([]ViolationEvent, error) {
	path := fmt.Sprintf("/api/v1/violations?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get violations: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Violations []ViolationEvent `json:"violations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode violations response: %w", err)
	}
	return result.Violations, nil
}

// doRequest performs an HTTP request to the Learning Contracts API.
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

// Package valueledger provides integration with the Value Ledger economic accounting system.
// Value Ledger tracks cognitive work value (ideas, effort, time, novelty) through an immutable ledger.
package valueledger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the Value Ledger API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the Value Ledger client.
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
		BaseURL:      "http://localhost:8100",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new Value Ledger client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// ValueVector represents the 7-dimensional value scoring.
type ValueVector struct {
	Time      float64 `json:"t"` // Time invested
	Effort    float64 `json:"e"` // Cognitive effort
	Novelty   float64 `json:"n"` // Originality score
	Failure   float64 `json:"f"` // Learning from failure
	Reuse     float64 `json:"r"` // Reusability potential
	Synthesis float64 `json:"s"` // Cross-domain synthesis
	Utility   float64 `json:"u"` // Practical utility
}

// LedgerEntry represents an entry in the value ledger.
type LedgerEntry struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	AgentID       string                 `json:"agent_id"`
	SessionID     string                 `json:"session_id"`
	EntryType     string                 `json:"entry_type"` // work, idea, synthesis, failure, export
	Description   string                 `json:"description"`
	Value         ValueVector            `json:"value"`
	TotalValue    float64                `json:"total_value"`
	ContentHash   string                 `json:"content_hash"`
	PreviousHash  string                 `json:"previous_hash"`
	Signature     string                 `json:"signature"`
	Revoked       bool                   `json:"revoked"`
	RevokedAt     *time.Time             `json:"revoked_at,omitempty"`
	RevokedReason string                 `json:"revoked_reason,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// MerkleProof represents a proof of entry inclusion.
type MerkleProof struct {
	EntryID   string   `json:"entry_id"`
	Root      string   `json:"root"`
	Path      []string `json:"path"`
	Indices   []int    `json:"indices"`
	Verified  bool     `json:"verified"`
	Timestamp time.Time `json:"timestamp"`
}

// SecurityEvent represents a security event from Value Ledger.
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Severity    string                 `json:"severity"`
	AgentID     string                 `json:"agent_id"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// LedgerStats represents statistics about the ledger.
type LedgerStats struct {
	TotalEntries    int64     `json:"total_entries"`
	TotalValue      float64   `json:"total_value"`
	ActiveAgents    int       `json:"active_agents"`
	RevokedEntries  int64     `json:"revoked_entries"`
	LastEntryTime   time.Time `json:"last_entry_time"`
	ChainIntegrity  bool      `json:"chain_integrity"`
}

// HealthStatus represents the health of the Value Ledger service.
type HealthStatus struct {
	Status    string    `json:"status"`
	Ready     bool      `json:"ready"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// GetHealth checks the health of the Value Ledger service.
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

// GetStats retrieves ledger statistics.
func (c *Client) GetStats(ctx context.Context) (*LedgerStats, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/stats", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}
	defer resp.Body.Close()

	var stats LedgerStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode stats response: %w", err)
	}
	return &stats, nil
}

// GetRecentEntries retrieves recent ledger entries.
func (c *Client) GetRecentEntries(ctx context.Context, since time.Time, limit int) ([]LedgerEntry, error) {
	path := fmt.Sprintf("/api/v1/entries?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Entries []LedgerEntry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode entries response: %w", err)
	}
	return result.Entries, nil
}

// GetSecurityEvents retrieves security events from the ledger.
func (c *Client) GetSecurityEvents(ctx context.Context, since time.Time, limit int) ([]SecurityEvent, error) {
	path := fmt.Sprintf("/api/v1/security/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get security events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []SecurityEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode security events response: %w", err)
	}
	return result.Events, nil
}

// GetRevokedEntries retrieves revoked entries.
func (c *Client) GetRevokedEntries(ctx context.Context, since time.Time, limit int) ([]LedgerEntry, error) {
	path := fmt.Sprintf("/api/v1/entries/revoked?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get revoked entries: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Entries []LedgerEntry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode revoked entries response: %w", err)
	}
	return result.Entries, nil
}

// VerifyProof verifies a Merkle proof for an entry.
func (c *Client) VerifyProof(ctx context.Context, entryID string) (*MerkleProof, error) {
	path := fmt.Sprintf("/api/v1/proof/%s", url.PathEscape(entryID))
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to verify proof: %w", err)
	}
	defer resp.Body.Close()

	var proof MerkleProof
	if err := json.NewDecoder(resp.Body).Decode(&proof); err != nil {
		return nil, fmt.Errorf("failed to decode proof response: %w", err)
	}
	return &proof, nil
}

// doRequest performs an HTTP request to the Value Ledger API.
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

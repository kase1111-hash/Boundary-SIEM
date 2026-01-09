// Package ilrmodule provides integration with the ILR-Module (Intellectual Property Dispute Resolution).
// ILR-Module is a NatLangChain-based protocol for resolving IP and licensing disputes.
package ilrmodule

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the ILR-Module API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the ILR-Module client.
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
		BaseURL:      "http://localhost:8200",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new ILR-Module client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// Dispute represents an IP dispute in the ILR-Module.
type Dispute struct {
	ID             string                 `json:"id"`
	ChainID        string                 `json:"chain_id"`
	FiledAt        time.Time              `json:"filed_at"`
	Claimant       string                 `json:"claimant"`
	Respondent     string                 `json:"respondent"`
	Subject        string                 `json:"subject"`
	DisputeType    string                 `json:"dispute_type"` // licensing, infringement, attribution, royalty
	Status         string                 `json:"status"`       // open, mediation, arbitration, resolved, dismissed
	Severity       string                 `json:"severity"`     // low, medium, high, critical
	StakeAmount    float64                `json:"stake_amount"`
	EvidenceHashes []string               `json:"evidence_hashes"`
	Resolution     *Resolution            `json:"resolution,omitempty"`
	L3BatchID      string                 `json:"l3_batch_id,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// Resolution represents a dispute resolution.
type Resolution struct {
	ResolvedAt      time.Time `json:"resolved_at"`
	ResolvedBy      string    `json:"resolved_by"`
	Outcome         string    `json:"outcome"` // claimant_wins, respondent_wins, settled, dismissed
	Award           float64   `json:"award"`
	Rationale       string    `json:"rationale"`
	EnforcementHash string    `json:"enforcement_hash"`
}

// Proposal represents an LLM-generated settlement proposal.
type Proposal struct {
	ID            string                 `json:"id"`
	DisputeID     string                 `json:"dispute_id"`
	ProposedAt    time.Time              `json:"proposed_at"`
	ProposerModel string                 `json:"proposer_model"`
	Content       string                 `json:"content"`
	Confidence    float64                `json:"confidence"`
	Status        string                 `json:"status"` // pending, accepted, rejected, countered
	Signature     string                 `json:"signature"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ComplianceEvent represents a compliance check event.
type ComplianceEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"`
	DisputeID string                 `json:"dispute_id,omitempty"`
	Actor     string                 `json:"actor"`
	Passed    bool                   `json:"passed"`
	Details   string                 `json:"details"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// L3BatchEvent represents a Layer 3 batch processing event.
type L3BatchEvent struct {
	ID            string    `json:"id"`
	BatchID       string    `json:"batch_id"`
	Timestamp     time.Time `json:"timestamp"`
	DisputeCount  int       `json:"dispute_count"`
	Status        string    `json:"status"` // pending, processing, finalized, challenged
	FraudProofEnd time.Time `json:"fraud_proof_end"`
	StateRoot     string    `json:"state_root"`
}

// OracleEvent represents an oracle interaction event.
type OracleEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	OracleType  string                 `json:"oracle_type"` // chainlink, uma
	DisputeID   string                 `json:"dispute_id"`
	RequestType string                 `json:"request_type"`
	Response    string                 `json:"response,omitempty"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ModuleStats represents statistics about the ILR-Module.
type ModuleStats struct {
	TotalDisputes    int64     `json:"total_disputes"`
	OpenDisputes     int64     `json:"open_disputes"`
	ResolvedDisputes int64     `json:"resolved_disputes"`
	TotalStaked      float64   `json:"total_staked"`
	AverageResTime   float64   `json:"average_resolution_time_hours"`
	LastDisputeTime  time.Time `json:"last_dispute_time"`
}

// HealthStatus represents the health of the ILR-Module service.
type HealthStatus struct {
	Status    string    `json:"status"`
	Ready     bool      `json:"ready"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// GetHealth checks the health of the ILR-Module service.
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

// GetDisputes retrieves disputes with optional status filter.
func (c *Client) GetDisputes(ctx context.Context, status string, since time.Time, limit int) ([]Dispute, error) {
	path := fmt.Sprintf("/api/v1/disputes?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	if status != "" {
		path += "&status=" + url.QueryEscape(status)
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get disputes: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Disputes []Dispute `json:"disputes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode disputes response: %w", err)
	}
	return result.Disputes, nil
}

// GetProposals retrieves settlement proposals.
func (c *Client) GetProposals(ctx context.Context, since time.Time, limit int) ([]Proposal, error) {
	path := fmt.Sprintf("/api/v1/proposals?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get proposals: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Proposals []Proposal `json:"proposals"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode proposals response: %w", err)
	}
	return result.Proposals, nil
}

// GetComplianceEvents retrieves compliance events.
func (c *Client) GetComplianceEvents(ctx context.Context, since time.Time, limit int) ([]ComplianceEvent, error) {
	path := fmt.Sprintf("/api/v1/compliance/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []ComplianceEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode compliance events response: %w", err)
	}
	return result.Events, nil
}

// GetL3BatchEvents retrieves L3 batch processing events.
func (c *Client) GetL3BatchEvents(ctx context.Context, since time.Time, limit int) ([]L3BatchEvent, error) {
	path := fmt.Sprintf("/api/v1/l3/batches?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get L3 batch events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Batches []L3BatchEvent `json:"batches"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode L3 batch events response: %w", err)
	}
	return result.Batches, nil
}

// GetOracleEvents retrieves oracle interaction events.
func (c *Client) GetOracleEvents(ctx context.Context, since time.Time, limit int) ([]OracleEvent, error) {
	path := fmt.Sprintf("/api/v1/oracle/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get oracle events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []OracleEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode oracle events response: %w", err)
	}
	return result.Events, nil
}

// doRequest performs an HTTP request to the ILR-Module API.
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

// Package rramodule provides integration with the RRA-Module (Revenant Repo Agent).
// RRA converts dormant repositories into autonomous, revenue-generating agents.
package rramodule

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the RRA-Module API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the RRA-Module client.
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
		BaseURL:      "http://localhost:8800",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new RRA-Module client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// RepoAgent represents an activated repository agent.
type RepoAgent struct {
	ID              string                 `json:"id"`
	RepoURL         string                 `json:"repo_url"`
	Status          string                 `json:"status"` // pending, active, suspended, terminated
	CreatedAt       time.Time              `json:"created_at"`
	ActivatedAt     *time.Time             `json:"activated_at,omitempty"`
	KnowledgeHash   string                 `json:"knowledge_hash"`
	TotalRevenue    float64                `json:"total_revenue"`
	LicenseType     string                 `json:"license_type"`
	ChainID         string                 `json:"chain_id"`
	ContractAddress string                 `json:"contract_address,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// IngestionEvent represents a repository ingestion event.
type IngestionEvent struct {
	ID           string    `json:"id"`
	AgentID      string    `json:"agent_id"`
	Timestamp    time.Time `json:"timestamp"`
	EventType    string    `json:"event_type"` // started, completed, failed, updated
	FilesScanned int       `json:"files_scanned"`
	TokensUsed   int64     `json:"tokens_used"`
	Success      bool      `json:"success"`
	ErrorMessage string    `json:"error_message,omitempty"`
}

// NegotiationEvent represents a licensing negotiation event.
type NegotiationEvent struct {
	ID            string                 `json:"id"`
	AgentID       string                 `json:"agent_id"`
	Timestamp     time.Time              `json:"timestamp"`
	CounterpartyID string                `json:"counterparty_id"`
	EventType     string                 `json:"event_type"` // initiated, offer_made, counter_offer, accepted, rejected, expired
	OfferAmount   float64                `json:"offer_amount,omitempty"`
	LicenseTerms  string                 `json:"license_terms,omitempty"`
	LLMModel      string                 `json:"llm_model"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ContractEvent represents a smart contract deployment/interaction event.
type ContractEvent struct {
	ID              string    `json:"id"`
	AgentID         string    `json:"agent_id"`
	Timestamp       time.Time `json:"timestamp"`
	ChainID         string    `json:"chain_id"`
	ContractAddress string    `json:"contract_address"`
	EventType       string    `json:"event_type"` // deployed, upgraded, called, revenue_received
	TxHash          string    `json:"tx_hash"`
	GasUsed         int64     `json:"gas_used"`
	Value           float64   `json:"value,omitempty"`
	Success         bool      `json:"success"`
}

// RevenueEvent represents a revenue distribution event.
type RevenueEvent struct {
	ID           string    `json:"id"`
	AgentID      string    `json:"agent_id"`
	Timestamp    time.Time `json:"timestamp"`
	EventType    string    `json:"event_type"` // license_fee, royalty, yield
	Amount       float64   `json:"amount"`
	Currency     string    `json:"currency"`
	Source       string    `json:"source"`
	Recipient    string    `json:"recipient"`
	TxHash       string    `json:"tx_hash,omitempty"`
}

// SecurityEvent represents a security-related event.
type SecurityEvent struct {
	ID          string                 `json:"id"`
	AgentID     string                 `json:"agent_id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"` // auth_attempt, rate_limit, suspicious_query, fido2_challenge
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	SourceIP    string                 `json:"source_ip,omitempty"`
	Blocked     bool                   `json:"blocked"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// GovernanceEvent represents a DAO governance event.
type GovernanceEvent struct {
	ID          string    `json:"id"`
	AgentID     string    `json:"agent_id"`
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"` // proposal_created, vote_cast, proposal_executed, quorum_reached
	ProposalID  string    `json:"proposal_id"`
	VoterID     string    `json:"voter_id,omitempty"`
	VoteWeight  float64   `json:"vote_weight,omitempty"`
	Outcome     string    `json:"outcome,omitempty"`
}

// ModuleStats represents statistics about the RRA module.
type ModuleStats struct {
	TotalAgents      int64     `json:"total_agents"`
	ActiveAgents     int64     `json:"active_agents"`
	TotalRevenue     float64   `json:"total_revenue"`
	TotalNegotiations int64    `json:"total_negotiations"`
	LastActivityTime time.Time `json:"last_activity_time"`
}

// HealthStatus represents the health of the RRA-Module service.
type HealthStatus struct {
	Status    string    `json:"status"`
	Ready     bool      `json:"ready"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// GetHealth checks the health of the RRA-Module service.
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

// GetIngestionEvents retrieves ingestion events.
func (c *Client) GetIngestionEvents(ctx context.Context, since time.Time, limit int) ([]IngestionEvent, error) {
	path := fmt.Sprintf("/api/v1/ingestion/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get ingestion events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []IngestionEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode ingestion events response: %w", err)
	}
	return result.Events, nil
}

// GetNegotiationEvents retrieves negotiation events.
func (c *Client) GetNegotiationEvents(ctx context.Context, since time.Time, limit int) ([]NegotiationEvent, error) {
	path := fmt.Sprintf("/api/v1/negotiations/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get negotiation events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []NegotiationEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode negotiation events response: %w", err)
	}
	return result.Events, nil
}

// GetContractEvents retrieves smart contract events.
func (c *Client) GetContractEvents(ctx context.Context, since time.Time, limit int) ([]ContractEvent, error) {
	path := fmt.Sprintf("/api/v1/contracts/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get contract events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []ContractEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode contract events response: %w", err)
	}
	return result.Events, nil
}

// GetRevenueEvents retrieves revenue events.
func (c *Client) GetRevenueEvents(ctx context.Context, since time.Time, limit int) ([]RevenueEvent, error) {
	path := fmt.Sprintf("/api/v1/revenue/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get revenue events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []RevenueEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode revenue events response: %w", err)
	}
	return result.Events, nil
}

// GetSecurityEvents retrieves security events.
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

// GetGovernanceEvents retrieves governance events.
func (c *Client) GetGovernanceEvents(ctx context.Context, since time.Time, limit int) ([]GovernanceEvent, error) {
	path := fmt.Sprintf("/api/v1/governance/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get governance events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []GovernanceEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode governance events response: %w", err)
	}
	return result.Events, nil
}

// doRequest performs an HTTP request to the RRA-Module API.
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

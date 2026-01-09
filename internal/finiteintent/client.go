// Package finiteintent provides integration with the Finite Intent Executor (FIE) blockchain system.
// FIE enables bounded, posthumous execution of predefined intents with automatic 20-year sunset.
package finiteintent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the Finite Intent Executor API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the FIE client.
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
		BaseURL:      "http://localhost:8900",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new Finite Intent Executor client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// Intent represents a captured posthumous intent in FIE.
type Intent struct {
	ID             string                 `json:"id"`
	CreatorID      string                 `json:"creator_id"`
	CreatorAddress string                 `json:"creator_address"`
	ContentHash    string                 `json:"content_hash"`
	Goals          []string               `json:"goals"`
	Assets         []Asset                `json:"assets,omitempty"`
	TriggerType    string                 `json:"trigger_type"` // deadman, quorum, oracle
	TriggerConfig  map[string]any         `json:"trigger_config,omitempty"`
	Status         string                 `json:"status"` // captured, active, executing, sunset, archived
	CreatedAt      time.Time              `json:"created_at"`
	ModifiedAt     *time.Time             `json:"modified_at,omitempty"`
	ActivatedAt    *time.Time             `json:"activated_at,omitempty"`
	SunsetAt       *time.Time             `json:"sunset_at,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// Asset represents an asset bound to an intent.
type Asset struct {
	ID           string `json:"id"`
	Type         string `json:"type"` // ip_token, crypto, document, credential
	TokenID      string `json:"token_id,omitempty"`
	ContractAddr string `json:"contract_address,omitempty"`
	Value        string `json:"value,omitempty"`
}

// TriggerEvent represents a trigger activation event.
type TriggerEvent struct {
	ID          string                 `json:"id"`
	IntentID    string                 `json:"intent_id"`
	TriggerType string                 `json:"trigger_type"` // deadman_switch, quorum_vote, oracle_verify
	Timestamp   time.Time              `json:"timestamp"`
	Status      string                 `json:"status"` // pending, validated, rejected, expired
	ValidatorID string                 `json:"validator_id,omitempty"`
	Confidence  float64                `json:"confidence,omitempty"`
	Evidence    []string               `json:"evidence,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ExecutionEvent represents an execution agent action.
type ExecutionEvent struct {
	ID              string                 `json:"id"`
	IntentID        string                 `json:"intent_id"`
	ActionType      string                 `json:"action_type"` // decision, ip_transfer, asset_distribute, goal_execute
	Timestamp       time.Time              `json:"timestamp"`
	Outcome         string                 `json:"outcome"` // success, failure, blocked, deferred
	ConfidenceScore float64                `json:"confidence_score"`
	CorpusCitation  string                 `json:"corpus_citation,omitempty"`
	BlockedReason   string                 `json:"blocked_reason,omitempty"` // political_content, low_confidence, constraint_violation
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// IPToken represents an intellectual property token.
type IPToken struct {
	ID            string                 `json:"id"`
	TokenID       string                 `json:"token_id"`
	IntentID      string                 `json:"intent_id"`
	ContractAddr  string                 `json:"contract_address"`
	Owner         string                 `json:"owner"`
	IPType        string                 `json:"ip_type"` // patent, copyright, trademark, trade_secret
	LicenseType   string                 `json:"license_type,omitempty"`
	RoyaltyRate   float64                `json:"royalty_rate,omitempty"`
	Status        string                 `json:"status"` // active, transferred, public_domain, revoked
	CreatedAt     time.Time              `json:"created_at"`
	TransferredAt *time.Time             `json:"transferred_at,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// SunsetEvent represents a 20-year sunset transition.
type SunsetEvent struct {
	ID             string                 `json:"id"`
	IntentID       string                 `json:"intent_id"`
	Phase          string                 `json:"phase"` // initiated, ip_transition, asset_release, complete
	Timestamp      time.Time              `json:"timestamp"`
	AssetsReleased int                    `json:"assets_released"`
	IPTransitioned int                    `json:"ip_transitioned"`
	PublicDomainTx string                 `json:"public_domain_tx,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// OracleEvent represents an oracle verification event.
type OracleEvent struct {
	ID         string                 `json:"id"`
	IntentID   string                 `json:"intent_id"`
	OracleType string                 `json:"oracle_type"` // chainlink, uma, zk_proof
	RequestID  string                 `json:"request_id"`
	Query      string                 `json:"query"`
	Response   string                 `json:"response,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
	Status     string                 `json:"status"` // requested, fulfilled, disputed, timeout
	DisputeID  string                 `json:"dispute_id,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// SecurityEvent represents a security-related event.
type SecurityEvent struct {
	ID          string                 `json:"id"`
	IntentID    string                 `json:"intent_id,omitempty"`
	EventType   string                 `json:"event_type"` // access_change, role_assignment, constraint_violation, anomaly
	Severity    string                 `json:"severity"`   // low, medium, high, critical
	Description string                 `json:"description"`
	ActorID     string                 `json:"actor_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// HealthStatus represents the health of the FIE node.
type HealthStatus struct {
	Status        string    `json:"status"`
	Ready         bool      `json:"ready"`
	Live          bool      `json:"live"`
	Version       string    `json:"version"`
	ActiveIntents int       `json:"active_intents"`
	Timestamp     time.Time `json:"timestamp"`
}

// GetHealth checks the health of the FIE node.
func (c *Client) GetHealth(ctx context.Context) (*HealthStatus, error) {
	resp, err := c.doRequest(ctx, "GET", "/health/ready", nil)
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

// GetIntents retrieves intents, optionally filtered by status.
func (c *Client) GetIntents(ctx context.Context, status string, limit int) ([]Intent, error) {
	path := fmt.Sprintf("/api/v1/intents?limit=%d", limit)
	if status != "" {
		path += "&status=" + url.QueryEscape(status)
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get intents: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Intents []Intent `json:"intents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode intents response: %w", err)
	}
	return result.Intents, nil
}

// GetTriggerEvents retrieves trigger activation events.
func (c *Client) GetTriggerEvents(ctx context.Context, since time.Time, limit int) ([]TriggerEvent, error) {
	path := fmt.Sprintf("/api/v1/triggers?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get trigger events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Triggers []TriggerEvent `json:"triggers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode triggers response: %w", err)
	}
	return result.Triggers, nil
}

// GetExecutionEvents retrieves execution agent events.
func (c *Client) GetExecutionEvents(ctx context.Context, since time.Time, limit int) ([]ExecutionEvent, error) {
	path := fmt.Sprintf("/api/v1/executions?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get execution events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Executions []ExecutionEvent `json:"executions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode executions response: %w", err)
	}
	return result.Executions, nil
}

// GetIPTokens retrieves IP token events.
func (c *Client) GetIPTokens(ctx context.Context, status string, limit int) ([]IPToken, error) {
	path := fmt.Sprintf("/api/v1/ip-tokens?limit=%d", limit)
	if status != "" {
		path += "&status=" + url.QueryEscape(status)
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP tokens: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Tokens []IPToken `json:"tokens"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode tokens response: %w", err)
	}
	return result.Tokens, nil
}

// GetSunsetEvents retrieves sunset/public domain transition events.
func (c *Client) GetSunsetEvents(ctx context.Context, since time.Time, limit int) ([]SunsetEvent, error) {
	path := fmt.Sprintf("/api/v1/sunset?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get sunset events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []SunsetEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode sunset response: %w", err)
	}
	return result.Events, nil
}

// GetOracleEvents retrieves oracle verification events.
func (c *Client) GetOracleEvents(ctx context.Context, since time.Time, limit int) ([]OracleEvent, error) {
	path := fmt.Sprintf("/api/v1/oracles?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get oracle events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []OracleEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode oracle response: %w", err)
	}
	return result.Events, nil
}

// GetSecurityEvents retrieves security-related events.
func (c *Client) GetSecurityEvents(ctx context.Context, since time.Time, minSeverity string) ([]SecurityEvent, error) {
	path := fmt.Sprintf("/api/v1/security?since=%s", since.Format(time.RFC3339))
	if minSeverity != "" {
		path += "&min_severity=" + url.QueryEscape(minSeverity)
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get security events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []SecurityEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode security response: %w", err)
	}
	return result.Events, nil
}

// doRequest performs an HTTP request to the FIE API.
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

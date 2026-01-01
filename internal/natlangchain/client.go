// Package natlangchain provides integration with the NatLangChain blockchain protocol.
// NatLangChain is a blockchain where natural language prose serves as the ledger substrate,
// using "Proof of Understanding" consensus via LLM validators.
package natlangchain

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the NatLangChain API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	chainID    string
}

// ClientConfig holds configuration for the NatLangChain client.
type ClientConfig struct {
	BaseURL        string        `yaml:"base_url"`
	APIKey         string        `yaml:"api_key"`
	ChainID        string        `yaml:"chain_id"`
	Timeout        time.Duration `yaml:"timeout"`
	MaxRetries     int           `yaml:"max_retries"`
	RetryBackoff   time.Duration `yaml:"retry_backoff"`
}

// DefaultClientConfig returns the default client configuration.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		BaseURL:      "http://localhost:5000",
		ChainID:      "main",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new NatLangChain client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		chainID: cfg.ChainID,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// Entry represents a natural language entry in the NatLangChain.
type Entry struct {
	ID            string                 `json:"id"`
	ChainID       string                 `json:"chain_id"`
	BlockNumber   int64                  `json:"block_number"`
	BlockHash     string                 `json:"block_hash"`
	PreviousHash  string                 `json:"previous_hash"`
	Timestamp     time.Time              `json:"timestamp"`
	Author        string                 `json:"author"`
	AuthorID      string                 `json:"author_id"`
	Content       string                 `json:"content"`
	ContentHash   string                 `json:"content_hash"`
	EntryType     string                 `json:"entry_type"`
	Signature     string                 `json:"signature"`
	Validated     bool                   `json:"validated"`
	ValidatorID   string                 `json:"validator_id,omitempty"`
	ValidationMsg string                 `json:"validation_message,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// Block represents a block in the NatLangChain.
type Block struct {
	Number       int64     `json:"number"`
	Hash         string    `json:"hash"`
	PreviousHash string    `json:"previous_hash"`
	Timestamp    time.Time `json:"timestamp"`
	Entries      []Entry   `json:"entries"`
	ValidatorID  string    `json:"validator_id"`
	Signature    string    `json:"signature"`
}

// Dispute represents a dispute filed in NatLangChain.
type Dispute struct {
	ID             string                 `json:"id"`
	EntryID        string                 `json:"entry_id"`
	FiledBy        string                 `json:"filed_by"`
	FiledAt        time.Time              `json:"filed_at"`
	Reason         string                 `json:"reason"`
	Status         string                 `json:"status"` // open, resolved, escalated, dismissed
	Evidence       []string               `json:"evidence,omitempty"`
	Resolution     string                 `json:"resolution,omitempty"`
	ResolvedAt     *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy     string                 `json:"resolved_by,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// Contract represents a smart contract in NatLangChain.
type Contract struct {
	ID          string                 `json:"id"`
	ChainID     string                 `json:"chain_id"`
	CreatedAt   time.Time              `json:"created_at"`
	Creator     string                 `json:"creator"`
	Content     string                 `json:"content"`
	Status      string                 `json:"status"` // draft, active, matched, completed, cancelled
	MatchedWith string                 `json:"matched_with,omitempty"`
	MatchedAt   *time.Time             `json:"matched_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Negotiation represents a negotiation session in NatLangChain.
type Negotiation struct {
	ID           string                 `json:"id"`
	Participants []string               `json:"participants"`
	StartedAt    time.Time              `json:"started_at"`
	Status       string                 `json:"status"` // active, completed, failed, timeout
	Rounds       int                    `json:"rounds"`
	LastActivity time.Time              `json:"last_activity"`
	Outcome      string                 `json:"outcome,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// SemanticDrift represents detected semantic drift in understanding.
type SemanticDrift struct {
	ID              string    `json:"id"`
	EntryID         string    `json:"entry_id"`
	DetectedAt      time.Time `json:"detected_at"`
	OriginalMeaning string    `json:"original_meaning"`
	DriftedMeaning  string    `json:"drifted_meaning"`
	DriftScore      float64   `json:"drift_score"`
	ValidatorID     string    `json:"validator_id"`
	Severity        string    `json:"severity"` // low, medium, high, critical
}

// ValidationEvent represents a validation event from the consensus process.
type ValidationEvent struct {
	ID            string    `json:"id"`
	EntryID       string    `json:"entry_id"`
	ValidatorID   string    `json:"validator_id"`
	Timestamp     time.Time `json:"timestamp"`
	EventType     string    `json:"event_type"` // paraphrase, debate, consensus, rejection
	Outcome       string    `json:"outcome"`
	Confidence    float64   `json:"confidence"`
	Paraphrase    string    `json:"paraphrase,omitempty"`
	DebateRole    string    `json:"debate_role,omitempty"` // skeptic, facilitator
	DebateMessage string    `json:"debate_message,omitempty"`
}

// ChainStats represents statistics about a NatLangChain.
type ChainStats struct {
	ChainID          string    `json:"chain_id"`
	BlockHeight      int64     `json:"block_height"`
	TotalEntries     int64     `json:"total_entries"`
	ActiveValidators int       `json:"active_validators"`
	OpenDisputes     int       `json:"open_disputes"`
	ActiveContracts  int       `json:"active_contracts"`
	LastBlockTime    time.Time `json:"last_block_time"`
}

// HealthStatus represents the health of the NatLangChain node.
type HealthStatus struct {
	Status    string `json:"status"`
	Ready     bool   `json:"ready"`
	Live      bool   `json:"live"`
	Version   string `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// GetHealth checks the health of the NatLangChain node.
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

// GetChainStats retrieves statistics for the current chain.
func (c *Client) GetChainStats(ctx context.Context) (*ChainStats, error) {
	path := fmt.Sprintf("/api/v1/chains/%s/stats", c.chainID)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain stats: %w", err)
	}
	defer resp.Body.Close()

	var stats ChainStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode stats response: %w", err)
	}
	return &stats, nil
}

// GetLatestBlocks retrieves the latest blocks from the chain.
func (c *Client) GetLatestBlocks(ctx context.Context, limit int) ([]Block, error) {
	path := fmt.Sprintf("/api/v1/chains/%s/blocks?limit=%d", c.chainID, limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocks: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Blocks []Block `json:"blocks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode blocks response: %w", err)
	}
	return result.Blocks, nil
}

// GetBlocksSince retrieves blocks since a specific block number.
func (c *Client) GetBlocksSince(ctx context.Context, blockNumber int64, limit int) ([]Block, error) {
	path := fmt.Sprintf("/api/v1/chains/%s/blocks?since=%d&limit=%d", c.chainID, blockNumber, limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocks: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Blocks []Block `json:"blocks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode blocks response: %w", err)
	}
	return result.Blocks, nil
}

// GetEntry retrieves a specific entry by ID.
func (c *Client) GetEntry(ctx context.Context, entryID string) (*Entry, error) {
	path := fmt.Sprintf("/api/v1/entries/%s", url.PathEscape(entryID))
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get entry: %w", err)
	}
	defer resp.Body.Close()

	var entry Entry
	if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
		return nil, fmt.Errorf("failed to decode entry response: %w", err)
	}
	return &entry, nil
}

// GetRecentEntries retrieves recent entries from the chain.
func (c *Client) GetRecentEntries(ctx context.Context, since time.Time, limit int) ([]Entry, error) {
	path := fmt.Sprintf("/api/v1/chains/%s/entries?since=%s&limit=%d",
		c.chainID, since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Entries []Entry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode entries response: %w", err)
	}
	return result.Entries, nil
}

// GetDisputes retrieves disputes, optionally filtered by status.
func (c *Client) GetDisputes(ctx context.Context, status string, limit int) ([]Dispute, error) {
	path := fmt.Sprintf("/api/v1/disputes?limit=%d", limit)
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

// GetContracts retrieves contracts, optionally filtered by status.
func (c *Client) GetContracts(ctx context.Context, status string, limit int) ([]Contract, error) {
	path := fmt.Sprintf("/api/v1/contracts?limit=%d", limit)
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

// GetNegotiations retrieves negotiation sessions.
func (c *Client) GetNegotiations(ctx context.Context, status string, limit int) ([]Negotiation, error) {
	path := fmt.Sprintf("/api/v1/negotiations?limit=%d", limit)
	if status != "" {
		path += "&status=" + url.QueryEscape(status)
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get negotiations: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Negotiations []Negotiation `json:"negotiations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode negotiations response: %w", err)
	}
	return result.Negotiations, nil
}

// GetSemanticDrifts retrieves detected semantic drift events.
func (c *Client) GetSemanticDrifts(ctx context.Context, since time.Time, minSeverity string) ([]SemanticDrift, error) {
	path := fmt.Sprintf("/api/v1/semantic/drift?since=%s", since.Format(time.RFC3339))
	if minSeverity != "" {
		path += "&min_severity=" + url.QueryEscape(minSeverity)
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get semantic drifts: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Drifts []SemanticDrift `json:"drifts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode drifts response: %w", err)
	}
	return result.Drifts, nil
}

// GetValidationEvents retrieves validation events from consensus.
func (c *Client) GetValidationEvents(ctx context.Context, since time.Time, limit int) ([]ValidationEvent, error) {
	path := fmt.Sprintf("/api/v1/validation/events?since=%s&limit=%d",
		since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get validation events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []ValidationEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode validation events response: %w", err)
	}
	return result.Events, nil
}

// SearchEntries performs a semantic search across entries.
func (c *Client) SearchEntries(ctx context.Context, query string, limit int) ([]Entry, error) {
	path := fmt.Sprintf("/api/v1/search/semantic?q=%s&limit=%d",
		url.QueryEscape(query), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to search entries: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Entries []Entry `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode search response: %w", err)
	}
	return result.Entries, nil
}

// doRequest performs an HTTP request to the NatLangChain API.
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

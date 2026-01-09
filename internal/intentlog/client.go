// Package intentlog provides integration with IntentLog version control system.
// IntentLog is a version control system that tracks reasoning through prose commits.
package intentlog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the IntentLog API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the IntentLog client.
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
		BaseURL:      "http://localhost:8700",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new IntentLog client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// ProseCommit represents a prose-based commit.
type ProseCommit struct {
	ID             string                 `json:"id"`
	RepoID         string                 `json:"repo_id"`
	Author         string                 `json:"author"`
	Timestamp      time.Time              `json:"timestamp"`
	Intent         string                 `json:"intent"`        // The prose explanation
	SemanticHash   string                 `json:"semantic_hash"` // LLM-derived semantic fingerprint
	PreviousHash   string                 `json:"previous_hash"`
	Signature      string                 `json:"signature"`
	Classification string                 `json:"classification"` // PUBLIC, INTERNAL, CONFIDENTIAL, SECRET, TOP_SECRET
	Branch         string                 `json:"branch"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// SemanticDiff represents a semantic diff between commits.
type SemanticDiff struct {
	ID           string    `json:"id"`
	RepoID       string    `json:"repo_id"`
	FromCommit   string    `json:"from_commit"`
	ToCommit     string    `json:"to_commit"`
	GeneratedAt  time.Time `json:"generated_at"`
	Summary      string    `json:"summary"`
	ChangeType   string    `json:"change_type"`  // refinement, contradiction, extension, retraction
	Significance float64   `json:"significance"` // 0-1
}

// BranchEvent represents a branch operation.
type BranchEvent struct {
	ID         string    `json:"id"`
	RepoID     string    `json:"repo_id"`
	Timestamp  time.Time `json:"timestamp"`
	EventType  string    `json:"event_type"` // create, merge, delete, checkout
	BranchName string    `json:"branch_name"`
	FromBranch string    `json:"from_branch,omitempty"`
	Author     string    `json:"author"`
	Success    bool      `json:"success"`
}

// ChainEvent represents a chain integrity event.
type ChainEvent struct {
	ID           string    `json:"id"`
	RepoID       string    `json:"repo_id"`
	Timestamp    time.Time `json:"timestamp"`
	EventType    string    `json:"event_type"` // verification, signature_check, anchor_check
	Passed       bool      `json:"passed"`
	FailurePoint string    `json:"failure_point,omitempty"`
	Details      string    `json:"details"`
}

// ExportEvent represents a data export event.
type ExportEvent struct {
	ID          string    `json:"id"`
	RepoID      string    `json:"repo_id"`
	Timestamp   time.Time `json:"timestamp"`
	ExportType  string    `json:"export_type"` // full, partial, filtered
	Format      string    `json:"format"`      // json, markdown, pdf
	CommitRange string    `json:"commit_range"`
	Requester   string    `json:"requester"`
	Success     bool      `json:"success"`
}

// ObservationEvent represents an MP-02 observation event.
type ObservationEvent struct {
	ID         string                 `json:"id"`
	RepoID     string                 `json:"repo_id"`
	Timestamp  time.Time              `json:"timestamp"`
	ObserverID string                 `json:"observer_id"`
	SessionID  string                 `json:"session_id"`
	EventType  string                 `json:"event_type"` // effort_signal, decision_point, milestone
	Duration   time.Duration          `json:"duration"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// KeyEvent represents a cryptographic key event.
type KeyEvent struct {
	ID        string    `json:"id"`
	RepoID    string    `json:"repo_id"`
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"` // generated, rotated, revoked, verified
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
	Success   bool      `json:"success"`
}

// RepoStats represents statistics about a repository.
type RepoStats struct {
	RepoID         string    `json:"repo_id"`
	TotalCommits   int64     `json:"total_commits"`
	TotalBranches  int       `json:"total_branches"`
	ChainIntegrity bool      `json:"chain_integrity"`
	LastCommitTime time.Time `json:"last_commit_time"`
}

// HealthStatus represents the health of the IntentLog service.
type HealthStatus struct {
	Status    string    `json:"status"`
	Ready     bool      `json:"ready"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// GetHealth checks the health of the IntentLog service.
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

// GetCommits retrieves prose commits.
func (c *Client) GetCommits(ctx context.Context, since time.Time, limit int) ([]ProseCommit, error) {
	path := fmt.Sprintf("/api/v1/commits?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get commits: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Commits []ProseCommit `json:"commits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode commits response: %w", err)
	}
	return result.Commits, nil
}

// GetSemanticDiffs retrieves semantic diffs.
func (c *Client) GetSemanticDiffs(ctx context.Context, since time.Time, limit int) ([]SemanticDiff, error) {
	path := fmt.Sprintf("/api/v1/diffs?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get semantic diffs: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Diffs []SemanticDiff `json:"diffs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode semantic diffs response: %w", err)
	}
	return result.Diffs, nil
}

// GetBranchEvents retrieves branch events.
func (c *Client) GetBranchEvents(ctx context.Context, since time.Time, limit int) ([]BranchEvent, error) {
	path := fmt.Sprintf("/api/v1/branches/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get branch events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []BranchEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode branch events response: %w", err)
	}
	return result.Events, nil
}

// GetChainEvents retrieves chain integrity events.
func (c *Client) GetChainEvents(ctx context.Context, since time.Time, limit int) ([]ChainEvent, error) {
	path := fmt.Sprintf("/api/v1/chain/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []ChainEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode chain events response: %w", err)
	}
	return result.Events, nil
}

// GetExportEvents retrieves export events.
func (c *Client) GetExportEvents(ctx context.Context, since time.Time, limit int) ([]ExportEvent, error) {
	path := fmt.Sprintf("/api/v1/export/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get export events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []ExportEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode export events response: %w", err)
	}
	return result.Events, nil
}

// GetKeyEvents retrieves key management events.
func (c *Client) GetKeyEvents(ctx context.Context, since time.Time, limit int) ([]KeyEvent, error) {
	path := fmt.Sprintf("/api/v1/keys/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get key events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []KeyEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode key events response: %w", err)
	}
	return result.Events, nil
}

// doRequest performs an HTTP request to the IntentLog API.
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

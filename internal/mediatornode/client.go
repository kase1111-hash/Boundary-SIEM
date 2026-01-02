// Package mediatornode provides integration with the Mediator Node service.
// Mediator Node discovers, negotiates, and proposes alignments between intents on NatLangChain.
package mediatornode

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the Mediator Node API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the Mediator Node client.
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
		BaseURL:      "http://localhost:8400",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new Mediator Node client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// Intent represents an intent on the NatLangChain.
type Intent struct {
	ID          string                 `json:"id"`
	Author      string                 `json:"author"`
	Content     string                 `json:"content"`
	IntentType  string                 `json:"intent_type"` // offer, request
	Status      string                 `json:"status"`      // pending, aligned, expired, flagged
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	Constraints map[string]interface{} `json:"constraints,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Alignment represents a proposed alignment between intents.
type Alignment struct {
	ID              string    `json:"id"`
	OfferIntentID   string    `json:"offer_intent_id"`
	RequestIntentID string    `json:"request_intent_id"`
	ProposedAt      time.Time `json:"proposed_at"`
	Status          string    `json:"status"` // proposed, accepted, rejected, expired
	Confidence      float64   `json:"confidence"`
	Rationale       string    `json:"rationale"`
	MediatorID      string    `json:"mediator_id"`
	ModelHash       string    `json:"model_hash"`
}

// NegotiationSession represents a negotiation between parties.
type NegotiationSession struct {
	ID           string                 `json:"id"`
	AlignmentID  string                 `json:"alignment_id"`
	Participants []string               `json:"participants"`
	StartedAt    time.Time              `json:"started_at"`
	Status       string                 `json:"status"` // active, completed, failed, timeout
	Rounds       int                    `json:"rounds"`
	CurrentRound int                    `json:"current_round"`
	Outcome      string                 `json:"outcome,omitempty"`
	SettlementID string                 `json:"settlement_id,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// Settlement represents a finalized settlement.
type Settlement struct {
	ID            string    `json:"id"`
	NegotiationID string    `json:"negotiation_id"`
	SettledAt     time.Time `json:"settled_at"`
	Terms         string    `json:"terms"`
	Signature     string    `json:"signature"`
	ChainEntryID  string    `json:"chain_entry_id"`
	Status        string    `json:"status"` // pending, confirmed, challenged, finalized
}

// MediatorEvent represents an event from the mediator.
type MediatorEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	MediatorID  string                 `json:"mediator_id"`
	RelatedID   string                 `json:"related_id,omitempty"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ReputationEvent represents a reputation change.
type ReputationEvent struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	MediatorID string    `json:"mediator_id"`
	ChangeType string    `json:"change_type"` // increase, decrease, reset
	Amount     float64   `json:"amount"`
	Reason     string    `json:"reason"`
	NewScore   float64   `json:"new_score"`
}

// FlagEvent represents an intent flagging event.
type FlagEvent struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	IntentID  string    `json:"intent_id"`
	FlagType  string    `json:"flag_type"` // coercive, vague, prohibited, spam
	FlaggedBy string    `json:"flagged_by"`
	Reason    string    `json:"reason"`
	Action    string    `json:"action"` // warned, archived, rejected
}

// NodeStats represents statistics about the Mediator Node.
type NodeStats struct {
	ActiveIntents      int64     `json:"active_intents"`
	PendingAlignments  int64     `json:"pending_alignments"`
	ActiveNegotiations int64     `json:"active_negotiations"`
	TotalSettlements   int64     `json:"total_settlements"`
	ReputationScore    float64   `json:"reputation_score"`
	LastActivityTime   time.Time `json:"last_activity_time"`
}

// HealthStatus represents the health of the Mediator Node service.
type HealthStatus struct {
	Status    string    `json:"status"`
	Ready     bool      `json:"ready"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// GetHealth checks the health of the Mediator Node service.
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

// GetStats retrieves node statistics.
func (c *Client) GetStats(ctx context.Context) (*NodeStats, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/stats", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}
	defer resp.Body.Close()

	var stats NodeStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode stats response: %w", err)
	}
	return &stats, nil
}

// GetAlignments retrieves alignments.
func (c *Client) GetAlignments(ctx context.Context, since time.Time, limit int) ([]Alignment, error) {
	path := fmt.Sprintf("/api/v1/alignments?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get alignments: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Alignments []Alignment `json:"alignments"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode alignments response: %w", err)
	}
	return result.Alignments, nil
}

// GetNegotiations retrieves negotiation sessions.
func (c *Client) GetNegotiations(ctx context.Context, since time.Time, limit int) ([]NegotiationSession, error) {
	path := fmt.Sprintf("/api/v1/negotiations?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get negotiations: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Negotiations []NegotiationSession `json:"negotiations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode negotiations response: %w", err)
	}
	return result.Negotiations, nil
}

// GetSettlements retrieves settlements.
func (c *Client) GetSettlements(ctx context.Context, since time.Time, limit int) ([]Settlement, error) {
	path := fmt.Sprintf("/api/v1/settlements?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get settlements: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Settlements []Settlement `json:"settlements"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode settlements response: %w", err)
	}
	return result.Settlements, nil
}

// GetMediatorEvents retrieves mediator events.
func (c *Client) GetMediatorEvents(ctx context.Context, since time.Time, limit int) ([]MediatorEvent, error) {
	path := fmt.Sprintf("/api/v1/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get mediator events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []MediatorEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode mediator events response: %w", err)
	}
	return result.Events, nil
}

// GetReputationEvents retrieves reputation events.
func (c *Client) GetReputationEvents(ctx context.Context, since time.Time, limit int) ([]ReputationEvent, error) {
	path := fmt.Sprintf("/api/v1/reputation/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get reputation events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []ReputationEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode reputation events response: %w", err)
	}
	return result.Events, nil
}

// GetFlagEvents retrieves flag events.
func (c *Client) GetFlagEvents(ctx context.Context, since time.Time, limit int) ([]FlagEvent, error) {
	path := fmt.Sprintf("/api/v1/flags?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get flag events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []FlagEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode flag events response: %w", err)
	}
	return result.Events, nil
}

// doRequest performs an HTTP request to the Mediator Node API.
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

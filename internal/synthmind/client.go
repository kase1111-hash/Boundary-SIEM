// Package synthmind provides integration with the Synth Mind AI agent system.
// Synth Mind is a psychologically-grounded AI agent with six interconnected modules.
package synthmind

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the Synth Mind API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the Synth Mind client.
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
		BaseURL:      "http://localhost:8600",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new Synth Mind client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// EmotionalState represents the agent's emotional state.
type EmotionalState struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	AgentID     string    `json:"agent_id"`
	Valence     float64   `json:"valence"`     // -1 to 1 (negative to positive)
	Arousal     float64   `json:"arousal"`     // 0 to 1 (calm to excited)
	Dominance   float64   `json:"dominance"`   // 0 to 1 (submissive to dominant)
	Uncertainty float64   `json:"uncertainty"` // 0 to 1
	FlowState   float64   `json:"flow_state"`  // 0 to 1 (boredom to flow)
	Anomaly     bool      `json:"anomaly"`
}

// ModuleEvent represents an event from one of the six psychological modules.
type ModuleEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	AgentID     string                 `json:"agent_id"`
	Module      string                 `json:"module"` // dreaming, assurance, reflection, purpose, reward, social
	EventType   string                 `json:"event_type"`
	Description string                 `json:"description"`
	Success     bool                   `json:"success"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// DreamingEvent represents a predictive dreaming event.
type DreamingEvent struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	AgentID       string    `json:"agent_id"`
	PredictionID  string    `json:"prediction_id"`
	Confidence    float64   `json:"confidence"`
	Validated     bool      `json:"validated"`
	ValidationGap float64   `json:"validation_gap"` // Difference from actual
}

// ReflectionEvent represents a meta-reflection event.
type ReflectionEvent struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	AgentID        string    `json:"agent_id"`
	ReflectionType string    `json:"reflection_type"` // behavior, belief, goal
	Insight        string    `json:"insight"`
	ActionTaken    string    `json:"action_taken,omitempty"`
	Severity       string    `json:"severity"` // minor, moderate, significant
}

// SocialEvent represents a social/peer interaction event.
type SocialEvent struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	AgentID     string    `json:"agent_id"`
	PeerID      string    `json:"peer_id"`
	EventType   string    `json:"event_type"` // connection, message, sync, disconnect
	Success     bool      `json:"success"`
	MessageHash string    `json:"message_hash,omitempty"`
}

// ToolUsageEvent represents a tool usage event.
type ToolUsageEvent struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	AgentID    string                 `json:"agent_id"`
	ToolName   string                 `json:"tool_name"`
	Operation  string                 `json:"operation"`
	Success    bool                   `json:"success"`
	Duration   time.Duration          `json:"duration"`
	Sandboxed  bool                   `json:"sandboxed"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// SafetyEvent represents a safety/guardrail event.
type SafetyEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	AgentID     string                 `json:"agent_id"`
	EventType   string                 `json:"event_type"` // boundary_check, content_filter, action_block
	Triggered   bool                   `json:"triggered"`
	Rule        string                 `json:"rule"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AgentStats represents statistics about the agent.
type AgentStats struct {
	AgentID           string    `json:"agent_id"`
	UptimeHours       float64   `json:"uptime_hours"`
	TotalInteractions int64     `json:"total_interactions"`
	AverageValence    float64   `json:"average_valence"`
	FlowStateRatio    float64   `json:"flow_state_ratio"`
	SafetyTriggers    int64     `json:"safety_triggers"`
	LastActivityTime  time.Time `json:"last_activity_time"`
}

// HealthStatus represents the health of the Synth Mind service.
type HealthStatus struct {
	Status    string    `json:"status"`
	Ready     bool      `json:"ready"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
}

// GetHealth checks the health of the Synth Mind service.
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

// GetEmotionalStates retrieves emotional state snapshots.
func (c *Client) GetEmotionalStates(ctx context.Context, since time.Time, limit int) ([]EmotionalState, error) {
	path := fmt.Sprintf("/api/v1/emotional/states?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get emotional states: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		States []EmotionalState `json:"states"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode emotional states response: %w", err)
	}
	return result.States, nil
}

// GetModuleEvents retrieves psychological module events.
func (c *Client) GetModuleEvents(ctx context.Context, since time.Time, limit int) ([]ModuleEvent, error) {
	path := fmt.Sprintf("/api/v1/modules/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get module events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []ModuleEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode module events response: %w", err)
	}
	return result.Events, nil
}

// GetDreamingEvents retrieves predictive dreaming events.
func (c *Client) GetDreamingEvents(ctx context.Context, since time.Time, limit int) ([]DreamingEvent, error) {
	path := fmt.Sprintf("/api/v1/dreaming/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get dreaming events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []DreamingEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode dreaming events response: %w", err)
	}
	return result.Events, nil
}

// GetReflectionEvents retrieves meta-reflection events.
func (c *Client) GetReflectionEvents(ctx context.Context, since time.Time, limit int) ([]ReflectionEvent, error) {
	path := fmt.Sprintf("/api/v1/reflection/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get reflection events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []ReflectionEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode reflection events response: %w", err)
	}
	return result.Events, nil
}

// GetSocialEvents retrieves social interaction events.
func (c *Client) GetSocialEvents(ctx context.Context, since time.Time, limit int) ([]SocialEvent, error) {
	path := fmt.Sprintf("/api/v1/social/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get social events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []SocialEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode social events response: %w", err)
	}
	return result.Events, nil
}

// GetToolUsageEvents retrieves tool usage events.
func (c *Client) GetToolUsageEvents(ctx context.Context, since time.Time, limit int) ([]ToolUsageEvent, error) {
	path := fmt.Sprintf("/api/v1/tools/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get tool usage events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []ToolUsageEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode tool usage events response: %w", err)
	}
	return result.Events, nil
}

// GetSafetyEvents retrieves safety/guardrail events.
func (c *Client) GetSafetyEvents(ctx context.Context, since time.Time, limit int) ([]SafetyEvent, error) {
	path := fmt.Sprintf("/api/v1/safety/events?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get safety events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []SafetyEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode safety events response: %w", err)
	}
	return result.Events, nil
}

// doRequest performs an HTTP request to the Synth Mind API.
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

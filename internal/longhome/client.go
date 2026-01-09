// Package longhome provides integration with the Long-Home mountaineering descent game telemetry.
// Long-Home is a Godot-based psychological realism mountain descent simulation.
package longhome

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the Long-Home telemetry API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the Long-Home client.
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
		BaseURL:      "http://localhost:9100",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new Long-Home client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// GameSession represents an active game session.
type GameSession struct {
	ID         string                 `json:"id"`
	PlayerID   string                 `json:"player_id"`
	StartedAt  time.Time              `json:"started_at"`
	EndedAt    *time.Time             `json:"ended_at,omitempty"`
	GameState  string                 `json:"game_state"` // menu, planning, descent, resolution, credits
	MountainID string                 `json:"mountain_id"`
	Difficulty string                 `json:"difficulty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// StateTransition represents a game or player state change.
type StateTransition struct {
	ID        string                 `json:"id"`
	SessionID string                 `json:"session_id"`
	PlayerID  string                 `json:"player_id"`
	Timestamp time.Time              `json:"timestamp"`
	StateType string                 `json:"state_type"` // game_state, movement_state, slide_state
	FromState string                 `json:"from_state"`
	ToState   string                 `json:"to_state"`
	Trigger   string                 `json:"trigger,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// FatalEvent represents a death/fatal event sequence.
type FatalEvent struct {
	ID         string                 `json:"id"`
	SessionID  string                 `json:"session_id"`
	PlayerID   string                 `json:"player_id"`
	Timestamp  time.Time              `json:"timestamp"`
	Phase      string                 `json:"phase"` // trigger, descent, impact, fade, aftermath
	Cause      string                 `json:"cause"` // fall, hypothermia, exhaustion, slide_uncontrolled
	Altitude   float64                `json:"altitude"`
	Duration   float64                `json:"duration_seconds"`
	ReplayData string                 `json:"replay_data,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// SlideEvent represents sliding mechanic events.
type SlideEvent struct {
	ID           string                 `json:"id"`
	SessionID    string                 `json:"session_id"`
	PlayerID     string                 `json:"player_id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"`    // slide_start, control_change, slide_end, control_lost
	ControlLevel string                 `json:"control_level"` // controlled, slipping, sliding, tumbling, lost
	Velocity     float64                `json:"velocity"`
	TerrainType  string                 `json:"terrain_type"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// RopeEvent represents rope system events.
type RopeEvent struct {
	ID            string                 `json:"id"`
	SessionID     string                 `json:"session_id"`
	PlayerID      string                 `json:"player_id"`
	Timestamp     time.Time              `json:"timestamp"`
	EventType     string                 `json:"event_type"` // deploy, rappel_start, rappel_end, anchor_set, rope_break
	RopeLength    float64                `json:"rope_length"`
	AnchorQuality float64                `json:"anchor_quality"`
	Stress        float64                `json:"stress_level"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// BodyCondition represents player body state tracking.
type BodyCondition struct {
	ID           string                 `json:"id"`
	SessionID    string                 `json:"session_id"`
	PlayerID     string                 `json:"player_id"`
	Timestamp    time.Time              `json:"timestamp"`
	Fatigue      float64                `json:"fatigue"`
	ColdExposure float64                `json:"cold_exposure"`
	Injuries     []string               `json:"injuries,omitempty"`
	Hydration    float64                `json:"hydration"`
	Altitude     float64                `json:"altitude"`
	HeartRate    int                    `json:"heart_rate"`
	Critical     bool                   `json:"critical"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// InputValidation represents player input validation events.
type InputValidation struct {
	ID         string                 `json:"id"`
	SessionID  string                 `json:"session_id"`
	PlayerID   string                 `json:"player_id"`
	Timestamp  time.Time              `json:"timestamp"`
	ActionType string                 `json:"action_type"` // slide, rappel, climb, jump
	InputValid bool                   `json:"input_valid"`
	RiskLevel  string                 `json:"risk_level"` // low, medium, high, critical
	Anomalies  []string               `json:"anomalies,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// SaveEvent represents save/load operations.
type SaveEvent struct {
	ID           string                 `json:"id"`
	SessionID    string                 `json:"session_id"`
	PlayerID     string                 `json:"player_id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"` // save, load, checkpoint, auto_save
	DataHash     string                 `json:"data_hash"`
	DataSize     int64                  `json:"data_size"`
	Valid        bool                   `json:"valid"`
	Modified     bool                   `json:"modified"` // Save file was modified externally
	ErrorMessage string                 `json:"error_message,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// PhysicsAnomaly represents physics system anomalies.
type PhysicsAnomaly struct {
	ID          string                 `json:"id"`
	SessionID   string                 `json:"session_id"`
	PlayerID    string                 `json:"player_id"`
	Timestamp   time.Time              `json:"timestamp"`
	AnomalyType string                 `json:"anomaly_type"` // velocity_violation, terrain_clip, impossible_position
	Expected    float64                `json:"expected_value"`
	Actual      float64                `json:"actual_value"`
	Severity    string                 `json:"severity"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// EventBusSignal represents sampled event bus signals.
type EventBusSignal struct {
	ID          string                 `json:"id"`
	SessionID   string                 `json:"session_id"`
	Timestamp   time.Time              `json:"timestamp"`
	SignalName  string                 `json:"signal_name"`
	EmitterType string                 `json:"emitter_type"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Unusual     bool                   `json:"unusual"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// HealthStatus represents the health of the telemetry service.
type HealthStatus struct {
	Status         string    `json:"status"`
	Ready          bool      `json:"ready"`
	Live           bool      `json:"live"`
	Version        string    `json:"version"`
	ActiveSessions int       `json:"active_sessions"`
	Timestamp      time.Time `json:"timestamp"`
}

// GetHealth checks the health of the telemetry service.
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

// GetSessions retrieves game sessions.
func (c *Client) GetSessions(ctx context.Context, state string, limit int) ([]GameSession, error) {
	path := fmt.Sprintf("/api/v1/sessions?limit=%d", limit)
	if state != "" {
		path += "&state=" + url.QueryEscape(state)
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Sessions []GameSession `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode sessions response: %w", err)
	}
	return result.Sessions, nil
}

// GetStateTransitions retrieves state transition events.
func (c *Client) GetStateTransitions(ctx context.Context, since time.Time, limit int) ([]StateTransition, error) {
	path := fmt.Sprintf("/api/v1/transitions?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get transitions: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Transitions []StateTransition `json:"transitions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode transitions response: %w", err)
	}
	return result.Transitions, nil
}

// GetFatalEvents retrieves fatal/death events.
func (c *Client) GetFatalEvents(ctx context.Context, since time.Time, limit int) ([]FatalEvent, error) {
	path := fmt.Sprintf("/api/v1/fatals?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get fatal events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []FatalEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode fatals response: %w", err)
	}
	return result.Events, nil
}

// GetSlideEvents retrieves slide mechanic events.
func (c *Client) GetSlideEvents(ctx context.Context, since time.Time, limit int) ([]SlideEvent, error) {
	path := fmt.Sprintf("/api/v1/slides?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get slide events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []SlideEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode slides response: %w", err)
	}
	return result.Events, nil
}

// GetRopeEvents retrieves rope system events.
func (c *Client) GetRopeEvents(ctx context.Context, since time.Time, limit int) ([]RopeEvent, error) {
	path := fmt.Sprintf("/api/v1/ropes?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get rope events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []RopeEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode ropes response: %w", err)
	}
	return result.Events, nil
}

// GetBodyConditions retrieves body condition snapshots.
func (c *Client) GetBodyConditions(ctx context.Context, since time.Time, criticalOnly bool) ([]BodyCondition, error) {
	path := fmt.Sprintf("/api/v1/body?since=%s", since.Format(time.RFC3339))
	if criticalOnly {
		path += "&critical_only=true"
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get body conditions: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Conditions []BodyCondition `json:"conditions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode body response: %w", err)
	}
	return result.Conditions, nil
}

// GetInputValidations retrieves input validation events.
func (c *Client) GetInputValidations(ctx context.Context, since time.Time, limit int) ([]InputValidation, error) {
	path := fmt.Sprintf("/api/v1/inputs?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get input validations: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Validations []InputValidation `json:"validations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode inputs response: %w", err)
	}
	return result.Validations, nil
}

// GetSaveEvents retrieves save/load events.
func (c *Client) GetSaveEvents(ctx context.Context, since time.Time, limit int) ([]SaveEvent, error) {
	path := fmt.Sprintf("/api/v1/saves?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get save events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []SaveEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode saves response: %w", err)
	}
	return result.Events, nil
}

// GetPhysicsAnomalies retrieves physics anomaly detections.
func (c *Client) GetPhysicsAnomalies(ctx context.Context, since time.Time, minSeverity string) ([]PhysicsAnomaly, error) {
	path := fmt.Sprintf("/api/v1/physics/anomalies?since=%s", since.Format(time.RFC3339))
	if minSeverity != "" {
		path += "&min_severity=" + url.QueryEscape(minSeverity)
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get physics anomalies: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Anomalies []PhysicsAnomaly `json:"anomalies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode physics response: %w", err)
	}
	return result.Anomalies, nil
}

// GetEventBusSignals retrieves sampled event bus signals.
func (c *Client) GetEventBusSignals(ctx context.Context, since time.Time, unusualOnly bool) ([]EventBusSignal, error) {
	path := fmt.Sprintf("/api/v1/signals?since=%s", since.Format(time.RFC3339))
	if unusualOnly {
		path += "&unusual_only=true"
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get signals: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Signals []EventBusSignal `json:"signals"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode signals response: %w", err)
	}
	return result.Signals, nil
}

// doRequest performs an HTTP request to the telemetry API.
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

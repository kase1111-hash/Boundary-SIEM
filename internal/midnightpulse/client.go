// Package midnightpulse provides integration with the Midnight Pulse (Nightflow) game telemetry system.
// Nightflow is a Unity-based endless procedural night-time freeway driving experience.
package midnightpulse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the Midnight Pulse telemetry API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the Midnight Pulse client.
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
		BaseURL:      "http://localhost:9000",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new Midnight Pulse client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// PlayerSession represents an active game session.
type PlayerSession struct {
	ID          string                 `json:"id"`
	PlayerID    string                 `json:"player_id"`
	StartedAt   time.Time              `json:"started_at"`
	EndedAt     *time.Time             `json:"ended_at,omitempty"`
	Duration    int64                  `json:"duration_seconds"`
	Status      string                 `json:"status"` // active, completed, crashed, disconnected
	Platform    string                 `json:"platform"`
	GameVersion string                 `json:"game_version"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CrashEvent represents a vehicle crash in the game.
type CrashEvent struct {
	ID           string                 `json:"id"`
	SessionID    string                 `json:"session_id"`
	PlayerID     string                 `json:"player_id"`
	Timestamp    time.Time              `json:"timestamp"`
	Distance     float64                `json:"distance_traveled"`
	FinalScore   int64                  `json:"final_score"`
	Speed        float64                `json:"speed_at_crash"`
	DamageValues map[string]float64     `json:"damage_values"`
	CrashType    string                 `json:"crash_type"` // traffic, hazard, obstacle, guardrail
	CauseObject  string                 `json:"cause_object,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// MultiplayerEvent represents multiplayer interaction events.
type MultiplayerEvent struct {
	ID         string                 `json:"id"`
	SessionID  string                 `json:"session_id"`
	PlayerID   string                 `json:"player_id"`
	EventType  string                 `json:"event_type"` // ghost_race_start, ghost_race_complete, spectator_join, spectator_leave
	Timestamp  time.Time              `json:"timestamp"`
	OpponentID string                 `json:"opponent_id,omitempty"`
	Outcome    string                 `json:"outcome,omitempty"` // win, loss, draw, abandoned
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// InputAnomaly represents suspicious input patterns.
type InputAnomaly struct {
	ID           string                 `json:"id"`
	SessionID    string                 `json:"session_id"`
	PlayerID     string                 `json:"player_id"`
	Timestamp    time.Time              `json:"timestamp"`
	AnomalyType  string                 `json:"anomaly_type"` // rapid_input, impossible_sequence, macro_detected, timing_anomaly
	Severity     string                 `json:"severity"`
	InputPattern string                 `json:"input_pattern"`
	Confidence   float64                `json:"confidence"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// SaveLoadEvent represents save/load operations.
type SaveLoadEvent struct {
	ID           string                 `json:"id"`
	SessionID    string                 `json:"session_id"`
	PlayerID     string                 `json:"player_id"`
	EventType    string                 `json:"event_type"` // save, load, auto_save, cloud_sync
	Timestamp    time.Time              `json:"timestamp"`
	DataSize     int64                  `json:"data_size_bytes"`
	Checksum     string                 `json:"checksum"`
	Valid        bool                   `json:"valid"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// PerformanceMetric represents game performance telemetry.
type PerformanceMetric struct {
	ID          string                 `json:"id"`
	SessionID   string                 `json:"session_id"`
	Timestamp   time.Time              `json:"timestamp"`
	FrameRate   float64                `json:"frame_rate"`
	MemoryUsage int64                  `json:"memory_usage_mb"`
	CPUUsage    float64                `json:"cpu_usage_percent"`
	GPUUsage    float64                `json:"gpu_usage_percent"`
	DrawCalls   int                    `json:"draw_calls"`
	LoadTime    float64                `json:"load_time_seconds,omitempty"`
	Anomalies   []string               `json:"anomalies,omitempty"` // frame_drop, memory_spike, shader_compile
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// LeaderboardSubmission represents a score submission.
type LeaderboardSubmission struct {
	ID            string                 `json:"id"`
	PlayerID      string                 `json:"player_id"`
	SessionID     string                 `json:"session_id"`
	Timestamp     time.Time              `json:"timestamp"`
	LeaderboardID string                 `json:"leaderboard_id"` // daily, weekly, all_time
	Score         int64                  `json:"score"`
	Distance      float64                `json:"distance"`
	Verified      bool                   `json:"verified"`
	Rank          int                    `json:"rank,omitempty"`
	Flags         []string               `json:"flags,omitempty"` // suspicious_score, replay_verified, hardware_verified
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// DifficultyEvent represents difficulty scaling changes.
type DifficultyEvent struct {
	ID        string                 `json:"id"`
	SessionID string                 `json:"session_id"`
	PlayerID  string                 `json:"player_id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"` // skill_adjustment, parameter_change, adaptive_difficulty
	OldValue  float64                `json:"old_value"`
	NewValue  float64                `json:"new_value"`
	Reason    string                 `json:"reason"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
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

// GetSessions retrieves player sessions.
func (c *Client) GetSessions(ctx context.Context, status string, limit int) ([]PlayerSession, error) {
	path := fmt.Sprintf("/api/v1/sessions?limit=%d", limit)
	if status != "" {
		path += "&status=" + url.QueryEscape(status)
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Sessions []PlayerSession `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode sessions response: %w", err)
	}
	return result.Sessions, nil
}

// GetCrashEvents retrieves crash events.
func (c *Client) GetCrashEvents(ctx context.Context, since time.Time, limit int) ([]CrashEvent, error) {
	path := fmt.Sprintf("/api/v1/crashes?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get crashes: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Crashes []CrashEvent `json:"crashes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode crashes response: %w", err)
	}
	return result.Crashes, nil
}

// GetMultiplayerEvents retrieves multiplayer events.
func (c *Client) GetMultiplayerEvents(ctx context.Context, since time.Time, limit int) ([]MultiplayerEvent, error) {
	path := fmt.Sprintf("/api/v1/multiplayer?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get multiplayer events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []MultiplayerEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode multiplayer response: %w", err)
	}
	return result.Events, nil
}

// GetInputAnomalies retrieves input anomaly detections.
func (c *Client) GetInputAnomalies(ctx context.Context, since time.Time, minSeverity string) ([]InputAnomaly, error) {
	path := fmt.Sprintf("/api/v1/anomalies/input?since=%s", since.Format(time.RFC3339))
	if minSeverity != "" {
		path += "&min_severity=" + url.QueryEscape(minSeverity)
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get input anomalies: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Anomalies []InputAnomaly `json:"anomalies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode anomalies response: %w", err)
	}
	return result.Anomalies, nil
}

// GetSaveLoadEvents retrieves save/load events.
func (c *Client) GetSaveLoadEvents(ctx context.Context, since time.Time, limit int) ([]SaveLoadEvent, error) {
	path := fmt.Sprintf("/api/v1/saveload?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get save/load events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []SaveLoadEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode save/load response: %w", err)
	}
	return result.Events, nil
}

// GetPerformanceMetrics retrieves performance telemetry.
func (c *Client) GetPerformanceMetrics(ctx context.Context, since time.Time, limit int) ([]PerformanceMetric, error) {
	path := fmt.Sprintf("/api/v1/performance?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get performance metrics: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Metrics []PerformanceMetric `json:"metrics"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode performance response: %w", err)
	}
	return result.Metrics, nil
}

// GetLeaderboardSubmissions retrieves leaderboard submissions.
func (c *Client) GetLeaderboardSubmissions(ctx context.Context, since time.Time, limit int) ([]LeaderboardSubmission, error) {
	path := fmt.Sprintf("/api/v1/leaderboard/submissions?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get leaderboard submissions: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Submissions []LeaderboardSubmission `json:"submissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode leaderboard response: %w", err)
	}
	return result.Submissions, nil
}

// GetDifficultyEvents retrieves difficulty scaling events.
func (c *Client) GetDifficultyEvents(ctx context.Context, since time.Time, limit int) ([]DifficultyEvent, error) {
	path := fmt.Sprintf("/api/v1/difficulty?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get difficulty events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []DifficultyEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode difficulty response: %w", err)
	}
	return result.Events, nil
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

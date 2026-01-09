// Package shredsquatch provides integration with the Shredsquatch snowboarding game telemetry.
// Shredsquatch is a Unity-based 3D first-person snowboarding game with procedural terrain.
package shredsquatch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the Shredsquatch telemetry API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the Shredsquatch client.
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
		BaseURL:      "http://localhost:9200",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}
}

// NewClient creates a new Shredsquatch client.
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
	ID          string                 `json:"id"`
	PlayerID    string                 `json:"player_id"`
	StartedAt   time.Time              `json:"started_at"`
	EndedAt     *time.Time             `json:"ended_at,omitempty"`
	Status      string                 `json:"status"`   // active, completed, crashed, abandoned
	Platform    string                 `json:"platform"` // webgl, steam, itch
	GameVersion string                 `json:"game_version"`
	Seed        int64                  `json:"terrain_seed"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// RunEvent represents a single descent/run.
type RunEvent struct {
	ID         string                 `json:"id"`
	SessionID  string                 `json:"session_id"`
	PlayerID   string                 `json:"player_id"`
	Timestamp  time.Time              `json:"timestamp"`
	EventType  string                 `json:"event_type"` // run_start, run_end, caught_by_sasquatch, crash
	Distance   float64                `json:"distance"`
	Score      int64                  `json:"score"`
	TrickScore int64                  `json:"trick_score"`
	Duration   float64                `json:"duration_seconds"`
	MaxSpeed   float64                `json:"max_speed"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// TrickEvent represents trick execution.
type TrickEvent struct {
	ID          string                 `json:"id"`
	SessionID   string                 `json:"session_id"`
	PlayerID    string                 `json:"player_id"`
	Timestamp   time.Time              `json:"timestamp"`
	TrickType   string                 `json:"trick_type"` // spin, grab, flip, combo, rail_grind
	TrickName   string                 `json:"trick_name"`
	Points      int64                  `json:"points"`
	Multiplier  float64                `json:"multiplier"`
	ComboLength int                    `json:"combo_length"`
	Landed      bool                   `json:"landed"`
	AirTime     float64                `json:"air_time"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// InputAnomaly represents suspicious input patterns.
type InputAnomaly struct {
	ID           string                 `json:"id"`
	SessionID    string                 `json:"session_id"`
	PlayerID     string                 `json:"player_id"`
	Timestamp    time.Time              `json:"timestamp"`
	AnomalyType  string                 `json:"anomaly_type"` // rapid_input, impossible_trick, timing_exploit
	Severity     string                 `json:"severity"`
	InputPattern string                 `json:"input_pattern"`
	Confidence   float64                `json:"confidence"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// LeaderboardSubmission represents a score submission.
type LeaderboardSubmission struct {
	ID            string                 `json:"id"`
	PlayerID      string                 `json:"player_id"`
	SessionID     string                 `json:"session_id"`
	RunID         string                 `json:"run_id"`
	Timestamp     time.Time              `json:"timestamp"`
	LeaderboardID string                 `json:"leaderboard_id"` // daily, weekly, all_time
	Distance      float64                `json:"distance"`
	Score         int64                  `json:"score"`
	TrickScore    int64                  `json:"trick_score"`
	Verified      bool                   `json:"verified"`
	Rank          int                    `json:"rank,omitempty"`
	Flags         []string               `json:"flags,omitempty"` // suspicious_score, replay_verified
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// PerformanceMetric represents game performance telemetry.
type PerformanceMetric struct {
	ID            string                 `json:"id"`
	SessionID     string                 `json:"session_id"`
	Timestamp     time.Time              `json:"timestamp"`
	FrameRate     float64                `json:"frame_rate"`
	MemoryUsage   int64                  `json:"memory_usage_mb"`
	DrawCalls     int                    `json:"draw_calls"`
	TerrainChunks int                    `json:"terrain_chunks"`
	ShaderCompile bool                   `json:"shader_compile"`
	Anomalies     []string               `json:"anomalies,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// AssetEvent represents asset loading events.
type AssetEvent struct {
	ID           string                 `json:"id"`
	SessionID    string                 `json:"session_id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"` // load_start, load_complete, load_failed
	AssetType    string                 `json:"asset_type"` // shader, terrain, model, audio
	AssetName    string                 `json:"asset_name"`
	LoadTime     float64                `json:"load_time_seconds"`
	Success      bool                   `json:"success"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// PowerupEvent represents powerup collection events.
type PowerupEvent struct {
	ID          string                 `json:"id"`
	SessionID   string                 `json:"session_id"`
	PlayerID    string                 `json:"player_id"`
	Timestamp   time.Time              `json:"timestamp"`
	PowerupType string                 `json:"powerup_type"` // golden_board, speed_boost, repellent, shield
	Effect      string                 `json:"effect"`
	Duration    float64                `json:"duration_seconds"`
	Location    map[string]float64     `json:"location"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SasquatchEvent represents Sasquatch AI events.
type SasquatchEvent struct {
	ID        string                 `json:"id"`
	SessionID string                 `json:"session_id"`
	PlayerID  string                 `json:"player_id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType string                 `json:"event_type"` // spawn, chase_start, caught, escaped, despawn
	Distance  float64                `json:"distance_to_player"`
	ChaseTime float64                `json:"chase_time_seconds"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// CollisionEvent represents collision events.
type CollisionEvent struct {
	ID            string                 `json:"id"`
	SessionID     string                 `json:"session_id"`
	PlayerID      string                 `json:"player_id"`
	Timestamp     time.Time              `json:"timestamp"`
	CollisionType string                 `json:"collision_type"` // tree, rock, rail, player, sasquatch
	Impact        float64                `json:"impact_force"`
	Ragdoll       bool                   `json:"ragdoll_triggered"`
	Damage        float64                `json:"damage"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
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
func (c *Client) GetSessions(ctx context.Context, status string, limit int) ([]GameSession, error) {
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
		Sessions []GameSession `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode sessions response: %w", err)
	}
	return result.Sessions, nil
}

// GetRunEvents retrieves run events.
func (c *Client) GetRunEvents(ctx context.Context, since time.Time, limit int) ([]RunEvent, error) {
	path := fmt.Sprintf("/api/v1/runs?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get runs: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Runs []RunEvent `json:"runs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode runs response: %w", err)
	}
	return result.Runs, nil
}

// GetTrickEvents retrieves trick events.
func (c *Client) GetTrickEvents(ctx context.Context, since time.Time, limit int) ([]TrickEvent, error) {
	path := fmt.Sprintf("/api/v1/tricks?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get tricks: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Tricks []TrickEvent `json:"tricks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode tricks response: %w", err)
	}
	return result.Tricks, nil
}

// GetInputAnomalies retrieves input anomaly detections.
func (c *Client) GetInputAnomalies(ctx context.Context, since time.Time, minSeverity string) ([]InputAnomaly, error) {
	path := fmt.Sprintf("/api/v1/anomalies?since=%s", since.Format(time.RFC3339))
	if minSeverity != "" {
		path += "&min_severity=" + url.QueryEscape(minSeverity)
	}
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get anomalies: %w", err)
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

// GetLeaderboardSubmissions retrieves leaderboard submissions.
func (c *Client) GetLeaderboardSubmissions(ctx context.Context, since time.Time, limit int) ([]LeaderboardSubmission, error) {
	path := fmt.Sprintf("/api/v1/leaderboard?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get leaderboard: %w", err)
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

// GetPerformanceMetrics retrieves performance telemetry.
func (c *Client) GetPerformanceMetrics(ctx context.Context, since time.Time, limit int) ([]PerformanceMetric, error) {
	path := fmt.Sprintf("/api/v1/performance?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get performance: %w", err)
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

// GetAssetEvents retrieves asset loading events.
func (c *Client) GetAssetEvents(ctx context.Context, since time.Time, limit int) ([]AssetEvent, error) {
	path := fmt.Sprintf("/api/v1/assets?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get assets: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []AssetEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode assets response: %w", err)
	}
	return result.Events, nil
}

// GetPowerupEvents retrieves powerup collection events.
func (c *Client) GetPowerupEvents(ctx context.Context, since time.Time, limit int) ([]PowerupEvent, error) {
	path := fmt.Sprintf("/api/v1/powerups?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get powerups: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []PowerupEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode powerups response: %w", err)
	}
	return result.Events, nil
}

// GetSasquatchEvents retrieves Sasquatch AI events.
func (c *Client) GetSasquatchEvents(ctx context.Context, since time.Time, limit int) ([]SasquatchEvent, error) {
	path := fmt.Sprintf("/api/v1/sasquatch?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get sasquatch events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []SasquatchEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode sasquatch response: %w", err)
	}
	return result.Events, nil
}

// GetCollisionEvents retrieves collision events.
func (c *Client) GetCollisionEvents(ctx context.Context, since time.Time, limit int) ([]CollisionEvent, error) {
	path := fmt.Sprintf("/api/v1/collisions?since=%s&limit=%d", since.Format(time.RFC3339), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get collisions: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []CollisionEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode collisions response: %w", err)
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

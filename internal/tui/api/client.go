// Package api provides HTTP client for connecting to Boundary-SIEM backend
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client handles API communication with the SIEM backend
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// Stats represents system statistics
type Stats struct {
	EventsTotal     int64   `json:"events_total"`
	EventsPerSecond float64 `json:"events_per_second"`
	QueueSize       int     `json:"queue_size"`
	QueueCapacity   int     `json:"queue_capacity"`
	Uptime          string  `json:"uptime"`
	Healthy         bool    `json:"healthy"`
}

// Event represents a security event
type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Category  string    `json:"category"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status    string            `json:"status"`
	Checks    map[string]string `json:"checks,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// MetricsResponse represents metrics response
type MetricsResponse struct {
	EventsReceived  int64   `json:"events_received"`
	EventsProcessed int64   `json:"events_processed"`
	EventsDropped   int64   `json:"events_dropped"`
	QueueDepth      int     `json:"queue_depth"`
	QueueCapacity   int     `json:"queue_capacity"`
	UptimeSeconds   float64 `json:"uptime_seconds"`
}

// NewClient creates a new API client
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// GetHealth fetches health status
func (c *Client) GetHealth() (*HealthResponse, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/health")
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, fmt.Errorf("failed to decode health response: %w", err)
	}

	return &health, nil
}

// GetMetrics fetches system metrics
func (c *Client) GetMetrics() (*MetricsResponse, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/metrics")
	if err != nil {
		return nil, fmt.Errorf("metrics fetch failed: %w", err)
	}
	defer resp.Body.Close()

	var metrics MetricsResponse
	if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
		return nil, fmt.Errorf("failed to decode metrics response: %w", err)
	}

	return &metrics, nil
}

// GetStats fetches combined stats for dashboard
func (c *Client) GetStats() (*Stats, error) {
	metrics, err := c.GetMetrics()
	if err != nil {
		// Return default stats on error
		return &Stats{
			Healthy: false,
		}, nil
	}

	health, _ := c.GetHealth()
	healthy := health != nil && health.Status == "ok"

	uptime := formatUptime(metrics.UptimeSeconds)

	return &Stats{
		EventsTotal:     metrics.EventsReceived,
		EventsPerSecond: float64(metrics.EventsProcessed) / metrics.UptimeSeconds,
		QueueSize:       metrics.QueueDepth,
		QueueCapacity:   metrics.QueueCapacity,
		Uptime:          uptime,
		Healthy:         healthy,
	}, nil
}

func formatUptime(seconds float64) string {
	d := time.Duration(seconds) * time.Second
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	secs := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, mins, secs)
	}
	if mins > 0 {
		return fmt.Sprintf("%dm %ds", mins, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

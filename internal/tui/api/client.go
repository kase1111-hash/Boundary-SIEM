// Package api provides HTTP client for connecting to Boundary-SIEM backend
package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
	HealthStatus    string  `json:"health_status"`
	StatusReason    string  `json:"status_reason"`
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
	Status        string `json:"status"`
	QueueDepth    int    `json:"queue_depth"`
	QueueCapacity int    `json:"queue_capacity"`
	UptimeSeconds int    `json:"uptime_seconds"`
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
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &health, nil
}

// parsePrometheusMetrics parses Prometheus-format metrics
func (c *Client) parsePrometheusMetrics(body string) map[string]float64 {
	metrics := make(map[string]float64)
	scanner := bufio.NewScanner(strings.NewReader(body))

	for scanner.Scan() {
		line := scanner.Text()
		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// Parse metric line: metric_name value
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			if val, err := strconv.ParseFloat(parts[1], 64); err == nil {
				metrics[parts[0]] = val
			}
		}
	}
	return metrics
}

// GetStats fetches combined stats for dashboard
func (c *Client) GetStats() (*Stats, error) {
	// Get health status first
	health, healthErr := c.GetHealth()

	stats := &Stats{
		Healthy:      false,
		HealthStatus: "unknown",
		StatusReason: "Unable to connect to backend",
	}

	if healthErr != nil {
		stats.StatusReason = healthErr.Error()
		return stats, nil
	}

	// Health endpoint returns status as "healthy" or "degraded"
	stats.HealthStatus = health.Status
	stats.Healthy = health.Status == "healthy"
	stats.QueueSize = health.QueueDepth
	stats.QueueCapacity = health.QueueCapacity
	stats.Uptime = formatUptime(float64(health.UptimeSeconds))

	if health.Status == "degraded" {
		queuePercent := 0.0
		if health.QueueCapacity > 0 {
			queuePercent = float64(health.QueueDepth) / float64(health.QueueCapacity) * 100
		}
		stats.StatusReason = fmt.Sprintf("Queue at %.0f%% capacity", queuePercent)
	} else if stats.Healthy {
		stats.StatusReason = "All systems operational"
	}

	// Try to get additional metrics from Prometheus endpoint
	resp, err := c.httpClient.Get(c.baseURL + "/metrics")
	if err == nil {
		defer resp.Body.Close()
		buf := new(strings.Builder)
		buf.Grow(4096)
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			buf.WriteString(scanner.Text())
			buf.WriteString("\n")
		}
		metrics := c.parsePrometheusMetrics(buf.String())

		if total, ok := metrics["siem_events_total"]; ok {
			stats.EventsTotal = int64(total)
		}
		if uptime, ok := metrics["siem_uptime_seconds"]; ok && uptime > 0 {
			stats.EventsPerSecond = float64(stats.EventsTotal) / uptime
		}
	}

	return stats, nil
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

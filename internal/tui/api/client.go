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
	QueuePushed     int64   `json:"queue_pushed"`
	QueuePopped     int64   `json:"queue_popped"`
	QueueDropped    int64   `json:"queue_dropped"`
	QueueUsage      float64 `json:"queue_usage_percent"`
	Uptime          string  `json:"uptime"`
	UptimeSeconds   int     `json:"uptime_seconds"`
	Healthy         bool    `json:"healthy"`
	HealthStatus    string  `json:"health_status"`
	StatusReason    string  `json:"status_reason"`
	Activity        string  `json:"activity"`
	ActivityDesc    string  `json:"activity_description"`
}

// DreamingResponse represents the system dreaming status
type DreamingResponse struct {
	Status      string          `json:"status"`
	Activity    string          `json:"activity"`
	Description string          `json:"description"`
	Metrics     DreamingMetrics `json:"metrics"`
}

// DreamingMetrics contains operational metrics from dreaming endpoint
type DreamingMetrics struct {
	EventsTotal   int64   `json:"events_total"`
	QueueDepth    int     `json:"queue_depth"`
	QueueCapacity int     `json:"queue_capacity"`
	QueueUsage    float64 `json:"queue_usage_percent"`
	UptimeSeconds int     `json:"uptime_seconds"`
	EventsPerSec  float64 `json:"events_per_second"`
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

// GetDreaming fetches the system dreaming status
func (c *Client) GetDreaming() (*DreamingResponse, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/api/system/dreaming")
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	var dreaming DreamingResponse
	if err := json.NewDecoder(resp.Body).Decode(&dreaming); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &dreaming, nil
}

// GetStats fetches combined stats for dashboard
func (c *Client) GetStats() (*Stats, error) {
	// Get health status first
	health, healthErr := c.GetHealth()

	stats := &Stats{
		Healthy:      false,
		HealthStatus: "unknown",
		StatusReason: "Unable to connect to backend",
		Activity:     "unknown",
		ActivityDesc: "Cannot connect to backend service",
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
	stats.UptimeSeconds = health.UptimeSeconds
	stats.Uptime = formatUptime(float64(health.UptimeSeconds))

	// Calculate queue usage percent
	if health.QueueCapacity > 0 {
		stats.QueueUsage = float64(health.QueueDepth) / float64(health.QueueCapacity) * 100
	}

	if health.Status == "degraded" {
		stats.StatusReason = fmt.Sprintf("Queue at %.0f%% capacity", stats.QueueUsage)
	} else if stats.Healthy {
		stats.StatusReason = "All systems operational"
	}

	// Try to get dreaming status (activity info)
	if dreaming, err := c.GetDreaming(); err == nil {
		stats.Activity = dreaming.Activity
		stats.ActivityDesc = dreaming.Description
		// Use dreaming metrics if available (more comprehensive)
		stats.EventsTotal = dreaming.Metrics.EventsTotal
		stats.EventsPerSecond = dreaming.Metrics.EventsPerSec
		stats.QueueUsage = dreaming.Metrics.QueueUsage
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

		// Queue processing metrics
		if pushed, ok := metrics["siem_queue_pushed_total"]; ok {
			stats.QueuePushed = int64(pushed)
		}
		if popped, ok := metrics["siem_queue_popped_total"]; ok {
			stats.QueuePopped = int64(popped)
		}
		if dropped, ok := metrics["siem_queue_dropped_total"]; ok {
			stats.QueueDropped = int64(dropped)
		}

		// Fallback to prometheus metrics if dreaming failed
		if stats.EventsTotal == 0 {
			if total, ok := metrics["siem_events_total"]; ok {
				stats.EventsTotal = int64(total)
			}
		}
		if stats.EventsPerSecond == 0 {
			if uptime, ok := metrics["siem_uptime_seconds"]; ok && uptime > 0 {
				stats.EventsPerSecond = float64(stats.EventsTotal) / uptime
			}
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

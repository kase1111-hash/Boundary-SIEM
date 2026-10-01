// Package api provides HTTP client for connecting to Boundary-SIEM backend
package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultAuthHeader is the header siem-ingest reads the API key from unless
// auth.api_key_header in config.yaml says otherwise.
const DefaultAuthHeader = "X-API-Key"

// Authentication states reported in Stats.AuthStatus.
const (
	AuthUnknown     = "unknown"
	AuthAccepted    = "accepted"
	AuthNotRequired = "not required"
	AuthRejected    = "rejected"
)

// maxErrorBody bounds how much of an error response body is read.
const maxErrorBody = 4096

// Client handles API communication with the SIEM backend
type Client struct {
	baseURL      string
	httpClient   *http.Client
	apiKey       string
	apiKeyHeader string
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey sets the API key sent with every request.
func WithAPIKey(key string) Option {
	return func(c *Client) {
		c.apiKey = key
	}
}

// WithAPIKeyHeader overrides the header the API key is sent in. An empty
// name keeps DefaultAuthHeader.
func WithAPIKeyHeader(header string) Option {
	return func(c *Client) {
		if header != "" {
			c.apiKeyHeader = header
		}
	}
}

// HTTPError is returned when the backend answers with a non-2xx status.
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// ComponentStatus is the state of one server module as reported in the
// optional "components" object of GET /health. The server may send either a
// bare status string ("up") or an object ({"status":"up","address":":5514"}).
type ComponentStatus struct {
	Status  string `json:"status"`
	Enabled *bool  `json:"enabled,omitempty"`
	Address string `json:"address,omitempty"`
	Message string `json:"message,omitempty"`
}

// UnmarshalJSON accepts both the string and the object form.
func (cs *ComponentStatus) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*cs = ComponentStatus{Status: sanitizeText(s)}
		return nil
	}
	type plain ComponentStatus
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*cs = ComponentStatus(p)
	cs.sanitize()
	return nil
}

// sanitize strips terminal control sequences from the server-supplied text.
func (cs *ComponentStatus) sanitize() {
	cs.Status = sanitizeText(cs.Status)
	cs.Address = sanitizeText(cs.Address)
	cs.Message = sanitizeText(cs.Message)
}

// sanitizeComponents returns components whose keys are safe to print; the
// values were sanitized when decoded.
func sanitizeComponents(in map[string]ComponentStatus) map[string]ComponentStatus {
	if in == nil {
		return nil
	}
	out := make(map[string]ComponentStatus, len(in))
	for key, cs := range in {
		if key = sanitizeText(key); key != "" {
			out[key] = cs
		}
	}
	return out
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

	// Connected is true when GET /health answered successfully.
	Connected bool `json:"connected"`
	// Reachable is true when the server sent any HTTP response to GET
	// /health, including an error status. Connected implies Reachable.
	Reachable bool `json:"reachable"`
	// AuthStatus is AuthUnknown, AuthAccepted, AuthNotRequired or
	// AuthRejected, derived from an authenticated request.
	AuthStatus string `json:"auth_status"`
	// AuthDetail carries the server's reason when the check failed.
	AuthDetail string `json:"auth_detail,omitempty"`
	// Components holds module status reported by /health, if any.
	Components map[string]ComponentStatus `json:"components,omitempty"`
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
	ID        string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Severity  int       `json:"severity"`
	Action    string    `json:"action"`
	Outcome   string    `json:"outcome"`
	Target    string    `json:"target,omitempty"`
	Actor     string    `json:"actor,omitempty"`
	Message   string    `json:"message"`
}

// SearchResponse represents the response from the search API
type SearchResponse struct {
	Results    []SearchResult `json:"results"`
	TotalCount int64          `json:"total_count"`
	Took       int64          `json:"took_ms"`
	Limit      int            `json:"limit"`
	Offset     int            `json:"offset"`
}

// SearchResult represents a single search result from the backend
type SearchResult struct {
	EventID       string                 `json:"event_id"`
	Timestamp     time.Time              `json:"timestamp"`
	ReceivedAt    time.Time              `json:"received_at"`
	TenantID      string                 `json:"tenant_id"`
	Action        string                 `json:"action"`
	Severity      int                    `json:"severity"`
	Outcome       string                 `json:"outcome"`
	Target        string                 `json:"target,omitempty"`
	Raw           string                 `json:"raw,omitempty"`
	SourceProduct string                 `json:"source_product"`
	SourceVendor  string                 `json:"source_vendor"`
	SourceIP      string                 `json:"source_ip,omitempty"`
	ActorName     string                 `json:"actor_name,omitempty"`
	ActorID       string                 `json:"actor_id,omitempty"`
	ActorIP       string                 `json:"actor_ip,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status        string                     `json:"status"`
	QueueDepth    int                        `json:"queue_depth"`
	QueueCapacity int                        `json:"queue_capacity"`
	UptimeSeconds int                        `json:"uptime_seconds"`
	Components    map[string]ComponentStatus `json:"components,omitempty"`
}

// NewClient creates a new API client. Options such as WithAPIKey configure
// authentication; without them no credentials are sent.
func NewClient(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		apiKeyHeader: DefaultAuthHeader,
	}
	c.httpClient = &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: c.checkRedirect,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// maxRedirects matches net/http's default redirect limit.
const maxRedirects = 10

// checkRedirect drops the API key when a redirect leaves the origin of the
// original request. net/http copies custom headers such as X-API-Key on
// every redirect (it only strips Authorization and cookies across domains),
// so without this a redirect to another host, or from https to http, would
// hand the key to a third party or send it in cleartext.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	orig := via[0].URL
	if !strings.EqualFold(req.URL.Scheme, orig.Scheme) || !strings.EqualFold(req.URL.Host, orig.Host) {
		req.Header.Del(c.apiKeyHeader)
	}
	return nil
}

// BaseURL returns the server URL the client talks to.
func (c *Client) BaseURL() string {
	if c == nil {
		return ""
	}
	return c.baseURL
}

// HasAPIKey reports whether an API key is configured.
func (c *Client) HasAPIKey() bool {
	return c.apiKey != ""
}

// get issues a GET request for path, attaching the API key if configured.
func (c *Client) get(path string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set(c.apiKeyHeader, c.apiKey)
	}
	return c.httpClient.Do(req)
}

// checkStatus converts a non-2xx response into an *HTTPError carrying the
// server's error message.
func checkStatus(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	return &HTTPError{StatusCode: resp.StatusCode, Message: errorMessage(body)}
}

// errorMessage extracts the "error" (or, as the rate limiter sends it,
// "message") field of a JSON error body, falling back to the body text. HTML
// error pages (reverse proxies) are dropped. The result is sanitized for
// display on one terminal line.
func errorMessage(body []byte) string {
	var parsed struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		if parsed.Error != "" {
			return sanitizeText(parsed.Error)
		}
		if parsed.Message != "" {
			return sanitizeText(parsed.Message)
		}
	}
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "<") {
		return ""
	}
	return sanitizeText(text)
}

// GetHealth fetches health status
func (c *Client) GetHealth() (*HealthResponse, error) {
	resp, err := c.get("/health")
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if err := checkStatus(resp); err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}

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

// GetDreaming fetches the system dreaming status. A non-2xx answer (for
// example 401 when the API key is missing) is returned as an *HTTPError.
func (c *Client) GetDreaming() (*DreamingResponse, error) {
	resp, err := c.get("/api/system/dreaming")
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if err := checkStatus(resp); err != nil {
		return nil, err
	}

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
		AuthStatus:   AuthUnknown,
	}

	if healthErr != nil {
		stats.StatusReason = healthErr.Error()
		var httpErr *HTTPError
		if errors.As(healthErr, &httpErr) {
			// The server answered, just not successfully.
			stats.Reachable = true
			stats.HealthStatus = "error"
		}
		return stats, nil
	}

	// Health endpoint returns status as "healthy" or "degraded"
	stats.Connected = true
	stats.Reachable = true
	stats.Components = sanitizeComponents(health.Components)
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

	// Try to get dreaming status (activity info). /health and /metrics are
	// public, so this authenticated endpoint also tells whether the API key
	// is accepted.
	dreaming, err := c.GetDreaming()
	if err == nil {
		stats.AuthStatus = AuthAccepted
		if c.apiKey == "" {
			stats.AuthStatus = AuthNotRequired
		}
		stats.Activity = dreaming.Activity
		stats.ActivityDesc = dreaming.Description
		// Use dreaming metrics if available (more comprehensive)
		stats.EventsTotal = dreaming.Metrics.EventsTotal
		stats.EventsPerSecond = dreaming.Metrics.EventsPerSec
		stats.QueueUsage = dreaming.Metrics.QueueUsage
	} else {
		var httpErr *HTTPError
		if errors.As(err, &httpErr) &&
			(httpErr.StatusCode == http.StatusUnauthorized || httpErr.StatusCode == http.StatusForbidden) {
			stats.AuthStatus = AuthRejected
			stats.AuthDetail = httpErr.Message
		} else {
			stats.AuthDetail = err.Error()
		}
	}

	// Try to get additional metrics from Prometheus endpoint
	if metrics, err := c.getMetrics(); err == nil {
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

// getMetrics fetches and parses GET /metrics.
func (c *Client) getMetrics() (map[string]float64, error) {
	resp, err := c.get("/metrics")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := checkStatus(resp); err != nil {
		return nil, err
	}

	buf := new(strings.Builder)
	buf.Grow(4096)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		buf.WriteString(scanner.Text())
		buf.WriteString("\n")
	}
	return c.parsePrometheusMetrics(buf.String()), nil
}

// EventsResponse wraps the events list with metadata
type EventsResponse struct {
	Events     []Event `json:"events"`
	TotalCount int64   `json:"total_count"`
	HasMore    bool    `json:"has_more"`
	Error      string  `json:"error,omitempty"`
	// StatusCode is the HTTP status of a failed search (0 when no response
	// was received).
	StatusCode int `json:"status_code,omitempty"`
	// Hint suggests how to resolve Error.
	Hint string `json:"hint,omitempty"`
}

// searchErrorHint explains a failed search request to the operator.
func searchErrorHint(status int) string {
	switch {
	case status == 0:
		return "Check that siem-ingest is running and reachable at the -server URL."
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return "Set a valid API key with -api-key or SIEM_API_KEY (header name: -api-key-header)."
	case status == http.StatusNotFound:
		return "The search API is not registered: enable storage in config.yaml to persist and query events."
	case status >= 500:
		return "The server failed to run the search; check the siem-ingest logs."
	default:
		return "The server rejected the search request."
	}
}

// GetEvents fetches events from the search API
func (c *Client) GetEvents(limit int) (*EventsResponse, error) {
	if limit <= 0 {
		limit = 50
	}

	resp, err := c.get(fmt.Sprintf("/v1/search?limit=%d&order=desc", limit))
	if err != nil {
		return &EventsResponse{
			Error: fmt.Sprintf("connection failed: %v", err),
			Hint:  searchErrorHint(0),
		}, nil
	}
	defer resp.Body.Close()

	if err := checkStatus(resp); err != nil {
		status := 0
		var httpErr *HTTPError
		if errors.As(err, &httpErr) {
			status = httpErr.StatusCode
		}
		return &EventsResponse{
			Error:      fmt.Sprintf("search API returned %v", err),
			StatusCode: status,
			Hint:       searchErrorHint(status),
		}, nil
	}

	var searchResp SearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return &EventsResponse{
			Error: fmt.Sprintf("failed to decode response: %v", err),
		}, nil
	}

	// Convert SearchResults to Events
	events := make([]Event, 0, len(searchResp.Results))
	for _, r := range searchResp.Results {
		event := Event{
			ID:        r.EventID,
			Timestamp: r.Timestamp,
			Source:    r.SourceProduct,
			Severity:  r.Severity,
			Action:    r.Action,
			Outcome:   r.Outcome,
			Target:    r.Target,
		}
		// Use vendor as source if product is empty
		if event.Source == "" && r.SourceVendor != "" {
			event.Source = r.SourceVendor
		}
		if r.ActorName != "" {
			event.Actor = r.ActorName
		}
		// Build a message from action and outcome
		event.Message = r.Action
		if r.Outcome != "" {
			event.Message = fmt.Sprintf("%s (%s)", r.Action, r.Outcome)
		}
		events = append(events, event)
	}

	return &EventsResponse{
		Events:     events,
		TotalCount: searchResp.TotalCount,
		HasMore:    int64(len(events)) < searchResp.TotalCount,
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

// Package boundarydaemon provides integration with the Boundary Daemon security service.
// Boundary Daemon monitors system boundaries, enforces security policies, and generates
// audit events including session management, authentication, access control, and threat detection.
package boundarydaemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client provides access to the Boundary Daemon API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// ClientConfig holds configuration for the Boundary Daemon client.
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

// NewClient creates a new Boundary Daemon client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		apiKey:  cfg.APIKey,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// SessionEvent represents a session management event from Boundary Daemon.
type SessionEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"` // session.created, session.terminated, session.expired
	SessionID   string                 `json:"session_id"`
	UserID      string                 `json:"user_id"`
	Username    string                 `json:"username"`
	SourceIP    string                 `json:"source_ip"`
	DestIP      string                 `json:"dest_ip"`
	Protocol    string                 `json:"protocol"`
	Port        int                    `json:"port"`
	Duration    int64                  `json:"duration_ms,omitempty"`
	TermReason  string                 `json:"termination_reason,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AuthEvent represents an authentication event from Boundary Daemon.
type AuthEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"` // auth.login, auth.logout, auth.failure, auth.mfa_failure
	UserID       string                 `json:"user_id"`
	Username     string                 `json:"username"`
	SourceIP     string                 `json:"source_ip"`
	AuthMethod   string                 `json:"auth_method"` // password, mfa, certificate, token
	Success      bool                   `json:"success"`
	FailReason   string                 `json:"failure_reason,omitempty"`
	MFAType      string                 `json:"mfa_type,omitempty"`
	SessionID    string                 `json:"session_id,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// AccessEvent represents an access control event from Boundary Daemon.
type AccessEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"` // access.granted, access.denied
	UserID      string                 `json:"user_id"`
	Username    string                 `json:"username"`
	SessionID   string                 `json:"session_id"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"` // read, write, execute, delete
	Granted     bool                   `json:"granted"`
	DenyReason  string                 `json:"deny_reason,omitempty"`
	PolicyID    string                 `json:"policy_id,omitempty"`
	RuleID      string                 `json:"rule_id,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ThreatEvent represents a threat detection event from Boundary Daemon.
type ThreatEvent struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	EventType     string                 `json:"event_type"` // threat.detected, threat.blocked, threat.quarantined
	ThreatType    string                 `json:"threat_type"` // malware, intrusion, policy_violation, anomaly
	Severity      string                 `json:"severity"`    // low, medium, high, critical
	SourceIP      string                 `json:"source_ip,omitempty"`
	DestIP        string                 `json:"dest_ip,omitempty"`
	UserID        string                 `json:"user_id,omitempty"`
	ProcessName   string                 `json:"process_name,omitempty"`
	ProcessPath   string                 `json:"process_path,omitempty"`
	Description   string                 `json:"description"`
	Indicators    []string               `json:"indicators,omitempty"`
	MITREAttack   []string               `json:"mitre_attack,omitempty"`
	ActionTaken   string                 `json:"action_taken"`
	Blocked       bool                   `json:"blocked"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyEvent represents a policy enforcement event from Boundary Daemon.
type PolicyEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"` // policy.applied, policy.violated, policy.changed
	PolicyID    string                 `json:"policy_id"`
	PolicyName  string                 `json:"policy_name"`
	PolicyType  string                 `json:"policy_type"` // access, network, process, file, usb
	Action      string                 `json:"action"`
	Target      string                 `json:"target"`
	UserID      string                 `json:"user_id,omitempty"`
	Enforced    bool                   `json:"enforced"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AuditLogEntry represents an immutable audit log entry with cryptographic verification.
type AuditLogEntry struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	EventType     string                 `json:"event_type"`
	Actor         string                 `json:"actor"`
	Action        string                 `json:"action"`
	Target        string                 `json:"target"`
	Outcome       string                 `json:"outcome"` // success, failure, partial
	ContentHash   string                 `json:"content_hash"`
	PreviousHash  string                 `json:"previous_hash"`
	Signature     string                 `json:"signature"`
	SignatureAlgo string                 `json:"signature_algo"` // ed25519, ecdsa
	Verified      bool                   `json:"verified"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// DaemonStatus represents the health and status of the Boundary Daemon.
type DaemonStatus struct {
	Status        string    `json:"status"`
	Ready         bool      `json:"ready"`
	Live          bool      `json:"live"`
	Version       string    `json:"version"`
	Mode          string    `json:"mode"` // normal, lockdown, maintenance
	Uptime        int64     `json:"uptime_seconds"`
	ActiveSessions int      `json:"active_sessions"`
	ThreatLevel   string    `json:"threat_level"` // low, medium, high, critical
	LastEvent     time.Time `json:"last_event"`
	Timestamp     time.Time `json:"timestamp"`
}

// DaemonStats represents statistics from the Boundary Daemon.
type DaemonStats struct {
	TotalSessions      int64     `json:"total_sessions"`
	ActiveSessions     int       `json:"active_sessions"`
	TotalAuthAttempts  int64     `json:"total_auth_attempts"`
	FailedAuthAttempts int64     `json:"failed_auth_attempts"`
	TotalAccessChecks  int64     `json:"total_access_checks"`
	DeniedAccesses     int64     `json:"denied_accesses"`
	ThreatsDetected    int64     `json:"threats_detected"`
	ThreatsBlocked     int64     `json:"threats_blocked"`
	PoliciesActive     int       `json:"policies_active"`
	LastUpdated        time.Time `json:"last_updated"`
}

// GetHealth checks the health of the Boundary Daemon.
func (c *Client) GetHealth(ctx context.Context) (*DaemonStatus, error) {
	resp, err := c.doRequest(ctx, "GET", "/health", nil)
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	var status DaemonStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode health response: %w", err)
	}
	status.Timestamp = time.Now().UTC()
	return &status, nil
}

// GetStats retrieves daemon statistics.
func (c *Client) GetStats(ctx context.Context) (*DaemonStats, error) {
	resp, err := c.doRequest(ctx, "GET", "/api/v1/stats", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}
	defer resp.Body.Close()

	var stats DaemonStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode stats response: %w", err)
	}
	return &stats, nil
}

// GetSessionEvents retrieves session events since a given time.
func (c *Client) GetSessionEvents(ctx context.Context, since time.Time, limit int) ([]SessionEvent, error) {
	path := fmt.Sprintf("/api/v1/events/sessions?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get session events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []SessionEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode session events response: %w", err)
	}
	return result.Events, nil
}

// GetAuthEvents retrieves authentication events since a given time.
func (c *Client) GetAuthEvents(ctx context.Context, since time.Time, limit int) ([]AuthEvent, error) {
	path := fmt.Sprintf("/api/v1/events/auth?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []AuthEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode auth events response: %w", err)
	}
	return result.Events, nil
}

// GetAccessEvents retrieves access control events since a given time.
func (c *Client) GetAccessEvents(ctx context.Context, since time.Time, limit int) ([]AccessEvent, error) {
	path := fmt.Sprintf("/api/v1/events/access?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get access events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []AccessEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode access events response: %w", err)
	}
	return result.Events, nil
}

// GetThreatEvents retrieves threat detection events since a given time.
func (c *Client) GetThreatEvents(ctx context.Context, since time.Time, limit int) ([]ThreatEvent, error) {
	path := fmt.Sprintf("/api/v1/events/threats?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get threat events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []ThreatEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode threat events response: %w", err)
	}
	return result.Events, nil
}

// GetPolicyEvents retrieves policy enforcement events since a given time.
func (c *Client) GetPolicyEvents(ctx context.Context, since time.Time, limit int) ([]PolicyEvent, error) {
	path := fmt.Sprintf("/api/v1/events/policies?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy events: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Events []PolicyEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode policy events response: %w", err)
	}
	return result.Events, nil
}

// GetAuditLogs retrieves cryptographically signed audit log entries.
func (c *Client) GetAuditLogs(ctx context.Context, since time.Time, limit int) ([]AuditLogEntry, error) {
	path := fmt.Sprintf("/api/v1/audit/logs?since=%s&limit=%d",
		url.QueryEscape(since.Format(time.RFC3339)), limit)
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Logs []AuditLogEntry `json:"logs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode audit logs response: %w", err)
	}
	return result.Logs, nil
}

// VerifyAuditLog verifies the cryptographic signature of an audit log entry.
func (c *Client) VerifyAuditLog(ctx context.Context, logID string) (*AuditLogEntry, error) {
	path := fmt.Sprintf("/api/v1/audit/verify/%s", url.PathEscape(logID))
	resp, err := c.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit log: %w", err)
	}
	defer resp.Body.Close()

	var entry AuditLogEntry
	if err := json.NewDecoder(resp.Body).Decode(&entry); err != nil {
		return nil, fmt.Errorf("failed to decode audit log response: %w", err)
	}
	return &entry, nil
}

// doRequest performs an HTTP request to the Boundary Daemon API.
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

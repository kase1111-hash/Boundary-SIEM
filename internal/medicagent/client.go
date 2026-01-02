package medicagent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client communicates with the Medic-Agent API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
}

// ClientConfig holds configuration for the Medic-Agent client.
type ClientConfig struct {
	BaseURL    string        `yaml:"base_url"`
	APIKey     string        `yaml:"api_key"`
	Timeout    time.Duration `yaml:"timeout"`
	MaxRetries int           `yaml:"max_retries"`
}

// DefaultClientConfig returns the default client configuration.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		BaseURL:    "http://localhost:9300",
		Timeout:    30 * time.Second,
		MaxRetries: 3,
	}
}

// NewClient creates a new Medic-Agent API client.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		baseURL: cfg.BaseURL,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		apiKey: cfg.APIKey,
	}
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status           string `json:"status"`
	Version          string `json:"version"`
	ActiveMonitors   int    `json:"active_monitors"`
	PendingApprovals int    `json:"pending_approvals"`
	Uptime           int64  `json:"uptime_seconds"`
}

// GetHealth checks the Medic-Agent service health.
func (c *Client) GetHealth(ctx context.Context) (*HealthResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/health", nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("health check failed: %d", resp.StatusCode)
	}

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return nil, err
	}
	return &health, nil
}

// KillNotification represents a Smith kill report received by medic-agent.
type KillNotification struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	ProcessID     string                 `json:"process_id"`
	ProcessName   string                 `json:"process_name"`
	KillReason    string                 `json:"kill_reason"`
	SmithNodeID   string                 `json:"smith_node_id"`
	Severity      string                 `json:"severity"`
	ResourceUsage map[string]float64     `json:"resource_usage"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// GetKillNotifications retrieves recent kill notifications.
func (c *Client) GetKillNotifications(ctx context.Context, since time.Time, limit int) ([]KillNotification, error) {
	url := fmt.Sprintf("%s/api/v1/kills?since=%s&limit=%d", c.baseURL, since.Format(time.RFC3339), limit)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get kill notifications: %d", resp.StatusCode)
	}

	var kills []KillNotification
	if err := json.NewDecoder(resp.Body).Decode(&kills); err != nil {
		return nil, err
	}
	return kills, nil
}

// RiskAssessment represents a legitimacy evaluation of a kill.
type RiskAssessment struct {
	ID                string                 `json:"id"`
	Timestamp         time.Time              `json:"timestamp"`
	KillID            string                 `json:"kill_id"`
	ProcessID         string                 `json:"process_id"`
	RiskScore         float64                `json:"risk_score"`
	Verdict           string                 `json:"verdict"` // legitimate, suspicious, invalid
	Factors           []RiskFactor           `json:"factors"`
	RecommendedAction string                 `json:"recommended_action"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// RiskFactor represents a contributing factor to risk assessment.
type RiskFactor struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
	Value  float64 `json:"value"`
	Impact string  `json:"impact"`
}

// GetRiskAssessments retrieves risk assessments.
func (c *Client) GetRiskAssessments(ctx context.Context, since time.Time, limit int) ([]RiskAssessment, error) {
	url := fmt.Sprintf("%s/api/v1/assessments?since=%s&limit=%d", c.baseURL, since.Format(time.RFC3339), limit)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get risk assessments: %d", resp.StatusCode)
	}

	var assessments []RiskAssessment
	if err := json.NewDecoder(resp.Body).Decode(&assessments); err != nil {
		return nil, err
	}
	return assessments, nil
}

// ResurrectionEvent represents a process resurrection workflow event.
type ResurrectionEvent struct {
	ID              string                 `json:"id"`
	Timestamp       time.Time              `json:"timestamp"`
	KillID          string                 `json:"kill_id"`
	ProcessID       string                 `json:"process_id"`
	ProcessName     string                 `json:"process_name"`
	Status          string                 `json:"status"` // initiated, approved, rejected, completed, failed, rolled_back
	ApprovalChain   []ApprovalStep         `json:"approval_chain"`
	ResurrectionTTL int                    `json:"resurrection_ttl_seconds"`
	Attempts        int                    `json:"attempts"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ApprovalStep represents a step in the approval workflow.
type ApprovalStep struct {
	Approver  string    `json:"approver"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
	Reason    string    `json:"reason,omitempty"`
}

// GetResurrectionEvents retrieves resurrection workflow events.
func (c *Client) GetResurrectionEvents(ctx context.Context, since time.Time, limit int) ([]ResurrectionEvent, error) {
	url := fmt.Sprintf("%s/api/v1/resurrections?since=%s&limit=%d", c.baseURL, since.Format(time.RFC3339), limit)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get resurrection events: %d", resp.StatusCode)
	}

	var events []ResurrectionEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, err
	}
	return events, nil
}

// AnomalyEvent represents an anomaly detected by medic-agent.
type AnomalyEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	Type         string                 `json:"type"` // kill_pattern, resurrection_abuse, threshold_violation, etc.
	Severity     string                 `json:"severity"`
	Description  string                 `json:"description"`
	AffectedIDs  []string               `json:"affected_ids"`
	Indicators   []AnomalyIndicator     `json:"indicators"`
	AutoResponse string                 `json:"auto_response,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// AnomalyIndicator represents a specific indicator of anomaly.
type AnomalyIndicator struct {
	Name      string  `json:"name"`
	Value     float64 `json:"value"`
	Threshold float64 `json:"threshold"`
	Deviation float64 `json:"deviation"`
}

// GetAnomalyEvents retrieves detected anomalies.
func (c *Client) GetAnomalyEvents(ctx context.Context, since time.Time, minSeverity string) ([]AnomalyEvent, error) {
	url := fmt.Sprintf("%s/api/v1/anomalies?since=%s&min_severity=%s", c.baseURL, since.Format(time.RFC3339), minSeverity)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get anomaly events: %d", resp.StatusCode)
	}

	var events []AnomalyEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, err
	}
	return events, nil
}

// ThresholdAdjustment represents a dynamic threshold change.
type ThresholdAdjustment struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	ThresholdKey string                 `json:"threshold_key"`
	OldValue     float64                `json:"old_value"`
	NewValue     float64                `json:"new_value"`
	Reason       string                 `json:"reason"`
	Triggeredby  string                 `json:"triggered_by"` // auto, manual, policy
	AppliedTo    []string               `json:"applied_to"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// GetThresholdAdjustments retrieves threshold adjustment events.
func (c *Client) GetThresholdAdjustments(ctx context.Context, since time.Time, limit int) ([]ThresholdAdjustment, error) {
	url := fmt.Sprintf("%s/api/v1/thresholds/adjustments?since=%s&limit=%d", c.baseURL, since.Format(time.RFC3339), limit)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get threshold adjustments: %d", resp.StatusCode)
	}

	var adjustments []ThresholdAdjustment
	if err := json.NewDecoder(resp.Body).Decode(&adjustments); err != nil {
		return nil, err
	}
	return adjustments, nil
}

// RollbackEvent represents a resurrection rollback event.
type RollbackEvent struct {
	ID              string                 `json:"id"`
	Timestamp       time.Time              `json:"timestamp"`
	ResurrectionID  string                 `json:"resurrection_id"`
	ProcessID       string                 `json:"process_id"`
	Reason          string                 `json:"reason"`
	InitiatedBy     string                 `json:"initiated_by"`
	RollbackStatus  string                 `json:"rollback_status"`
	StateSnapshot   string                 `json:"state_snapshot,omitempty"`
	RecoveryActions []string               `json:"recovery_actions"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// GetRollbackEvents retrieves rollback events.
func (c *Client) GetRollbackEvents(ctx context.Context, since time.Time, limit int) ([]RollbackEvent, error) {
	url := fmt.Sprintf("%s/api/v1/rollbacks?since=%s&limit=%d", c.baseURL, since.Format(time.RFC3339), limit)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get rollback events: %d", resp.StatusCode)
	}

	var events []RollbackEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, err
	}
	return events, nil
}

// ApprovalWorkflowEvent represents approval workflow activity.
type ApprovalWorkflowEvent struct {
	ID             string                 `json:"id"`
	Timestamp      time.Time              `json:"timestamp"`
	WorkflowID     string                 `json:"workflow_id"`
	ResurrectionID string                 `json:"resurrection_id"`
	Step           int                    `json:"step"`
	Approver       string                 `json:"approver"`
	Action         string                 `json:"action"` // requested, approved, rejected, escalated, timeout
	Reason         string                 `json:"reason,omitempty"`
	TimeToDecision int                    `json:"time_to_decision_seconds"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// GetApprovalEvents retrieves approval workflow events.
func (c *Client) GetApprovalEvents(ctx context.Context, since time.Time, limit int) ([]ApprovalWorkflowEvent, error) {
	url := fmt.Sprintf("%s/api/v1/approvals?since=%s&limit=%d", c.baseURL, since.Format(time.RFC3339), limit)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get approval events: %d", resp.StatusCode)
	}

	var events []ApprovalWorkflowEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, err
	}
	return events, nil
}

// SmithIntegrationEvent represents Smith event bus integration activity.
type SmithIntegrationEvent struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"`
	SmithNodeID  string                 `json:"smith_node_id"`
	Direction    string                 `json:"direction"` // inbound, outbound
	Status       string                 `json:"status"`
	PayloadSize  int                    `json:"payload_size_bytes"`
	Latency      int                    `json:"latency_ms"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// GetSmithIntegrationEvents retrieves Smith integration events.
func (c *Client) GetSmithIntegrationEvents(ctx context.Context, since time.Time, limit int) ([]SmithIntegrationEvent, error) {
	url := fmt.Sprintf("%s/api/v1/smith/events?since=%s&limit=%d", c.baseURL, since.Format(time.RFC3339), limit)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get Smith integration events: %d", resp.StatusCode)
	}

	var events []SmithIntegrationEvent
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		return nil, err
	}
	return events, nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
}

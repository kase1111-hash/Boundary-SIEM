// Package playbook provides incident response playbooks.
package playbook

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// PlaybookType categorizes playbook types.
type PlaybookType string

const (
	PlaybookValidator     PlaybookType = "validator"
	PlaybookTransaction   PlaybookType = "transaction"
	PlaybookInfrastructure PlaybookType = "infrastructure"
	PlaybookSecurity      PlaybookType = "security"
	PlaybookCompliance    PlaybookType = "compliance"
)

// ActionType represents types of automated actions.
type ActionType string

const (
	ActionAlert        ActionType = "alert"
	ActionNotify       ActionType = "notify"
	ActionEscalate     ActionType = "escalate"
	ActionBlock        ActionType = "block"
	ActionIsolate      ActionType = "isolate"
	ActionRestart      ActionType = "restart"
	ActionSnapshot     ActionType = "snapshot"
	ActionForensics    ActionType = "forensics"
	ActionRunbook      ActionType = "runbook"
	ActionWebhook      ActionType = "webhook"
	ActionScript       ActionType = "script"
	ActionTicket       ActionType = "ticket"
)

// ActionStatus tracks action execution status.
type ActionStatus string

const (
	StatusPending    ActionStatus = "pending"
	StatusRunning    ActionStatus = "running"
	StatusCompleted  ActionStatus = "completed"
	StatusFailed     ActionStatus = "failed"
	StatusSkipped    ActionStatus = "skipped"
)

// Severity levels for incident classification.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Action represents an automated response action.
type Action struct {
	ID          string                 `json:"id"`
	Type        ActionType             `json:"type"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Config      map[string]interface{} `json:"config"`
	Timeout     time.Duration          `json:"timeout"`
	RetryCount  int                    `json:"retry_count"`
	Condition   string                 `json:"condition,omitempty"` // Expression for conditional execution
}

// Playbook defines an incident response playbook.
type Playbook struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Type        PlaybookType `json:"type"`
	Severity    Severity     `json:"severity"`
	Enabled     bool         `json:"enabled"`
	Tags        []string     `json:"tags"`
	Triggers    []Trigger    `json:"triggers"`
	Actions     []Action     `json:"actions"`
	Escalation  *Escalation  `json:"escalation,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// Trigger defines when a playbook should be executed.
type Trigger struct {
	Type      string                 `json:"type"` // event, alert, schedule, manual
	Condition map[string]interface{} `json:"condition"`
}

// Escalation defines escalation rules.
type Escalation struct {
	Enabled     bool          `json:"enabled"`
	Timeout     time.Duration `json:"timeout"`
	Levels      []EscLevel    `json:"levels"`
}

// EscLevel represents an escalation level.
type EscLevel struct {
	Level    int      `json:"level"`
	Contacts []string `json:"contacts"`
	Timeout  time.Duration `json:"timeout"`
}

// Incident represents an active incident.
type Incident struct {
	ID            uuid.UUID              `json:"id"`
	PlaybookID    string                 `json:"playbook_id"`
	TriggerEvent  *schema.Event          `json:"trigger_event"`
	Status        ActionStatus           `json:"status"`
	Severity      Severity               `json:"severity"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time,omitempty"`
	ActionResults []ActionResult         `json:"action_results"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ActionResult records the result of an action execution.
type ActionResult struct {
	ActionID   string                 `json:"action_id"`
	ActionType ActionType             `json:"action_type"`
	Status     ActionStatus           `json:"status"`
	StartTime  time.Time              `json:"start_time"`
	EndTime    time.Time              `json:"end_time,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Output     map[string]interface{} `json:"output,omitempty"`
}

// ActionExecutor executes playbook actions.
type ActionExecutor interface {
	Execute(ctx context.Context, action *Action, event *schema.Event) (*ActionResult, error)
	Type() ActionType
}

// EngineConfig configures the playbook engine.
type EngineConfig struct {
	MaxConcurrentPlaybooks int
	DefaultTimeout         time.Duration
	EnableDryRun           bool
}

// DefaultEngineConfig returns default configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		MaxConcurrentPlaybooks: 10,
		DefaultTimeout:         5 * time.Minute,
		EnableDryRun:           false,
	}
}

// Engine manages playbook execution.
type Engine struct {
	config    EngineConfig
	playbooks map[string]*Playbook
	executors map[ActionType]ActionExecutor
	incidents map[uuid.UUID]*Incident
	mu        sync.RWMutex

	incidentChan chan *Incident
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// NewEngine creates a new playbook engine.
func NewEngine(config EngineConfig) *Engine {
	e := &Engine{
		config:       config,
		playbooks:    make(map[string]*Playbook),
		executors:    make(map[ActionType]ActionExecutor),
		incidents:    make(map[uuid.UUID]*Incident),
		incidentChan: make(chan *Incident, 100),
		stopCh:       make(chan struct{}),
	}

	// Register default executors
	e.registerDefaultExecutors()

	// Load built-in playbooks
	e.loadBuiltInPlaybooks()

	return e
}

// RegisterExecutor registers an action executor.
func (e *Engine) RegisterExecutor(executor ActionExecutor) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.executors[executor.Type()] = executor
}

// AddPlaybook adds a playbook.
func (e *Engine) AddPlaybook(playbook *Playbook) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.playbooks[playbook.ID] = playbook
}

// RemovePlaybook removes a playbook.
func (e *Engine) RemovePlaybook(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.playbooks, id)
}

// GetPlaybook returns a playbook by ID.
func (e *Engine) GetPlaybook(id string) (*Playbook, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	pb, ok := e.playbooks[id]
	return pb, ok
}

// Start starts the playbook engine.
func (e *Engine) Start(ctx context.Context) {
	for i := 0; i < e.config.MaxConcurrentPlaybooks; i++ {
		e.wg.Add(1)
		go e.worker(ctx)
	}

	slog.Info("playbook engine started", "workers", e.config.MaxConcurrentPlaybooks)
}

// Stop stops the playbook engine.
func (e *Engine) Stop() {
	close(e.stopCh)
	e.wg.Wait()
	slog.Info("playbook engine stopped")
}

func (e *Engine) worker(ctx context.Context) {
	defer e.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case incident := <-e.incidentChan:
			e.executeIncident(ctx, incident)
		}
	}
}

// TriggerPlaybook triggers a playbook for an event.
func (e *Engine) TriggerPlaybook(ctx context.Context, playbookID string, event *schema.Event) (*Incident, error) {
	e.mu.RLock()
	playbook, ok := e.playbooks[playbookID]
	e.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("playbook not found: %s", playbookID)
	}

	if !playbook.Enabled {
		return nil, fmt.Errorf("playbook is disabled: %s", playbookID)
	}

	incident := &Incident{
		ID:           uuid.New(),
		PlaybookID:   playbookID,
		TriggerEvent: event,
		Status:       StatusPending,
		Severity:     playbook.Severity,
		StartTime:    time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	e.mu.Lock()
	e.incidents[incident.ID] = incident
	e.mu.Unlock()

	// Queue for execution
	select {
	case e.incidentChan <- incident:
		return incident, nil
	default:
		return nil, fmt.Errorf("incident queue full")
	}
}

// ProcessEvent processes an event and triggers matching playbooks.
func (e *Engine) ProcessEvent(ctx context.Context, event *schema.Event) []*Incident {
	var incidents []*Incident

	e.mu.RLock()
	playbooks := make([]*Playbook, 0, len(e.playbooks))
	for _, pb := range e.playbooks {
		playbooks = append(playbooks, pb)
	}
	e.mu.RUnlock()

	for _, pb := range playbooks {
		if !pb.Enabled {
			continue
		}

		if e.matchesTriggers(pb, event) {
			incident, err := e.TriggerPlaybook(ctx, pb.ID, event)
			if err != nil {
				slog.Error("failed to trigger playbook", "playbook", pb.ID, "error", err)
				continue
			}
			incidents = append(incidents, incident)
		}
	}

	return incidents
}

func (e *Engine) matchesTriggers(pb *Playbook, event *schema.Event) bool {
	for _, trigger := range pb.Triggers {
		if trigger.Type != "event" {
			continue
		}

		// Check action pattern
		if actionPattern, ok := trigger.Condition["action"].(string); ok {
			if !matchPattern(event.Action, actionPattern) {
				continue
			}
		}

		// Check severity
		if minSeverity, ok := trigger.Condition["min_severity"].(int); ok {
			if event.Severity < minSeverity {
				continue
			}
		}

		// Check outcome
		if outcome, ok := trigger.Condition["outcome"].(string); ok {
			if string(event.Outcome) != outcome {
				continue
			}
		}

		return true
	}

	return false
}

func matchPattern(value, pattern string) bool {
	// Simple pattern matching with * wildcard
	if pattern == "*" {
		return true
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(value) >= len(prefix) && value[:len(prefix)] == prefix
	}
	return value == pattern
}

func (e *Engine) executeIncident(ctx context.Context, incident *Incident) {
	e.mu.Lock()
	incident.Status = StatusRunning
	e.mu.Unlock()

	e.mu.RLock()
	playbook, ok := e.playbooks[incident.PlaybookID]
	e.mu.RUnlock()

	if !ok {
		e.mu.Lock()
		incident.Status = StatusFailed
		e.mu.Unlock()
		return
	}

	slog.Info("executing playbook",
		"playbook", playbook.Name,
		"incident", incident.ID,
		"event_action", incident.TriggerEvent.Action)

	for _, action := range playbook.Actions {
		if e.config.EnableDryRun {
			slog.Info("dry-run: would execute action",
				"action", action.Name,
				"type", action.Type)
			continue
		}

		result := e.executeAction(ctx, &action, incident.TriggerEvent)
		e.mu.Lock()
		incident.ActionResults = append(incident.ActionResults, *result)
		e.mu.Unlock()

		if result.Status == StatusFailed {
			slog.Error("action failed",
				"action", action.Name,
				"error", result.Error)
			// Continue with other actions unless critical
		}
	}

	e.mu.Lock()
	incident.Status = StatusCompleted
	incident.EndTime = time.Now()
	e.mu.Unlock()

	slog.Info("playbook completed",
		"playbook", playbook.Name,
		"incident", incident.ID,
		"duration", incident.EndTime.Sub(incident.StartTime))
}

func (e *Engine) executeAction(ctx context.Context, action *Action, event *schema.Event) *ActionResult {
	result := &ActionResult{
		ActionID:   action.ID,
		ActionType: action.Type,
		Status:     StatusRunning,
		StartTime:  time.Now(),
		Output:     make(map[string]interface{}),
	}

	e.mu.RLock()
	executor, ok := e.executors[action.Type]
	e.mu.RUnlock()

	if !ok {
		result.Status = StatusFailed
		result.Error = fmt.Sprintf("no executor for action type: %s", action.Type)
		result.EndTime = time.Now()
		return result
	}

	timeout := action.Timeout
	if timeout == 0 {
		timeout = e.config.DefaultTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	execResult, err := executor.Execute(execCtx, action, event)
	if err != nil {
		result.Status = StatusFailed
		result.Error = err.Error()
	} else {
		result.Status = execResult.Status
		result.Output = execResult.Output
	}

	result.EndTime = time.Now()
	return result
}

// GetIncident returns a copy of an incident by ID to avoid race conditions.
func (e *Engine) GetIncident(id uuid.UUID) (*Incident, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	inc, ok := e.incidents[id]
	if !ok {
		return nil, false
	}
	// Return a shallow copy to avoid race conditions on fields
	incCopy := *inc
	return &incCopy, true
}

// GetStats returns engine statistics.
func (e *Engine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	completed := 0
	failed := 0
	pending := 0
	for _, inc := range e.incidents {
		switch inc.Status {
		case StatusCompleted:
			completed++
		case StatusFailed:
			failed++
		case StatusPending, StatusRunning:
			pending++
		}
	}

	return map[string]interface{}{
		"playbook_count":    len(e.playbooks),
		"executor_count":    len(e.executors),
		"total_incidents":   len(e.incidents),
		"completed":         completed,
		"failed":            failed,
		"pending":           pending,
	}
}

func (e *Engine) registerDefaultExecutors() {
	e.RegisterExecutor(&AlertExecutor{})
	e.RegisterExecutor(&NotifyExecutor{})
	e.RegisterExecutor(&WebhookExecutor{})
	e.RegisterExecutor(&TicketExecutor{})
}

func (e *Engine) loadBuiltInPlaybooks() {
	playbooks := GetBuiltInPlaybooks()
	for _, pb := range playbooks {
		e.AddPlaybook(pb)
	}
	slog.Info("loaded built-in playbooks", "count", len(playbooks))
}

// GetBuiltInPlaybooks returns the built-in playbooks.
func GetBuiltInPlaybooks() []*Playbook {
	return []*Playbook{
		// Validator Incident Playbooks
		{
			ID:          "validator-slashing-detected",
			Name:        "Validator Slashing Detected",
			Description: "Responds to validator slashing events with immediate alerting and forensics",
			Type:        PlaybookValidator,
			Severity:    SeverityCritical,
			Enabled:     true,
			Tags:        []string{"validator", "slashing", "critical"},
			Triggers: []Trigger{
				{
					Type: "event",
					Condition: map[string]interface{}{
						"action":       "validator.slashing_detected",
						"min_severity": 8,
					},
				},
			},
			Actions: []Action{
				{
					ID:          "alert-oncall",
					Type:        ActionAlert,
					Name:        "Alert On-Call Team",
					Description: "Send immediate alert to on-call team",
					Config: map[string]interface{}{
						"channel":  "critical",
						"priority": "P1",
					},
					Timeout: 30 * time.Second,
				},
				{
					ID:          "capture-forensics",
					Type:        ActionForensics,
					Name:        "Capture Forensic Data",
					Description: "Capture validator logs and state for investigation",
					Config: map[string]interface{}{
						"include_logs":  true,
						"include_state": true,
					},
					Timeout: 2 * time.Minute,
				},
				{
					ID:          "create-ticket",
					Type:        ActionTicket,
					Name:        "Create Incident Ticket",
					Description: "Create a high-priority incident ticket",
					Config: map[string]interface{}{
						"priority": "critical",
						"queue":    "security-incidents",
					},
					Timeout: 30 * time.Second,
				},
			},
			Escalation: &Escalation{
				Enabled: true,
				Timeout: 5 * time.Minute,
				Levels: []EscLevel{
					{Level: 1, Contacts: []string{"oncall-primary"}, Timeout: 5 * time.Minute},
					{Level: 2, Contacts: []string{"oncall-secondary", "security-lead"}, Timeout: 10 * time.Minute},
					{Level: 3, Contacts: []string{"vp-engineering"}, Timeout: 15 * time.Minute},
				},
			},
		},
		{
			ID:          "validator-missed-duties",
			Name:        "Validator Missed Duties",
			Description: "Responds to validators missing attestations or proposals",
			Type:        PlaybookValidator,
			Severity:    SeverityHigh,
			Enabled:     true,
			Tags:        []string{"validator", "attestation", "proposal"},
			Triggers: []Trigger{
				{
					Type: "event",
					Condition: map[string]interface{}{
						"action":       "validator.attestation_missed",
						"min_severity": 5,
					},
				},
				{
					Type: "event",
					Condition: map[string]interface{}{
						"action":       "validator.proposal_missed",
						"min_severity": 6,
					},
				},
			},
			Actions: []Action{
				{
					ID:          "alert-ops",
					Type:        ActionAlert,
					Name:        "Alert Operations",
					Description: "Notify operations team of missed duties",
					Config: map[string]interface{}{
						"channel":  "validator-ops",
						"priority": "P2",
					},
				},
				{
					ID:          "check-connectivity",
					Type:        ActionRunbook,
					Name:        "Check Node Connectivity",
					Description: "Run connectivity diagnostics",
					Config: map[string]interface{}{
						"runbook": "validator-health-check",
					},
					Timeout: 1 * time.Minute,
				},
			},
		},

		// Transaction Incident Playbooks
		{
			ID:          "large-transfer-detected",
			Name:        "Large Transfer Detected",
			Description: "Responds to unusually large token transfers",
			Type:        PlaybookTransaction,
			Severity:    SeverityMedium,
			Enabled:     true,
			Tags:        []string{"transaction", "transfer", "whale"},
			Triggers: []Trigger{
				{
					Type: "event",
					Condition: map[string]interface{}{
						"action":       "contract.erc20.transfer",
						"min_severity": 6,
					},
				},
			},
			Actions: []Action{
				{
					ID:          "notify-treasury",
					Type:        ActionNotify,
					Name:        "Notify Treasury Team",
					Description: "Alert treasury team of large transfer",
					Config: map[string]interface{}{
						"channel": "treasury-alerts",
					},
				},
				{
					ID:          "screen-addresses",
					Type:        ActionScript,
					Name:        "Screen Addresses",
					Description: "Run threat intelligence screening",
					Config: map[string]interface{}{
						"script": "threat-screen",
					},
				},
			},
		},
		{
			ID:          "sandwich-attack-detected",
			Name:        "Sandwich Attack Detected",
			Description: "Responds to MEV sandwich attacks",
			Type:        PlaybookTransaction,
			Severity:    SeverityHigh,
			Enabled:     true,
			Tags:        []string{"mev", "sandwich", "attack"},
			Triggers: []Trigger{
				{
					Type: "event",
					Condition: map[string]interface{}{
						"action":       "tx.sandwich",
						"min_severity": 7,
					},
				},
			},
			Actions: []Action{
				{
					ID:          "alert-security",
					Type:        ActionAlert,
					Name:        "Alert Security Team",
					Description: "Notify security team of MEV attack",
					Config: map[string]interface{}{
						"channel":  "security-alerts",
						"priority": "P2",
					},
				},
				{
					ID:          "capture-tx-data",
					Type:        ActionForensics,
					Name:        "Capture Transaction Data",
					Description: "Record full transaction details for analysis",
					Config: map[string]interface{}{
						"include_mempool": true,
					},
				},
			},
		},
		{
			ID:          "sanctioned-address-interaction",
			Name:        "Sanctioned Address Interaction",
			Description: "Responds to transactions involving sanctioned addresses",
			Type:        PlaybookCompliance,
			Severity:    SeverityCritical,
			Enabled:     true,
			Tags:        []string{"compliance", "ofac", "sanctions"},
			Triggers: []Trigger{
				{
					Type: "event",
					Condition: map[string]interface{}{
						"action":       "threat.screening",
						"outcome":      "failure",
						"min_severity": 8,
					},
				},
			},
			Actions: []Action{
				{
					ID:          "alert-compliance",
					Type:        ActionAlert,
					Name:        "Alert Compliance Team",
					Description: "Immediate alert to compliance",
					Config: map[string]interface{}{
						"channel":  "compliance-critical",
						"priority": "P1",
					},
				},
				{
					ID:          "block-address",
					Type:        ActionBlock,
					Name:        "Block Address",
					Description: "Add address to block list",
					Config: map[string]interface{}{
						"list": "blocked-addresses",
					},
				},
				{
					ID:          "create-sar",
					Type:        ActionTicket,
					Name:        "Create SAR Draft",
					Description: "Create suspicious activity report draft",
					Config: map[string]interface{}{
						"type":  "SAR",
						"queue": "compliance-reports",
					},
				},
			},
			Escalation: &Escalation{
				Enabled: true,
				Timeout: 15 * time.Minute,
				Levels: []EscLevel{
					{Level: 1, Contacts: []string{"compliance-officer"}, Timeout: 15 * time.Minute},
					{Level: 2, Contacts: []string{"cco", "legal"}, Timeout: 30 * time.Minute},
				},
			},
		},

		// Infrastructure Incident Playbooks
		{
			ID:          "node-high-resource-usage",
			Name:        "Node High Resource Usage",
			Description: "Responds to high CPU/memory usage on nodes",
			Type:        PlaybookInfrastructure,
			Severity:    SeverityMedium,
			Enabled:     true,
			Tags:        []string{"infrastructure", "performance", "resources"},
			Triggers: []Trigger{
				{
					Type: "event",
					Condition: map[string]interface{}{
						"action":       "metric.cpu.*",
						"min_severity": 5,
					},
				},
				{
					Type: "event",
					Condition: map[string]interface{}{
						"action":       "metric.memory.*",
						"min_severity": 5,
					},
				},
			},
			Actions: []Action{
				{
					ID:          "alert-infra",
					Type:        ActionAlert,
					Name:        "Alert Infrastructure Team",
					Description: "Notify infrastructure team",
					Config: map[string]interface{}{
						"channel": "infra-alerts",
					},
				},
				{
					ID:          "capture-metrics",
					Type:        ActionSnapshot,
					Name:        "Capture Metrics Snapshot",
					Description: "Save current metrics state",
					Config: map[string]interface{}{
						"duration": "5m",
					},
				},
			},
		},
		{
			ID:          "rpc-attack-detected",
			Name:        "RPC Attack Detected",
			Description: "Responds to RPC enumeration or abuse attempts",
			Type:        PlaybookSecurity,
			Severity:    SeverityHigh,
			Enabled:     true,
			Tags:        []string{"rpc", "security", "attack"},
			Triggers: []Trigger{
				{
					Type: "event",
					Condition: map[string]interface{}{
						"action":       "rpc.admin*",
						"min_severity": 7,
					},
				},
			},
			Actions: []Action{
				{
					ID:          "alert-security",
					Type:        ActionAlert,
					Name:        "Alert Security Team",
					Description: "Notify security team of RPC attack",
					Config: map[string]interface{}{
						"channel":  "security-alerts",
						"priority": "P2",
					},
				},
				{
					ID:          "block-ip",
					Type:        ActionBlock,
					Name:        "Block Attacker IP",
					Description: "Add IP to firewall block list",
					Config: map[string]interface{}{
						"list":     "blocked-ips",
						"duration": "24h",
					},
				},
			},
		},
		{
			ID:          "key-export-attempt",
			Name:        "Key Export Attempt Detected",
			Description: "Responds to attempts to export cryptographic keys",
			Type:        PlaybookSecurity,
			Severity:    SeverityCritical,
			Enabled:     true,
			Tags:        []string{"keys", "security", "export"},
			Triggers: []Trigger{
				{
					Type: "event",
					Condition: map[string]interface{}{
						"action":       "key.export",
						"min_severity": 8,
					},
				},
			},
			Actions: []Action{
				{
					ID:          "alert-security-critical",
					Type:        ActionAlert,
					Name:        "Critical Security Alert",
					Description: "Immediate alert to security team",
					Config: map[string]interface{}{
						"channel":  "security-critical",
						"priority": "P1",
					},
				},
				{
					ID:          "isolate-system",
					Type:        ActionIsolate,
					Name:        "Isolate Affected System",
					Description: "Network isolate the affected system",
					Config: map[string]interface{}{
						"isolation_level": "network",
					},
				},
				{
					ID:          "capture-forensics",
					Type:        ActionForensics,
					Name:        "Full Forensic Capture",
					Description: "Capture full system state for investigation",
					Config: map[string]interface{}{
						"full_capture": true,
					},
				},
			},
			Escalation: &Escalation{
				Enabled: true,
				Timeout: 5 * time.Minute,
				Levels: []EscLevel{
					{Level: 1, Contacts: []string{"security-oncall"}, Timeout: 5 * time.Minute},
					{Level: 2, Contacts: []string{"ciso"}, Timeout: 10 * time.Minute},
					{Level: 3, Contacts: []string{"ceo"}, Timeout: 15 * time.Minute},
				},
			},
		},
		{
			ID:          "cloud-unauthorized-access",
			Name:        "Cloud Unauthorized Access",
			Description: "Responds to unauthorized cloud resource access",
			Type:        PlaybookSecurity,
			Severity:    SeverityHigh,
			Enabled:     true,
			Tags:        []string{"cloud", "security", "access"},
			Triggers: []Trigger{
				{
					Type: "event",
					Condition: map[string]interface{}{
						"action":       "cloud.*",
						"outcome":      "failure",
						"min_severity": 6,
					},
				},
			},
			Actions: []Action{
				{
					ID:          "alert-cloud-security",
					Type:        ActionAlert,
					Name:        "Alert Cloud Security",
					Description: "Notify cloud security team",
					Config: map[string]interface{}{
						"channel": "cloud-security",
					},
				},
				{
					ID:          "webhook-siem",
					Type:        ActionWebhook,
					Name:        "Send to External SIEM",
					Description: "Forward to enterprise SIEM",
					Config: map[string]interface{}{
						"url":    "https://siem.internal/api/events",
						"method": "POST",
					},
				},
			},
		},
	}
}

// AlertExecutor executes alert actions.
type AlertExecutor struct{}

func (e *AlertExecutor) Type() ActionType { return ActionAlert }

func (e *AlertExecutor) Execute(ctx context.Context, action *Action, event *schema.Event) (*ActionResult, error) {
	channel := "default"
	if ch, ok := action.Config["channel"].(string); ok {
		channel = ch
	}
	priority := "P3"
	if p, ok := action.Config["priority"].(string); ok {
		priority = p
	}

	slog.Info("executing alert action",
		"channel", channel,
		"priority", priority,
		"event", event.Action)

	return &ActionResult{
		Status: StatusCompleted,
		Output: map[string]interface{}{
			"channel":  channel,
			"priority": priority,
			"sent":     true,
		},
	}, nil
}

// NotifyExecutor executes notification actions.
type NotifyExecutor struct{}

func (e *NotifyExecutor) Type() ActionType { return ActionNotify }

func (e *NotifyExecutor) Execute(ctx context.Context, action *Action, event *schema.Event) (*ActionResult, error) {
	channel := "general"
	if ch, ok := action.Config["channel"].(string); ok {
		channel = ch
	}

	slog.Info("executing notify action",
		"channel", channel,
		"event", event.Action)

	return &ActionResult{
		Status: StatusCompleted,
		Output: map[string]interface{}{
			"channel": channel,
			"sent":    true,
		},
	}, nil
}

// WebhookExecutor executes webhook actions.
type WebhookExecutor struct{}

func (e *WebhookExecutor) Type() ActionType { return ActionWebhook }

func (e *WebhookExecutor) Execute(ctx context.Context, action *Action, event *schema.Event) (*ActionResult, error) {
	url := ""
	if u, ok := action.Config["url"].(string); ok {
		url = u
	}

	slog.Info("executing webhook action",
		"url", url,
		"event", event.Action)

	// In production, this would make an HTTP request
	return &ActionResult{
		Status: StatusCompleted,
		Output: map[string]interface{}{
			"url":         url,
			"status_code": 200,
		},
	}, nil
}

// TicketExecutor executes ticket creation actions.
type TicketExecutor struct{}

func (e *TicketExecutor) Type() ActionType { return ActionTicket }

func (e *TicketExecutor) Execute(ctx context.Context, action *Action, event *schema.Event) (*ActionResult, error) {
	queue := "default"
	if q, ok := action.Config["queue"].(string); ok {
		queue = q
	}
	priority := "medium"
	if p, ok := action.Config["priority"].(string); ok {
		priority = p
	}

	ticketID := fmt.Sprintf("INC-%d", time.Now().UnixNano()%100000)

	slog.Info("executing ticket action",
		"queue", queue,
		"priority", priority,
		"ticket_id", ticketID)

	return &ActionResult{
		Status: StatusCompleted,
		Output: map[string]interface{}{
			"ticket_id": ticketID,
			"queue":     queue,
			"priority":  priority,
		},
	}, nil
}

// Package soar provides Security Orchestration, Automation, and Response capabilities
package soar

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// WorkflowStatus represents the status of a workflow
type WorkflowStatus string

const (
	WorkflowStatusDraft     WorkflowStatus = "draft"
	WorkflowStatusActive    WorkflowStatus = "active"
	WorkflowStatusPaused    WorkflowStatus = "paused"
	WorkflowStatusDisabled  WorkflowStatus = "disabled"
)

// ExecutionStatus represents the status of a workflow execution
type ExecutionStatus string

const (
	ExecutionStatusPending   ExecutionStatus = "pending"
	ExecutionStatusRunning   ExecutionStatus = "running"
	ExecutionStatusCompleted ExecutionStatus = "completed"
	ExecutionStatusFailed    ExecutionStatus = "failed"
	ExecutionStatusCancelled ExecutionStatus = "cancelled"
	ExecutionStatusWaiting   ExecutionStatus = "waiting_approval"
)

// StepType represents the type of workflow step
type StepType string

const (
	StepTypeAction      StepType = "action"
	StepTypeCondition   StepType = "condition"
	StepTypeParallel    StepType = "parallel"
	StepTypeLoop        StepType = "loop"
	StepTypeDelay       StepType = "delay"
	StepTypeApproval    StepType = "approval"
	StepTypeNotification StepType = "notification"
	StepTypeIntegration StepType = "integration"
	StepTypeScript      StepType = "script"
)

// Workflow represents an automation workflow
type Workflow struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Status      WorkflowStatus         `json:"status"`
	Trigger     Trigger                `json:"trigger"`
	Steps       []Step                 `json:"steps"`
	Variables   map[string]interface{} `json:"variables"`
	Tags        []string               `json:"tags"`
	Owner       string                 `json:"owner"`
	Version     int                    `json:"version"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Trigger represents what triggers a workflow
type Trigger struct {
	Type       TriggerType            `json:"type"`
	Conditions []TriggerCondition     `json:"conditions"`
	Schedule   *ScheduleConfig        `json:"schedule,omitempty"`
	Event      *EventConfig           `json:"event,omitempty"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// TriggerType represents the type of trigger
type TriggerType string

const (
	TriggerTypeAlert    TriggerType = "alert"
	TriggerTypeEvent    TriggerType = "event"
	TriggerTypeSchedule TriggerType = "schedule"
	TriggerTypeManual   TriggerType = "manual"
	TriggerTypeWebhook  TriggerType = "webhook"
	TriggerTypeAPI      TriggerType = "api"
)

// TriggerCondition represents a condition for triggering
type TriggerCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// ScheduleConfig represents schedule configuration
type ScheduleConfig struct {
	Cron     string `json:"cron"`
	Timezone string `json:"timezone"`
}

// EventConfig represents event trigger configuration
type EventConfig struct {
	EventType string   `json:"event_type"`
	Sources   []string `json:"sources"`
	Filters   map[string]interface{} `json:"filters"`
}

// Step represents a workflow step
type Step struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        StepType               `json:"type"`
	Action      *ActionConfig          `json:"action,omitempty"`
	Condition   *ConditionConfig       `json:"condition,omitempty"`
	Parallel    *ParallelConfig        `json:"parallel,omitempty"`
	Loop        *LoopConfig            `json:"loop,omitempty"`
	Delay       *DelayConfig           `json:"delay,omitempty"`
	Approval    *ApprovalConfig        `json:"approval,omitempty"`
	Notification *NotificationConfig   `json:"notification,omitempty"`
	Integration *IntegrationConfig     `json:"integration,omitempty"`
	Script      *ScriptConfig          `json:"script,omitempty"`
	NextSteps   []string               `json:"next_steps"`
	OnError     string                 `json:"on_error,omitempty"`
	Timeout     time.Duration          `json:"timeout"`
	Retries     int                    `json:"retries"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ActionConfig represents action step configuration
type ActionConfig struct {
	ActionType string                 `json:"action_type"`
	Target     string                 `json:"target"`
	Parameters map[string]interface{} `json:"parameters"`
}

// ConditionConfig represents condition step configuration
type ConditionConfig struct {
	Expression string   `json:"expression"`
	TrueBranch []string `json:"true_branch"`
	FalseBranch []string `json:"false_branch"`
}

// ParallelConfig represents parallel execution configuration
type ParallelConfig struct {
	Branches      [][]Step `json:"branches"`
	WaitForAll    bool     `json:"wait_for_all"`
	FailFast      bool     `json:"fail_fast"`
	MaxConcurrent int      `json:"max_concurrent"`
}

// LoopConfig represents loop step configuration
type LoopConfig struct {
	Collection string `json:"collection"`
	Iterator   string `json:"iterator"`
	Steps      []Step `json:"steps"`
	MaxIterations int  `json:"max_iterations"`
}

// DelayConfig represents delay step configuration
type DelayConfig struct {
	Duration time.Duration `json:"duration"`
	Until    *time.Time    `json:"until,omitempty"`
}

// ApprovalConfig represents approval step configuration
type ApprovalConfig struct {
	Approvers    []string      `json:"approvers"`
	RequiredCount int          `json:"required_count"`
	Timeout      time.Duration `json:"timeout"`
	Message      string        `json:"message"`
}

// NotificationConfig represents notification step configuration
type NotificationConfig struct {
	Channels   []string               `json:"channels"`
	Template   string                 `json:"template"`
	Recipients []string               `json:"recipients"`
	Priority   string                 `json:"priority"`
	Data       map[string]interface{} `json:"data"`
}

// IntegrationConfig represents integration step configuration
type IntegrationConfig struct {
	IntegrationType string                 `json:"integration_type"`
	Endpoint        string                 `json:"endpoint"`
	Method          string                 `json:"method"`
	Headers         map[string]string      `json:"headers"`
	Body            map[string]interface{} `json:"body"`
	Auth            *AuthConfig            `json:"auth,omitempty"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Type        string `json:"type"`
	CredentialID string `json:"credential_id"`
}

// ScriptConfig represents script step configuration
type ScriptConfig struct {
	Language string   `json:"language"`
	Code     string   `json:"code"`
	Inputs   []string `json:"inputs"`
	Outputs  []string `json:"outputs"`
}

// Execution represents a workflow execution instance
type Execution struct {
	ID           string                 `json:"id"`
	WorkflowID   string                 `json:"workflow_id"`
	WorkflowName string                 `json:"workflow_name"`
	Status       ExecutionStatus        `json:"status"`
	TriggerData  map[string]interface{} `json:"trigger_data"`
	Variables    map[string]interface{} `json:"variables"`
	StepResults  []StepResult           `json:"step_results"`
	CurrentStep  string                 `json:"current_step"`
	Error        string                 `json:"error,omitempty"`
	StartedAt    time.Time              `json:"started_at"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
	Duration     time.Duration          `json:"duration"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// StepResult represents the result of a step execution
type StepResult struct {
	StepID      string                 `json:"step_id"`
	StepName    string                 `json:"step_name"`
	Status      ExecutionStatus        `json:"status"`
	Output      map[string]interface{} `json:"output"`
	Error       string                 `json:"error,omitempty"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Duration    time.Duration          `json:"duration"`
	Retries     int                    `json:"retries"`
}

// Integration represents an external integration
type Integration struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Config      map[string]interface{} `json:"config"`
	Actions     []IntegrationAction    `json:"actions"`
	CreatedAt   time.Time              `json:"created_at"`
}

// IntegrationAction represents an action available from an integration
type IntegrationAction struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  []ActionParameter      `json:"parameters"`
	Outputs     []string               `json:"outputs"`
}

// ActionParameter represents a parameter for an action
type ActionParameter struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Required    bool        `json:"required"`
	Default     interface{} `json:"default,omitempty"`
	Description string      `json:"description"`
}

// Engine provides SOAR workflow automation
type Engine struct {
	mu           sync.RWMutex
	workflows    map[string]*Workflow
	executions   map[string]*Execution
	integrations map[string]*Integration
	executor     StepExecutor
}

// StepExecutor executes workflow steps
type StepExecutor interface {
	ExecuteAction(ctx context.Context, config *ActionConfig, variables map[string]interface{}) (map[string]interface{}, error)
	ExecuteScript(ctx context.Context, config *ScriptConfig, variables map[string]interface{}) (map[string]interface{}, error)
	SendNotification(ctx context.Context, config *NotificationConfig, variables map[string]interface{}) error
	CallIntegration(ctx context.Context, config *IntegrationConfig, variables map[string]interface{}) (map[string]interface{}, error)
}

// Config holds engine configuration
type Config struct {
	MaxConcurrentExecutions int
	DefaultTimeout          time.Duration
	MaxRetries              int
	EnableAuditLogging      bool
}

// NewEngine creates a new SOAR engine
func NewEngine(cfg Config, executor StepExecutor) *Engine {
	e := &Engine{
		workflows:    make(map[string]*Workflow),
		executions:   make(map[string]*Execution),
		integrations: make(map[string]*Integration),
		executor:     executor,
	}
	e.loadBuiltInWorkflows()
	e.loadBuiltInIntegrations()
	return e
}

// loadBuiltInWorkflows loads built-in response workflows
func (e *Engine) loadBuiltInWorkflows() {
	workflows := []Workflow{
		{
			ID:          "wf-001",
			Name:        "Suspicious Transaction Response",
			Description: "Automated response for suspicious blockchain transactions",
			Status:      WorkflowStatusActive,
			Trigger: Trigger{
				Type: TriggerTypeAlert,
				Conditions: []TriggerCondition{
					{Field: "alert.category", Operator: "eq", Value: "suspicious_transaction"},
				},
			},
			Steps: []Step{
				{
					ID:   "step-1",
					Name: "Enrich Transaction",
					Type: StepTypeAction,
					Action: &ActionConfig{
						ActionType: "enrich",
						Target:     "transaction",
						Parameters: map[string]interface{}{
							"fetch_trace":   true,
							"check_labels":  true,
							"risk_scoring":  true,
						},
					},
					NextSteps: []string{"step-2"},
				},
				{
					ID:   "step-2",
					Name: "Check Risk Score",
					Type: StepTypeCondition,
					Condition: &ConditionConfig{
						Expression:  "risk_score > 80",
						TrueBranch:  []string{"step-3a"},
						FalseBranch: []string{"step-3b"},
					},
				},
				{
					ID:   "step-3a",
					Name: "High Risk - Notify SOC",
					Type: StepTypeNotification,
					Notification: &NotificationConfig{
						Channels:   []string{"slack", "pagerduty"},
						Template:   "high_risk_transaction",
						Priority:   "high",
					},
					NextSteps: []string{"step-4"},
				},
				{
					ID:   "step-3b",
					Name: "Medium Risk - Log Only",
					Type: StepTypeAction,
					Action: &ActionConfig{
						ActionType: "log",
						Parameters: map[string]interface{}{
							"level":   "warning",
							"message": "Medium risk transaction detected",
						},
					},
				},
				{
					ID:   "step-4",
					Name: "Create Incident",
					Type: StepTypeAction,
					Action: &ActionConfig{
						ActionType: "create_incident",
						Parameters: map[string]interface{}{
							"severity": "high",
							"category": "suspicious_transaction",
						},
					},
				},
			},
			Tags:      []string{"blockchain", "transaction", "automated"},
			Owner:     "system",
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "wf-002",
			Name:        "Flash Loan Attack Response",
			Description: "Response workflow for detected flash loan attacks",
			Status:      WorkflowStatusActive,
			Trigger: Trigger{
				Type: TriggerTypeAlert,
				Conditions: []TriggerCondition{
					{Field: "alert.type", Operator: "eq", Value: "flash_loan_attack"},
				},
			},
			Steps: []Step{
				{
					ID:   "step-1",
					Name: "Immediate Notification",
					Type: StepTypeNotification,
					Notification: &NotificationConfig{
						Channels:   []string{"slack", "pagerduty", "email"},
						Template:   "critical_attack",
						Priority:   "critical",
						Recipients: []string{"security-team", "on-call"},
					},
					NextSteps: []string{"step-2"},
				},
				{
					ID:   "step-2",
					Name: "Collect Evidence",
					Type: StepTypeParallel,
					Parallel: &ParallelConfig{
						Branches: [][]Step{
							{{ID: "collect-tx", Name: "Collect Transaction", Type: StepTypeAction}},
							{{ID: "collect-trace", Name: "Collect Trace", Type: StepTypeAction}},
							{{ID: "collect-state", Name: "Collect State Changes", Type: StepTypeAction}},
						},
						WaitForAll: true,
					},
					NextSteps: []string{"step-3"},
				},
				{
					ID:   "step-3",
					Name: "Create Forensics Case",
					Type: StepTypeIntegration,
					Integration: &IntegrationConfig{
						IntegrationType: "forensics",
						Method:          "create_case",
						Body: map[string]interface{}{
							"type":     "flash_loan_attack",
							"priority": "critical",
						},
					},
					NextSteps: []string{"step-4"},
				},
				{
					ID:   "step-4",
					Name: "Await Analyst Review",
					Type: StepTypeApproval,
					Approval: &ApprovalConfig{
						Approvers:     []string{"security-analyst", "security-lead"},
						RequiredCount: 1,
						Timeout:       30 * time.Minute,
						Message:       "Please review flash loan attack and confirm containment actions",
					},
				},
			},
			Tags:      []string{"flash-loan", "defi", "critical"},
			Owner:     "system",
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "wf-003",
			Name:        "Validator Anomaly Response",
			Description: "Response workflow for validator anomalies",
			Status:      WorkflowStatusActive,
			Trigger: Trigger{
				Type: TriggerTypeAlert,
				Conditions: []TriggerCondition{
					{Field: "alert.category", Operator: "contains", Value: "validator"},
				},
			},
			Steps: []Step{
				{
					ID:   "step-1",
					Name: "Check Validator Status",
					Type: StepTypeIntegration,
					Integration: &IntegrationConfig{
						IntegrationType: "validator_monitor",
						Method:          "GET",
						Endpoint:        "/api/v1/validators/{{validator_id}}/status",
					},
					NextSteps: []string{"step-2"},
				},
				{
					ID:   "step-2",
					Name: "Evaluate Status",
					Type: StepTypeCondition,
					Condition: &ConditionConfig{
						Expression:  "status == 'slashed' || status == 'jailed'",
						TrueBranch:  []string{"step-3a"},
						FalseBranch: []string{"step-3b"},
					},
				},
				{
					ID:   "step-3a",
					Name: "Critical - Validator Compromised",
					Type: StepTypeNotification,
					Notification: &NotificationConfig{
						Channels:   []string{"pagerduty"},
						Template:   "validator_compromised",
						Priority:   "critical",
					},
				},
				{
					ID:   "step-3b",
					Name: "Warning - Validator Performance",
					Type: StepTypeNotification,
					Notification: &NotificationConfig{
						Channels:   []string{"slack"},
						Template:   "validator_warning",
						Priority:   "medium",
					},
				},
			},
			Tags:      []string{"validator", "consensus"},
			Owner:     "system",
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "wf-004",
			Name:        "OFAC Address Detection Response",
			Description: "Automated response for OFAC sanctioned address interactions",
			Status:      WorkflowStatusActive,
			Trigger: Trigger{
				Type: TriggerTypeAlert,
				Conditions: []TriggerCondition{
					{Field: "alert.type", Operator: "eq", Value: "ofac_interaction"},
				},
			},
			Steps: []Step{
				{
					ID:   "step-1",
					Name: "Verify OFAC Match",
					Type: StepTypeIntegration,
					Integration: &IntegrationConfig{
						IntegrationType: "threat_intel",
						Method:          "verify_ofac",
					},
					NextSteps: []string{"step-2"},
				},
				{
					ID:   "step-2",
					Name: "Confirmed Match Check",
					Type: StepTypeCondition,
					Condition: &ConditionConfig{
						Expression:  "verified == true",
						TrueBranch:  []string{"step-3"},
						FalseBranch: []string{"step-4"},
					},
				},
				{
					ID:   "step-3",
					Name: "Compliance Alert",
					Type: StepTypeNotification,
					Notification: &NotificationConfig{
						Channels:   []string{"email", "slack"},
						Template:   "ofac_confirmed",
						Priority:   "critical",
						Recipients: []string{"compliance-team", "legal"},
					},
					NextSteps: []string{"step-5"},
				},
				{
					ID:   "step-4",
					Name: "False Positive - Close",
					Type: StepTypeAction,
					Action: &ActionConfig{
						ActionType: "close_alert",
						Parameters: map[string]interface{}{
							"reason": "false_positive",
						},
					},
				},
				{
					ID:   "step-5",
					Name: "Generate SAR",
					Type: StepTypeAction,
					Action: &ActionConfig{
						ActionType: "generate_report",
						Parameters: map[string]interface{}{
							"type": "suspicious_activity_report",
						},
					},
				},
			},
			Tags:      []string{"compliance", "ofac", "sanctions"},
			Owner:     "system",
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "wf-005",
			Name:        "Bridge Exploit Response",
			Description: "Response workflow for cross-chain bridge exploits",
			Status:      WorkflowStatusActive,
			Trigger: Trigger{
				Type: TriggerTypeAlert,
				Conditions: []TriggerCondition{
					{Field: "alert.type", Operator: "contains", Value: "bridge"},
					{Field: "alert.severity", Operator: "gte", Value: "high"},
				},
			},
			Steps: []Step{
				{
					ID:   "step-1",
					Name: "Immediate Bridge Analysis",
					Type: StepTypeParallel,
					Parallel: &ParallelConfig{
						Branches: [][]Step{
							{{ID: "check-src", Name: "Check Source Chain", Type: StepTypeAction}},
							{{ID: "check-dst", Name: "Check Destination Chain", Type: StepTypeAction}},
							{{ID: "check-balance", Name: "Check Bridge Balance", Type: StepTypeAction}},
						},
						WaitForAll:    true,
						MaxConcurrent: 3,
					},
					NextSteps: []string{"step-2"},
				},
				{
					ID:   "step-2",
					Name: "Alert All Stakeholders",
					Type: StepTypeNotification,
					Notification: &NotificationConfig{
						Channels:   []string{"pagerduty", "slack", "email", "sms"},
						Template:   "bridge_exploit",
						Priority:   "critical",
						Recipients: []string{"security-team", "bridge-operators", "executive"},
					},
					NextSteps: []string{"step-3"},
				},
				{
					ID:   "step-3",
					Name: "Pause Bridge",
					Type: StepTypeApproval,
					Approval: &ApprovalConfig{
						Approvers:     []string{"security-lead", "cto"},
						RequiredCount: 1,
						Timeout:       5 * time.Minute,
						Message:       "Approve emergency bridge pause?",
					},
					NextSteps: []string{"step-4"},
				},
				{
					ID:   "step-4",
					Name: "Execute Bridge Pause",
					Type: StepTypeIntegration,
					Integration: &IntegrationConfig{
						IntegrationType: "bridge_control",
						Method:          "pause",
					},
				},
			},
			Tags:      []string{"bridge", "critical", "exploit"},
			Owner:     "system",
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "wf-006",
			Name:        "Smart Contract Vulnerability Alert",
			Description: "Response for newly discovered smart contract vulnerabilities",
			Status:      WorkflowStatusActive,
			Trigger: Trigger{
				Type: TriggerTypeEvent,
				Event: &EventConfig{
					EventType: "vulnerability_disclosure",
					Sources:   []string{"internal_scan", "external_feed"},
				},
			},
			Steps: []Step{
				{
					ID:   "step-1",
					Name: "Check Affected Contracts",
					Type: StepTypeAction,
					Action: &ActionConfig{
						ActionType: "scan_contracts",
						Parameters: map[string]interface{}{
							"vulnerability_id": "{{vuln_id}}",
						},
					},
					NextSteps: []string{"step-2"},
				},
				{
					ID:   "step-2",
					Name: "Affected Check",
					Type: StepTypeCondition,
					Condition: &ConditionConfig{
						Expression:  "affected_count > 0",
						TrueBranch:  []string{"step-3"},
						FalseBranch: []string{"step-4"},
					},
				},
				{
					ID:   "step-3",
					Name: "Loop Through Affected",
					Type: StepTypeLoop,
					Loop: &LoopConfig{
						Collection:    "affected_contracts",
						Iterator:      "contract",
						MaxIterations: 100,
						Steps: []Step{
							{ID: "notify", Name: "Notify Owner", Type: StepTypeNotification},
							{ID: "create-ticket", Name: "Create Ticket", Type: StepTypeAction},
						},
					},
				},
				{
					ID:   "step-4",
					Name: "Log No Impact",
					Type: StepTypeAction,
					Action: &ActionConfig{
						ActionType: "log",
						Parameters: map[string]interface{}{
							"message": "Vulnerability does not affect monitored contracts",
						},
					},
				},
			},
			Tags:      []string{"vulnerability", "smart-contract"},
			Owner:     "system",
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "wf-007",
			Name:        "Wallet Drainer Detection Response",
			Description: "Response for wallet drainer/phishing attacks",
			Status:      WorkflowStatusActive,
			Trigger: Trigger{
				Type: TriggerTypeAlert,
				Conditions: []TriggerCondition{
					{Field: "alert.type", Operator: "in", Value: []string{"wallet_drainer", "phishing"}},
				},
			},
			Steps: []Step{
				{
					ID:   "step-1",
					Name: "Identify Victims",
					Type: StepTypeAction,
					Action: &ActionConfig{
						ActionType: "analyze_drainer",
						Parameters: map[string]interface{}{
							"drainer_address": "{{alert.address}}",
							"lookback_hours":  24,
						},
					},
					NextSteps: []string{"step-2"},
				},
				{
					ID:   "step-2",
					Name: "Block Drainer Address",
					Type: StepTypeIntegration,
					Integration: &IntegrationConfig{
						IntegrationType: "blocklist",
						Method:          "add",
						Body: map[string]interface{}{
							"address": "{{drainer_address}}",
							"reason":  "wallet_drainer",
						},
					},
					NextSteps: []string{"step-3"},
				},
				{
					ID:   "step-3",
					Name: "Share Threat Intel",
					Type: StepTypeIntegration,
					Integration: &IntegrationConfig{
						IntegrationType: "threat_sharing",
						Method:          "publish",
					},
				},
			},
			Tags:      []string{"phishing", "drainer"},
			Owner:     "system",
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "wf-008",
			Name:        "Scheduled Threat Intel Update",
			Description: "Scheduled workflow to update threat intelligence feeds",
			Status:      WorkflowStatusActive,
			Trigger: Trigger{
				Type: TriggerTypeSchedule,
				Schedule: &ScheduleConfig{
					Cron:     "0 */4 * * *",
					Timezone: "UTC",
				},
			},
			Steps: []Step{
				{
					ID:   "step-1",
					Name: "Update Intel Feeds",
					Type: StepTypeParallel,
					Parallel: &ParallelConfig{
						Branches: [][]Step{
							{{ID: "ofac", Name: "Update OFAC List", Type: StepTypeIntegration}},
							{{ID: "chainalysis", Name: "Update Chainalysis", Type: StepTypeIntegration}},
							{{ID: "internal", Name: "Update Internal Blocklist", Type: StepTypeIntegration}},
						},
						WaitForAll: true,
					},
					NextSteps: []string{"step-2"},
				},
				{
					ID:   "step-2",
					Name: "Rescan Active Alerts",
					Type: StepTypeAction,
					Action: &ActionConfig{
						ActionType: "rescan_alerts",
					},
				},
			},
			Tags:      []string{"scheduled", "threat-intel"},
			Owner:     "system",
			Version:   1,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	for i := range workflows {
		e.workflows[workflows[i].ID] = &workflows[i]
	}
}

// loadBuiltInIntegrations loads built-in integrations
func (e *Engine) loadBuiltInIntegrations() {
	integrations := []Integration{
		{
			ID:          "int-001",
			Name:        "Slack",
			Type:        "notification",
			Description: "Slack workspace notifications",
			Enabled:     true,
			Actions: []IntegrationAction{
				{ID: "send_message", Name: "Send Message", Parameters: []ActionParameter{
					{Name: "channel", Type: "string", Required: true},
					{Name: "message", Type: "string", Required: true},
				}},
				{ID: "create_channel", Name: "Create Channel"},
			},
		},
		{
			ID:          "int-002",
			Name:        "PagerDuty",
			Type:        "alerting",
			Description: "PagerDuty incident management",
			Enabled:     true,
			Actions: []IntegrationAction{
				{ID: "create_incident", Name: "Create Incident"},
				{ID: "acknowledge", Name: "Acknowledge"},
				{ID: "resolve", Name: "Resolve"},
			},
		},
		{
			ID:          "int-003",
			Name:        "Jira",
			Type:        "ticketing",
			Description: "Jira issue tracking",
			Enabled:     true,
			Actions: []IntegrationAction{
				{ID: "create_issue", Name: "Create Issue"},
				{ID: "update_issue", Name: "Update Issue"},
				{ID: "transition", Name: "Transition Issue"},
			},
		},
		{
			ID:          "int-004",
			Name:        "Chainalysis",
			Type:        "threat_intel",
			Description: "Chainalysis blockchain intelligence",
			Enabled:     true,
			Actions: []IntegrationAction{
				{ID: "screen_address", Name: "Screen Address"},
				{ID: "get_risk_score", Name: "Get Risk Score"},
				{ID: "trace_funds", Name: "Trace Funds"},
			},
		},
		{
			ID:          "int-005",
			Name:        "Elliptic",
			Type:        "threat_intel",
			Description: "Elliptic blockchain analytics",
			Enabled:     true,
			Actions: []IntegrationAction{
				{ID: "wallet_screening", Name: "Wallet Screening"},
				{ID: "transaction_screening", Name: "Transaction Screening"},
			},
		},
		{
			ID:          "int-006",
			Name:        "AWS S3",
			Type:        "storage",
			Description: "AWS S3 artifact storage",
			Enabled:     true,
			Actions: []IntegrationAction{
				{ID: "upload", Name: "Upload File"},
				{ID: "download", Name: "Download File"},
			},
		},
		{
			ID:          "int-007",
			Name:        "TheGraph",
			Type:        "blockchain",
			Description: "TheGraph protocol indexer",
			Enabled:     true,
			Actions: []IntegrationAction{
				{ID: "query", Name: "Query Subgraph"},
			},
		},
		{
			ID:          "int-008",
			Name:        "Tenderly",
			Type:        "blockchain",
			Description: "Tenderly transaction simulation",
			Enabled:     true,
			Actions: []IntegrationAction{
				{ID: "simulate", Name: "Simulate Transaction"},
				{ID: "debug", Name: "Debug Transaction"},
			},
		},
	}

	for i := range integrations {
		e.integrations[integrations[i].ID] = &integrations[i]
	}
}

// CreateWorkflow creates a new workflow
func (e *Engine) CreateWorkflow(ctx context.Context, wf *Workflow) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if wf.ID == "" {
		wf.ID = fmt.Sprintf("wf-%d", time.Now().UnixNano())
	}
	wf.Status = WorkflowStatusDraft
	wf.Version = 1
	wf.CreatedAt = time.Now()
	wf.UpdatedAt = time.Now()

	e.workflows[wf.ID] = wf
	return nil
}

// GetWorkflow retrieves a workflow by ID
func (e *Engine) GetWorkflow(ctx context.Context, workflowID string) (*Workflow, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	wf, exists := e.workflows[workflowID]
	if !exists {
		return nil, fmt.Errorf("workflow not found: %s", workflowID)
	}
	return wf, nil
}

// ListWorkflows lists all workflows
func (e *Engine) ListWorkflows(ctx context.Context, status *WorkflowStatus) []*Workflow {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*Workflow
	for _, wf := range e.workflows {
		if status != nil && wf.Status != *status {
			continue
		}
		result = append(result, wf)
	}
	return result
}

// ActivateWorkflow activates a workflow
func (e *Engine) ActivateWorkflow(ctx context.Context, workflowID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	wf, exists := e.workflows[workflowID]
	if !exists {
		return fmt.Errorf("workflow not found: %s", workflowID)
	}

	wf.Status = WorkflowStatusActive
	wf.UpdatedAt = time.Now()
	return nil
}

// TriggerWorkflow triggers a workflow execution
func (e *Engine) TriggerWorkflow(ctx context.Context, workflowID string, triggerData map[string]interface{}) (*Execution, error) {
	e.mu.RLock()
	wf, exists := e.workflows[workflowID]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("workflow not found: %s", workflowID)
	}

	if wf.Status != WorkflowStatusActive {
		return nil, fmt.Errorf("workflow is not active: %s", wf.Status)
	}

	exec := &Execution{
		ID:           fmt.Sprintf("exec-%d", time.Now().UnixNano()),
		WorkflowID:   workflowID,
		WorkflowName: wf.Name,
		Status:       ExecutionStatusPending,
		TriggerData:  triggerData,
		Variables:    make(map[string]interface{}),
		StepResults:  []StepResult{},
		StartedAt:    time.Now(),
		Metadata:     make(map[string]interface{}),
	}

	// Copy workflow variables
	for k, v := range wf.Variables {
		exec.Variables[k] = v
	}

	e.mu.Lock()
	e.executions[exec.ID] = exec
	e.mu.Unlock()

	return exec, nil
}

// GetExecution retrieves an execution by ID
func (e *Engine) GetExecution(ctx context.Context, executionID string) (*Execution, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	exec, exists := e.executions[executionID]
	if !exists {
		return nil, fmt.Errorf("execution not found: %s", executionID)
	}
	return exec, nil
}

// ListExecutions lists workflow executions
func (e *Engine) ListExecutions(ctx context.Context, workflowID string, status *ExecutionStatus) []*Execution {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*Execution
	for _, exec := range e.executions {
		if workflowID != "" && exec.WorkflowID != workflowID {
			continue
		}
		if status != nil && exec.Status != *status {
			continue
		}
		result = append(result, exec)
	}
	return result
}

// ListIntegrations lists all integrations
func (e *Engine) ListIntegrations(ctx context.Context) []*Integration {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*Integration
	for _, integ := range e.integrations {
		result = append(result, integ)
	}
	return result
}

// ExportWorkflow exports a workflow to JSON
func (e *Engine) ExportWorkflow(ctx context.Context, workflowID string) ([]byte, error) {
	e.mu.RLock()
	wf, exists := e.workflows[workflowID]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("workflow not found: %s", workflowID)
	}

	return json.MarshalIndent(wf, "", "  ")
}

// GetWorkflowCount returns the number of workflows
func (e *Engine) GetWorkflowCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.workflows)
}

// GetIntegrationCount returns the number of integrations
func (e *Engine) GetIntegrationCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.integrations)
}

// GetExecutionCount returns the number of executions
func (e *Engine) GetExecutionCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.executions)
}

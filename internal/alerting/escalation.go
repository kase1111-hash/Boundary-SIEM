package alerting

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"boundary-siem/internal/correlation"

	"github.com/google/uuid"
)

// EscalationPolicy defines how unacknowledged alerts escalate over time.
type EscalationPolicy struct {
	ID       string           `yaml:"id" json:"id"`
	Name     string           `yaml:"name" json:"name"`
	Enabled  bool             `yaml:"enabled" json:"enabled"`
	Severity *correlation.Severity `yaml:"severity,omitempty" json:"severity,omitempty"` // nil = all severities
	Rules    []EscalationRule `yaml:"rules" json:"rules"`
}

// EscalationRule defines a single escalation step.
type EscalationRule struct {
	After    time.Duration `yaml:"after" json:"after"`       // Time since alert creation
	Channels []string      `yaml:"channels" json:"channels"` // Channel names to notify
	Message  string        `yaml:"message" json:"message"`   // Optional escalation message
}

// SuppressionWindow defines a time window during which alerting is suppressed.
type SuppressionWindow struct {
	ID          string     `yaml:"id" json:"id"`
	Name        string     `yaml:"name" json:"name"`
	Enabled     bool       `yaml:"enabled" json:"enabled"`
	StartTime   time.Time  `yaml:"start_time" json:"start_time"`
	EndTime     time.Time  `yaml:"end_time" json:"end_time"`
	RuleIDs     []string   `yaml:"rule_ids,omitempty" json:"rule_ids,omitempty"`     // Empty = all rules
	Severities  []string   `yaml:"severities,omitempty" json:"severities,omitempty"` // Empty = all severities
	CreatedBy   string     `yaml:"created_by" json:"created_by"`
	Description string     `yaml:"description" json:"description"`
}

// EscalationEngine monitors alerts and triggers escalations.
type EscalationEngine struct {
	policies     []EscalationPolicy
	suppressions []SuppressionWindow
	manager      *Manager
	channels     map[string]NotificationChannel
	escalated    map[string]map[int]bool // alertID -> ruleIndex -> escalated
	mu           sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// NewEscalationEngine creates a new escalation engine.
func NewEscalationEngine(manager *Manager) *EscalationEngine {
	return &EscalationEngine{
		manager:   manager,
		channels:  make(map[string]NotificationChannel),
		escalated: make(map[string]map[int]bool),
		stopCh:    make(chan struct{}),
	}
}

// AddPolicy registers an escalation policy.
func (e *EscalationEngine) AddPolicy(policy EscalationPolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies = append(e.policies, policy)
	slog.Info("escalation policy registered", "id", policy.ID, "name", policy.Name)
}

// AddSuppression registers a suppression window.
func (e *EscalationEngine) AddSuppression(window SuppressionWindow) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.suppressions = append(e.suppressions, window)
	slog.Info("suppression window registered", "id", window.ID, "name", window.Name,
		"start", window.StartTime, "end", window.EndTime)
}

// RemoveSuppression removes a suppression window by ID.
func (e *EscalationEngine) RemoveSuppression(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, s := range e.suppressions {
		if s.ID == id {
			e.suppressions = append(e.suppressions[:i], e.suppressions[i+1:]...)
			slog.Info("suppression window removed", "id", id)
			return
		}
	}
}

// RegisterChannel makes a notification channel available for escalation.
func (e *EscalationEngine) RegisterChannel(ch NotificationChannel) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.channels[ch.Name()] = ch
}

// IsSuppressed checks if an alert should be suppressed based on active windows.
func (e *EscalationEngine) IsSuppressed(alert *Alert) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now()
	for _, window := range e.suppressions {
		if !window.Enabled {
			continue
		}
		if now.Before(window.StartTime) || now.After(window.EndTime) {
			continue
		}

		// Check rule filter
		if len(window.RuleIDs) > 0 {
			matched := false
			for _, ruleID := range window.RuleIDs {
				if ruleID == alert.RuleID {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Check severity filter
		if len(window.Severities) > 0 {
			matched := false
			for _, sev := range window.Severities {
				if sev == string(alert.Severity) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		return true
	}
	return false
}

// Start begins the escalation check loop.
func (e *EscalationEngine) Start(ctx context.Context, checkInterval time.Duration) {
	if checkInterval <= 0 {
		checkInterval = 1 * time.Minute
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()

		ticker := time.NewTicker(checkInterval)
		defer ticker.Stop()

		slog.Info("escalation engine started", "check_interval", checkInterval)

		for {
			select {
			case <-ctx.Done():
				return
			case <-e.stopCh:
				return
			case <-ticker.C:
				e.checkEscalations(ctx)
			}
		}
	}()
}

// Stop halts the escalation engine.
func (e *EscalationEngine) Stop() {
	close(e.stopCh)
	e.wg.Wait()
	slog.Info("escalation engine stopped")
}

func (e *EscalationEngine) checkEscalations(ctx context.Context) {
	e.mu.RLock()
	policies := make([]EscalationPolicy, len(e.policies))
	copy(policies, e.policies)
	e.mu.RUnlock()

	// Get all new (unacknowledged) alerts
	alerts, err := e.manager.ListAlerts(ctx, AlertFilter{
		Status: statusPtr(StatusNew),
	})
	if err != nil {
		slog.Warn("escalation check failed to list alerts", "error", err)
		return
	}

	now := time.Now()

	for _, alert := range alerts {
		for _, policy := range policies {
			if !policy.Enabled {
				continue
			}

			// Check severity match
			if policy.Severity != nil && alert.Severity != *policy.Severity {
				continue
			}

			// Check suppression
			if e.IsSuppressed(alert) {
				continue
			}

			alertKey := alert.ID.String()

			for ruleIdx, rule := range policy.Rules {
				elapsed := now.Sub(alert.CreatedAt)
				if elapsed < rule.After {
					continue
				}

				// Check if already escalated for this rule
				e.mu.RLock()
				alreadyEscalated := false
				if m, ok := e.escalated[alertKey]; ok {
					alreadyEscalated = m[ruleIdx]
				}
				e.mu.RUnlock()

				if alreadyEscalated {
					continue
				}

				// Trigger escalation
				e.triggerEscalation(ctx, alert, &policy, ruleIdx, &rule)
			}
		}
	}

	// Clean up escalation tracking for resolved/acknowledged alerts
	e.cleanupTracking()
}

func (e *EscalationEngine) triggerEscalation(ctx context.Context, alert *Alert, policy *EscalationPolicy, ruleIdx int, rule *EscalationRule) {
	alertKey := alert.ID.String()

	// Mark as escalated
	e.mu.Lock()
	if _, ok := e.escalated[alertKey]; !ok {
		e.escalated[alertKey] = make(map[int]bool)
	}
	e.escalated[alertKey][ruleIdx] = true
	e.mu.Unlock()

	slog.Warn("escalating alert",
		"alert_id", alert.ID,
		"policy", policy.Name,
		"after", rule.After,
		"channels", rule.Channels,
	)

	// Add escalation note to alert
	note := fmt.Sprintf("Escalated by policy %q after %s: %s", policy.Name, rule.After, rule.Message)
	if err := e.manager.AddNote(ctx, alert.ID, "escalation-engine", note); err != nil {
		slog.Warn("failed to add escalation note", "alert_id", alert.ID, "error", err)
	}

	// Send to escalation channels
	e.mu.RLock()
	for _, chName := range rule.Channels {
		ch, ok := e.channels[chName]
		if !ok {
			slog.Warn("escalation channel not found", "channel", chName, "alert_id", alert.ID)
			continue
		}
		go func(c NotificationChannel) {
			if err := c.Send(ctx, alert); err != nil {
				slog.Error("escalation notification failed",
					"channel", c.Name(),
					"alert_id", alert.ID,
					"error", err)
			}
		}(ch)
	}
	e.mu.RUnlock()
}

func (e *EscalationEngine) cleanupTracking() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for alertKey := range e.escalated {
		id, err := uuid.Parse(alertKey)
		if err != nil {
			delete(e.escalated, alertKey)
			continue
		}
		alert, err := e.manager.GetAlert(context.Background(), id)
		if err != nil || alert.Status == StatusResolved || alert.Status == StatusAcknowledged {
			delete(e.escalated, alertKey)
		}
	}
}

// BuiltinEscalationPolicies returns default escalation policies.
func BuiltinEscalationPolicies() []EscalationPolicy {
	critSev := correlation.SeverityCritical
	highSev := correlation.SeverityHigh

	return []EscalationPolicy{
		{
			ID:       "escalation-critical",
			Name:     "Critical Alert Escalation",
			Enabled:  true,
			Severity: &critSev,
			Rules: []EscalationRule{
				{After: 15 * time.Minute, Channels: []string{"default"}, Message: "Critical alert unacknowledged for 15 minutes"},
				{After: 30 * time.Minute, Channels: []string{"default"}, Message: "Critical alert unacknowledged for 30 minutes — immediate action required"},
				{After: 1 * time.Hour, Channels: []string{"default"}, Message: "Critical alert unacknowledged for 1 hour — executive escalation"},
			},
		},
		{
			ID:       "escalation-high",
			Name:     "High Severity Alert Escalation",
			Enabled:  true,
			Severity: &highSev,
			Rules: []EscalationRule{
				{After: 30 * time.Minute, Channels: []string{"default"}, Message: "High severity alert unacknowledged for 30 minutes"},
				{After: 2 * time.Hour, Channels: []string{"default"}, Message: "High severity alert unacknowledged for 2 hours — management escalation"},
			},
		},
	}
}

// ActiveSuppressions returns currently active suppression windows.
func (e *EscalationEngine) ActiveSuppressions() []SuppressionWindow {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now()
	var active []SuppressionWindow
	for _, w := range e.suppressions {
		if w.Enabled && now.After(w.StartTime) && now.Before(w.EndTime) {
			active = append(active, w)
		}
	}
	return active
}

func statusPtr(s AlertStatus) *AlertStatus {
	return &s
}

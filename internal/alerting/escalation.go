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
	ID       string                `yaml:"id" json:"id"`
	Name     string                `yaml:"name" json:"name"`
	Enabled  bool                  `yaml:"enabled" json:"enabled"`
	Severity *correlation.Severity `yaml:"severity,omitempty" json:"severity,omitempty"` // nil = all severities
	Rules    []EscalationRule      `yaml:"rules" json:"rules"`
}

// EscalationRule defines a single escalation step.
type EscalationRule struct {
	After    time.Duration `yaml:"after" json:"after"`       // Time since alert creation
	Channels []string      `yaml:"channels" json:"channels"` // Channel names to notify
	Message  string        `yaml:"message" json:"message"`   // Optional escalation message
}

// SuppressionWindow defines a time window during which alerting is suppressed.
type SuppressionWindow struct {
	ID          string    `yaml:"id" json:"id"`
	Name        string    `yaml:"name" json:"name"`
	Enabled     bool      `yaml:"enabled" json:"enabled"`
	StartTime   time.Time `yaml:"start_time" json:"start_time"`
	EndTime     time.Time `yaml:"end_time" json:"end_time"`
	RuleIDs     []string  `yaml:"rule_ids,omitempty" json:"rule_ids,omitempty"`     // Empty = all rules
	Severities  []string  `yaml:"severities,omitempty" json:"severities,omitempty"` // Empty = all severities
	CreatedBy   string    `yaml:"created_by" json:"created_by"`
	Description string    `yaml:"description" json:"description"`
}

// EscalationEngine monitors alerts and triggers escalations.
type EscalationEngine struct {
	policies     []EscalationPolicy
	suppressions []SuppressionWindow
	manager      *Manager
	channels     map[string]NotificationChannel
	escalated    map[string]map[escalationStep]bool // alertID -> policy step -> escalated
	mu           sync.RWMutex
	stopCh       chan struct{}
	wg           sync.WaitGroup
	notifySem    chan struct{} // semaphore to limit concurrent notification goroutines
}

// escalationNoteAuthor is the author of the note the engine adds to an alert
// for every escalation step it fires.
const escalationNoteAuthor = "escalation-engine"

// escalationStep identifies one rule of one policy. Tracking must include the
// policy: rule indexes restart at 0 in every policy, so keying by rule index
// alone lets one policy's step suppress another policy's step of the same
// index. The policy's position is included alongside its ID so policies with
// empty or duplicate IDs are still tracked separately (policies are only
// ever appended, so positions are stable).
type escalationStep struct {
	policyIdx int
	policyID  string
	ruleIdx   int
}

// NewEscalationEngine creates a new escalation engine.
func NewEscalationEngine(manager *Manager) *EscalationEngine {
	return &EscalationEngine{
		manager:   manager,
		channels:  make(map[string]NotificationChannel),
		escalated: make(map[string]map[escalationStep]bool),
		stopCh:    make(chan struct{}),
		notifySem: make(chan struct{}, 50), // limit to 50 concurrent notification goroutines
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

	// Get all new (unacknowledged) alerts. Escalation works on the in-memory
	// alerts, which LoadFromDB restores at startup. ListAlerts is not used:
	// it falls back to scanning the alerts table whenever no in-memory alert
	// matches (the normal state once every alert is triaged), and that scan
	// can return stale versions of alerts already handled in memory.
	alerts, _ := e.manager.listInMemory(AlertFilter{
		Status: statusPtr(StatusNew),
	})

	now := time.Now()

	for _, alert := range alerts {
		for policyIdx, policy := range policies {
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

				step := escalationStep{policyIdx: policyIdx, policyID: policy.ID, ruleIdx: ruleIdx}

				// Check if already escalated for this policy step
				e.mu.RLock()
				alreadyEscalated := false
				if m, ok := e.escalated[alertKey]; ok {
					alreadyEscalated = m[step]
				}
				e.mu.RUnlock()

				if alreadyEscalated {
					continue
				}

				// The tracking above is lost on restart, but the step's
				// note, persisted with the alert, records that it fired.
				note := escalationNote(&policy, &rule)
				if hasNote(alert, escalationNoteAuthor, note) {
					e.markEscalated(alertKey, step)
					continue
				}

				// Trigger escalation
				e.triggerEscalation(ctx, alert, &policy, step, &rule, note)
			}
		}
	}

	// Clean up escalation tracking for resolved/acknowledged alerts
	e.cleanupTracking()
}

// escalationNote is the note added to an alert when rule of policy fires.
func escalationNote(policy *EscalationPolicy, rule *EscalationRule) string {
	return fmt.Sprintf("Escalated by policy %q after %s: %s", policy.Name, rule.After, rule.Message)
}

// hasNote reports whether alert has a note with the given author and content.
func hasNote(alert *Alert, author, content string) bool {
	for _, n := range alert.Notes {
		if n.Author == author && n.Content == content {
			return true
		}
	}
	return false
}

func (e *EscalationEngine) markEscalated(alertKey string, step escalationStep) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.escalated[alertKey]; !ok {
		e.escalated[alertKey] = make(map[escalationStep]bool)
	}
	e.escalated[alertKey][step] = true
}

func (e *EscalationEngine) triggerEscalation(ctx context.Context, alert *Alert, policy *EscalationPolicy, step escalationStep, rule *EscalationRule, note string) {
	e.markEscalated(alert.ID.String(), step)

	slog.Warn("escalating alert",
		"alert_id", alert.ID,
		"policy", policy.Name,
		"after", rule.After,
		"channels", rule.Channels,
	)

	// Add escalation note to alert
	if err := e.manager.AddNote(ctx, alert.ID, escalationNoteAuthor, note); err != nil {
		slog.Warn("failed to add escalation note", "alert_id", alert.ID, "error", err)
	}

	// Send to escalation channels with bounded concurrency
	e.mu.RLock()
	for _, chName := range rule.Channels {
		ch, ok := e.channels[chName]
		if !ok {
			slog.Warn("escalation channel not found", "channel", chName, "alert_id", alert.ID)
			continue
		}
		go func(c NotificationChannel) {
			// Acquire semaphore slot to limit concurrent goroutines
			e.notifySem <- struct{}{}
			defer func() { <-e.notifySem }()

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
	// Collect keys under lock to avoid holding lock during DB calls.
	e.mu.RLock()
	keys := make([]string, 0, len(e.escalated))
	for alertKey := range e.escalated {
		keys = append(keys, alertKey)
	}
	e.mu.RUnlock()

	// Query DB without holding lock.
	toDelete := make([]string, 0)
	for _, alertKey := range keys {
		id, err := uuid.Parse(alertKey)
		if err != nil {
			toDelete = append(toDelete, alertKey)
			continue
		}
		alert, err := e.manager.GetAlert(context.Background(), id)
		if err != nil || alert.Status == StatusResolved || alert.Status == StatusAcknowledged {
			toDelete = append(toDelete, alertKey)
		}
	}

	// Re-acquire lock to delete stale entries.
	if len(toDelete) > 0 {
		e.mu.Lock()
		for _, key := range toDelete {
			delete(e.escalated, key)
		}
		e.mu.Unlock()
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

package correlation

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// Alert represents a correlation alert.
type Alert struct {
	ID          uuid.UUID      `json:"id"`
	RuleID      string         `json:"rule_id"`
	RuleName    string         `json:"rule_name"`
	Severity    int            `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Timestamp   time.Time      `json:"timestamp"`
	Events      []EventRef     `json:"events"`
	GroupKey    string         `json:"group_key,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	MITRE       *MITREMapping  `json:"mitre,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	Status      AlertStatus    `json:"status"`
}

// EventRef references an event that contributed to the alert.
type EventRef struct {
	EventID   uuid.UUID `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
}

// AlertStatus represents the status of an alert.
type AlertStatus string

const (
	AlertStatusNew      AlertStatus = "new"
	AlertStatusAck      AlertStatus = "acknowledged"
	AlertStatusResolved AlertStatus = "resolved"
)

// AlertHandler is called when an alert is generated.
type AlertHandler func(context.Context, *Alert) error

// EngineConfig configures the correlation engine.
type EngineConfig struct {
	MaxStateEntries  int           // Maximum entries per rule state
	StateCleanupFreq time.Duration // How often to clean expired state
	WorkerCount      int           // Number of correlation workers
}

// DefaultEngineConfig returns default engine configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		MaxStateEntries:  100000,
		StateCleanupFreq: 30 * time.Second,
		WorkerCount:      4,
	}
}

// Engine processes events and evaluates correlation rules.
type Engine struct {
	config   EngineConfig
	rules    map[string]*Rule
	states   map[string]*RuleState
	handlers []AlertHandler
	mu       sync.RWMutex
	eventCh  chan *schema.Event
	alertCh  chan *Alert
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// RuleState maintains correlation state for a rule.
type RuleState struct {
	mu       sync.Mutex
	windows  map[string]*Window // Keyed by group key
	rule     *Rule
	lastFire map[string]time.Time // For dedup
}

// Window tracks events in a time window.
type Window struct {
	Events    []*schema.Event
	StartTime time.Time
	Count     int
	Sum       float64
	// Sequence tracking
	StepIndex int
	Steps     map[int]bool
}

// NewEngine creates a new correlation engine.
func NewEngine(config EngineConfig) *Engine {
	return &Engine{
		config:  config,
		rules:   make(map[string]*Rule),
		states:  make(map[string]*RuleState),
		eventCh: make(chan *schema.Event, 10000),
		alertCh: make(chan *Alert, 1000),
		stopCh:  make(chan struct{}),
	}
}

// AddRule adds a correlation rule.
func (e *Engine) AddRule(rule *Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := rule.Validate(); err != nil {
		return err
	}

	e.rules[rule.ID] = rule
	e.states[rule.ID] = &RuleState{
		windows:  make(map[string]*Window),
		rule:     rule,
		lastFire: make(map[string]time.Time),
	}

	slog.Info("added correlation rule", "rule_id", rule.ID, "type", rule.Type)
	return nil
}

// RemoveRule removes a correlation rule.
func (e *Engine) RemoveRule(ruleID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.rules, ruleID)
	delete(e.states, ruleID)
}

// AddHandler adds an alert handler.
func (e *Engine) AddHandler(handler AlertHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers = append(e.handlers, handler)
}

// ProcessEvent queues an event for correlation processing.
func (e *Engine) ProcessEvent(event *schema.Event) {
	select {
	case e.eventCh <- event:
	default:
		slog.Warn("correlation event channel full, dropping event")
	}
}

// Start starts the correlation engine.
func (e *Engine) Start(ctx context.Context) {
	// Start workers
	for i := 0; i < e.config.WorkerCount; i++ {
		e.wg.Add(1)
		go e.worker(ctx, i)
	}

	// Start alert dispatcher
	e.wg.Add(1)
	go e.alertDispatcher(ctx)

	// Start state cleanup
	e.wg.Add(1)
	go e.stateCleanup(ctx)

	slog.Info("correlation engine started", "workers", e.config.WorkerCount)
}

// Stop stops the correlation engine.
func (e *Engine) Stop() {
	close(e.stopCh)
	e.wg.Wait()
	slog.Info("correlation engine stopped")
}

func (e *Engine) worker(ctx context.Context, id int) {
	defer e.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case event := <-e.eventCh:
			e.processEvent(ctx, event)
		}
	}
}

func (e *Engine) processEvent(ctx context.Context, event *schema.Event) {
	e.mu.RLock()
	rules := make([]*Rule, 0, len(e.rules))
	for _, rule := range e.rules {
		if rule.Enabled {
			rules = append(rules, rule)
		}
	}
	e.mu.RUnlock()

	for _, rule := range rules {
		if e.matchesRuleConditions(event, rule.Conditions) {
			e.evaluateRule(ctx, rule, event)
		}
	}
}

// matchesRuleConditions checks if event matches rule's Conditions struct.
func (e *Engine) matchesRuleConditions(event *schema.Event, conditions Conditions) bool {
	for _, cond := range conditions.Match {
		value := e.getEventField(event, cond.Field)
		if !matchValue(value, cond.Operator, cond.Value) {
			return false
		}
	}
	return true
}

// matchValue checks if a value matches an operator and expected value.
func matchValue(eventValue any, operator string, expected any) bool {
	switch operator {
	case "eq":
		return fmt.Sprintf("%v", eventValue) == fmt.Sprintf("%v", expected)
	case "ne":
		return fmt.Sprintf("%v", eventValue) != fmt.Sprintf("%v", expected)
	case "prefix":
		return strings.HasPrefix(fmt.Sprintf("%v", eventValue), fmt.Sprintf("%v", expected))
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", eventValue), fmt.Sprintf("%v", expected))
	case "gt", "gte", "lt", "lte":
		ev, ok1 := toFloat64(eventValue)
		exp, ok2 := toFloat64(expected)
		if !ok1 || !ok2 {
			return false
		}
		switch operator {
		case "gt":
			return ev > exp
		case "gte":
			return ev >= exp
		case "lt":
			return ev < exp
		case "lte":
			return ev <= exp
		}
	case "in":
		eventStr := fmt.Sprintf("%v", eventValue)
		if vals, ok := expected.([]string); ok {
			for _, v := range vals {
				if eventStr == v {
					return true
				}
			}
		}
		if vals, ok := expected.([]any); ok {
			for _, v := range vals {
				if eventStr == fmt.Sprintf("%v", v) {
					return true
				}
			}
		}
		return false
	}
	return false
}

func (e *Engine) matchesConditions(event *schema.Event, conditions []Condition) bool {
	for _, cond := range conditions {
		value := e.getEventField(event, cond.Field)
		if !cond.Match(value) {
			return false
		}
	}
	return true
}

func (e *Engine) getEventField(event *schema.Event, field string) any {
	switch field {
	case "action":
		return event.Action
	case "outcome":
		return string(event.Outcome)
	case "severity":
		return event.Severity
	case "target":
		return event.Target
	case "tenant_id":
		return event.TenantID
	case "source.product", "source_product":
		return event.Source.Product
	case "source.host", "source_host":
		return event.Source.Host
	case "source.version", "source_version":
		return event.Source.Version
	case "source.instance_id", "source_instance_id":
		return event.Source.InstanceID
	case "actor.name", "actor_name":
		if event.Actor != nil {
			return event.Actor.Name
		}
	case "actor.id", "actor_id":
		if event.Actor != nil {
			return event.Actor.ID
		}
	case "actor.ip", "actor_ip":
		if event.Actor != nil {
			return event.Actor.IPAddress
		}
	case "actor.type", "actor_type":
		if event.Actor != nil {
			return event.Actor.Type
		}
	default:
		// Check metadata
		if event.Metadata != nil {
			if v, ok := event.Metadata[field]; ok {
				return v
			}
		}
	}
	return nil
}

func (e *Engine) evaluateRule(ctx context.Context, rule *Rule, event *schema.Event) {
	e.mu.RLock()
	state := e.states[rule.ID]
	e.mu.RUnlock()

	if state == nil {
		return
	}

	groupKey := e.buildGroupKey(event, rule.GroupBy)

	state.mu.Lock()
	defer state.mu.Unlock()

	window := state.windows[groupKey]
	now := time.Now()

	// Create or reset window if needed
	if window == nil || now.Sub(window.StartTime) > rule.Window {
		window = &Window{
			Events:    make([]*schema.Event, 0, 100),
			StartTime: now,
			Steps:     make(map[int]bool),
		}
		state.windows[groupKey] = window
	}

	// Trim old events
	cutoff := now.Add(-rule.Window)
	newEvents := make([]*schema.Event, 0, len(window.Events))
	for _, e := range window.Events {
		if e.Timestamp.After(cutoff) {
			newEvents = append(newEvents, e)
		}
	}
	window.Events = append(newEvents, event)
	window.Count = len(window.Events)

	// Evaluate based on rule type
	var fired bool
	switch rule.Type {
	case RuleTypeThreshold:
		fired = e.evaluateThreshold(window, rule)
	case RuleTypeSequence:
		fired = e.evaluateSequence(window, rule, event)
	case RuleTypeAggregate:
		fired = e.evaluateAggregate(window, rule)
	}

	if fired {
		// Check for duplicate suppression
		if lastFire, ok := state.lastFire[groupKey]; ok {
			if now.Sub(lastFire) < rule.Window {
				return // Suppress duplicate
			}
		}
		state.lastFire[groupKey] = now

		alert := e.createAlert(rule, window, groupKey)
		select {
		case e.alertCh <- alert:
		default:
			slog.Warn("alert channel full, dropping alert", "rule_id", rule.ID)
		}
	}
}

func (e *Engine) buildGroupKey(event *schema.Event, groupBy []string) string {
	if len(groupBy) == 0 {
		return "default"
	}

	parts := make([]string, len(groupBy))
	for i, field := range groupBy {
		val := e.getEventField(event, field)
		parts[i] = fmt.Sprintf("%s=%v", field, val)
	}
	return fmt.Sprintf("%v", parts)
}

func (e *Engine) evaluateThreshold(window *Window, rule *Rule) bool {
	if rule.Threshold == nil {
		return false
	}

	count := window.Count
	threshold := rule.Threshold.Count

	switch rule.Threshold.Operator {
	case "gt", ">":
		return count > threshold
	case "gte", ">=":
		return count >= threshold
	case "lt", "<":
		return count < threshold
	case "lte", "<=":
		return count <= threshold
	case "eq", "=":
		return count == threshold
	default:
		return count >= threshold
	}
}

func (e *Engine) evaluateSequence(window *Window, rule *Rule, event *schema.Event) bool {
	if rule.Sequence == nil || len(rule.Sequence.Steps) == 0 {
		return false
	}

	// Find which step this event matches
	for i, step := range rule.Sequence.Steps {
		if e.matchesConditions(event, step.Conditions) {
			if rule.Sequence.Ordered {
				// Must match steps in order
				if i == window.StepIndex {
					window.StepIndex++
					window.Steps[i] = true
				}
			} else {
				// Can match any step
				window.Steps[i] = true
			}
			break
		}
	}

	// Check if sequence is complete
	requiredSteps := 0
	matchedRequired := 0
	for i, step := range rule.Sequence.Steps {
		if step.Required || true { // All steps required for now
			requiredSteps++
			if window.Steps[i] {
				matchedRequired++
			}
		}
	}

	return matchedRequired >= requiredSteps
}

func (e *Engine) evaluateAggregate(window *Window, rule *Rule) bool {
	if rule.Aggregate == nil {
		return false
	}

	var value float64
	field := rule.Aggregate.Field

	switch rule.Aggregate.Function {
	case "count":
		value = float64(window.Count)
	case "sum":
		for _, event := range window.Events {
			if v, ok := toFloat64(e.getEventField(event, field)); ok {
				value += v
			}
		}
	case "avg":
		var sum float64
		for _, event := range window.Events {
			if v, ok := toFloat64(e.getEventField(event, field)); ok {
				sum += v
			}
		}
		if window.Count > 0 {
			value = sum / float64(window.Count)
		}
	case "max":
		value = -1e99
		for _, event := range window.Events {
			if v, ok := toFloat64(e.getEventField(event, field)); ok {
				if v > value {
					value = v
				}
			}
		}
	case "min":
		value = 1e99
		for _, event := range window.Events {
			if v, ok := toFloat64(e.getEventField(event, field)); ok {
				if v < value {
					value = v
				}
			}
		}
	case "count_distinct":
		distinct := make(map[string]bool)
		for _, event := range window.Events {
			v := e.getEventField(event, field)
			distinct[fmt.Sprintf("%v", v)] = true
		}
		value = float64(len(distinct))
	}

	threshold := rule.Aggregate.Value
	switch rule.Aggregate.Operator {
	case "gt", ">":
		return value > threshold
	case "gte", ">=":
		return value >= threshold
	case "lt", "<":
		return value < threshold
	case "lte", "<=":
		return value <= threshold
	case "eq", "=":
		return value == threshold
	default:
		return value >= threshold
	}
}

func (e *Engine) createAlert(rule *Rule, window *Window, groupKey string) *Alert {
	events := make([]EventRef, 0, len(window.Events))
	for _, event := range window.Events {
		events = append(events, EventRef{
			EventID:   event.EventID,
			Timestamp: event.Timestamp,
			Action:    event.Action,
		})
	}

	return &Alert{
		ID:          uuid.New(),
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Severity:    rule.Severity,
		Title:       rule.Name,
		Description: rule.Description,
		Timestamp:   time.Now(),
		Events:      events,
		GroupKey:    groupKey,
		Tags:        rule.Tags,
		MITRE:       rule.MITRE,
		Metadata:    rule.Metadata,
		Status:      AlertStatusNew,
	}
}

func (e *Engine) alertDispatcher(ctx context.Context) {
	defer e.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case alert := <-e.alertCh:
			e.mu.RLock()
			handlers := e.handlers
			e.mu.RUnlock()

			for _, handler := range handlers {
				if err := handler(ctx, alert); err != nil {
					slog.Error("alert handler failed",
						"error", err,
						"rule_id", alert.RuleID)
				}
			}
		}
	}
}

func (e *Engine) stateCleanup(ctx context.Context) {
	defer e.wg.Done()

	ticker := time.NewTicker(e.config.StateCleanupFreq)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.cleanupExpiredState()
		}
	}
}

func (e *Engine) cleanupExpiredState() {
	e.mu.RLock()
	states := make(map[string]*RuleState)
	for k, v := range e.states {
		states[k] = v
	}
	e.mu.RUnlock()

	now := time.Now()
	for _, state := range states {
		state.mu.Lock()
		for groupKey, window := range state.windows {
			if now.Sub(window.StartTime) > state.rule.Window*2 {
				delete(state.windows, groupKey)
			}
		}
		// Cleanup old fire times
		for groupKey, fireTime := range state.lastFire {
			if now.Sub(fireTime) > state.rule.Window*2 {
				delete(state.lastFire, groupKey)
			}
		}
		state.mu.Unlock()
	}
}

// Stats returns engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := map[string]interface{}{
		"rules_count":    len(e.rules),
		"event_queue":    len(e.eventCh),
		"alert_queue":    len(e.alertCh),
		"handler_count":  len(e.handlers),
	}

	// Count windows
	totalWindows := 0
	for _, state := range e.states {
		state.mu.Lock()
		totalWindows += len(state.windows)
		state.mu.Unlock()
	}
	stats["active_windows"] = totalWindows

	return stats
}

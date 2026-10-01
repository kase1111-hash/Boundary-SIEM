package correlation

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
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

	// trigger is the event whose arrival made the rule fire. AlertReinjector
	// copies its actor and metadata into the re-injected alert.fired event,
	// so that chains can correlate their stages by entity (see ChainDef).
	trigger *schema.Event
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
	DedupWindow      time.Duration // Alert deduplication window (0 = use rule window)
	EventChannelSize int           // Event channel buffer size
	AlertChannelSize int           // Alert channel buffer size
}

// DefaultEngineConfig returns default engine configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		MaxStateEntries:  100000,
		StateCleanupFreq: 30 * time.Second,
		WorkerCount:      4,
		DedupWindow:      0, // Use per-rule window by default
		EventChannelSize: 10000,
		AlertChannelSize: 1000,
	}
}

// defaultGroupKey is the group key of rules without GroupBy.
const defaultGroupKey = "default"

// Engine processes events and evaluates correlation rules.
//
// Windows are sliding and measured in processing time: an event counts for
// Rule.Window after the engine receives it, whatever its own Timestamp says,
// so late or clock-skewed events still correlate.
type Engine struct {
	config    EngineConfig
	rules     map[string]*Rule
	consumers map[string]bool // rule ID -> rule evaluates re-injected alert.fired events
	states    map[string]*RuleState
	handlers  []AlertHandler
	baseline  *BaselineEngine
	mu        sync.RWMutex
	eventCh   chan *schema.Event
	alertCh   chan *Alert
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// RuleState maintains correlation state for a rule.
type RuleState struct {
	mu       sync.Mutex
	windows  map[string]*Window // Keyed by group key
	rule     *Rule
	lastFire map[string]time.Time // For dedup
}

// Window tracks events in a sliding time window.
type Window struct {
	Events    []*schema.Event
	StartTime time.Time // creation, or start of the current absence period
	LastSeen  time.Time // arrival of the most recent event
	Count     int
	Sum       float64
	// Sequence tracking
	StepIndex int
	Steps     map[int]bool
	SeqStart  time.Time // when the first step of the current sequence matched
	// Absence tracking
	AbsenceSeen    bool
	AbsenceChecked time.Time

	arrivals []time.Time // arrival time of each entry of Events
}

func newWindow(now time.Time) *Window {
	return &Window{
		Events:    make([]*schema.Event, 0, 16),
		StartTime: now,
		LastSeen:  now,
		Steps:     make(map[int]bool),
	}
}

// trim drops events that arrived more than span before now.
func (w *Window) trim(now time.Time, span time.Duration) {
	cutoff := now.Add(-span)
	drop := 0
	for drop < len(w.arrivals) && !w.arrivals[drop].After(cutoff) {
		drop++
	}
	if drop > 0 {
		w.Events = append(w.Events[:0], w.Events[drop:]...)
		w.arrivals = append(w.arrivals[:0], w.arrivals[drop:]...)
	}
	w.Count = len(w.Events)
}

func (w *Window) add(event *schema.Event, now time.Time) {
	w.Events = append(w.Events, event)
	w.arrivals = append(w.arrivals, now)
	w.Count = len(w.Events)
	w.LastSeen = now
}

func (w *Window) clearEvents() {
	w.Events = w.Events[:0]
	w.arrivals = w.arrivals[:0]
	w.Count = 0
}

func (w *Window) resetSequence() {
	w.StepIndex = 0
	w.Steps = make(map[int]bool)
	w.SeqStart = time.Time{}
}

// NewEngine creates a new correlation engine. Zero or negative sizes, counts
// and frequencies in config are replaced by DefaultEngineConfig values.
func NewEngine(config EngineConfig) *Engine {
	defaults := DefaultEngineConfig()
	if config.EventChannelSize <= 0 {
		config.EventChannelSize = defaults.EventChannelSize
	}
	if config.AlertChannelSize <= 0 {
		config.AlertChannelSize = defaults.AlertChannelSize
	}
	if config.MaxStateEntries <= 0 {
		config.MaxStateEntries = defaults.MaxStateEntries
	}
	if config.StateCleanupFreq <= 0 {
		config.StateCleanupFreq = defaults.StateCleanupFreq
	}
	if config.WorkerCount <= 0 {
		config.WorkerCount = defaults.WorkerCount
	}
	return &Engine{
		config:    config,
		rules:     make(map[string]*Rule),
		consumers: make(map[string]bool),
		states:    make(map[string]*RuleState),
		baseline:  NewBaselineEngine(),
		eventCh:   make(chan *schema.Event, config.EventChannelSize),
		alertCh:   make(chan *Alert, config.AlertChannelSize),
		stopCh:    make(chan struct{}),
	}
}

// Baseline returns the engine's baseline engine for external metric recording.
func (e *Engine) Baseline() *BaselineEngine {
	return e.baseline
}

// AddRule adds a correlation rule, replacing any rule with the same ID (and
// its correlation state).
func (e *Engine) AddRule(rule *Rule) error {
	if err := rule.Validate(); err != nil {
		return err
	}

	now := time.Now()
	state := &RuleState{
		windows:  make(map[string]*Window),
		rule:     rule,
		lastFire: make(map[string]time.Time),
	}
	if rule.Type == RuleTypeAbsence && len(rule.GroupBy) == 0 {
		// The expected event is due within one window from now.
		state.windows[defaultGroupKey] = newWindow(now)
	}

	e.mu.Lock()
	e.rules[rule.ID] = rule
	e.consumers[rule.ID] = rule.consumesAlerts()
	e.states[rule.ID] = state
	e.mu.Unlock()

	slog.Info("added correlation rule", "rule_id", rule.ID, "type", rule.Type)
	return nil
}

// RemoveRule removes a correlation rule.
func (e *Engine) RemoveRule(ruleID string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.rules, ruleID)
	delete(e.consumers, ruleID)
	delete(e.states, ruleID)
}

// SetRuleEnabled enables or disables a loaded rule and returns the updated
// rule. Rules are shared with running workers and API readers, so the rule is
// replaced by an updated copy instead of being modified in place; its
// correlation state is kept, except that enabling an absence rule starts a
// new period for every group (no event reached the rule while it was
// disabled, so that time must not count as an absence).
func (e *Engine) SetRuleEnabled(ruleID string, enabled bool) (*Rule, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	rule, ok := e.rules[ruleID]
	if !ok {
		return nil, false
	}
	if rule.Enabled == enabled {
		return rule, true
	}
	updated := *rule
	updated.Enabled = enabled
	e.rules[ruleID] = &updated
	if state := e.states[ruleID]; state != nil {
		state.mu.Lock()
		state.rule = &updated
		if enabled && updated.Type == RuleTypeAbsence {
			now := time.Now()
			for _, window := range state.windows {
				window.StartTime = now
				window.AbsenceSeen = false
				window.clearEvents()
			}
		}
		state.mu.Unlock()
	}
	return &updated, true
}

// CheckDependencies reports every loaded rule that builds on a rule which is
// not loaded (depends_on entries and kill-chain stages, see
// ReferencedRuleIDs). Call it once all rules are registered: such rules can
// never fire.
func (e *Engine) CheckDependencies() error {
	return ValidateDependencies(e.GetRules(), nil)
}

// AddHandler adds an alert handler.
func (e *Engine) AddHandler(handler AlertHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers = append(e.handlers, handler)
}

// ProcessEvent queues an event for correlation processing.
// Applies backpressure by blocking for up to 100ms before dropping.
func (e *Engine) ProcessEvent(event *schema.Event) {
	select {
	case e.eventCh <- event:
		return
	default:
	}

	// Backpressure: wait briefly before dropping
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case e.eventCh <- event:
	case <-timer.C:
		slog.Warn("correlation event channel full after backpressure, dropping event",
			"channel_len", len(e.eventCh),
			"channel_cap", cap(e.eventCh),
		)
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

	// Start absence rule checker
	e.wg.Add(1)
	go e.absenceChecker(ctx)

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

// isSynthetic reports whether event is an alert re-injected by
// AlertReinjector. An ingested event's own is_synthetic metadata does not
// count (see metaReinjected).
func isSynthetic(event *schema.Event) bool {
	_, ok := reinjectedDepth(event)
	return ok
}

func (e *Engine) processEvent(ctx context.Context, event *schema.Event) {
	synthetic := isSynthetic(event)

	e.mu.RLock()
	rules := make([]*Rule, 0, len(e.rules))
	for id, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		// Re-injected alerts only reach rules written to consume them, so an
		// alert cannot re-trigger loosely filtered rules (alert storms).
		if synthetic && !e.consumers[id] {
			continue
		}
		rules = append(rules, rule)
	}
	e.mu.RUnlock()

	for _, rule := range rules {
		if e.matchesRuleFilter(event, rule) {
			e.evaluateRule(ctx, rule, event)
		}
	}
}

// matchesRuleFilter checks the event against all of the rule's filters:
// Conditions.Match, EventConditions and the Condition tree.
func (e *Engine) matchesRuleFilter(event *schema.Event, rule *Rule) bool {
	if !e.matchesRuleConditions(event, rule.Conditions) {
		return false
	}
	if !e.matchesConditions(event, rule.EventConditions) {
		return false
	}
	return rule.Condition.IsZero() || e.matchConditionTree(event, rule.Condition)
}

// matchesRuleConditions checks if event matches rule's Conditions struct.
// All match conditions are ANDed together (all must match).
func (e *Engine) matchesRuleConditions(event *schema.Event, conditions Conditions) bool {
	for _, cond := range conditions.Match {
		value := e.getEventField(event, cond.Field)
		if !matchValue(value, cond.Operator, cond.Value) {
			return false
		}
	}
	return true
}

// matchConditionTree evaluates a Condition including nested And/Or sub-conditions.
func (e *Engine) matchConditionTree(event *schema.Event, cond Condition) bool {
	// Evaluate the leaf condition itself (if Field is set)
	if cond.Field != "" {
		value := e.getEventField(event, cond.Field)
		if !cond.Match(value) {
			return false
		}
	}

	// Evaluate AND sub-conditions: all must match
	for _, sub := range cond.And {
		if !e.matchConditionTree(event, sub) {
			return false
		}
	}

	// Evaluate OR sub-conditions: at least one must match
	if len(cond.Or) > 0 {
		orMatched := false
		for _, sub := range cond.Or {
			if e.matchConditionTree(event, sub) {
				orMatched = true
				break
			}
		}
		if !orMatched {
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
		for _, v := range listValues(expected) {
			if eventStr == v {
				return true
			}
		}
		return false
	case "regex", "not_in", "exists", "not_exists":
		cond := Condition{Operator: operator, Value: expected}
		return cond.Match(eventValue)
	}
	return false
}

func (e *Engine) matchesConditions(event *schema.Event, conditions []Condition) bool {
	for _, cond := range conditions {
		if !e.matchConditionTree(event, cond) {
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
		// Check metadata — support both "metadata.key" and bare "key"
		if event.Metadata != nil {
			metaKey := field
			if strings.HasPrefix(field, "metadata.") {
				metaKey = strings.TrimPrefix(field, "metadata.")
			}
			if v, ok := event.Metadata[metaKey]; ok {
				return v
			}
		}
	}
	return nil
}

// dedupWindow is how long an alert for a rule and group suppresses the next.
func (e *Engine) dedupWindow(rule *Rule) time.Duration {
	if e.config.DedupWindow > 0 {
		return e.config.DedupWindow
	}
	return rule.Window
}

// sequenceSpan is how far apart the first and last step of a sequence may be.
func sequenceSpan(rule *Rule) time.Duration {
	if rule.Sequence != nil && rule.Sequence.MaxSpan > 0 {
		return rule.Sequence.MaxSpan
	}
	return rule.Window
}

func (e *Engine) evaluateRule(ctx context.Context, rule *Rule, event *schema.Event) {
	// Absence rules only track the expected event; anything else neither
	// satisfies nor opens an absence period.
	if rule.Type == RuleTypeAbsence &&
		(rule.Absence == nil || !e.matchesConditions(event, rule.Absence.ExpectedConditions)) {
		return
	}

	e.mu.RLock()
	state := e.states[rule.ID]
	e.mu.RUnlock()

	if state == nil {
		return
	}

	groupKey := e.buildGroupKey(event, rule.GroupBy)

	state.mu.Lock()
	defer state.mu.Unlock()

	// Taken under the state lock so arrival times within a window never
	// decrease.
	now := time.Now()

	window := state.windows[groupKey]
	if window == nil {
		// Enforce MaxStateEntries: evict the least recently used window.
		if len(state.windows) >= e.config.MaxStateEntries {
			var oldestKey string
			var oldestTime time.Time
			for k, w := range state.windows {
				if oldestKey == "" || w.LastSeen.Before(oldestTime) {
					oldestKey = k
					oldestTime = w.LastSeen
				}
			}
			if oldestKey != "" {
				delete(state.windows, oldestKey)
			}
		}
		window = newWindow(now)
		state.windows[groupKey] = window
	}

	// Sliding window: keep what arrived during the last rule.Window.
	window.trim(now, rule.Window)
	window.add(event, now)

	// Evaluate based on rule type
	var fired bool
	switch rule.Type {
	case RuleTypeThreshold:
		fired = e.evaluateThreshold(window, rule, groupKey)
	case RuleTypeSequence:
		fired = e.evaluateSequence(window, rule, event, now)
		if fired {
			// A completed sequence is consumed; the next alert needs a new one.
			defer window.resetSequence()
		}
	case RuleTypeAggregate:
		fired = e.evaluateAggregate(window, rule)
	case RuleTypeAbsence:
		// The expected event arrived: the current absence period is satisfied.
		if !window.AbsenceSeen {
			slog.Debug("absence rule: expected event seen, resetting timer",
				"rule_id", rule.ID,
				"group_key", groupKey,
				"window_start", window.StartTime,
			)
		}
		window.AbsenceSeen = true
	}

	if fired {
		// Check for duplicate suppression
		if lastFire, ok := state.lastFire[groupKey]; ok {
			if now.Sub(lastFire) < e.dedupWindow(rule) {
				return // Suppress duplicate
			}
		}
		state.lastFire[groupKey] = now

		alert := e.createAlert(rule, window, groupKey)
		alert.trigger = event
		e.sendAlert(alert)
	}
}

// sendAlert sends an alert with backpressure, blocking briefly before dropping.
func (e *Engine) sendAlert(alert *Alert) {
	select {
	case e.alertCh <- alert:
		return
	default:
	}

	// Backpressure: wait briefly before dropping
	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()
	select {
	case e.alertCh <- alert:
	case <-timer.C:
		slog.Warn("alert channel full after backpressure, dropping alert",
			"rule_id", alert.RuleID,
			"alert_id", alert.ID,
			"channel_len", len(e.alertCh),
			"channel_cap", cap(e.alertCh),
		)
	}
}

func (e *Engine) buildGroupKey(event *schema.Event, groupBy []string) string {
	if len(groupBy) == 0 {
		return defaultGroupKey
	}

	parts := make([]string, len(groupBy))
	for i, field := range groupBy {
		val := e.getEventField(event, field)
		parts[i] = fmt.Sprintf("%s=%v", field, val)
	}
	return fmt.Sprintf("%v", parts)
}

func (e *Engine) evaluateThreshold(window *Window, rule *Rule, groupKey string) bool {
	if rule.Threshold == nil {
		return false
	}

	count := float64(window.Count)
	threshold := float64(rule.Threshold.Count)

	// Adaptive threshold: learn the rule's normal count and raise the static
	// threshold for groups that are routinely busier. The learned value never
	// lowers a gt/gte threshold below the static one the rule author chose.
	if rule.Baseline != nil && e.baseline != nil {
		metric := baselineMetric(rule.Baseline)
		e.baseline.Record(rule.ID, groupKey, metric, count)
		if adaptive, active := e.baseline.AdaptiveThreshold(rule.ID, groupKey, rule.Baseline); active {
			switch rule.Threshold.Operator {
			case "", "gt", ">", "gte", ">=":
				threshold = math.Max(threshold, adaptive)
			default:
				threshold = adaptive
			}
			slog.Debug("using adaptive threshold",
				"rule_id", rule.ID,
				"group_key", groupKey,
				"static_threshold", rule.Threshold.Count,
				"adaptive_threshold", adaptive,
				"effective_threshold", threshold,
			)
		}
	}

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

// evaluateSequence advances the sequence state with event and reports
// whether the sequence is now complete.
//
// If any step is marked Required, only those steps are required and the
// others are optional; otherwise every step is required. In ordered mode an
// event may complete the next expected step or, if the steps before it are
// optional, a later one. The steps must all happen within the span
// (MaxSpan, or the rule window) of the first one.
func (e *Engine) evaluateSequence(window *Window, rule *Rule, event *schema.Event, now time.Time) bool {
	seq := rule.Sequence
	if seq == nil || len(seq.Steps) == 0 {
		return false
	}
	if window.Steps == nil {
		window.Steps = make(map[int]bool)
	}
	if len(window.Steps) > 0 && now.Sub(window.SeqStart) > sequenceSpan(rule) {
		window.resetSequence()
	}

	anyMarkedRequired := false
	for _, step := range seq.Steps {
		if step.Required {
			anyMarkedRequired = true
			break
		}
	}
	required := func(i int) bool { return !anyMarkedRequired || seq.Steps[i].Required }

	matched := -1
	if seq.Ordered {
		for i := window.StepIndex; i < len(seq.Steps); i++ {
			if e.matchesConditions(event, seq.Steps[i].Conditions) {
				matched = i
				break
			}
			if required(i) {
				break // a required step cannot be skipped
			}
		}
		if matched < 0 {
			// A fresh occurrence of the first step restarts a sequence that
			// has not got past it, so its span counts from the latest one.
			if window.StepIndex == 1 && e.matchesConditions(event, seq.Steps[0].Conditions) {
				window.SeqStart = now
			}
			return false
		}
		window.StepIndex = matched + 1
	} else {
		for i, step := range seq.Steps {
			if !window.Steps[i] && e.matchesConditions(event, step.Conditions) {
				matched = i
				break
			}
		}
		if matched < 0 {
			return false
		}
	}

	if len(window.Steps) == 0 {
		window.SeqStart = now
	}
	window.Steps[matched] = true

	for i := range seq.Steps {
		if required(i) && !window.Steps[i] {
			return false
		}
	}
	return true
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
		value = math.Inf(-1)
		for _, event := range window.Events {
			if v, ok := toFloat64(e.getEventField(event, field)); ok {
				if v > value {
					value = v
				}
			}
		}
	case "min":
		value = math.Inf(1)
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

	threshold := rule.Aggregate.threshold()
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
	depth := 0
	for _, event := range window.Events {
		events = append(events, EventRef{
			EventID:   event.EventID,
			Timestamp: event.Timestamp,
			Action:    event.Action,
		})
		if d, ok := reinjectedDepth(event); ok && d > depth {
			depth = d
		}
	}

	// Copy the rule metadata: alert consumers must not share (and mutate)
	// the rule's map. chain_depth is the engine's to set.
	var metadata map[string]any
	if len(rule.Metadata) > 0 || depth > 0 {
		metadata = make(map[string]any, len(rule.Metadata)+1)
		for k, v := range rule.Metadata {
			metadata[k] = v
		}
		delete(metadata, metaChainDepth)
		if depth > 0 {
			metadata[metaChainDepth] = depth
		}
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
		Metadata:    metadata,
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
		rule := state.rule
		// Absence windows are how the engine remembers which groups must keep
		// reporting; the absence checker manages them.
		if rule.Type != RuleTypeAbsence {
			retention := max(rule.Window, sequenceSpan(rule))
			for groupKey, window := range state.windows {
				if now.Sub(window.LastSeen) > retention {
					delete(state.windows, groupKey)
				}
			}
		}
		// Cleanup old fire times
		dedup := max(e.dedupWindow(rule), rule.Window)
		for groupKey, fireTime := range state.lastFire {
			if now.Sub(fireTime) > dedup {
				delete(state.lastFire, groupKey)
			}
		}
		state.mu.Unlock()
	}

	if e.baseline != nil {
		e.baseline.Cleanup()
	}
}

func (e *Engine) absenceChecker(ctx context.Context) {
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
			e.checkAbsenceRules()
		}
	}
}

// checkAbsenceRules fires for every absence group whose current period (one
// rule window) ended without the expected event, then starts the next period.
// Rules without GroupBy track one "default" group from the moment they are
// added; rules with GroupBy track each group once it has sent the expected
// event.
func (e *Engine) checkAbsenceRules() {
	e.mu.RLock()
	var absenceRules []*Rule
	for _, rule := range e.rules {
		if rule.Type == RuleTypeAbsence && rule.Enabled {
			absenceRules = append(absenceRules, rule)
		}
	}
	e.mu.RUnlock()

	now := time.Now()
	for _, rule := range absenceRules {
		e.mu.RLock()
		state := e.states[rule.ID]
		e.mu.RUnlock()
		if state == nil {
			continue
		}

		state.mu.Lock()

		if len(rule.GroupBy) == 0 && state.windows[defaultGroupKey] == nil {
			// Start a full period now rather than firing before the expected
			// event could have arrived.
			state.windows[defaultGroupKey] = newWindow(now)
		}

		for groupKey, window := range state.windows {
			// Only check once a full period has passed
			if now.Sub(window.StartTime) < rule.Window {
				continue
			}

			// If the expected event was NOT seen, fire the alert
			if !window.AbsenceSeen {
				lastFire, fired := state.lastFire[groupKey]
				if !fired || now.Sub(lastFire) >= e.dedupWindow(rule) {
					state.lastFire[groupKey] = now
					e.sendAlert(e.createAlert(rule, window, groupKey))
				}
			}

			// Reset the window for the next period
			slog.Debug("absence rule: resetting window for next period",
				"rule_id", rule.ID,
				"group_key", groupKey,
				"was_seen", window.AbsenceSeen,
			)
			window.AbsenceSeen = false
			window.StartTime = now
			window.clearEvents()
			window.AbsenceChecked = now
		}

		state.mu.Unlock()
	}
}

// GetRules returns all loaded rules (for API use), ordered by ID.
func (e *Engine) GetRules() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]*Rule, 0, len(e.rules))
	for _, rule := range e.rules {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

// GetRule returns a single rule by ID.
func (e *Engine) GetRule(id string) (*Rule, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rule, ok := e.rules[id]
	return rule, ok
}

// Stats returns engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := map[string]interface{}{
		"rules_count":   len(e.rules),
		"event_queue":   len(e.eventCh),
		"alert_queue":   len(e.alertCh),
		"handler_count": len(e.handlers),
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

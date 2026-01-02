package integrity

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"
	"github.com/google/uuid"
)

// StateCheck represents a state integrity check result.
type StateCheck struct {
	Slot          uint64
	Timestamp     time.Time
	StateRoot     string
	Expected      string
	Valid         bool
	CheckType     string
	ErrorMessage  string
}

// ReorgInfo contains information about a chain reorganization.
type ReorgInfo struct {
	Timestamp    time.Time
	Depth        uint64
	OldHead      string
	NewHead      string
	SlotAffected uint64
	BlocksLost   int
}

// IntegrityMetrics contains aggregated integrity metrics.
type IntegrityMetrics struct {
	Timestamp time.Time

	// State root validation
	StateRootChecks     int
	StateRootFailures   int
	StateRootFailureRate float64
	LastStateRootError   string

	// Database integrity
	DBCorruptionDetected bool
	DBCheckTimestamp     time.Time
	DBConsistencyErrors  int

	// Reorg tracking
	ReorgCount1h         int
	ReorgCount24h        int
	MaxReorgDepth        uint64
	DeepReorgDetected    bool

	// State consistency
	ConsistencyChecks    int
	ConsistencyFailures  int
	LastConsistencyCheck time.Time
}

// MonitorConfig contains configuration for the integrity monitor.
type MonitorConfig struct {
	// State root thresholds
	StateRootFailureThreshold float64       // Percentage threshold
	StateRootCheckInterval    time.Duration

	// Database checks
	DBCheckInterval       time.Duration
	DBCorruptionThreshold int // Number of errors before alert

	// Reorg thresholds
	DeepReorgThreshold    uint64        // Slots
	FrequentReorgCount    int           // Count per hour
	ReorgCheckWindow      time.Duration

	// Consistency checks
	ConsistencyCheckInterval time.Duration
	ConsistencyFailureLimit  int

	// Monitoring
	CheckInterval    time.Duration
	MetricsRetention time.Duration
}

// DefaultMonitorConfig returns default configuration.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		StateRootFailureThreshold: 1.0,               // 1% failure rate
		StateRootCheckInterval:    5 * time.Minute,

		DBCheckInterval:       1 * time.Hour,
		DBCorruptionThreshold: 3,

		DeepReorgThreshold: 64,   // 64 slots = critical
		FrequentReorgCount: 5,    // 5 reorgs/hour = suspicious
		ReorgCheckWindow:   1 * time.Hour,

		ConsistencyCheckInterval: 30 * time.Minute,
		ConsistencyFailureLimit:  5,

		CheckInterval:    30 * time.Second,
		MetricsRetention: 24 * time.Hour,
	}
}

// Alert represents an integrity alert.
type Alert struct {
	ID          uuid.UUID
	Type        string
	Severity    string
	Title       string
	Description string
	Timestamp   time.Time
	Metadata    map[string]interface{}
	Metrics     *IntegrityMetrics
}

// AlertHandler is a function that handles alerts.
type AlertHandler func(ctx context.Context, alert *Alert) error

// Monitor monitors blockchain state integrity.
type Monitor struct {
	config MonitorConfig
	logger *slog.Logger

	mu                sync.RWMutex
	stateChecks       []StateCheck
	reorgHistory      []ReorgInfo
	metricsHistory    []IntegrityMetrics
	lastMetrics       *IntegrityMetrics
	handlers          []AlertHandler
	recentAlerts      map[string]time.Time
	dbErrorCount      int
	lastDBCheck       time.Time
	lastConsistencyCheck time.Time

	running bool
	stopCh  chan struct{}
}

// NewMonitor creates a new integrity monitor.
func NewMonitor(config MonitorConfig) *Monitor {
	return &Monitor{
		config:         config,
		logger:         slog.Default(),
		stateChecks:    make([]StateCheck, 0),
		reorgHistory:   make([]ReorgInfo, 0),
		metricsHistory: make([]IntegrityMetrics, 0),
		handlers:       make([]AlertHandler, 0),
		recentAlerts:   make(map[string]time.Time),
		stopCh:         make(chan struct{}),
	}
}

// AddHandler adds an alert handler.
func (m *Monitor) AddHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// RecordStateRootCheck records a state root validation check.
func (m *Monitor) RecordStateRootCheck(slot uint64, stateRoot, expected string, valid bool, errorMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	check := StateCheck{
		Slot:         slot,
		Timestamp:    time.Now(),
		StateRoot:    stateRoot,
		Expected:     expected,
		Valid:        valid,
		CheckType:    "state_root",
		ErrorMessage: errorMsg,
	}

	m.stateChecks = append(m.stateChecks, check)

	// Keep only recent checks (last 1000)
	if len(m.stateChecks) > 1000 {
		m.stateChecks = m.stateChecks[len(m.stateChecks)-1000:]
	}
}

// RecordReorg records a chain reorganization event.
func (m *Monitor) RecordReorg(depth uint64, oldHead, newHead string, slotAffected uint64, blocksLost int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	reorg := ReorgInfo{
		Timestamp:    time.Now(),
		Depth:        depth,
		OldHead:      oldHead,
		NewHead:      newHead,
		SlotAffected: slotAffected,
		BlocksLost:   blocksLost,
	}

	m.reorgHistory = append(m.reorgHistory, reorg)

	// Keep only recent reorgs (last 100)
	if len(m.reorgHistory) > 100 {
		m.reorgHistory = m.reorgHistory[len(m.reorgHistory)-100:]
	}
}

// RecordDBError records a database error.
func (m *Monitor) RecordDBError() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dbErrorCount++
}

// ResetDBErrorCount resets the database error counter.
func (m *Monitor) ResetDBErrorCount() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dbErrorCount = 0
	m.lastDBCheck = time.Now()
}

// CollectMetrics collects current integrity metrics.
func (m *Monitor) CollectMetrics() *IntegrityMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()

	metrics := &IntegrityMetrics{
		Timestamp:            time.Now(),
		DBCheckTimestamp:     m.lastDBCheck,
		LastConsistencyCheck: m.lastConsistencyCheck,
	}

	// Calculate state root metrics
	if len(m.stateChecks) > 0 {
		cutoff := time.Now().Add(-1 * time.Hour)
		checksInWindow := 0
		failuresInWindow := 0

		for i := len(m.stateChecks) - 1; i >= 0; i-- {
			check := m.stateChecks[i]
			if check.Timestamp.Before(cutoff) {
				break
			}
			checksInWindow++
			if !check.Valid {
				failuresInWindow++
				metrics.LastStateRootError = check.ErrorMessage
			}
		}

		metrics.StateRootChecks = checksInWindow
		metrics.StateRootFailures = failuresInWindow
		if checksInWindow > 0 {
			metrics.StateRootFailureRate = float64(failuresInWindow) / float64(checksInWindow) * 100.0
		}
	}

	// Calculate reorg metrics
	cutoff1h := time.Now().Add(-1 * time.Hour)
	cutoff24h := time.Now().Add(-24 * time.Hour)
	reorgs1h := 0
	reorgs24h := 0
	maxDepth := uint64(0)

	for i := len(m.reorgHistory) - 1; i >= 0; i-- {
		reorg := m.reorgHistory[i]

		if reorg.Timestamp.After(cutoff1h) {
			reorgs1h++
		}
		if reorg.Timestamp.After(cutoff24h) {
			reorgs24h++
		}

		if reorg.Depth > maxDepth {
			maxDepth = reorg.Depth
		}

		// Stop if we're past 24h window
		if reorg.Timestamp.Before(cutoff24h) {
			break
		}
	}

	metrics.ReorgCount1h = reorgs1h
	metrics.ReorgCount24h = reorgs24h
	metrics.MaxReorgDepth = maxDepth
	metrics.DeepReorgDetected = maxDepth >= m.config.DeepReorgThreshold

	// Database integrity
	metrics.DBConsistencyErrors = m.dbErrorCount
	metrics.DBCorruptionDetected = m.dbErrorCount >= m.config.DBCorruptionThreshold

	// Store metrics
	m.lastMetrics = metrics
	m.metricsHistory = append(m.metricsHistory, *metrics)

	// Clean old metrics
	cutoff := time.Now().Add(-m.config.MetricsRetention)
	for len(m.metricsHistory) > 0 && m.metricsHistory[0].Timestamp.Before(cutoff) {
		m.metricsHistory = m.metricsHistory[1:]
	}

	return metrics
}

// Start starts the monitoring loop.
func (m *Monitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("monitor already running")
	}
	m.running = true
	m.mu.Unlock()

	m.logger.Info("starting state integrity monitor",
		"check_interval", m.config.CheckInterval,
		"deep_reorg_threshold", m.config.DeepReorgThreshold)

	go m.monitorLoop(ctx)
	return nil
}

// Stop stops the monitoring loop.
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	close(m.stopCh)
	m.running = false
	m.logger.Info("state integrity monitor stopped")
}

// monitorLoop is the main monitoring loop.
func (m *Monitor) monitorLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			metrics := m.CollectMetrics()
			if metrics != nil {
				m.checkAlerts(ctx, metrics)
			}
			m.cleanup()
		}
	}
}

// checkAlerts checks for alert conditions.
func (m *Monitor) checkAlerts(ctx context.Context, metrics *IntegrityMetrics) {
	m.checkStateRootAlerts(ctx, metrics)
	m.checkDBCorruptionAlerts(ctx, metrics)
	m.checkReorgAlerts(ctx, metrics)
}

// checkStateRootAlerts checks for state root validation failures.
func (m *Monitor) checkStateRootAlerts(ctx context.Context, metrics *IntegrityMetrics) {
	if metrics.StateRootFailureRate >= m.config.StateRootFailureThreshold && metrics.StateRootFailures > 0 {
		severity := "high"
		if metrics.StateRootFailureRate >= 5.0 {
			severity = "critical"
		}

		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "integrity-state-root-failures",
			Severity: severity,
			Title:    "State Root Validation Failures",
			Description: fmt.Sprintf("%.1f%% of state root validations failing (%d/%d checks). "+
				"This may indicate state corruption or sync issues.",
				metrics.StateRootFailureRate, metrics.StateRootFailures, metrics.StateRootChecks),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"failure_rate":       metrics.StateRootFailureRate,
				"failures":           metrics.StateRootFailures,
				"total_checks":       metrics.StateRootChecks,
				"last_error":         metrics.LastStateRootError,
			},
			Metrics: metrics,
		})
	}
}

// checkDBCorruptionAlerts checks for database corruption.
func (m *Monitor) checkDBCorruptionAlerts(ctx context.Context, metrics *IntegrityMetrics) {
	if metrics.DBCorruptionDetected {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "integrity-db-corruption",
			Severity: "critical",
			Title:    "CRITICAL: Database Corruption Detected",
			Description: fmt.Sprintf("Detected %d database consistency errors (threshold: %d). "+
				"Database may be corrupted. Immediate action required.",
				metrics.DBConsistencyErrors, m.config.DBCorruptionThreshold),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"error_count": metrics.DBConsistencyErrors,
				"threshold":   m.config.DBCorruptionThreshold,
				"last_check":  metrics.DBCheckTimestamp,
			},
			Metrics: metrics,
		})
	}
}

// checkReorgAlerts checks for deep or frequent reorganizations.
func (m *Monitor) checkReorgAlerts(ctx context.Context, metrics *IntegrityMetrics) {
	// Deep reorg alert
	if metrics.DeepReorgDetected {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "integrity-deep-reorg",
			Severity: "critical",
			Title:    "CRITICAL: Deep Chain Reorganization",
			Description: fmt.Sprintf("Chain reorganization depth of %d slots detected (threshold: %d). "+
				"This is a severe event that may indicate consensus issues or attacks.",
				metrics.MaxReorgDepth, m.config.DeepReorgThreshold),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"max_depth": metrics.MaxReorgDepth,
				"threshold": m.config.DeepReorgThreshold,
			},
			Metrics: metrics,
		})
	}

	// Frequent reorg alert
	if metrics.ReorgCount1h >= m.config.FrequentReorgCount {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "integrity-frequent-reorgs",
			Severity: "high",
			Title:    "Frequent Chain Reorganizations",
			Description: fmt.Sprintf("%d chain reorganizations in the last hour (threshold: %d). "+
				"This may indicate network instability or sync issues.",
				metrics.ReorgCount1h, m.config.FrequentReorgCount),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"reorg_count_1h": metrics.ReorgCount1h,
				"threshold":      m.config.FrequentReorgCount,
				"max_depth":      metrics.MaxReorgDepth,
			},
			Metrics: metrics,
		})
	}
}

// emitAlert emits an alert to all handlers.
func (m *Monitor) emitAlert(ctx context.Context, alert *Alert) {
	m.mu.Lock()
	lastAlert, exists := m.recentAlerts[alert.Type]
	if exists && time.Since(lastAlert) < 5*time.Minute {
		m.mu.Unlock()
		return
	}
	m.recentAlerts[alert.Type] = time.Now()
	handlers := m.handlers
	m.mu.Unlock()

	m.logger.Warn("integrity alert generated",
		"type", alert.Type,
		"severity", alert.Severity,
		"title", alert.Title)

	for _, handler := range handlers {
		go func(h AlertHandler) {
			if err := h(ctx, alert); err != nil {
				m.logger.Error("alert handler failed", "error", err)
			}
		}(handler)
	}
}

// cleanup removes old data.
func (m *Monitor) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clean old state checks (keep last 1000)
	if len(m.stateChecks) > 1000 {
		m.stateChecks = m.stateChecks[len(m.stateChecks)-1000:]
	}

	// Clean old reorg history (keep last 100)
	if len(m.reorgHistory) > 100 {
		m.reorgHistory = m.reorgHistory[len(m.reorgHistory)-100:]
	}
}

// GetCurrentMetrics returns the most recent metrics.
func (m *Monitor) GetCurrentMetrics() *IntegrityMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastMetrics
}

// GetMetricsHistory returns historical metrics.
func (m *Monitor) GetMetricsHistory() []IntegrityMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]IntegrityMetrics{}, m.metricsHistory...)
}

// GetStateChecks returns recent state checks.
func (m *Monitor) GetStateChecks() []StateCheck {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]StateCheck{}, m.stateChecks...)
}

// GetReorgHistory returns recent reorganizations.
func (m *Monitor) GetReorgHistory() []ReorgInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]ReorgInfo{}, m.reorgHistory...)
}

// GetStats returns monitor statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"total_state_checks": len(m.stateChecks),
		"total_reorgs":       len(m.reorgHistory),
		"metrics_count":      len(m.metricsHistory),
		"db_error_count":     m.dbErrorCount,
	}

	if m.lastMetrics != nil {
		stats["state_root_failure_rate"] = m.lastMetrics.StateRootFailureRate
		stats["reorg_count_1h"] = m.lastMetrics.ReorgCount1h
		stats["max_reorg_depth"] = m.lastMetrics.MaxReorgDepth
	}

	return stats
}

// NormalizeToEvent converts an integrity alert to a schema.Event.
func (m *Monitor) NormalizeToEvent(alert *Alert, tenantID string) *schema.Event {
	outcome := schema.OutcomeFailure
	severity := 5

	switch alert.Severity {
	case "critical":
		severity = 9
	case "high":
		severity = 7
	case "medium":
		severity = 5
	}

	metadata := map[string]interface{}{
		"alert_type": alert.Type,
	}

	if alert.Metadata != nil {
		for k, v := range alert.Metadata {
			metadata[k] = v
		}
	}

	if alert.Metrics != nil {
		metadata["state_root_failure_rate"] = alert.Metrics.StateRootFailureRate
		metadata["reorg_count_1h"] = alert.Metrics.ReorgCount1h
		metadata["max_reorg_depth"] = alert.Metrics.MaxReorgDepth
		metadata["db_corruption_detected"] = alert.Metrics.DBCorruptionDetected
	}

	return &schema.Event{
		EventID:   alert.ID,
		Timestamp: alert.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: "integrity-monitor",
			Host:    getHostname(),
			Version: "1.0",
		},
		Action:   fmt.Sprintf("integrity.%s", alert.Type),
		Outcome:  outcome,
		Severity: severity,
		Metadata: metadata,
	}
}

// getHostname returns the system hostname.
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// CreateCorrelationRules creates correlation rules for integrity monitoring.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "integrity-state-corruption",
			Name:        "State Corruption Pattern",
			Description: "Multiple state root validation failures indicating possible corruption",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"blockchain", "integrity", "corruption"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1485", // Data Destruction
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "integrity.integrity-state-root-failures"},
			},
			GroupBy: []string{"source.host"},
			Window:  15 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    3,
				Operator: "gte",
			},
		},
		{
			ID:          "integrity-db-corruption-critical",
			Name:        "Critical Database Corruption",
			Description: "Database corruption detected - immediate action required",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"blockchain", "integrity", "database"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1485", // Data Destruction
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "integrity.integrity-db-corruption"},
			},
			GroupBy: []string{"source.host"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "integrity-deep-reorg-attack",
			Name:        "Deep Reorganization Attack Pattern",
			Description: "Deep chain reorganization detected - possible attack or severe consensus issue",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"blockchain", "integrity", "reorg", "attack"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1499", // Endpoint Denial of Service
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "integrity.integrity-deep-reorg"},
			},
			GroupBy: []string{"source.host"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "integrity-frequent-reorgs",
			Name:        "Frequent Chain Reorganizations",
			Description: "Multiple chain reorganizations indicating network instability",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "integrity", "reorg"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "integrity.integrity-frequent-reorgs"},
			},
			GroupBy: []string{"source.host"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    2,
				Operator: "gte",
			},
		},
	}
}

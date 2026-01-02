package consensus

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

// ValidatorDuty represents a validator's assigned duty.
type ValidatorDuty struct {
	ValidatorIndex uint64
	Slot           uint64
	DutyType       string // "attestation", "proposal", "sync_committee"
	Executed       bool
	Timestamp      time.Time
}

// SlashingEvent represents a slashing occurrence.
type SlashingEvent struct {
	Timestamp      time.Time
	ValidatorIndex uint64
	SlashingType   string // "proposer", "attester"
	Slot           uint64
	Penalty        uint64 // In Gwei
}

// ValidatorMetrics contains validator performance metrics.
type ValidatorMetrics struct {
	Timestamp time.Time

	// Duty tracking
	TotalDuties        int
	ExecutedDuties     int
	MissedDuties       int
	ParticipationRate  float64

	// Attestation performance
	AttestationDuties  int
	MissedAttestations int
	AttestationRate    float64

	// Block proposal performance
	ProposalDuties     int
	MissedProposals    int
	ProposalRate       float64

	// Slashing
	SlashingEvents     int
	TotalSlashingLoss  uint64

	// Performance scoring
	PerformanceScore   float64 // 0.0 to 100.0
	Effectiveness      float64 // Attestations/Expected
}

// MonitorConfig contains configuration for the consensus monitor.
type MonitorConfig struct {
	// Performance thresholds
	MinParticipationRate float64 // Percentage
	MinAttestationRate   float64
	MinProposalRate      float64

	// Alerts
	ConsecutiveMissesThreshold int
	SlashingAlertEnabled       bool

	// Performance scoring
	PerformanceWindow    time.Duration
	MinPerformanceScore  float64

	// Monitoring
	CheckInterval    time.Duration
	MetricsRetention time.Duration
}

// DefaultMonitorConfig returns default configuration.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		MinParticipationRate:       95.0,  // 95% minimum
		MinAttestationRate:         98.0,  // 98% minimum
		MinProposalRate:            90.0,  // 90% minimum
		ConsecutiveMissesThreshold: 3,
		SlashingAlertEnabled:       true,
		PerformanceWindow:          24 * time.Hour,
		MinPerformanceScore:        90.0,
		CheckInterval:              30 * time.Second,
		MetricsRetention:           7 * 24 * time.Hour,
	}
}

// Alert represents a consensus alert.
type Alert struct {
	ID          uuid.UUID
	Type        string
	Severity    string
	Title       string
	Description string
	Timestamp   time.Time
	Metadata    map[string]interface{}
	Metrics     *ValidatorMetrics
}

// AlertHandler is a function that handles alerts.
type AlertHandler func(ctx context.Context, alert *Alert) error

// Monitor monitors consensus participation.
type Monitor struct {
	config MonitorConfig
	logger *slog.Logger

	mu                   sync.RWMutex
	duties               []ValidatorDuty
	slashingEvents       []SlashingEvent
	metricsHistory       []ValidatorMetrics
	lastMetrics          *ValidatorMetrics
	handlers             []AlertHandler
	recentAlerts         map[string]time.Time
	consecutiveMisses    int
	validatorIndices     map[uint64]bool

	running bool
	stopCh  chan struct{}
}

// NewMonitor creates a new consensus monitor.
func NewMonitor(config MonitorConfig) *Monitor {
	return &Monitor{
		config:           config,
		logger:           slog.Default(),
		duties:           make([]ValidatorDuty, 0),
		slashingEvents:   make([]SlashingEvent, 0),
		metricsHistory:   make([]ValidatorMetrics, 0),
		handlers:         make([]AlertHandler, 0),
		recentAlerts:     make(map[string]time.Time),
		validatorIndices: make(map[uint64]bool),
		stopCh:           make(chan struct{}),
	}
}

// AddHandler adds an alert handler.
func (m *Monitor) AddHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// RecordDuty records a validator duty.
func (m *Monitor) RecordDuty(validatorIndex, slot uint64, dutyType string, executed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	duty := ValidatorDuty{
		ValidatorIndex: validatorIndex,
		Slot:           slot,
		DutyType:       dutyType,
		Executed:       executed,
		Timestamp:      time.Now(),
	}

	m.duties = append(m.duties, duty)
	m.validatorIndices[validatorIndex] = true

	// Track consecutive misses
	if !executed {
		m.consecutiveMisses++
	} else {
		m.consecutiveMisses = 0
	}

	// Keep only recent duties (last 10000)
	if len(m.duties) > 10000 {
		m.duties = m.duties[len(m.duties)-10000:]
	}
}

// RecordSlashing records a slashing event.
func (m *Monitor) RecordSlashing(validatorIndex, slot uint64, slashingType string, penalty uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	event := SlashingEvent{
		Timestamp:      time.Now(),
		ValidatorIndex: validatorIndex,
		SlashingType:   slashingType,
		Slot:           slot,
		Penalty:        penalty,
	}

	m.slashingEvents = append(m.slashingEvents, event)

	// Keep only recent slashing events (last 100)
	if len(m.slashingEvents) > 100 {
		m.slashingEvents = m.slashingEvents[1:]
	}
}

// CollectMetrics collects current consensus metrics.
func (m *Monitor) CollectMetrics() *ValidatorMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.duties) == 0 {
		return nil
	}

	metrics := &ValidatorMetrics{
		Timestamp: time.Now(),
	}

	// Calculate duty metrics within performance window
	cutoff := time.Now().Add(-m.config.PerformanceWindow)
	totalDuties := 0
	executedDuties := 0
	attestationDuties := 0
	missedAttestations := 0
	proposalDuties := 0
	missedProposals := 0

	for i := len(m.duties) - 1; i >= 0; i-- {
		duty := m.duties[i]
		if duty.Timestamp.Before(cutoff) {
			break
		}

		totalDuties++
		if duty.Executed {
			executedDuties++
		}

		switch duty.DutyType {
		case "attestation":
			attestationDuties++
			if !duty.Executed {
				missedAttestations++
			}
		case "proposal":
			proposalDuties++
			if !duty.Executed {
				missedProposals++
			}
		}
	}

	metrics.TotalDuties = totalDuties
	metrics.ExecutedDuties = executedDuties
	metrics.MissedDuties = totalDuties - executedDuties

	if totalDuties > 0 {
		metrics.ParticipationRate = float64(executedDuties) / float64(totalDuties) * 100.0
	}

	metrics.AttestationDuties = attestationDuties
	metrics.MissedAttestations = missedAttestations
	if attestationDuties > 0 {
		metrics.AttestationRate = float64(attestationDuties-missedAttestations) / float64(attestationDuties) * 100.0
	}

	metrics.ProposalDuties = proposalDuties
	metrics.MissedProposals = missedProposals
	if proposalDuties > 0 {
		metrics.ProposalRate = float64(proposalDuties-missedProposals) / float64(proposalDuties) * 100.0
	}

	// Calculate slashing metrics
	slashingCutoff := time.Now().Add(-24 * time.Hour)
	slashingCount := 0
	totalLoss := uint64(0)

	for i := len(m.slashingEvents) - 1; i >= 0; i-- {
		event := m.slashingEvents[i]
		if event.Timestamp.Before(slashingCutoff) {
			break
		}
		slashingCount++
		totalLoss += event.Penalty
	}

	metrics.SlashingEvents = slashingCount
	metrics.TotalSlashingLoss = totalLoss

	// Calculate performance score (0-100)
	metrics.PerformanceScore = m.calculatePerformanceScore(metrics)
	if attestationDuties > 0 {
		metrics.Effectiveness = float64(attestationDuties-missedAttestations) / float64(attestationDuties)
	}

	// Store metrics
	m.lastMetrics = metrics
	m.metricsHistory = append(m.metricsHistory, *metrics)

	// Clean old metrics
	cutoffTime := time.Now().Add(-m.config.MetricsRetention)
	for len(m.metricsHistory) > 0 && m.metricsHistory[0].Timestamp.Before(cutoffTime) {
		m.metricsHistory = m.metricsHistory[1:]
	}

	return metrics
}

// calculatePerformanceScore calculates overall validator performance score.
func (m *Monitor) calculatePerformanceScore(metrics *ValidatorMetrics) float64 {
	// Weighted scoring:
	// 60% participation rate
	// 30% attestation rate
	// 10% proposal rate (if applicable)

	score := 0.0

	// Participation component (60%)
	score += metrics.ParticipationRate * 0.6

	// Attestation component (30%)
	score += metrics.AttestationRate * 0.3

	// Proposal component (10%)
	if metrics.ProposalDuties > 0 {
		score += metrics.ProposalRate * 0.1
	} else {
		// If no proposals, redistribute weight to participation
		score += metrics.ParticipationRate * 0.1
	}

	// Penalty for slashing
	if metrics.SlashingEvents > 0 {
		score -= float64(metrics.SlashingEvents) * 10.0
		if score < 0 {
			score = 0
		}
	}

	return score
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

	m.logger.Info("starting consensus participation monitor",
		"check_interval", m.config.CheckInterval,
		"min_participation", m.config.MinParticipationRate)

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
	m.logger.Info("consensus participation monitor stopped")
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
		}
	}
}

// checkAlerts checks for alert conditions.
func (m *Monitor) checkAlerts(ctx context.Context, metrics *ValidatorMetrics) {
	m.checkParticipationAlerts(ctx, metrics)
	m.checkAttestationAlerts(ctx, metrics)
	m.checkProposalAlerts(ctx, metrics)
	m.checkSlashingAlerts(ctx, metrics)
	m.checkPerformanceAlerts(ctx, metrics)
	m.checkConsecutiveMissesAlerts(ctx)
}

// checkParticipationAlerts checks for low participation rate.
func (m *Monitor) checkParticipationAlerts(ctx context.Context, metrics *ValidatorMetrics) {
	if metrics.ParticipationRate < m.config.MinParticipationRate && metrics.TotalDuties > 0 {
		severity := "medium"
		if metrics.ParticipationRate < 90.0 {
			severity = "high"
		}

		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "consensus-low-participation",
			Severity: severity,
			Title:    "Low Validator Participation Rate",
			Description: fmt.Sprintf("Validator participation is %.1f%% (threshold: %.1f%%). "+
				"Missing duties may result in penalties.",
				metrics.ParticipationRate, m.config.MinParticipationRate),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"participation_rate": metrics.ParticipationRate,
				"threshold":          m.config.MinParticipationRate,
				"missed_duties":      metrics.MissedDuties,
				"total_duties":       metrics.TotalDuties,
			},
			Metrics: metrics,
		})
	}
}

// checkAttestationAlerts checks for missed attestations.
func (m *Monitor) checkAttestationAlerts(ctx context.Context, metrics *ValidatorMetrics) {
	if metrics.AttestationRate < m.config.MinAttestationRate && metrics.AttestationDuties > 0 {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "consensus-missed-attestations",
			Severity: "high",
			Title:    "High Attestation Miss Rate",
			Description: fmt.Sprintf("Attestation rate is %.1f%% (threshold: %.1f%%). "+
				"Missed %d of %d attestations.",
				metrics.AttestationRate, m.config.MinAttestationRate,
				metrics.MissedAttestations, metrics.AttestationDuties),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"attestation_rate":    metrics.AttestationRate,
				"threshold":           m.config.MinAttestationRate,
				"missed_attestations": metrics.MissedAttestations,
				"total_attestations":  metrics.AttestationDuties,
			},
			Metrics: metrics,
		})
	}
}

// checkProposalAlerts checks for missed block proposals.
func (m *Monitor) checkProposalAlerts(ctx context.Context, metrics *ValidatorMetrics) {
	if metrics.MissedProposals > 0 {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "consensus-missed-proposals",
			Severity: "critical",
			Title:    "CRITICAL: Missed Block Proposals",
			Description: fmt.Sprintf("Missed %d block proposal(s). "+
				"This results in significant penalties and lost rewards.",
				metrics.MissedProposals),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"missed_proposals": metrics.MissedProposals,
				"total_proposals":  metrics.ProposalDuties,
				"proposal_rate":    metrics.ProposalRate,
			},
			Metrics: metrics,
		})
	}
}

// checkSlashingAlerts checks for slashing events.
func (m *Monitor) checkSlashingAlerts(ctx context.Context, metrics *ValidatorMetrics) {
	if m.config.SlashingAlertEnabled && metrics.SlashingEvents > 0 {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "consensus-slashing",
			Severity: "critical",
			Title:    "CRITICAL: Validator Slashing Event",
			Description: fmt.Sprintf("Validator was slashed %d time(s) in the last 24 hours. "+
				"Total penalty: %d Gwei. Immediate investigation required.",
				metrics.SlashingEvents, metrics.TotalSlashingLoss),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"slashing_events": metrics.SlashingEvents,
				"total_loss_gwei": metrics.TotalSlashingLoss,
			},
			Metrics: metrics,
		})
	}
}

// checkPerformanceAlerts checks overall performance score.
func (m *Monitor) checkPerformanceAlerts(ctx context.Context, metrics *ValidatorMetrics) {
	if metrics.PerformanceScore < m.config.MinPerformanceScore && metrics.TotalDuties > 10 {
		severity := "medium"
		if metrics.PerformanceScore < 80.0 {
			severity = "high"
		}

		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "consensus-low-performance",
			Severity: severity,
			Title:    "Low Validator Performance Score",
			Description: fmt.Sprintf("Validator performance score is %.1f (threshold: %.1f). "+
				"Performance improvements needed.",
				metrics.PerformanceScore, m.config.MinPerformanceScore),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"performance_score": metrics.PerformanceScore,
				"threshold":         m.config.MinPerformanceScore,
				"effectiveness":     metrics.Effectiveness,
			},
			Metrics: metrics,
		})
	}
}

// checkConsecutiveMissesAlerts checks for consecutive missed duties.
func (m *Monitor) checkConsecutiveMissesAlerts(ctx context.Context) {
	m.mu.RLock()
	consecutiveMisses := m.consecutiveMisses
	m.mu.RUnlock()

	if consecutiveMisses >= m.config.ConsecutiveMissesThreshold {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "consensus-consecutive-misses",
			Severity: "critical",
			Title:    "CRITICAL: Consecutive Duty Misses",
			Description: fmt.Sprintf("Validator missed %d consecutive duties (threshold: %d). "+
				"Check validator health immediately.",
				consecutiveMisses, m.config.ConsecutiveMissesThreshold),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"consecutive_misses": consecutiveMisses,
				"threshold":          m.config.ConsecutiveMissesThreshold,
			},
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

	m.logger.Warn("consensus alert generated",
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

// GetCurrentMetrics returns the most recent metrics.
func (m *Monitor) GetCurrentMetrics() *ValidatorMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastMetrics
}

// GetMetricsHistory returns historical metrics.
func (m *Monitor) GetMetricsHistory() []ValidatorMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]ValidatorMetrics{}, m.metricsHistory...)
}

// GetDuties returns recent duties.
func (m *Monitor) GetDuties() []ValidatorDuty {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]ValidatorDuty{}, m.duties...)
}

// GetSlashingEvents returns recent slashing events.
func (m *Monitor) GetSlashingEvents() []SlashingEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]SlashingEvent{}, m.slashingEvents...)
}

// GetStats returns monitor statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"total_duties":       len(m.duties),
		"slashing_events":    len(m.slashingEvents),
		"metrics_count":      len(m.metricsHistory),
		"validator_count":    len(m.validatorIndices),
		"consecutive_misses": m.consecutiveMisses,
	}

	if m.lastMetrics != nil {
		stats["participation_rate"] = m.lastMetrics.ParticipationRate
		stats["attestation_rate"] = m.lastMetrics.AttestationRate
		stats["performance_score"] = m.lastMetrics.PerformanceScore
	}

	return stats
}

// NormalizeToEvent converts a consensus alert to a schema.Event.
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
		metadata["participation_rate"] = alert.Metrics.ParticipationRate
		metadata["attestation_rate"] = alert.Metrics.AttestationRate
		metadata["performance_score"] = alert.Metrics.PerformanceScore
		metadata["slashing_events"] = alert.Metrics.SlashingEvents
	}

	return &schema.Event{
		EventID:   alert.ID,
		Timestamp: alert.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: "consensus-monitor",
			Host:    getHostname(),
			Version: "1.0",
		},
		Action:   fmt.Sprintf("consensus.%s", alert.Type),
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

// CreateCorrelationRules creates correlation rules for consensus monitoring.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "consensus-participation-degradation",
			Name:        "Validator Participation Degradation",
			Description: "Sustained low validator participation indicating operational issues",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "consensus", "validator"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1499", // Endpoint Denial of Service
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "consensus.consensus-low-participation"},
			},
			GroupBy: []string{"source.host"},
			Window:  30 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    3,
				Operator: "gte",
			},
		},
		{
			ID:          "consensus-slashing-critical",
			Name:        "Critical Validator Slashing",
			Description: "Validator slashing event detected - immediate action required",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"blockchain", "consensus", "slashing", "critical"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1496", // Resource Hijacking
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "consensus.consensus-slashing"},
			},
			GroupBy: []string{"source.host"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "consensus-missed-proposals",
			Name:        "Missed Block Proposals",
			Description: "Validator missing block proposals resulting in penalties",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"blockchain", "consensus", "proposals"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "consensus.consensus-missed-proposals"},
			},
			GroupBy: []string{"source.host"},
			Window:  2 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "consensus-consecutive-failures",
			Name:        "Consecutive Duty Failures",
			Description: "Multiple consecutive duty misses indicating validator offline",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"blockchain", "consensus", "availability"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "consensus.consensus-consecutive-misses"},
			},
			GroupBy: []string{"source.host"},
			Window:  15 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
	}
}

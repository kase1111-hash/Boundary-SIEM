// Package validator provides validator security monitoring capabilities.
package validator

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// ValidatorStatus represents the current status of a validator.
type ValidatorStatus string

const (
	StatusActive         ValidatorStatus = "active"
	StatusPending        ValidatorStatus = "pending"
	StatusExiting        ValidatorStatus = "exiting"
	StatusSlashed        ValidatorStatus = "slashed"
	StatusWithdrawable   ValidatorStatus = "withdrawable"
	StatusOffline        ValidatorStatus = "offline"
)

// ValidatorState tracks the state of a single validator.
type ValidatorState struct {
	Index              int64           `json:"index"`
	PublicKey          string          `json:"public_key"`
	Status             ValidatorStatus `json:"status"`
	EffectiveBalance   uint64          `json:"effective_balance"`
	ActivationEpoch    int64           `json:"activation_epoch"`
	ExitEpoch          int64           `json:"exit_epoch"`
	WithdrawableEpoch  int64           `json:"withdrawable_epoch"`
	Slashed            bool            `json:"slashed"`

	// Performance metrics
	AttestationsSubmitted   int64     `json:"attestations_submitted"`
	AttestationsMissed      int64     `json:"attestations_missed"`
	ProposalsSubmitted      int64     `json:"proposals_submitted"`
	ProposalsMissed         int64     `json:"proposals_missed"`
	SyncCommitteeSubmitted  int64     `json:"sync_committee_submitted"`
	SyncCommitteeMissed     int64     `json:"sync_committee_missed"`

	// Timing
	LastAttestationSlot     int64     `json:"last_attestation_slot"`
	LastProposalSlot        int64     `json:"last_proposal_slot"`
	LastSyncContributionSlot int64    `json:"last_sync_contribution_slot"`
	LastSeenAt              time.Time `json:"last_seen_at"`

	// Risk assessment
	SlashingRiskScore       float64   `json:"slashing_risk_score"`
	PerformanceScore        float64   `json:"performance_score"`
}

// Alert represents a validator alert.
type Alert struct {
	ID          uuid.UUID       `json:"id"`
	Type        AlertType       `json:"type"`
	Severity    string          `json:"severity"`
	Validator   int64           `json:"validator_index"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Timestamp   time.Time       `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertType represents the type of validator alert.
type AlertType string

const (
	AlertSlashingRisk        AlertType = "slashing_risk"
	AlertMissedAttestation   AlertType = "missed_attestation"
	AlertMissedProposal      AlertType = "missed_proposal"
	AlertMissedSyncCommittee AlertType = "missed_sync_committee"
	AlertOffline             AlertType = "offline"
	AlertBalanceDecrease     AlertType = "balance_decrease"
	AlertUnexpectedExit      AlertType = "unexpected_exit"
	AlertKeyAccess           AlertType = "key_access"
	AlertDoubleVote          AlertType = "double_vote"
	AlertSurroundVote        AlertType = "surround_vote"
)

// MonitorConfig configures the validator monitor.
type MonitorConfig struct {
	// Thresholds for alerts
	MissedAttestationThreshold int     // Consecutive missed attestations before alert
	MissedProposalAlert        bool    // Alert on any missed proposal
	OfflineThresholdMinutes    int     // Minutes before considering validator offline
	BalanceDecreaseThreshold   float64 // Percentage balance decrease to alert

	// Monitoring intervals
	HealthCheckInterval  time.Duration
	MetricsInterval      time.Duration
	CleanupInterval      time.Duration

	// Retention
	MaxHistoryEntries    int
}

// DefaultMonitorConfig returns default monitor configuration.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		MissedAttestationThreshold: 3,
		MissedProposalAlert:        true,
		OfflineThresholdMinutes:    15,
		BalanceDecreaseThreshold:   0.01, // 1%

		HealthCheckInterval: 1 * time.Minute,
		MetricsInterval:     5 * time.Minute,
		CleanupInterval:     1 * time.Hour,

		MaxHistoryEntries: 1000,
	}
}

// AlertHandler is called when a validator alert is generated.
type AlertHandler func(context.Context, *Alert) error

// Monitor monitors validator health and security.
type Monitor struct {
	config     MonitorConfig
	validators map[int64]*ValidatorState
	alerts     []*Alert
	handlers   []AlertHandler
	mu         sync.RWMutex
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// NewMonitor creates a new validator monitor.
func NewMonitor(config MonitorConfig) *Monitor {
	return &Monitor{
		config:     config,
		validators: make(map[int64]*ValidatorState),
		alerts:     make([]*Alert, 0),
		stopCh:     make(chan struct{}),
	}
}

// AddHandler adds an alert handler.
func (m *Monitor) AddHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// AddWatchedValidator adds a validator to be monitored.
func (m *Monitor) AddWatchedValidator(index int64, pubkey string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.validators[index]; !exists {
		m.validators[index] = &ValidatorState{
			Index:     index,
			PublicKey: pubkey,
			Status:    StatusActive,
		}
		slog.Info("added watched validator", "index", index)
	}
}

// Start starts the validator monitor.
func (m *Monitor) Start(ctx context.Context) {
	m.wg.Add(1)
	go m.healthChecker(ctx)

	slog.Info("validator monitor started")
}

// Stop stops the validator monitor.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	slog.Info("validator monitor stopped")
}

// ProcessEvent processes a validator-related event.
func (m *Monitor) ProcessEvent(event *schema.Event) {
	// Extract validator index from event
	var validatorIndex int64
	if idx, ok := event.Metadata["validator_index"].(int64); ok {
		validatorIndex = idx
	} else if idx, ok := event.Metadata["validator_index"].(float64); ok {
		validatorIndex = int64(idx)
	}

	if validatorIndex <= 0 {
		return
	}

	m.mu.Lock()
	validator := m.getOrCreateValidator(validatorIndex)
	m.mu.Unlock()

	// Process based on event action
	switch event.Action {
	case "validator.attestation_submitted":
		m.handleAttestationSubmitted(validator, event)
	case "validator.attestation_missed":
		m.handleAttestationMissed(validator, event)
	case "validator.block_proposed":
		m.handleBlockProposed(validator, event)
	case "validator.proposal_missed":
		m.handleProposalMissed(validator, event)
	case "validator.sync_committee_submitted":
		m.handleSyncCommitteeSubmitted(validator, event)
	case "validator.sync_committee_missed":
		m.handleSyncCommitteeMissed(validator, event)
	case "validator.slashing_detected":
		m.handleSlashingDetected(validator, event)
	case "validator.double_vote":
		m.handleDoubleVote(validator, event)
	case "validator.surround_vote":
		m.handleSurroundVote(validator, event)
	case "validator.exited":
		m.handleValidatorExited(validator, event)
	}

	// Update last seen
	m.mu.Lock()
	validator.LastSeenAt = time.Now()
	m.updatePerformanceScore(validator)
	m.mu.Unlock()
}

func (m *Monitor) getOrCreateValidator(index int64) *ValidatorState {
	if v, ok := m.validators[index]; ok {
		return v
	}

	v := &ValidatorState{
		Index:            index,
		Status:           StatusActive,
		LastSeenAt:       time.Now(),
		PerformanceScore: 100.0,
	}
	m.validators[index] = v
	return v
}

func (m *Monitor) handleAttestationSubmitted(v *ValidatorState, event *schema.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v.AttestationsSubmitted++
	if slot, ok := event.Metadata["slot"].(int64); ok {
		v.LastAttestationSlot = slot
	}
}

func (m *Monitor) handleAttestationMissed(v *ValidatorState, event *schema.Event) {
	m.mu.Lock()
	v.AttestationsMissed++
	consecutiveMissed := m.countConsecutiveMissed(v)
	m.mu.Unlock()

	if consecutiveMissed >= m.config.MissedAttestationThreshold {
		m.generateAlert(AlertMissedAttestation, v, "high",
			"Multiple Attestations Missed",
			fmt.Sprintf("Validator %d has missed %d consecutive attestations", v.Index, consecutiveMissed),
			map[string]interface{}{
				"consecutive_missed": consecutiveMissed,
				"total_missed":       v.AttestationsMissed,
			})
	}
}

func (m *Monitor) handleBlockProposed(v *ValidatorState, event *schema.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v.ProposalsSubmitted++
	if slot, ok := event.Metadata["slot"].(int64); ok {
		v.LastProposalSlot = slot
	}
}

func (m *Monitor) handleProposalMissed(v *ValidatorState, event *schema.Event) {
	m.mu.Lock()
	v.ProposalsMissed++
	m.mu.Unlock()

	if m.config.MissedProposalAlert {
		m.generateAlert(AlertMissedProposal, v, "high",
			"Block Proposal Missed",
			fmt.Sprintf("Validator %d missed a block proposal duty", v.Index),
			map[string]interface{}{
				"total_missed": v.ProposalsMissed,
			})
	}
}

func (m *Monitor) handleSyncCommitteeSubmitted(v *ValidatorState, event *schema.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()

	v.SyncCommitteeSubmitted++
	if slot, ok := event.Metadata["slot"].(int64); ok {
		v.LastSyncContributionSlot = slot
	}
}

func (m *Monitor) handleSyncCommitteeMissed(v *ValidatorState, event *schema.Event) {
	m.mu.Lock()
	v.SyncCommitteeMissed++
	m.mu.Unlock()

	m.generateAlert(AlertMissedSyncCommittee, v, "medium",
		"Sync Committee Contribution Missed",
		fmt.Sprintf("Validator %d missed a sync committee contribution", v.Index),
		nil)
}

func (m *Monitor) handleSlashingDetected(v *ValidatorState, event *schema.Event) {
	m.mu.Lock()
	v.Status = StatusSlashed
	v.Slashed = true
	v.SlashingRiskScore = 100
	m.mu.Unlock()

	m.generateAlert(AlertSlashingRisk, v, "critical",
		"VALIDATOR SLASHED",
		fmt.Sprintf("Validator %d has been SLASHED! Immediate investigation required.", v.Index),
		map[string]interface{}{
			"slashed": true,
		})
}

func (m *Monitor) handleDoubleVote(v *ValidatorState, event *schema.Event) {
	m.mu.Lock()
	v.SlashingRiskScore = 100
	m.mu.Unlock()

	m.generateAlert(AlertDoubleVote, v, "critical",
		"DOUBLE VOTE DETECTED",
		fmt.Sprintf("Validator %d attempted a double vote - slashing imminent!", v.Index),
		nil)
}

func (m *Monitor) handleSurroundVote(v *ValidatorState, event *schema.Event) {
	m.mu.Lock()
	v.SlashingRiskScore = 100
	m.mu.Unlock()

	m.generateAlert(AlertSurroundVote, v, "critical",
		"SURROUND VOTE DETECTED",
		fmt.Sprintf("Validator %d attempted a surround vote - slashing imminent!", v.Index),
		nil)
}

func (m *Monitor) handleValidatorExited(v *ValidatorState, event *schema.Event) {
	m.mu.Lock()
	prevStatus := v.Status
	v.Status = StatusExiting
	m.mu.Unlock()

	if prevStatus == StatusActive {
		m.generateAlert(AlertUnexpectedExit, v, "high",
			"Validator Exit Detected",
			fmt.Sprintf("Validator %d has initiated exit from active state", v.Index),
			nil)
	}
}

func (m *Monitor) countConsecutiveMissed(v *ValidatorState) int {
	// Simplified: use ratio for approximation
	if v.AttestationsSubmitted == 0 {
		return int(v.AttestationsMissed)
	}
	ratio := float64(v.AttestationsMissed) / float64(v.AttestationsSubmitted+v.AttestationsMissed)
	if ratio > 0.5 {
		return m.config.MissedAttestationThreshold + 1
	}
	return 0
}

func (m *Monitor) updatePerformanceScore(v *ValidatorState) {
	total := v.AttestationsSubmitted + v.AttestationsMissed
	if total == 0 {
		v.PerformanceScore = 100.0
		return
	}

	// Calculate attestation success rate (80% weight)
	attestationScore := float64(v.AttestationsSubmitted) / float64(total) * 80

	// Proposal success rate (15% weight)
	proposalTotal := v.ProposalsSubmitted + v.ProposalsMissed
	var proposalScore float64
	if proposalTotal > 0 {
		proposalScore = float64(v.ProposalsSubmitted) / float64(proposalTotal) * 15
	} else {
		proposalScore = 15 // No proposals yet = full score
	}

	// Sync committee (5% weight)
	syncTotal := v.SyncCommitteeSubmitted + v.SyncCommitteeMissed
	var syncScore float64
	if syncTotal > 0 {
		syncScore = float64(v.SyncCommitteeSubmitted) / float64(syncTotal) * 5
	} else {
		syncScore = 5
	}

	v.PerformanceScore = attestationScore + proposalScore + syncScore
}

func (m *Monitor) generateAlert(alertType AlertType, v *ValidatorState, severity, title, description string, metadata map[string]interface{}) {
	alert := &Alert{
		ID:          uuid.New(),
		Type:        alertType,
		Severity:    severity,
		Validator:   v.Index,
		Title:       title,
		Description: description,
		Timestamp:   time.Now(),
		Metadata:    metadata,
	}

	m.mu.Lock()
	m.alerts = append(m.alerts, alert)
	handlers := m.handlers
	m.mu.Unlock()

	slog.Warn("validator alert generated",
		"type", alertType,
		"severity", severity,
		"validator", v.Index,
		"title", title)

	// Dispatch to handlers
	ctx := context.Background()
	for _, handler := range handlers {
		go func(h AlertHandler) {
			if err := h(ctx, alert); err != nil {
				slog.Error("alert handler failed", "error", err)
			}
		}(handler)
	}
}

func (m *Monitor) healthChecker(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkValidatorHealth()
		}
	}
}

func (m *Monitor) checkValidatorHealth() {
	m.mu.RLock()
	validators := make([]*ValidatorState, 0, len(m.validators))
	for _, v := range m.validators {
		validators = append(validators, v)
	}
	m.mu.RUnlock()

	now := time.Now()
	offlineThreshold := time.Duration(m.config.OfflineThresholdMinutes) * time.Minute

	for _, v := range validators {
		if v.Status == StatusActive && now.Sub(v.LastSeenAt) > offlineThreshold {
			m.mu.Lock()
			v.Status = StatusOffline
			m.mu.Unlock()

			m.generateAlert(AlertOffline, v, "high",
				"Validator Offline",
				fmt.Sprintf("Validator %d has not been seen for %d minutes", v.Index, m.config.OfflineThresholdMinutes),
				nil)
		}
	}
}

// GetValidator returns the state of a specific validator.
func (m *Monitor) GetValidator(index int64) (*ValidatorState, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.validators[index]
	return v, ok
}

// GetAllValidators returns all monitored validators.
func (m *Monitor) GetAllValidators() []*ValidatorState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*ValidatorState, 0, len(m.validators))
	for _, v := range m.validators {
		result = append(result, v)
	}
	return result
}

// GetAlerts returns recent alerts.
func (m *Monitor) GetAlerts(limit int) []*Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.alerts) {
		limit = len(m.alerts)
	}

	start := len(m.alerts) - limit
	if start < 0 {
		start = 0
	}

	return m.alerts[start:]
}

// GetStats returns monitor statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"total_validators": len(m.validators),
		"total_alerts":     len(m.alerts),
	}

	// Count by status
	statusCounts := make(map[ValidatorStatus]int)
	var totalPerformance float64
	for _, v := range m.validators {
		statusCounts[v.Status]++
		totalPerformance += v.PerformanceScore
	}
	stats["by_status"] = statusCounts

	if len(m.validators) > 0 {
		stats["avg_performance"] = totalPerformance / float64(len(m.validators))
	}

	return stats
}

// CreateCorrelationRules returns correlation rules for validator monitoring.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "validator-missed-attestations",
			Name:        "Validator Missing Attestations",
			Description: "Validator has missed multiple attestations in a short period",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "validator", "attestation"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "validator.attestation_missed"},
			},
			GroupBy: []string{"metadata.validator_index"},
			Window:  30 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    3,
				Operator: "gte",
			},
		},
		{
			ID:          "validator-slashing-sequence",
			Name:        "Slashing Condition Detected",
			Description: "Potential slashing condition (double vote or surround vote)",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"blockchain", "validator", "slashing", "critical"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "in", Values: []string{
					"validator.double_vote",
					"validator.surround_vote",
					"validator.slashing_detected",
				}},
			},
			GroupBy: []string{"metadata.validator_index"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "validator-proposal-missed",
			Name:        "Block Proposal Missed",
			Description: "Validator missed a block proposal duty",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "validator", "proposal"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "validator.proposal_missed"},
			},
			GroupBy: []string{"metadata.validator_index"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
	}
}

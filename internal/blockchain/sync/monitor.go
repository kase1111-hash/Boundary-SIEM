// Package sync provides blockchain synchronization monitoring capabilities.
package sync

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

// SyncMode represents the synchronization mode.
type SyncMode string

const (
	SyncModeFull  SyncMode = "full"
	SyncModeFast  SyncMode = "fast"
	SyncModeSnap  SyncMode = "snap"
	SyncModeLight SyncMode = "light"
)

// SyncState represents the current synchronization state.
type SyncState struct {
	// Sync status
	IsSyncing     bool      `json:"is_syncing"`
	SyncMode      SyncMode  `json:"sync_mode"`
	SyncStartTime time.Time `json:"sync_start_time,omitempty"`
	SyncProgress  float64   `json:"sync_progress"` // 0.0 to 100.0

	// Block heights
	HeadSlot        uint64 `json:"head_slot"`         // Current local head
	NetworkHeadSlot uint64 `json:"network_head_slot"` // Network canonical head
	FinalizedSlot   uint64 `json:"finalized_slot"`    // Last finalized slot
	JustifiedSlot   uint64 `json:"justified_slot"`    // Last justified slot

	// Lag metrics
	SyncLagSlots   uint64 `json:"sync_lag_slots"`   // Slots behind network
	SyncLagSeconds int64  `json:"sync_lag_seconds"` // Time behind in seconds
	FinalityDelay  uint64 `json:"finality_delay"`   // Epochs since last finality

	// Peer information
	PeerCount        int               `json:"peer_count"`
	PeerHeadSlots    map[string]uint64 `json:"peer_head_slots,omitempty"` // peer ID -> head slot
	MajorityPeerHead uint64            `json:"majority_peer_head"`        // What most peers report

	// Reorg tracking
	LastReorgDepth uint64    `json:"last_reorg_depth"`
	LastReorgTime  time.Time `json:"last_reorg_time,omitempty"`
	ReorgCount1h   int       `json:"reorg_count_1h"` // Reorgs in last hour

	// Progress tracking
	LastHeadUpdate time.Time `json:"last_head_update"`
	HeadUpdateRate float64   `json:"head_update_rate"` // Slots per second

	Timestamp time.Time `json:"timestamp"`
}

// Alert represents a sync-related alert.
type Alert struct {
	ID          uuid.UUID              `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	State       *SyncState             `json:"state,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertHandler processes sync alerts.
type AlertHandler func(context.Context, *Alert) error

// MonitorConfig configures the sync monitor.
type MonitorConfig struct {
	// Lag thresholds
	LagThresholdSlots   uint64 // Slots behind to trigger warning (default: 32 = 2 epochs for Ethereum)
	LagCriticalSlots    uint64 // Slots behind for critical alert (default: 128 = 8 epochs)
	LagThresholdSeconds int64  // Time behind to alert (default: 384 seconds = ~6.4 minutes)

	// Finality monitoring
	FinalityTimeoutEpochs uint64        // Epochs without finality before alert (default: 4 = ~25 min)
	JustificationTimeout  time.Duration // Timeout for justification (default: 10 minutes)

	// Sync progress monitoring
	SyncStuckThreshold time.Duration // No progress for this long = stuck (default: 10 min)
	SyncSlowThreshold  float64       // Slots per second (default: 0.5 for Ethereum)

	// Reorg monitoring
	MaxSafeReorgDepth  uint64 // Max safe reorg depth (default: 32 blocks)
	DeepReorgThreshold uint64 // Reorg deeper than this = critical (default: 64)
	FrequentReorgCount int    // Reorgs per hour to trigger alert (default: 3)

	// Peer monitoring
	MinPeerConsensus float64 // Min % of peers agreeing on head (default: 0.8 = 80%)
	MinPeerCount     int     // Minimum peer count (default: 10)

	// Monitoring intervals
	CheckInterval   time.Duration // How often to check sync status (default: 30s)
	StateRetention  int           // Number of historical states to keep (default: 2880 = 24h at 30s)
	CleanupInterval time.Duration // Cleanup old data (default: 5 minutes)

	// Network-specific settings
	SecondsPerSlot uint64 // Seconds per slot (12 for Ethereum, 0.4 for Solana)
	SlotsPerEpoch  uint64 // Slots per epoch (32 for Ethereum)
}

// DefaultMonitorConfig returns default configuration for Ethereum.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		LagThresholdSlots:   32,  // 2 epochs
		LagCriticalSlots:    128, // 8 epochs
		LagThresholdSeconds: 384, // ~6.4 minutes

		FinalityTimeoutEpochs: 4, // ~25 minutes
		JustificationTimeout:  10 * time.Minute,

		SyncStuckThreshold: 10 * time.Minute,
		SyncSlowThreshold:  0.5, // slots per second

		MaxSafeReorgDepth:  32,
		DeepReorgThreshold: 64,
		FrequentReorgCount: 3,

		MinPeerConsensus: 0.8,
		MinPeerCount:     10,

		CheckInterval:   30 * time.Second,
		StateRetention:  2880, // 24 hours
		CleanupInterval: 5 * time.Minute,

		SecondsPerSlot: 12,
		SlotsPerEpoch:  32,
	}
}

// Monitor monitors blockchain synchronization status.
type Monitor struct {
	config   MonitorConfig
	handlers []AlertHandler
	mu       sync.RWMutex

	// Current state
	currentState *SyncState
	stateHistory []SyncState

	// Reorg tracking
	reorgHistory []ReorgEvent

	// Alert deduplication
	recentAlerts map[string]time.Time

	// Lifecycle
	stopCh chan struct{}
	wg     sync.WaitGroup
	logger *slog.Logger
}

// ReorgEvent represents a chain reorganization event.
type ReorgEvent struct {
	Timestamp time.Time     `json:"timestamp"`
	OldHead   uint64        `json:"old_head"`
	NewHead   uint64        `json:"new_head"`
	Depth     uint64        `json:"depth"`
	Duration  time.Duration `json:"duration"`
}

// NewMonitor creates a new sync monitor.
func NewMonitor(config MonitorConfig) *Monitor {
	return &Monitor{
		config:       config,
		stateHistory: make([]SyncState, 0, config.StateRetention),
		reorgHistory: make([]ReorgEvent, 0, 100),
		recentAlerts: make(map[string]time.Time),
		stopCh:       make(chan struct{}),
		logger:       slog.Default(),
	}
}

// AddHandler adds an alert handler.
func (m *Monitor) AddHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// Start starts the sync monitor.
func (m *Monitor) Start(ctx context.Context) error {
	m.logger.Info("starting sync monitor",
		"check_interval", m.config.CheckInterval,
		"lag_threshold_slots", m.config.LagThresholdSlots)

	// Start monitoring loop
	m.wg.Add(1)
	go m.monitorLoop(ctx)

	// Start cleanup loop
	m.wg.Add(1)
	go m.cleanupLoop(ctx)

	return nil
}

// Stop stops the sync monitor.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	m.logger.Info("sync monitor stopped")
}

// UpdateSyncState updates the current sync state and checks for issues.
func (m *Monitor) UpdateSyncState(ctx context.Context, state *SyncState) {
	state.Timestamp = time.Now()

	// Calculate derived metrics
	m.calculateDerivedMetrics(state)

	// Store state
	m.mu.Lock()
	m.currentState = state
	m.stateHistory = append(m.stateHistory, *state)
	if len(m.stateHistory) > m.config.StateRetention {
		m.stateHistory = m.stateHistory[1:]
	}
	m.mu.Unlock()

	// Analyze state and generate alerts
	m.analyzeState(ctx, state)
}

// calculateDerivedMetrics calculates derived metrics from state.
func (m *Monitor) calculateDerivedMetrics(state *SyncState) {
	// Calculate sync lag
	if state.NetworkHeadSlot > state.HeadSlot {
		state.SyncLagSlots = state.NetworkHeadSlot - state.HeadSlot
		state.SyncLagSeconds = int64(state.SyncLagSlots * m.config.SecondsPerSlot)
	} else {
		state.SyncLagSlots = 0
		state.SyncLagSeconds = 0
	}

	// Calculate finality delay (in epochs)
	if state.HeadSlot > state.FinalizedSlot {
		state.FinalityDelay = (state.HeadSlot - state.FinalizedSlot) / m.config.SlotsPerEpoch
	}

	// Calculate majority peer head
	if len(state.PeerHeadSlots) > 0 {
		state.MajorityPeerHead = calculateMajorityHead(state.PeerHeadSlots)
	}

	// Calculate sync progress
	if state.NetworkHeadSlot > 0 {
		state.SyncProgress = float64(state.HeadSlot) / float64(state.NetworkHeadSlot) * 100.0
		if state.SyncProgress > 100.0 {
			state.SyncProgress = 100.0
		}
	}

	// Calculate head update rate
	m.mu.RLock()
	if len(m.stateHistory) > 0 {
		oldState := m.stateHistory[len(m.stateHistory)-1]
		timeDiff := state.Timestamp.Sub(oldState.Timestamp)
		if timeDiff > 0 {
			slotDiff := int64(state.HeadSlot) - int64(oldState.HeadSlot)
			state.HeadUpdateRate = float64(slotDiff) / timeDiff.Seconds()
		}
	}
	m.mu.RUnlock()
}

// calculateMajorityHead finds the head slot that most peers agree on.
func calculateMajorityHead(peerHeads map[string]uint64) uint64 {
	counts := make(map[uint64]int)
	for _, head := range peerHeads {
		counts[head]++
	}

	var majorityHead uint64
	var maxCount int
	for head, count := range counts {
		if count > maxCount {
			maxCount = count
			majorityHead = head
		}
	}

	return majorityHead
}

// analyzeState analyzes sync state and generates alerts.
func (m *Monitor) analyzeState(ctx context.Context, state *SyncState) {
	// Check sync lag
	m.checkSyncLag(ctx, state)

	// Check finality
	m.checkFinality(ctx, state)

	// Check sync progress
	m.checkSyncProgress(ctx, state)

	// Check peer consensus
	m.checkPeerConsensus(ctx, state)

	// Check for stuck sync
	m.checkStuckSync(ctx, state)
}

// checkSyncLag checks for excessive sync lag.
func (m *Monitor) checkSyncLag(ctx context.Context, state *SyncState) {
	if state.SyncLagSlots >= m.config.LagCriticalSlots {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "sync-lag-critical",
			Severity: "critical",
			Title:    "CRITICAL: Node Severely Behind Network",
			Description: fmt.Sprintf("Node is %d slots (%s) behind network head. Validator duties at risk!",
				state.SyncLagSlots,
				formatDuration(time.Duration(state.SyncLagSeconds)*time.Second)),
			Timestamp: state.Timestamp,
			State:     state,
			Metadata: map[string]interface{}{
				"lag_slots":    state.SyncLagSlots,
				"lag_seconds":  state.SyncLagSeconds,
				"head_slot":    state.HeadSlot,
				"network_head": state.NetworkHeadSlot,
			},
		})
	} else if state.SyncLagSlots >= m.config.LagThresholdSlots {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "sync-lag-warning",
			Severity: "high",
			Title:    "Node Behind Network",
			Description: fmt.Sprintf("Node is %d slots (%s) behind network head",
				state.SyncLagSlots,
				formatDuration(time.Duration(state.SyncLagSeconds)*time.Second)),
			Timestamp: state.Timestamp,
			State:     state,
			Metadata: map[string]interface{}{
				"lag_slots":   state.SyncLagSlots,
				"lag_seconds": state.SyncLagSeconds,
			},
		})
	}
}

// checkFinality checks for finality delays.
func (m *Monitor) checkFinality(ctx context.Context, state *SyncState) {
	if state.FinalityDelay >= m.config.FinalityTimeoutEpochs {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "sync-finality-delayed",
			Severity: "critical",
			Title:    "Finality Delayed",
			Description: fmt.Sprintf("No finality for %d epochs (%s). Network-wide issue or node isolated.",
				state.FinalityDelay,
				formatDuration(time.Duration(state.FinalityDelay*m.config.SlotsPerEpoch*m.config.SecondsPerSlot)*time.Second)),
			Timestamp: state.Timestamp,
			State:     state,
			Metadata: map[string]interface{}{
				"finality_delay_epochs": state.FinalityDelay,
				"finalized_slot":        state.FinalizedSlot,
				"head_slot":             state.HeadSlot,
			},
		})
	}

	// Check justification
	if state.JustifiedSlot > 0 && state.HeadSlot > state.JustifiedSlot {
		justificationDelay := (state.HeadSlot - state.JustifiedSlot) / m.config.SlotsPerEpoch
		if time.Duration(justificationDelay*m.config.SlotsPerEpoch*m.config.SecondsPerSlot)*time.Second > m.config.JustificationTimeout {
			m.emitAlert(ctx, &Alert{
				ID:          uuid.New(),
				Type:        "sync-justification-delayed",
				Severity:    "high",
				Title:       "Justification Delayed",
				Description: fmt.Sprintf("No justification for %d epochs", justificationDelay),
				Timestamp:   state.Timestamp,
				State:       state,
			})
		}
	}
}

// checkSyncProgress checks if sync is making progress.
func (m *Monitor) checkSyncProgress(ctx context.Context, state *SyncState) {
	if !state.IsSyncing {
		return
	}

	// Check if sync is slow
	if state.HeadUpdateRate > 0 && state.HeadUpdateRate < m.config.SyncSlowThreshold {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "sync-slow-progress",
			Severity: "medium",
			Title:    "Slow Sync Progress",
			Description: fmt.Sprintf("Syncing at %.2f slots/second (threshold: %.2f slots/sec)",
				state.HeadUpdateRate,
				m.config.SyncSlowThreshold),
			Timestamp: state.Timestamp,
			State:     state,
			Metadata: map[string]interface{}{
				"sync_rate":     state.HeadUpdateRate,
				"sync_progress": state.SyncProgress,
			},
		})
	}
}

// checkPeerConsensus checks if node agrees with majority of peers.
func (m *Monitor) checkPeerConsensus(ctx context.Context, state *SyncState) {
	if len(state.PeerHeadSlots) < m.config.MinPeerCount {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "sync-low-peer-count",
			Severity: "medium",
			Title:    "Low Peer Count",
			Description: fmt.Sprintf("Only %d peers connected (minimum: %d)",
				len(state.PeerHeadSlots),
				m.config.MinPeerCount),
			Timestamp: state.Timestamp,
			State:     state,
		})
		return
	}

	// Calculate consensus
	consensusCount := 0
	for _, peerHead := range state.PeerHeadSlots {
		if peerHead == state.MajorityPeerHead {
			consensusCount++
		}
	}

	consensusPercent := float64(consensusCount) / float64(len(state.PeerHeadSlots))

	if consensusPercent < m.config.MinPeerConsensus {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "sync-peer-mismatch",
			Severity: "high",
			Title:    "Node Disagrees with Peers",
			Description: fmt.Sprintf("Only %.0f%% of peers agree on head (local: %d, majority: %d)",
				consensusPercent*100,
				state.HeadSlot,
				state.MajorityPeerHead),
			Timestamp: state.Timestamp,
			State:     state,
			Metadata: map[string]interface{}{
				"consensus_percent": consensusPercent * 100,
				"local_head":        state.HeadSlot,
				"majority_head":     state.MajorityPeerHead,
			},
		})
	}
}

// checkStuckSync checks if sync is stuck (no progress).
func (m *Monitor) checkStuckSync(ctx context.Context, state *SyncState) {
	if !state.IsSyncing || state.LastHeadUpdate.IsZero() {
		return
	}

	timeSinceUpdate := time.Since(state.LastHeadUpdate)
	if timeSinceUpdate > m.config.SyncStuckThreshold {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "sync-stuck",
			Severity: "high",
			Title:    "Sync Stuck - No Progress",
			Description: fmt.Sprintf("No sync progress for %s (stuck at slot %d)",
				formatDuration(timeSinceUpdate),
				state.HeadSlot),
			Timestamp: state.Timestamp,
			State:     state,
			Metadata: map[string]interface{}{
				"stuck_duration": timeSinceUpdate.Seconds(),
				"stuck_at_slot":  state.HeadSlot,
			},
		})
	}
}

// ReportReorg reports a chain reorganization event.
func (m *Monitor) ReportReorg(ctx context.Context, oldHead, newHead uint64, duration time.Duration) {
	var depth uint64
	if oldHead > newHead {
		depth = oldHead - newHead
	} else {
		depth = newHead - oldHead
	}

	event := ReorgEvent{
		Timestamp: time.Now(),
		OldHead:   oldHead,
		NewHead:   newHead,
		Depth:     depth,
		Duration:  duration,
	}

	m.mu.Lock()
	m.reorgHistory = append(m.reorgHistory, event)
	if len(m.reorgHistory) > 100 {
		m.reorgHistory = m.reorgHistory[1:]
	}

	// Update current state
	if m.currentState != nil {
		m.currentState.LastReorgDepth = depth
		m.currentState.LastReorgTime = event.Timestamp
	}

	// Count recent reorgs
	reorgCount := 0
	cutoff := time.Now().Add(-1 * time.Hour)
	for _, r := range m.reorgHistory {
		if r.Timestamp.After(cutoff) {
			reorgCount++
		}
	}
	if m.currentState != nil {
		m.currentState.ReorgCount1h = reorgCount
	}
	m.mu.Unlock()

	// Check for deep reorg
	if depth > m.config.DeepReorgThreshold {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "sync-deep-reorg",
			Severity: "critical",
			Title:    "CRITICAL: Deep Chain Reorganization",
			Description: fmt.Sprintf("Chain reorganization of %d blocks detected (threshold: %d)",
				depth,
				m.config.DeepReorgThreshold),
			Timestamp: event.Timestamp,
			Metadata: map[string]interface{}{
				"old_head": oldHead,
				"new_head": newHead,
				"depth":    depth,
				"duration": duration.Seconds(),
			},
		})
	} else if depth > m.config.MaxSafeReorgDepth {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "sync-reorg-warning",
			Severity: "high",
			Title:    "Chain Reorganization Detected",
			Description: fmt.Sprintf("Chain reorganization of %d blocks (max safe: %d)",
				depth,
				m.config.MaxSafeReorgDepth),
			Timestamp: event.Timestamp,
			Metadata: map[string]interface{}{
				"depth": depth,
			},
		})
	}

	// Check for frequent reorgs
	if reorgCount >= m.config.FrequentReorgCount {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "sync-frequent-reorgs",
			Severity: "high",
			Title:    "Frequent Chain Reorganizations",
			Description: fmt.Sprintf("%d reorgs in last hour (threshold: %d)",
				reorgCount,
				m.config.FrequentReorgCount),
			Timestamp: event.Timestamp,
			Metadata: map[string]interface{}{
				"reorg_count": reorgCount,
			},
		})
	}
}

// emitAlert emits an alert with deduplication.
func (m *Monitor) emitAlert(ctx context.Context, alert *Alert) {
	// Deduplicate
	m.mu.Lock()
	lastAlert, exists := m.recentAlerts[alert.Type]
	if exists && time.Since(lastAlert) < 5*time.Minute {
		m.mu.Unlock()
		return
	}
	m.recentAlerts[alert.Type] = time.Now()
	handlers := m.handlers
	m.mu.Unlock()

	m.logger.Warn("sync alert generated",
		"type", alert.Type,
		"severity", alert.Severity,
		"title", alert.Title)

	// Dispatch to handlers
	for _, handler := range handlers {
		go func(h AlertHandler) {
			if err := h(ctx, alert); err != nil {
				m.logger.Error("alert handler failed", "error", err)
			}
		}(handler)
	}
}

// monitorLoop runs the main monitoring loop.
func (m *Monitor) monitorLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			// Periodic checks would go here
			// In real implementation, would poll blockchain node for sync status
		}
	}
}

// cleanupLoop runs the cleanup loop.
func (m *Monitor) cleanupLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

// cleanup removes old data.
func (m *Monitor) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clean old alerts
	cutoff := time.Now().Add(-30 * time.Minute)
	for alertType, lastTime := range m.recentAlerts {
		if lastTime.Before(cutoff) {
			delete(m.recentAlerts, alertType)
		}
	}
}

// GetCurrentState returns the current sync state.
func (m *Monitor) GetCurrentState() *SyncState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.currentState != nil {
		state := *m.currentState
		return &state
	}
	return nil
}

// GetStateHistory returns historical sync states.
func (m *Monitor) GetStateHistory(limit int) []SyncState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.stateHistory) {
		limit = len(m.stateHistory)
	}

	start := len(m.stateHistory) - limit
	if start < 0 {
		start = 0
	}

	result := make([]SyncState, limit)
	copy(result, m.stateHistory[start:])
	return result
}

// GetReorgHistory returns recent reorg events.
func (m *Monitor) GetReorgHistory(limit int) []ReorgEvent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.reorgHistory) {
		limit = len(m.reorgHistory)
	}

	start := len(m.reorgHistory) - limit
	if start < 0 {
		start = 0
	}

	result := make([]ReorgEvent, limit)
	copy(result, m.reorgHistory[start:])
	return result
}

// GetStats returns monitor statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"state_history_count": len(m.stateHistory),
		"reorg_history_count": len(m.reorgHistory),
		"check_interval":      m.config.CheckInterval.String(),
	}

	if m.currentState != nil {
		stats["is_syncing"] = m.currentState.IsSyncing
		stats["head_slot"] = m.currentState.HeadSlot
		stats["network_head_slot"] = m.currentState.NetworkHeadSlot
		stats["sync_lag_slots"] = m.currentState.SyncLagSlots
		stats["finality_delay"] = m.currentState.FinalityDelay
		stats["peer_count"] = m.currentState.PeerCount
		stats["sync_progress"] = m.currentState.SyncProgress
	}

	return stats
}

// NormalizeToEvent converts a sync alert to a schema.Event.
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

	if alert.State != nil {
		metadata["sync_lag_slots"] = alert.State.SyncLagSlots
		metadata["head_slot"] = alert.State.HeadSlot
		metadata["network_head_slot"] = alert.State.NetworkHeadSlot
		metadata["finality_delay"] = alert.State.FinalityDelay
		metadata["is_syncing"] = alert.State.IsSyncing
	}

	return &schema.Event{
		EventID:   alert.ID,
		Timestamp: alert.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: "sync-monitor",
			Host:    getHostname(),
			Version: "1.0",
		},
		Action:   fmt.Sprintf("sync.%s", alert.Type),
		Outcome:  outcome,
		Severity: severity,
		Metadata: metadata,
	}
}

// formatDuration formats a duration into human-readable format.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

// getHostname returns the system hostname.
func getHostname() string {
	// This would import "os" and call os.Hostname() in real implementation
	return "blockchain-node"
}

// CreateCorrelationRules creates sync-related correlation rules.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "sync-behind-network",
			Name:        "Node Behind Network",
			Description: "Node is significantly behind the network head",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"sync", "lag", "blockchain"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1499",
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "sync.sync-lag"},
			},
			GroupBy: []string{"source.host"},
			Window:  10 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    2,
				Operator: "gte",
			},
		},
		{
			ID:          "sync-finality-failure",
			Name:        "Finality Failure",
			Description: "Chain has not finalized for extended period",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"sync", "finality", "consensus"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "sync.sync-finality-delayed"},
			},
			GroupBy: []string{"source.host"},
			Window:  30 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "sync-deep-reorg-detected",
			Name:        "Deep Chain Reorganization",
			Description: "Deep chain reorganization indicates potential attack or major network issue",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"sync", "reorg", "attack"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1498",
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "sync.sync-deep-reorg"},
			},
			GroupBy: []string{"source.host"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "sync-peer-isolation",
			Name:        "Node Isolated from Peers",
			Description: "Node's view of chain differs from majority of peers",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"sync", "peers", "isolation"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "sync.sync-peer-mismatch"},
			},
			GroupBy: []string{"source.host"},
			Window:  15 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    3,
				Operator: "gte",
			},
		},
	}
}

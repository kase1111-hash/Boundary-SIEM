package sync

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewMonitor(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	if monitor == nil {
		t.Fatal("expected monitor to be created")
	}

	if monitor.config.LagThresholdSlots != 32 {
		t.Errorf("expected lag threshold 32 slots, got %d", monitor.config.LagThresholdSlots)
	}

	if monitor.config.FinalityTimeoutEpochs != 4 {
		t.Errorf("expected finality timeout 4 epochs, got %d", monitor.config.FinalityTimeoutEpochs)
	}
}

func TestDefaultMonitorConfig(t *testing.T) {
	config := DefaultMonitorConfig()

	// Verify lag settings
	if config.LagThresholdSlots != 32 {
		t.Errorf("expected lag threshold 32, got %d", config.LagThresholdSlots)
	}
	if config.LagCriticalSlots != 128 {
		t.Errorf("expected lag critical 128, got %d", config.LagCriticalSlots)
	}

	// Verify finality settings
	if config.FinalityTimeoutEpochs != 4 {
		t.Errorf("expected finality timeout 4 epochs, got %d", config.FinalityTimeoutEpochs)
	}

	// Verify reorg settings
	if config.MaxSafeReorgDepth != 32 {
		t.Errorf("expected max safe reorg 32, got %d", config.MaxSafeReorgDepth)
	}
	if config.DeepReorgThreshold != 64 {
		t.Errorf("expected deep reorg threshold 64, got %d", config.DeepReorgThreshold)
	}

	// Verify peer settings
	if config.MinPeerConsensus != 0.8 {
		t.Errorf("expected min peer consensus 0.8, got %.1f", config.MinPeerConsensus)
	}

	// Verify network settings
	if config.SecondsPerSlot != 12 {
		t.Errorf("expected 12 seconds per slot (Ethereum), got %d", config.SecondsPerSlot)
	}
	if config.SlotsPerEpoch != 32 {
		t.Errorf("expected 32 slots per epoch, got %d", config.SlotsPerEpoch)
	}
}

func TestCalculateDerivedMetrics(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	state := &SyncState{
		HeadSlot:        100,
		NetworkHeadSlot: 150,
		FinalizedSlot:   50,
		PeerHeadSlots: map[string]uint64{
			"peer1": 150,
			"peer2": 150,
			"peer3": 148,
		},
	}

	monitor.calculateDerivedMetrics(state)

	// Check sync lag
	if state.SyncLagSlots != 50 {
		t.Errorf("expected sync lag 50 slots, got %d", state.SyncLagSlots)
	}

	expectedLagSeconds := int64(50 * 12) // 50 slots * 12 seconds
	if state.SyncLagSeconds != expectedLagSeconds {
		t.Errorf("expected sync lag %d seconds, got %d", expectedLagSeconds, state.SyncLagSeconds)
	}

	// Check finality delay
	expectedFinalityDelay := uint64((100 - 50) / 32) // (head - finalized) / slotsPerEpoch
	if state.FinalityDelay != expectedFinalityDelay {
		t.Errorf("expected finality delay %d epochs, got %d", expectedFinalityDelay, state.FinalityDelay)
	}

	// Check majority peer head
	if state.MajorityPeerHead != 150 {
		t.Errorf("expected majority peer head 150, got %d", state.MajorityPeerHead)
	}

	// Check sync progress
	expectedProgress := float64(100) / float64(150) * 100.0
	if state.SyncProgress != expectedProgress {
		t.Errorf("expected sync progress %.1f%%, got %.1f%%", expectedProgress, state.SyncProgress)
	}
}

func TestCalculateMajorityHead(t *testing.T) {
	tests := []struct {
		name     string
		peerHeads map[string]uint64
		expected  uint64
	}{
		{
			name: "clear majority",
			peerHeads: map[string]uint64{
				"peer1": 100,
				"peer2": 100,
				"peer3": 100,
				"peer4": 95,
			},
			expected: 100,
		},
		{
			name: "split vote",
			peerHeads: map[string]uint64{
				"peer1": 100,
				"peer2": 100,
				"peer3": 99,
				"peer4": 99,
			},
			expected: 100, // First majority found
		},
		{
			name: "single peer",
			peerHeads: map[string]uint64{
				"peer1": 100,
			},
			expected: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateMajorityHead(tt.peerHeads)
			if result != tt.expected {
				t.Errorf("expected majority head %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestCheckSyncLag(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertReceived = true
		if alert.Type != "sync-lag-critical" {
			t.Errorf("expected sync-lag-critical, got %s", alert.Type)
		}
		if alert.Severity != "critical" {
			t.Errorf("expected critical severity, got %s", alert.Severity)
		}
		done <- true
		return nil
	})

	state := &SyncState{
		HeadSlot:        1000,
		NetworkHeadSlot: 1150,
		SyncLagSlots:    150, // Above critical threshold of 128
		SyncLagSeconds:  1800,
		Timestamp:       time.Now(),
	}

	monitor.checkSyncLag(ctx, state)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for critical sync lag")
	}
}

func TestCheckFinality(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertReceived = true
		if alert.Type != "sync-finality-delayed" {
			t.Errorf("expected sync-finality-delayed, got %s", alert.Type)
		}
		done <- true
		return nil
	})

	state := &SyncState{
		HeadSlot:       200,
		FinalizedSlot:  50,
		FinalityDelay:  4, // Equals finality timeout threshold
		Timestamp:      time.Now(),
	}

	monitor.checkFinality(ctx, state)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for finality delay")
	}
}

func TestCheckSyncProgress(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertReceived = true
		if alert.Type != "sync-slow-progress" {
			t.Errorf("expected sync-slow-progress, got %s", alert.Type)
		}
		done <- true
		return nil
	})

	state := &SyncState{
		IsSyncing:       true,
		HeadUpdateRate:  0.3, // Below threshold of 0.5 slots/sec
		SyncProgress:    75.0,
		Timestamp:       time.Now(),
	}

	monitor.checkSyncProgress(ctx, state)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for slow sync progress")
	}
}

func TestCheckPeerConsensus(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertReceived = true
		if alert.Type != "sync-peer-mismatch" {
			t.Errorf("expected sync-peer-mismatch, got %s", alert.Type)
		}
		done <- true
		return nil
	})

	// Create state where only 50% of peers agree (below 80% threshold)
	state := &SyncState{
		HeadSlot:         100,
		MajorityPeerHead: 150,
		PeerHeadSlots: map[string]uint64{
			"peer1":  150,
			"peer2":  150,
			"peer3":  100,
			"peer4":  100,
			"peer5":  100,
			"peer6":  100,
			"peer7":  100,
			"peer8":  100,
			"peer9":  100,
			"peer10": 100,
		},
		Timestamp: time.Now(),
	}

	monitor.checkPeerConsensus(ctx, state)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for peer mismatch")
	}
}

func TestCheckStuckSync(t *testing.T) {
	config := DefaultMonitorConfig()
	config.SyncStuckThreshold = 1 * time.Second // Short for testing
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertReceived = true
		if alert.Type != "sync-stuck" {
			t.Errorf("expected sync-stuck, got %s", alert.Type)
		}
		done <- true
		return nil
	})

	state := &SyncState{
		IsSyncing:      true,
		HeadSlot:       1000,
		LastHeadUpdate: time.Now().Add(-2 * time.Second), // 2 seconds ago, past threshold
		Timestamp:      time.Now(),
	}

	monitor.checkStuckSync(ctx, state)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for stuck sync")
	}
}

func TestReportReorg(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertReceived = true
		if alert.Type != "sync-deep-reorg" {
			t.Errorf("expected sync-deep-reorg, got %s", alert.Type)
		}
		if alert.Severity != "critical" {
			t.Errorf("expected critical severity, got %s", alert.Severity)
		}
		done <- true
		return nil
	})

	// Report deep reorg (70 blocks, above threshold of 64)
	monitor.ReportReorg(ctx, 1000, 930, 5*time.Second)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for deep reorg")
	}

	// Verify reorg was recorded
	history := monitor.GetReorgHistory(10)
	if len(history) != 1 {
		t.Errorf("expected 1 reorg in history, got %d", len(history))
	}

	if history[0].Depth != 70 {
		t.Errorf("expected reorg depth 70, got %d", history[0].Depth)
	}
}

func TestFrequentReorgs(t *testing.T) {
	config := DefaultMonitorConfig()
	config.FrequentReorgCount = 3
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "sync-frequent-reorgs" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Initialize state
	monitor.currentState = &SyncState{}

	// Report 3 reorgs (reaching threshold)
	for i := 0; i < 3; i++ {
		monitor.ReportReorg(ctx, uint64(1000+i), uint64(999+i), 1*time.Second)
		time.Sleep(10 * time.Millisecond)
	}

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Error("timeout waiting for frequent reorg alert")
	}

	if !alertReceived {
		t.Error("expected alert for frequent reorgs")
	}
}

func TestUpdateSyncState(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	ctx := context.Background()

	state := &SyncState{
		IsSyncing:       false,
		HeadSlot:        1000,
		NetworkHeadSlot: 1000,
		FinalizedSlot:   968,
		PeerHeadSlots: map[string]uint64{
			"peer1": 1000,
			"peer2": 1000,
		},
	}

	monitor.UpdateSyncState(ctx, state)

	// Verify state was stored
	current := monitor.GetCurrentState()
	if current == nil {
		t.Fatal("expected current state to be set")
	}

	if current.HeadSlot != 1000 {
		t.Errorf("expected head slot 1000, got %d", current.HeadSlot)
	}

	// Verify derived metrics were calculated
	if current.SyncLagSlots != 0 {
		t.Errorf("expected sync lag 0, got %d", current.SyncLagSlots)
	}

	if current.MajorityPeerHead != 1000 {
		t.Errorf("expected majority peer head 1000, got %d", current.MajorityPeerHead)
	}
}

func TestGetCurrentState(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// No state yet
	state := monitor.GetCurrentState()
	if state != nil {
		t.Error("expected nil state when none set")
	}

	// Set state
	testState := &SyncState{
		HeadSlot:    100,
		Timestamp:   time.Now(),
	}
	monitor.mu.Lock()
	monitor.currentState = testState
	monitor.mu.Unlock()

	// Get state
	state = monitor.GetCurrentState()
	if state == nil {
		t.Fatal("expected state to be returned")
	}

	if state.HeadSlot != 100 {
		t.Errorf("expected head slot 100, got %d", state.HeadSlot)
	}
}

func TestGetStateHistory(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Add some historical states
	for i := 0; i < 10; i++ {
		monitor.stateHistory = append(monitor.stateHistory, SyncState{
			HeadSlot:  uint64(100 + i),
			Timestamp: time.Now().Add(-time.Duration(i) * time.Minute),
		})
	}

	// Get last 5
	history := monitor.GetStateHistory(5)
	if len(history) != 5 {
		t.Errorf("expected 5 states, got %d", len(history))
	}

	// Get all
	history = monitor.GetStateHistory(0)
	if len(history) != 10 {
		t.Errorf("expected 10 states, got %d", len(history))
	}
}

func TestGetReorgHistory(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Add some reorgs
	for i := 0; i < 5; i++ {
		monitor.reorgHistory = append(monitor.reorgHistory, ReorgEvent{
			Timestamp: time.Now().Add(-time.Duration(i) * time.Minute),
			OldHead:   uint64(1000 + i),
			NewHead:   uint64(999 + i),
			Depth:     uint64(i + 1),
		})
	}

	// Get last 3
	history := monitor.GetReorgHistory(3)
	if len(history) != 3 {
		t.Errorf("expected 3 reorg events, got %d", len(history))
	}

	// Get all
	history = monitor.GetReorgHistory(0)
	if len(history) != 5 {
		t.Errorf("expected 5 reorg events, got %d", len(history))
	}
}

func TestGetStats(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Set some state
	testState := &SyncState{
		IsSyncing:       true,
		HeadSlot:        1000,
		NetworkHeadSlot: 1050,
		SyncLagSlots:    50,
		FinalityDelay:   2,
		PeerCount:       15,
		SyncProgress:    95.2,
	}
	monitor.mu.Lock()
	monitor.currentState = testState
	monitor.stateHistory = append(monitor.stateHistory, *testState)
	monitor.mu.Unlock()

	stats := monitor.GetStats()

	if stats["is_syncing"] != true {
		t.Errorf("expected is_syncing true, got %v", stats["is_syncing"])
	}

	if stats["head_slot"] != uint64(1000) {
		t.Errorf("expected head_slot 1000, got %v", stats["head_slot"])
	}

	if stats["sync_lag_slots"] != uint64(50) {
		t.Errorf("expected sync_lag_slots 50, got %v", stats["sync_lag_slots"])
	}

	if stats["sync_progress"] != 95.2 {
		t.Errorf("expected sync_progress 95.2, got %v", stats["sync_progress"])
	}
}

func TestNormalizeToEvent(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	alert := &Alert{
		ID:       uuid.New(),
		Type:     "sync-lag-critical",
		Severity: "critical",
		Title:    "Node Behind Network",
		Description: "Node is 150 slots behind",
		Timestamp: time.Now(),
		State: &SyncState{
			SyncLagSlots:    150,
			HeadSlot:        1000,
			NetworkHeadSlot: 1150,
			FinalityDelay:   3,
			IsSyncing:       true,
		},
		Metadata: map[string]interface{}{
			"lag_slots": 150,
		},
	}

	event := monitor.NormalizeToEvent(alert, "test-tenant")

	if event.EventID != alert.ID {
		t.Error("expected event ID to match alert ID")
	}

	if event.TenantID != "test-tenant" {
		t.Errorf("expected tenant ID 'test-tenant', got %s", event.TenantID)
	}

	if event.Severity != 9 {
		t.Errorf("expected severity 9 for critical, got %d", event.Severity)
	}

	if event.Source.Product != "sync-monitor" {
		t.Errorf("expected product 'sync-monitor', got %s", event.Source.Product)
	}

	// Check metadata
	if event.Metadata["sync_lag_slots"] != uint64(150) {
		t.Errorf("expected sync_lag_slots in metadata, got %v", event.Metadata["sync_lag_slots"])
	}

	if event.Metadata["lag_slots"] != 150 {
		t.Errorf("expected lag_slots in metadata, got %v", event.Metadata["lag_slots"])
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{30 * time.Second, "30s"},
		{90 * time.Second, "1.5m"},
		{5 * time.Minute, "5.0m"},
		{90 * time.Minute, "1.5h"},
		{3 * time.Hour, "3.0h"},
		{30 * time.Hour, "1.2d"},
	}

	for _, tt := range tests {
		result := formatDuration(tt.duration)
		if result != tt.expected {
			t.Errorf("formatDuration(%v) = %s, want %s", tt.duration, result, tt.expected)
		}
	}
}

func TestCreateCorrelationRules(t *testing.T) {
	rules := CreateCorrelationRules()

	if len(rules) != 4 {
		t.Errorf("expected 4 correlation rules, got %d", len(rules))
	}

	// Check first rule (sync behind network)
	if rules[0].ID != "sync-behind-network" {
		t.Errorf("expected first rule ID 'sync-behind-network', got %s", rules[0].ID)
	}

	if !rules[0].Enabled {
		t.Error("expected sync-behind-network rule to be enabled")
	}

	// Check second rule (finality failure)
	if rules[1].ID != "sync-finality-failure" {
		t.Errorf("expected second rule ID 'sync-finality-failure', got %s", rules[1].ID)
	}

	// Check third rule (deep reorg)
	if rules[2].ID != "sync-deep-reorg-detected" {
		t.Errorf("expected third rule ID 'sync-deep-reorg-detected', got %s", rules[2].ID)
	}

	// Check fourth rule (peer isolation)
	if rules[3].ID != "sync-peer-isolation" {
		t.Errorf("expected fourth rule ID 'sync-peer-isolation', got %s", rules[3].ID)
	}

	// Verify MITRE mappings for rules that should have them
	// Rule 0 (sync-behind-network) and Rule 2 (sync-deep-reorg) have MITRE mappings
	if rules[0].MITRE == nil {
		t.Error("expected MITRE mapping for sync-behind-network rule")
	}
	if rules[2].MITRE == nil {
		t.Error("expected MITRE mapping for sync-deep-reorg rule")
	}
}

func TestAlertDeduplication(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertCount := 0

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertCount++
		return nil
	})

	alert := &Alert{
		ID:        uuid.New(),
		Type:      "test-alert",
		Severity:  "high",
		Title:     "Test Alert",
		Timestamp: time.Now(),
	}

	// First alert should go through
	monitor.emitAlert(ctx, alert)
	time.Sleep(10 * time.Millisecond)

	if alertCount != 1 {
		t.Errorf("expected 1 alert, got %d", alertCount)
	}

	// Second alert within 5 minutes should be deduplicated
	monitor.emitAlert(ctx, alert)
	time.Sleep(10 * time.Millisecond)

	if alertCount != 1 {
		t.Errorf("expected alert to be deduplicated, got %d alerts", alertCount)
	}
}

func TestMonitorStartStop(t *testing.T) {
	config := DefaultMonitorConfig()
	config.CheckInterval = 100 * time.Millisecond
	monitor := NewMonitor(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor
	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start monitor: %v", err)
	}

	// Wait a bit
	time.Sleep(250 * time.Millisecond)

	// Stop monitor
	monitor.Stop()
}

func TestCleanup(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Add some old alerts
	monitor.recentAlerts["old-alert"] = time.Now().Add(-1 * time.Hour)
	monitor.recentAlerts["recent-alert"] = time.Now()

	// Run cleanup
	monitor.cleanup()

	// Old alert should be removed
	if _, exists := monitor.recentAlerts["old-alert"]; exists {
		t.Error("expected old alert to be cleaned up")
	}

	// Recent alert should remain
	if _, exists := monitor.recentAlerts["recent-alert"]; !exists {
		t.Error("expected recent alert to remain")
	}
}

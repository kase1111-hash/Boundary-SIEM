package integrity

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

	if monitor.config.DeepReorgThreshold != 64 {
		t.Errorf("expected deep reorg threshold 64, got %d", monitor.config.DeepReorgThreshold)
	}

	if monitor.config.FrequentReorgCount != 5 {
		t.Errorf("expected frequent reorg count 5, got %d", monitor.config.FrequentReorgCount)
	}
}

func TestDefaultMonitorConfig(t *testing.T) {
	config := DefaultMonitorConfig()

	if config.StateRootFailureThreshold != 1.0 {
		t.Errorf("expected state root failure threshold 1.0, got %f", config.StateRootFailureThreshold)
	}

	if config.DBCorruptionThreshold != 3 {
		t.Errorf("expected DB corruption threshold 3, got %d", config.DBCorruptionThreshold)
	}

	if config.DeepReorgThreshold != 64 {
		t.Errorf("expected deep reorg threshold 64, got %d", config.DeepReorgThreshold)
	}

	if config.FrequentReorgCount != 5 {
		t.Errorf("expected frequent reorg count 5, got %d", config.FrequentReorgCount)
	}
}

func TestRecordStateRootCheck(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.RecordStateRootCheck(1000, "0xabc", "0xabc", true, "")

	checks := monitor.GetStateChecks()
	if len(checks) != 1 {
		t.Fatalf("expected 1 state check, got %d", len(checks))
	}

	check := checks[0]
	if check.Slot != 1000 {
		t.Errorf("expected slot 1000, got %d", check.Slot)
	}

	if check.StateRoot != "0xabc" {
		t.Errorf("expected state root '0xabc', got %s", check.StateRoot)
	}

	if !check.Valid {
		t.Error("expected check to be valid")
	}
}

func TestRecordStateRootCheck_Failure(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.RecordStateRootCheck(1000, "0xabc", "0xdef", false, "state root mismatch")

	checks := monitor.GetStateChecks()
	if len(checks) != 1 {
		t.Fatalf("expected 1 state check, got %d", len(checks))
	}

	check := checks[0]
	if check.Valid {
		t.Error("expected check to be invalid")
	}

	if check.ErrorMessage != "state root mismatch" {
		t.Errorf("expected error message 'state root mismatch', got %s", check.ErrorMessage)
	}
}

func TestRecordReorg(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.RecordReorg(10, "0xold", "0xnew", 1000, 10)

	reorgs := monitor.GetReorgHistory()
	if len(reorgs) != 1 {
		t.Fatalf("expected 1 reorg, got %d", len(reorgs))
	}

	reorg := reorgs[0]
	if reorg.Depth != 10 {
		t.Errorf("expected depth 10, got %d", reorg.Depth)
	}

	if reorg.OldHead != "0xold" {
		t.Errorf("expected old head '0xold', got %s", reorg.OldHead)
	}

	if reorg.BlocksLost != 10 {
		t.Errorf("expected 10 blocks lost, got %d", reorg.BlocksLost)
	}
}

func TestRecordDBError(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.RecordDBError()
	monitor.RecordDBError()
	monitor.RecordDBError()

	stats := monitor.GetStats()
	if stats["db_error_count"] != 3 {
		t.Errorf("expected 3 DB errors, got %v", stats["db_error_count"])
	}
}

func TestResetDBErrorCount(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.RecordDBError()
	monitor.RecordDBError()
	monitor.ResetDBErrorCount()

	stats := monitor.GetStats()
	if stats["db_error_count"] != 0 {
		t.Errorf("expected 0 DB errors after reset, got %v", stats["db_error_count"])
	}
}

func TestCollectMetrics_StateRootFailures(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record 10 checks: 8 valid, 2 invalid = 20% failure rate
	for i := 0; i < 8; i++ {
		monitor.RecordStateRootCheck(uint64(1000+i), "0xabc", "0xabc", true, "")
	}
	monitor.RecordStateRootCheck(1008, "0xbad1", "0xabc", false, "error1")
	monitor.RecordStateRootCheck(1009, "0xbad2", "0xabc", false, "error2")

	metrics := monitor.CollectMetrics()

	if metrics == nil {
		t.Fatal("expected metrics to be collected")
	}

	if metrics.StateRootChecks != 10 {
		t.Errorf("expected 10 checks, got %d", metrics.StateRootChecks)
	}

	if metrics.StateRootFailures != 2 {
		t.Errorf("expected 2 failures, got %d", metrics.StateRootFailures)
	}

	expectedRate := 20.0
	if metrics.StateRootFailureRate != expectedRate {
		t.Errorf("expected failure rate %.1f%%, got %.1f%%", expectedRate, metrics.StateRootFailureRate)
	}
}

func TestCollectMetrics_Reorgs(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record multiple reorgs
	monitor.RecordReorg(10, "0xa", "0xb", 1000, 10)
	monitor.RecordReorg(20, "0xb", "0xc", 1020, 20)
	monitor.RecordReorg(70, "0xc", "0xd", 1090, 70) // Deep reorg

	metrics := monitor.CollectMetrics()

	if metrics.ReorgCount1h != 3 {
		t.Errorf("expected 3 reorgs in 1h, got %d", metrics.ReorgCount1h)
	}

	if metrics.MaxReorgDepth != 70 {
		t.Errorf("expected max depth 70, got %d", metrics.MaxReorgDepth)
	}

	if !metrics.DeepReorgDetected {
		t.Error("expected deep reorg to be detected")
	}
}

func TestCollectMetrics_DBCorruption(t *testing.T) {
	config := DefaultMonitorConfig()
	config.DBCorruptionThreshold = 3
	monitor := NewMonitor(config)

	// Record 3 DB errors to trigger corruption detection
	monitor.RecordDBError()
	monitor.RecordDBError()
	monitor.RecordDBError()

	metrics := monitor.CollectMetrics()

	if metrics.DBConsistencyErrors != 3 {
		t.Errorf("expected 3 DB errors, got %d", metrics.DBConsistencyErrors)
	}

	if !metrics.DBCorruptionDetected {
		t.Error("expected DB corruption to be detected")
	}
}

func TestCheckStateRootAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.StateRootFailureThreshold = 10.0 // 10% threshold
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "integrity-state-root-failures" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record 10 checks with 2 failures = 20% failure rate
	for i := 0; i < 8; i++ {
		monitor.RecordStateRootCheck(uint64(1000+i), "0xabc", "0xabc", true, "")
	}
	monitor.RecordStateRootCheck(1008, "0xbad1", "0xabc", false, "error1")
	monitor.RecordStateRootCheck(1009, "0xbad2", "0xabc", false, "error2")

	metrics := monitor.CollectMetrics()
	monitor.checkStateRootAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for state root alert")
	}

	if !alertReceived {
		t.Error("expected state root failure alert")
	}
}

func TestCheckDBCorruptionAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.DBCorruptionThreshold = 3
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "integrity-db-corruption" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record 3 DB errors
	monitor.RecordDBError()
	monitor.RecordDBError()
	monitor.RecordDBError()

	metrics := monitor.CollectMetrics()
	monitor.checkDBCorruptionAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for DB corruption alert")
	}

	if !alertReceived {
		t.Error("expected DB corruption alert")
	}
}

func TestCheckReorgAlerts_DeepReorg(t *testing.T) {
	config := DefaultMonitorConfig()
	config.DeepReorgThreshold = 64
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "integrity-deep-reorg" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record a deep reorg
	monitor.RecordReorg(70, "0xold", "0xnew", 1000, 70)

	metrics := monitor.CollectMetrics()
	monitor.checkReorgAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for deep reorg alert")
	}

	if !alertReceived {
		t.Error("expected deep reorg alert")
	}
}

func TestCheckReorgAlerts_FrequentReorgs(t *testing.T) {
	config := DefaultMonitorConfig()
	config.FrequentReorgCount = 3
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "integrity-frequent-reorgs" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record 4 reorgs (above threshold of 3)
	monitor.RecordReorg(5, "0xa", "0xb", 1000, 5)
	monitor.RecordReorg(6, "0xb", "0xc", 1006, 6)
	monitor.RecordReorg(7, "0xc", "0xd", 1013, 7)
	monitor.RecordReorg(8, "0xd", "0xe", 1021, 8)

	metrics := monitor.CollectMetrics()
	monitor.checkReorgAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for frequent reorgs alert")
	}

	if !alertReceived {
		t.Error("expected frequent reorgs alert")
	}
}

func TestGetCurrentMetrics(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// No metrics yet
	metrics := monitor.GetCurrentMetrics()
	if metrics != nil {
		t.Error("expected nil metrics when none collected")
	}

	// Record and collect
	monitor.RecordStateRootCheck(1000, "0xabc", "0xabc", true, "")
	monitor.CollectMetrics()

	metrics = monitor.GetCurrentMetrics()
	if metrics == nil {
		t.Error("expected metrics after collection")
	}
}

func TestGetMetricsHistory(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record and collect multiple times
	monitor.RecordStateRootCheck(1000, "0xabc", "0xabc", true, "")
	monitor.CollectMetrics()

	monitor.RecordStateRootCheck(1001, "0xdef", "0xdef", true, "")
	monitor.CollectMetrics()

	history := monitor.GetMetricsHistory()
	if len(history) != 2 {
		t.Errorf("expected 2 metrics in history, got %d", len(history))
	}
}

func TestGetStateChecks(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.RecordStateRootCheck(1000, "0xabc", "0xabc", true, "")
	monitor.RecordStateRootCheck(1001, "0xdef", "0xdef", false, "error")

	checks := monitor.GetStateChecks()
	if len(checks) != 2 {
		t.Errorf("expected 2 state checks, got %d", len(checks))
	}

	if checks[0].Slot != 1000 {
		t.Errorf("expected first slot 1000, got %d", checks[0].Slot)
	}

	if checks[1].Valid {
		t.Error("expected second check to be invalid")
	}
}

func TestGetReorgHistory(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.RecordReorg(10, "0xa", "0xb", 1000, 10)
	monitor.RecordReorg(20, "0xb", "0xc", 1020, 20)

	reorgs := monitor.GetReorgHistory()
	if len(reorgs) != 2 {
		t.Errorf("expected 2 reorgs, got %d", len(reorgs))
	}

	if reorgs[0].Depth != 10 {
		t.Errorf("expected first depth 10, got %d", reorgs[0].Depth)
	}

	if reorgs[1].Depth != 20 {
		t.Errorf("expected second depth 20, got %d", reorgs[1].Depth)
	}
}

func TestGetStats(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	stats := monitor.GetStats()
	if stats == nil {
		t.Fatal("expected stats to be returned")
	}

	if stats["total_state_checks"] != 0 {
		t.Errorf("expected 0 state checks, got %v", stats["total_state_checks"])
	}

	// Record some data and collect
	monitor.RecordStateRootCheck(1000, "0xabc", "0xabc", true, "")
	monitor.RecordReorg(10, "0xa", "0xb", 1000, 10)
	monitor.CollectMetrics()

	stats = monitor.GetStats()
	if stats["total_state_checks"] != 1 {
		t.Errorf("expected 1 state check, got %v", stats["total_state_checks"])
	}

	if stats["total_reorgs"] != 1 {
		t.Errorf("expected 1 reorg, got %v", stats["total_reorgs"])
	}
}

func TestNormalizeToEvent(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	alert := &Alert{
		ID:       uuid.New(),
		Type:     "integrity-state-root-failures",
		Severity: "high",
		Title:    "State Root Validation Failures",
		Description: "State root validation failing",
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"failure_rate": 20.0,
		},
	}

	event := monitor.NormalizeToEvent(alert, "tenant-123")

	if event == nil {
		t.Fatal("expected event to be created")
	}

	if event.TenantID != "tenant-123" {
		t.Errorf("expected tenant ID 'tenant-123', got %s", event.TenantID)
	}

	if event.Action != "integrity.integrity-state-root-failures" {
		t.Errorf("expected action 'integrity.integrity-state-root-failures', got %s", event.Action)
	}

	if event.Severity != 7 {
		t.Errorf("expected severity 7, got %d", event.Severity)
	}

	if event.Metadata["alert_type"] != "integrity-state-root-failures" {
		t.Errorf("expected alert_type 'integrity-state-root-failures', got %v", event.Metadata["alert_type"])
	}
}

func TestCreateCorrelationRules(t *testing.T) {
	rules := CreateCorrelationRules()

	if len(rules) != 4 {
		t.Errorf("expected 4 correlation rules, got %d", len(rules))
	}

	// Check first rule
	if rules[0].ID != "integrity-state-corruption" {
		t.Errorf("expected first rule ID 'integrity-state-corruption', got %s", rules[0].ID)
	}

	// Check second rule
	if rules[1].ID != "integrity-db-corruption-critical" {
		t.Errorf("expected second rule ID 'integrity-db-corruption-critical', got %s", rules[1].ID)
	}

	// Verify MITRE mappings for rules that should have them
	if rules[0].MITRE == nil {
		t.Error("expected MITRE mapping for state corruption rule")
	}

	if rules[1].MITRE == nil {
		t.Error("expected MITRE mapping for DB corruption rule")
	}

	if rules[2].MITRE == nil {
		t.Error("expected MITRE mapping for deep reorg rule")
	}
}

func TestAlertDeduplication(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertCount := 0
	done := make(chan bool, 2)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertCount++
		done <- true
		return nil
	})

	alert := &Alert{
		ID:       uuid.New(),
		Type:     "test-alert",
		Severity: "high",
		Title:    "Test Alert",
		Timestamp: time.Now(),
	}

	// Emit same alert twice quickly
	monitor.emitAlert(ctx, alert)
	monitor.emitAlert(ctx, alert)

	// Wait for first alert
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
	}

	// Should only get 1 alert due to deduplication
	if alertCount != 1 {
		t.Errorf("expected 1 alert due to deduplication, got %d", alertCount)
	}
}

func TestMonitorStartStop(t *testing.T) {
	config := DefaultMonitorConfig()
	config.CheckInterval = 100 * time.Millisecond
	monitor := NewMonitor(config)

	ctx := context.Background()

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start monitor: %v", err)
	}

	// Record data during monitoring
	monitor.RecordStateRootCheck(1000, "0xabc", "0xabc", true, "")

	time.Sleep(250 * time.Millisecond)

	monitor.Stop()

	// Verify metrics were collected
	metrics := monitor.GetCurrentMetrics()
	if metrics == nil {
		t.Error("expected metrics to be collected during monitoring")
	}
}

func TestStateCheckLimit(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record more checks than the limit (1000)
	for i := 0; i < 1100; i++ {
		monitor.RecordStateRootCheck(uint64(1000+i), "0xabc", "0xabc", true, "")
	}

	checks := monitor.GetStateChecks()
	if len(checks) != 1000 {
		t.Errorf("expected state checks limit of 1000, got %d", len(checks))
	}

	// Verify we kept the most recent checks
	if checks[0].Slot != 1100 {
		t.Errorf("expected oldest check slot 1100, got %d", checks[0].Slot)
	}

	if checks[999].Slot != 2099 {
		t.Errorf("expected newest check slot 2099, got %d", checks[999].Slot)
	}
}

func TestReorgHistoryLimit(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record more reorgs than the limit (100)
	for i := 0; i < 120; i++ {
		monitor.RecordReorg(uint64(i+1), "0xold", "0xnew", uint64(1000+i), i+1)
	}

	reorgs := monitor.GetReorgHistory()
	if len(reorgs) != 100 {
		t.Errorf("expected reorg history limit of 100, got %d", len(reorgs))
	}

	// Verify we kept the most recent reorgs
	if reorgs[0].Depth != 21 {
		t.Errorf("expected oldest reorg depth 21, got %d", reorgs[0].Depth)
	}

	if reorgs[99].Depth != 120 {
		t.Errorf("expected newest reorg depth 120, got %d", reorgs[99].Depth)
	}
}

package consensus

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

	if monitor.config.MinParticipationRate != 95.0 {
		t.Errorf("expected min participation rate 95.0, got %f", monitor.config.MinParticipationRate)
	}

	if monitor.config.MinAttestationRate != 98.0 {
		t.Errorf("expected min attestation rate 98.0, got %f", monitor.config.MinAttestationRate)
	}
}

func TestDefaultMonitorConfig(t *testing.T) {
	config := DefaultMonitorConfig()

	if config.MinParticipationRate != 95.0 {
		t.Errorf("expected min participation 95.0, got %f", config.MinParticipationRate)
	}

	if config.MinAttestationRate != 98.0 {
		t.Errorf("expected min attestation rate 98.0, got %f", config.MinAttestationRate)
	}

	if config.MinProposalRate != 90.0 {
		t.Errorf("expected min proposal rate 90.0, got %f", config.MinProposalRate)
	}

	if config.ConsecutiveMissesThreshold != 3 {
		t.Errorf("expected consecutive misses threshold 3, got %d", config.ConsecutiveMissesThreshold)
	}
}

func TestRecordDuty(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.RecordDuty(1, 1000, "attestation", true)
	monitor.RecordDuty(1, 1001, "attestation", false)
	monitor.RecordDuty(1, 1002, "proposal", true)

	duties := monitor.GetDuties()
	if len(duties) != 3 {
		t.Errorf("expected 3 duties, got %d", len(duties))
	}

	if duties[0].DutyType != "attestation" {
		t.Errorf("expected duty type 'attestation', got %s", duties[0].DutyType)
	}

	if duties[1].Executed {
		t.Error("expected second duty to be not executed")
	}
}

func TestRecordSlashing(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.RecordSlashing(1, 1000, "proposer", 1000000000) // 1 ETH penalty

	events := monitor.GetSlashingEvents()
	if len(events) != 1 {
		t.Fatalf("expected 1 slashing event, got %d", len(events))
	}

	event := events[0]
	if event.ValidatorIndex != 1 {
		t.Errorf("expected validator index 1, got %d", event.ValidatorIndex)
	}

	if event.SlashingType != "proposer" {
		t.Errorf("expected slashing type 'proposer', got %s", event.SlashingType)
	}

	if event.Penalty != 1000000000 {
		t.Errorf("expected penalty 1000000000, got %d", event.Penalty)
	}
}

func TestCollectMetrics_ParticipationRate(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record 10 duties: 8 executed, 2 missed = 80% participation
	for i := 0; i < 8; i++ {
		monitor.RecordDuty(1, uint64(1000+i), "attestation", true)
	}
	monitor.RecordDuty(1, 1008, "attestation", false)
	monitor.RecordDuty(1, 1009, "attestation", false)

	metrics := monitor.CollectMetrics()

	if metrics == nil {
		t.Fatal("expected metrics to be collected")
	}

	if metrics.TotalDuties != 10 {
		t.Errorf("expected 10 total duties, got %d", metrics.TotalDuties)
	}

	if metrics.ExecutedDuties != 8 {
		t.Errorf("expected 8 executed duties, got %d", metrics.ExecutedDuties)
	}

	if metrics.MissedDuties != 2 {
		t.Errorf("expected 2 missed duties, got %d", metrics.MissedDuties)
	}

	expectedRate := 80.0
	if metrics.ParticipationRate != expectedRate {
		t.Errorf("expected participation rate %.1f%%, got %.1f%%", expectedRate, metrics.ParticipationRate)
	}
}

func TestCollectMetrics_AttestationRate(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record 20 attestations: 19 executed, 1 missed = 95% attestation rate
	for i := 0; i < 19; i++ {
		monitor.RecordDuty(1, uint64(1000+i), "attestation", true)
	}
	monitor.RecordDuty(1, 1019, "attestation", false)

	metrics := monitor.CollectMetrics()

	if metrics.AttestationDuties != 20 {
		t.Errorf("expected 20 attestation duties, got %d", metrics.AttestationDuties)
	}

	if metrics.MissedAttestations != 1 {
		t.Errorf("expected 1 missed attestation, got %d", metrics.MissedAttestations)
	}

	expectedRate := 95.0
	if metrics.AttestationRate != expectedRate {
		t.Errorf("expected attestation rate %.1f%%, got %.1f%%", expectedRate, metrics.AttestationRate)
	}
}

func TestCollectMetrics_ProposalTracking(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record 3 proposals: 2 executed, 1 missed
	monitor.RecordDuty(1, 1000, "proposal", true)
	monitor.RecordDuty(1, 1100, "proposal", true)
	monitor.RecordDuty(1, 1200, "proposal", false)

	metrics := monitor.CollectMetrics()

	if metrics.ProposalDuties != 3 {
		t.Errorf("expected 3 proposal duties, got %d", metrics.ProposalDuties)
	}

	if metrics.MissedProposals != 1 {
		t.Errorf("expected 1 missed proposal, got %d", metrics.MissedProposals)
	}

	expectedRate := float64(2) / float64(3) * 100.0
	if metrics.ProposalRate != expectedRate {
		t.Errorf("expected proposal rate %.1f%%, got %.1f%%", expectedRate, metrics.ProposalRate)
	}
}

func TestCollectMetrics_SlashingTracking(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record 2 slashing events
	monitor.RecordSlashing(1, 1000, "proposer", 500000000)  // 0.5 ETH
	monitor.RecordSlashing(1, 1100, "attester", 1000000000) // 1.0 ETH

	metrics := monitor.CollectMetrics()
	if metrics == nil {
		// Need at least one duty for metrics
		monitor.RecordDuty(1, 1000, "attestation", true)
		metrics = monitor.CollectMetrics()
	}

	if metrics.SlashingEvents != 2 {
		t.Errorf("expected 2 slashing events, got %d", metrics.SlashingEvents)
	}

	expectedLoss := uint64(1500000000) // 1.5 ETH total
	if metrics.TotalSlashingLoss != expectedLoss {
		t.Errorf("expected total loss %d, got %d", expectedLoss, metrics.TotalSlashingLoss)
	}
}

func TestCalculatePerformanceScore(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	metrics := &ValidatorMetrics{
		ParticipationRate: 100.0,
		AttestationRate:   100.0,
		ProposalRate:      100.0,
		ProposalDuties:    1,
		SlashingEvents:    0,
	}

	score := monitor.calculatePerformanceScore(metrics)
	expectedScore := 100.0 // Perfect score
	if score != expectedScore {
		t.Errorf("expected performance score %.1f, got %.1f", expectedScore, score)
	}
}

func TestCalculatePerformanceScore_WithPenalty(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	metrics := &ValidatorMetrics{
		ParticipationRate: 100.0,
		AttestationRate:   100.0,
		ProposalRate:      100.0,
		ProposalDuties:    1,
		SlashingEvents:    1, // 10 point penalty
	}

	score := monitor.calculatePerformanceScore(metrics)
	expectedScore := 90.0 // 100 - 10
	if score != expectedScore {
		t.Errorf("expected performance score %.1f, got %.1f", expectedScore, score)
	}
}

func TestCheckParticipationAlerts_LowRate(t *testing.T) {
	config := DefaultMonitorConfig()
	config.MinParticipationRate = 95.0
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "consensus-low-participation" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record 90% participation (below threshold)
	for i := 0; i < 9; i++ {
		monitor.RecordDuty(1, uint64(1000+i), "attestation", true)
	}
	monitor.RecordDuty(1, 1009, "attestation", false)

	metrics := monitor.CollectMetrics()
	monitor.checkParticipationAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for participation alert")
	}

	if !alertReceived {
		t.Error("expected low participation alert")
	}
}

func TestCheckAttestationAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.MinAttestationRate = 98.0
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "consensus-missed-attestations" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record 95% attestation rate (below 98% threshold)
	for i := 0; i < 19; i++ {
		monitor.RecordDuty(1, uint64(1000+i), "attestation", true)
	}
	monitor.RecordDuty(1, 1019, "attestation", false)

	metrics := monitor.CollectMetrics()
	monitor.checkAttestationAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for attestation alert")
	}

	if !alertReceived {
		t.Error("expected missed attestations alert")
	}
}

func TestCheckProposalAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "consensus-missed-proposals" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record a missed proposal
	monitor.RecordDuty(1, 1000, "proposal", false)

	metrics := monitor.CollectMetrics()
	monitor.checkProposalAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for missed proposal alert")
	}

	if !alertReceived {
		t.Error("expected missed proposal alert")
	}
}

func TestCheckSlashingAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.SlashingAlertEnabled = true
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "consensus-slashing" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record slashing event and a duty for metrics
	monitor.RecordSlashing(1, 1000, "proposer", 1000000000)
	monitor.RecordDuty(1, 1000, "attestation", true)

	metrics := monitor.CollectMetrics()
	monitor.checkSlashingAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for slashing alert")
	}

	if !alertReceived {
		t.Error("expected slashing alert")
	}
}

func TestCheckConsecutiveMissesAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.ConsecutiveMissesThreshold = 3
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "consensus-consecutive-misses" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record 3 consecutive misses
	monitor.RecordDuty(1, 1000, "attestation", false)
	monitor.RecordDuty(1, 1001, "attestation", false)
	monitor.RecordDuty(1, 1002, "attestation", false)

	monitor.checkConsecutiveMissesAlerts(ctx)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for consecutive misses alert")
	}

	if !alertReceived {
		t.Error("expected consecutive misses alert")
	}
}

func TestConsecutiveMissesReset(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record 2 misses, then a success
	monitor.RecordDuty(1, 1000, "attestation", false)
	monitor.RecordDuty(1, 1001, "attestation", false)
	monitor.RecordDuty(1, 1002, "attestation", true)

	if monitor.consecutiveMisses != 0 {
		t.Errorf("expected consecutive misses to reset to 0, got %d", monitor.consecutiveMisses)
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
	monitor.RecordDuty(1, 1000, "attestation", true)
	monitor.CollectMetrics()

	metrics = monitor.GetCurrentMetrics()
	if metrics == nil {
		t.Error("expected metrics after collection")
	}
}

func TestGetMetricsHistory(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Collect multiple times
	monitor.RecordDuty(1, 1000, "attestation", true)
	monitor.CollectMetrics()

	monitor.RecordDuty(1, 1001, "attestation", true)
	monitor.CollectMetrics()

	history := monitor.GetMetricsHistory()
	if len(history) != 2 {
		t.Errorf("expected 2 metrics in history, got %d", len(history))
	}
}

func TestGetStats(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	stats := monitor.GetStats()
	if stats == nil {
		t.Fatal("expected stats to be returned")
	}

	if stats["total_duties"] != 0 {
		t.Errorf("expected 0 duties, got %v", stats["total_duties"])
	}

	// Record and collect
	monitor.RecordDuty(1, 1000, "attestation", true)
	monitor.RecordDuty(2, 1001, "attestation", true)
	monitor.CollectMetrics()

	stats = monitor.GetStats()
	if stats["total_duties"] != 2 {
		t.Errorf("expected 2 duties, got %v", stats["total_duties"])
	}

	if stats["validator_count"] != 2 {
		t.Errorf("expected 2 validators, got %v", stats["validator_count"])
	}
}

func TestNormalizeToEvent(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	alert := &Alert{
		ID:          uuid.New(),
		Type:        "consensus-low-participation",
		Severity:    "high",
		Title:       "Low Validator Participation",
		Description: "Participation rate low",
		Timestamp:   time.Now(),
		Metadata: map[string]interface{}{
			"participation_rate": 90.0,
		},
	}

	event := monitor.NormalizeToEvent(alert, "tenant-123")

	if event == nil {
		t.Fatal("expected event to be created")
	}

	if event.TenantID != "tenant-123" {
		t.Errorf("expected tenant ID 'tenant-123', got %s", event.TenantID)
	}

	if event.Action != "consensus.consensus-low-participation" {
		t.Errorf("expected action 'consensus.consensus-low-participation', got %s", event.Action)
	}

	if event.Severity != 7 {
		t.Errorf("expected severity 7, got %d", event.Severity)
	}

	if event.Metadata["alert_type"] != "consensus-low-participation" {
		t.Errorf("expected alert_type 'consensus-low-participation', got %v", event.Metadata["alert_type"])
	}
}

func TestCreateCorrelationRules(t *testing.T) {
	rules := CreateCorrelationRules()

	if len(rules) != 4 {
		t.Errorf("expected 4 correlation rules, got %d", len(rules))
	}

	// Check first rule
	if rules[0].ID != "consensus-participation-degradation" {
		t.Errorf("expected first rule ID 'consensus-participation-degradation', got %s", rules[0].ID)
	}

	// Check second rule
	if rules[1].ID != "consensus-slashing-critical" {
		t.Errorf("expected second rule ID 'consensus-slashing-critical', got %s", rules[1].ID)
	}

	// Verify MITRE mappings
	if rules[0].MITRE == nil {
		t.Error("expected MITRE mapping for participation degradation rule")
	}

	if rules[1].MITRE == nil {
		t.Error("expected MITRE mapping for slashing rule")
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
		ID:        uuid.New(),
		Type:      "test-alert",
		Severity:  "high",
		Title:     "Test Alert",
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
	monitor.RecordDuty(1, 1000, "attestation", true)

	time.Sleep(250 * time.Millisecond)

	monitor.Stop()

	// Verify metrics were collected
	metrics := monitor.GetCurrentMetrics()
	if metrics == nil {
		t.Error("expected metrics to be collected during monitoring")
	}
}

func TestDutyLimit(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Add more duties than the limit (10000)
	for i := 0; i < 10100; i++ {
		monitor.RecordDuty(1, uint64(1000+i), "attestation", true)
	}

	duties := monitor.GetDuties()
	if len(duties) != 10000 {
		t.Errorf("expected duty limit of 10000, got %d", len(duties))
	}
}

func TestSlashingEventLimit(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Add more slashing events than the limit (100)
	for i := 0; i < 120; i++ {
		monitor.RecordSlashing(1, uint64(1000+i), "proposer", 1000000000)
	}

	events := monitor.GetSlashingEvents()
	if len(events) != 100 {
		t.Errorf("expected slashing event limit of 100, got %d", len(events))
	}
}

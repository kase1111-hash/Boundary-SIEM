package processing

import (
	"context"
	"fmt"
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

	if monitor.config.SlowBlockThresholdMS != 5000 {
		t.Errorf("expected slow block threshold 5000ms, got %d", monitor.config.SlowBlockThresholdMS)
	}

	if monitor.config.StuckBlockTimeout != 10*time.Minute {
		t.Errorf("expected stuck block timeout 10m, got %s", monitor.config.StuckBlockTimeout)
	}
}

func TestDefaultMonitorConfig(t *testing.T) {
	config := DefaultMonitorConfig()

	if config.SlowBlockThresholdMS != 5000 {
		t.Errorf("expected slow block threshold 5000, got %d", config.SlowBlockThresholdMS)
	}

	if config.StuckBlockTimeout != 10*time.Minute {
		t.Errorf("expected stuck block timeout 10m, got %s", config.StuckBlockTimeout)
	}

	if config.LowThroughputThreshold != 0.05 {
		t.Errorf("expected low throughput threshold 0.05, got %f", config.LowThroughputThreshold)
	}

	if config.HighFailureRate != 5.0 {
		t.Errorf("expected high failure rate 5.0, got %f", config.HighFailureRate)
	}
}

func TestStartEndBlock(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	slot := uint64(1000)
	hash := "0xabc123"
	parentHash := "0xdef456"

	monitor.StartBlock(slot, hash, parentHash)

	if monitor.currentBlock == nil {
		t.Fatal("expected current block to be set")
	}

	if monitor.currentBlock.Slot != slot {
		t.Errorf("expected slot %d, got %d", slot, monitor.currentBlock.Slot)
	}

	time.Sleep(10 * time.Millisecond)

	monitor.EndBlock(true, 128, 50, 250, "")

	if monitor.currentBlock != nil {
		t.Error("expected current block to be cleared after EndBlock")
	}

	if len(monitor.recentBlocks) != 1 {
		t.Errorf("expected 1 recent block, got %d", len(monitor.recentBlocks))
	}

	block := monitor.recentBlocks[0]
	if block.Slot != slot {
		t.Errorf("expected slot %d, got %d", slot, block.Slot)
	}

	if block.ProcessingMS < 10 {
		t.Errorf("expected processing time >= 10ms, got %d", block.ProcessingMS)
	}

	if block.Attestations != 128 {
		t.Errorf("expected 128 attestations, got %d", block.Attestations)
	}

	if block.StateRootMS != 250 {
		t.Errorf("expected state root time 250ms, got %d", block.StateRootMS)
	}
}

func TestRecordBlockProcessing(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.RecordBlockProcessing(1000, "0xabc", "0xdef", 500, 200, 128, 50, true, "")

	if len(monitor.recentBlocks) != 1 {
		t.Fatalf("expected 1 recent block, got %d", len(monitor.recentBlocks))
	}

	block := monitor.recentBlocks[0]
	if block.Slot != 1000 {
		t.Errorf("expected slot 1000, got %d", block.Slot)
	}

	if block.ProcessingMS != 500 {
		t.Errorf("expected processing time 500ms, got %d", block.ProcessingMS)
	}

	if block.StateRootMS != 200 {
		t.Errorf("expected state root time 200ms, got %d", block.StateRootMS)
	}

	if block.Attestations != 128 {
		t.Errorf("expected 128 attestations, got %d", block.Attestations)
	}

	if !block.Success {
		t.Error("expected block to be successful")
	}
}

func TestCollectMetrics(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record multiple blocks
	monitor.RecordBlockProcessing(1000, "0xa", "0xb", 100, 50, 128, 10, true, "")
	monitor.RecordBlockProcessing(1001, "0xb", "0xa", 200, 75, 130, 12, true, "")
	monitor.RecordBlockProcessing(1002, "0xc", "0xb", 150, 60, 125, 15, true, "")
	monitor.RecordBlockProcessing(1003, "0xd", "0xc", 300, 100, 127, 20, false, "error")

	metrics := monitor.CollectMetrics()

	if metrics == nil {
		t.Fatal("expected metrics to be collected")
	}

	// Check average processing time (100+200+150+300)/4 = 187.5
	expectedAvg := int64((100 + 200 + 150 + 300) / 4)
	if metrics.AvgBlockProcessingMS != expectedAvg {
		t.Errorf("expected avg processing time %d, got %d", expectedAvg, metrics.AvgBlockProcessingMS)
	}

	// Check P50 (median of [100, 150, 200, 300] = 200, at index 2 of 4)
	if metrics.P50BlockProcessingMS != 200 {
		t.Errorf("expected P50 200, got %d", metrics.P50BlockProcessingMS)
	}

	// Check max
	if metrics.MaxBlockProcessingMS != 300 {
		t.Errorf("expected max 300, got %d", metrics.MaxBlockProcessingMS)
	}

	// Check attestation average (128+130+125+127)/4 = 127.5 = 127
	expectedAttestations := (128 + 130 + 125 + 127) / 4
	if metrics.AvgAttestationsPerBlock != expectedAttestations {
		t.Errorf("expected avg attestations %d, got %d", expectedAttestations, metrics.AvgAttestationsPerBlock)
	}

	// Check failure rate (1 failed out of 4 = 25%)
	if metrics.FailedBlocks1m != 1 {
		t.Errorf("expected 1 failed block, got %d", metrics.FailedBlocks1m)
	}
}

func TestCollectMetrics_NoBlocks(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	metrics := monitor.CollectMetrics()

	if metrics != nil {
		t.Error("expected nil metrics when no blocks processed")
	}
}

func TestPercentileCalculation(t *testing.T) {
	tests := []struct {
		name     string
		values   []int64
		p        int
		expected int64
	}{
		{
			name:     "P50 of [100, 200, 300, 400, 500]",
			values:   []int64{100, 200, 300, 400, 500},
			p:        50,
			expected: 300,
		},
		{
			name:     "P95 of [100, 200, 300, 400, 500]",
			values:   []int64{100, 200, 300, 400, 500},
			p:        95,
			expected: 500,
		},
		{
			name:     "P99 of [100, 200, 300, 400, 500]",
			values:   []int64{100, 200, 300, 400, 500},
			p:        99,
			expected: 500,
		},
		{
			name:     "empty slice",
			values:   []int64{},
			p:        50,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := percentile(tt.values, tt.p)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestCheckSlowBlockAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.SlowBlockThresholdMS = 1000
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "processing-slow-blocks" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record blocks with slow P95
	for i := 0; i < 20; i++ {
		processingMS := int64(1500) // Above threshold
		monitor.RecordBlockProcessing(uint64(1000+i), fmt.Sprintf("0x%d", i), "0xparent", processingMS, 100, 128, 10, true, "")
	}

	metrics := monitor.CollectMetrics()
	monitor.checkSlowBlockAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for slow block alert")
	}

	if !alertReceived {
		t.Error("expected slow block alert")
	}
}

func TestCheckStuckBlockAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.StuckBlockTimeout = 1 * time.Second // Short for testing
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "processing-stuck-block" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record a block and set last block time to past
	monitor.RecordBlockProcessing(1000, "0xabc", "0xdef", 500, 200, 128, 10, true, "")
	monitor.lastBlockTime = time.Now().Add(-2 * time.Second)

	metrics := monitor.CollectMetrics()
	monitor.checkStuckBlockAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for stuck block alert")
	}

	if !alertReceived {
		t.Error("expected stuck block alert")
	}

	if !metrics.StuckBlock {
		t.Error("expected metrics to indicate stuck block")
	}
}

func TestCheckThroughputAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.LowThroughputThreshold = 0.5 // 0.5 blocks/sec
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "processing-low-throughput" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record only 2 blocks in a minute (very low throughput)
	monitor.RecordBlockProcessing(1000, "0xa", "0xb", 500, 200, 128, 10, true, "")
	monitor.RecordBlockProcessing(1001, "0xb", "0xc", 500, 200, 128, 10, true, "")

	metrics := monitor.CollectMetrics()
	monitor.checkThroughputAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for low throughput alert")
	}

	if !alertReceived {
		t.Error("expected low throughput alert")
	}
}

func TestCheckFailureRateAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.HighFailureRate = 10.0 // 10% failure rate
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "processing-high-failure-rate" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record 10 blocks: 2 failures = 20% failure rate
	for i := 0; i < 8; i++ {
		monitor.RecordBlockProcessing(uint64(1000+i), fmt.Sprintf("0x%d", i), "0xparent", 500, 200, 128, 10, true, "")
	}
	monitor.RecordBlockProcessing(1008, "0x8", "0xparent", 500, 200, 128, 10, false, "error1")
	monitor.RecordBlockProcessing(1009, "0x9", "0xparent", 500, 200, 128, 10, false, "error2")

	metrics := monitor.CollectMetrics()
	monitor.checkFailureRateAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for high failure rate alert")
	}

	if !alertReceived {
		t.Error("expected high failure rate alert")
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
	monitor.RecordBlockProcessing(1000, "0xa", "0xb", 500, 200, 128, 10, true, "")
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
	monitor.RecordBlockProcessing(1000, "0xa", "0xb", 500, 200, 128, 10, true, "")
	monitor.CollectMetrics()

	monitor.RecordBlockProcessing(1001, "0xb", "0xc", 600, 250, 130, 12, true, "")
	monitor.CollectMetrics()

	history := monitor.GetMetricsHistory()
	if len(history) != 2 {
		t.Errorf("expected 2 metrics in history, got %d", len(history))
	}
}

func TestGetRecentBlocks(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.RecordBlockProcessing(1000, "0xa", "0xb", 500, 200, 128, 10, true, "")
	monitor.RecordBlockProcessing(1001, "0xb", "0xc", 600, 250, 130, 12, true, "")

	blocks := monitor.GetRecentBlocks()
	if len(blocks) != 2 {
		t.Errorf("expected 2 recent blocks, got %d", len(blocks))
	}

	if blocks[0].Slot != 1000 {
		t.Errorf("expected first slot 1000, got %d", blocks[0].Slot)
	}

	if blocks[1].Slot != 1001 {
		t.Errorf("expected second slot 1001, got %d", blocks[1].Slot)
	}
}

func TestGetStats(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	stats := monitor.GetStats()
	if stats == nil {
		t.Fatal("expected stats to be returned")
	}

	if stats["total_blocks_tracked"] != 0 {
		t.Errorf("expected 0 blocks tracked, got %v", stats["total_blocks_tracked"])
	}

	// Record and collect
	monitor.RecordBlockProcessing(1000, "0xa", "0xb", 500, 200, 128, 10, true, "")
	monitor.CollectMetrics()

	stats = monitor.GetStats()
	if stats["total_blocks_tracked"] != 1 {
		t.Errorf("expected 1 block tracked, got %v", stats["total_blocks_tracked"])
	}

	if stats["avg_processing_ms"] == nil {
		t.Error("expected avg_processing_ms in stats")
	}
}

func TestNormalizeToEvent(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	alert := &Alert{
		ID:          uuid.New(),
		Type:        "processing-slow-blocks",
		Severity:    "high",
		Title:       "Slow Block Processing",
		Description: "Block processing is slow",
		Timestamp:   time.Now(),
		Metadata: map[string]interface{}{
			"p95_ms": int64(5000),
		},
	}

	event := monitor.NormalizeToEvent(alert, "tenant-123")

	if event == nil {
		t.Fatal("expected event to be created")
	}

	if event.TenantID != "tenant-123" {
		t.Errorf("expected tenant ID 'tenant-123', got %s", event.TenantID)
	}

	if event.Action != "processing.processing-slow-blocks" {
		t.Errorf("expected action 'processing.processing-slow-blocks', got %s", event.Action)
	}

	if event.Severity != 7 {
		t.Errorf("expected severity 7, got %d", event.Severity)
	}

	if event.Metadata["alert_type"] != "processing-slow-blocks" {
		t.Errorf("expected alert_type 'processing-slow-blocks', got %v", event.Metadata["alert_type"])
	}
}

func TestCreateCorrelationRules(t *testing.T) {
	rules := CreateCorrelationRules()

	if len(rules) != 4 {
		t.Errorf("expected 4 correlation rules, got %d", len(rules))
	}

	// Check first rule
	if rules[0].ID != "processing-performance-degradation" {
		t.Errorf("expected first rule ID 'processing-performance-degradation', got %s", rules[0].ID)
	}

	// Check second rule
	if rules[1].ID != "processing-stuck-critical" {
		t.Errorf("expected second rule ID 'processing-stuck-critical', got %s", rules[1].ID)
	}

	// Verify MITRE mappings for rules that should have them
	if rules[0].MITRE == nil {
		t.Error("expected MITRE mapping for performance degradation rule")
	}

	if rules[1].MITRE == nil {
		t.Error("expected MITRE mapping for stuck critical rule")
	}

	if rules[3].MITRE == nil {
		t.Error("expected MITRE mapping for high failures rule")
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

	// Record a block during monitoring
	monitor.RecordBlockProcessing(1000, "0xa", "0xb", 500, 200, 128, 10, true, "")

	time.Sleep(250 * time.Millisecond)

	monitor.Stop()

	// Verify metrics were collected
	metrics := monitor.GetCurrentMetrics()
	if metrics == nil {
		t.Error("expected metrics to be collected during monitoring")
	}
}

func TestSampleSizeLimit(t *testing.T) {
	config := DefaultMonitorConfig()
	config.SampleSize = 10
	monitor := NewMonitor(config)

	// Record more blocks than sample size
	for i := 0; i < 20; i++ {
		monitor.RecordBlockProcessing(uint64(1000+i), fmt.Sprintf("0x%d", i), "0xparent", 500, 200, 128, 10, true, "")
	}

	blocks := monitor.GetRecentBlocks()
	if len(blocks) != 10 {
		t.Errorf("expected sample size limit of 10 blocks, got %d", len(blocks))
	}

	// Verify we kept the most recent blocks
	if blocks[0].Slot != 1010 {
		t.Errorf("expected oldest block in sample to be slot 1010, got %d", blocks[0].Slot)
	}

	if blocks[9].Slot != 1019 {
		t.Errorf("expected newest block in sample to be slot 1019, got %d", blocks[9].Slot)
	}
}

func TestThroughputTracking(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record 10 blocks
	for i := 0; i < 10; i++ {
		monitor.RecordBlockProcessing(uint64(1000+i), fmt.Sprintf("0x%d", i), "0xparent", 500, 200, 128, 10, true, "")
	}

	metrics := monitor.CollectMetrics()

	if metrics.BlocksProcessed1m != 10 {
		t.Errorf("expected 10 blocks in 1m window, got %d", metrics.BlocksProcessed1m)
	}

	// Throughput should be 10 blocks / 60 seconds = 0.166... bps
	expectedThroughput := 10.0 / 60.0
	if metrics.AvgThroughputBPS < expectedThroughput-0.01 || metrics.AvgThroughputBPS > expectedThroughput+0.01 {
		t.Errorf("expected throughput ~%.3f bps, got %.3f", expectedThroughput, metrics.AvgThroughputBPS)
	}
}

func TestStateRootMetrics(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record blocks with varying state root times
	monitor.RecordBlockProcessing(1000, "0xa", "0xb", 500, 100, 128, 10, true, "")
	monitor.RecordBlockProcessing(1001, "0xb", "0xc", 500, 200, 128, 10, true, "")
	monitor.RecordBlockProcessing(1002, "0xc", "0xd", 500, 300, 128, 10, true, "")
	monitor.RecordBlockProcessing(1003, "0xd", "0xe", 500, 400, 128, 10, true, "")

	metrics := monitor.CollectMetrics()

	// Average state root time = (100+200+300+400)/4 = 250
	expectedAvg := int64(250)
	if metrics.AvgStateRootMS != expectedAvg {
		t.Errorf("expected avg state root time %d, got %d", expectedAvg, metrics.AvgStateRootMS)
	}

	// P95 of [100, 200, 300, 400] = 400
	if metrics.P95StateRootMS != 400 {
		t.Errorf("expected P95 state root time 400, got %d", metrics.P95StateRootMS)
	}
}

package spam

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

	if monitor.config.TxRateThreshold != 10.0 {
		t.Errorf("expected tx rate threshold 10.0, got %f", monitor.config.TxRateThreshold)
	}

	if monitor.config.StorageGrowthThreshold != 50.0 {
		t.Errorf("expected storage growth threshold 50.0, got %f", monitor.config.StorageGrowthThreshold)
	}
}

func TestDefaultMonitorConfig(t *testing.T) {
	config := DefaultMonitorConfig()

	if config.TxRateThreshold != 10.0 {
		t.Errorf("expected tx rate threshold 10.0, got %f", config.TxRateThreshold)
	}

	if config.TxPoolFullThreshold != 80.0 {
		t.Errorf("expected tx pool threshold 80.0, got %f", config.TxPoolFullThreshold)
	}

	if config.StorageGrowthThreshold != 50.0 {
		t.Errorf("expected storage growth threshold 50.0, got %f", config.StorageGrowthThreshold)
	}

	if config.DOSTxRateThreshold != 1000.0 {
		t.Errorf("expected DOS tx rate threshold 1000.0, got %f", config.DOSTxRateThreshold)
	}
}

func TestRecordTransaction(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	address := "0xabc123"
	monitor.RecordTransaction(address, time.Now())
	monitor.RecordTransaction(address, time.Now())
	monitor.RecordTransaction(address, time.Now())

	count := monitor.addressTxCounts[address]
	if count != 3 {
		t.Errorf("expected 3 transactions, got %d", count)
	}
}

func TestRecordTransactionBatch(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.RecordTransactionBatch(100)
	monitor.RecordTransactionBatch(150)
	monitor.RecordTransactionBatch(200)

	if len(monitor.recentTxCounts) != 3 {
		t.Errorf("expected 3 batch records, got %d", len(monitor.recentTxCounts))
	}

	if monitor.recentTxCounts[2] != 200 {
		t.Errorf("expected last batch count 200, got %d", monitor.recentTxCounts[2])
	}
}

func TestUpdateTxPoolSize(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.UpdateTxPoolSize(5000)

	if monitor.currentTxPoolSize != 5000 {
		t.Errorf("expected tx pool size 5000, got %d", monitor.currentTxPoolSize)
	}
}

func TestUpdateStorageSize(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.UpdateStorageSize(100.5) // 100.5 GB

	if monitor.currentStorageGB != 100.5 {
		t.Errorf("expected storage size 100.5 GB, got %f", monitor.currentStorageGB)
	}

	if len(monitor.storageHistory) != 1 {
		t.Errorf("expected 1 storage sample, got %d", len(monitor.storageHistory))
	}
}

func TestCollectMetrics_TxPool(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.UpdateTxPoolSize(40000) // 80% of 50000

	metrics := monitor.CollectMetrics()

	if metrics == nil {
		t.Fatal("expected metrics to be collected")
	}

	if metrics.TxPoolSize != 40000 {
		t.Errorf("expected tx pool size 40000, got %d", metrics.TxPoolSize)
	}

	expectedPercent := 80.0
	if metrics.TxPoolSizePercent != expectedPercent {
		t.Errorf("expected tx pool percent %.1f%%, got %.1f%%", expectedPercent, metrics.TxPoolSizePercent)
	}
}

func TestCollectMetrics_StorageGrowth(t *testing.T) {
	config := DefaultMonitorConfig()
	config.CheckInterval = 1 * time.Hour // For easier calculation
	monitor := NewMonitor(config)

	// Simulate storage growth over time
	monitor.UpdateStorageSize(100.0) // Start at 100 GB
	monitor.UpdateStorageSize(150.0) // Grow to 150 GB

	metrics := monitor.CollectMetrics()

	if metrics.StorageGrowthRate <= 0 {
		t.Error("expected positive storage growth rate")
	}
}

func TestCollectMetrics_SpamDetection(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record spam transactions from an address
	spamAddress := "0xspammer"
	for i := 0; i < 500; i++ {
		monitor.RecordTransaction(spamAddress, time.Now())
	}

	metrics := monitor.CollectMetrics()

	if metrics.SpamTxCount1h != 500 {
		t.Errorf("expected 500 spam transactions, got %d", metrics.SpamTxCount1h)
	}

	if metrics.TopSpammerAddress != spamAddress {
		t.Errorf("expected top spammer %s, got %s", spamAddress, metrics.TopSpammerAddress)
	}

	if metrics.TopSpammerTxCount != 500 {
		t.Errorf("expected top spammer count 500, got %d", metrics.TopSpammerTxCount)
	}
}

func TestCollectMetrics_DOSDetection_Burst(t *testing.T) {
	config := DefaultMonitorConfig()
	config.DOSBurstSize = 5000
	monitor := NewMonitor(config)

	// Record a burst of transactions
	monitor.RecordTransactionBatch(10000) // Above burst threshold

	metrics := monitor.CollectMetrics()

	if !metrics.DOSPatternDetected {
		t.Error("expected DOS pattern to be detected")
	}

	if metrics.DOSAttackType != "burst" {
		t.Errorf("expected DOS attack type 'burst', got %s", metrics.DOSAttackType)
	}
}

func TestCheckTxPoolAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.TxPoolFullThreshold = 80.0
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "spam-txpool-saturation" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	monitor.UpdateTxPoolSize(42000) // 84% of 50000

	metrics := monitor.CollectMetrics()
	monitor.checkTxPoolAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for tx pool alert")
	}

	if !alertReceived {
		t.Error("expected tx pool saturation alert")
	}
}

func TestCheckStorageAlerts_HighGrowth(t *testing.T) {
	config := DefaultMonitorConfig()
	config.StorageGrowthThreshold = 40.0
	config.CheckInterval = 1 * time.Hour
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "spam-storage-bloat" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Simulate high storage growth
	monitor.UpdateStorageSize(100.0)
	monitor.UpdateStorageSize(200.0) // 100 GB/hour = 2400 GB/day

	metrics := monitor.CollectMetrics()
	monitor.checkStorageAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for storage bloat alert")
	}

	if !alertReceived {
		t.Error("expected storage bloat alert")
	}
}

func TestCheckSpamAlerts_HighVolumeAddress(t *testing.T) {
	config := DefaultMonitorConfig()
	config.TxRateThreshold = 1.0 // 1 tx/sec = 3600 tx/hour
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "spam-high-volume-address" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record spam from address
	spamAddress := "0xspammer123"
	for i := 0; i < 5000; i++ {
		monitor.RecordTransaction(spamAddress, time.Now())
	}

	metrics := monitor.CollectMetrics()
	monitor.checkSpamAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for high-volume spam alert")
	}

	if !alertReceived {
		t.Error("expected high-volume spam alert")
	}
}

func TestCheckDOSAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.DOSBurstSize = 5000
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertReceived := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "spam-dos-attack" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Record DOS burst
	monitor.RecordTransactionBatch(10000)

	metrics := monitor.CollectMetrics()
	monitor.checkDOSAlerts(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for DOS attack alert")
	}

	if !alertReceived {
		t.Error("expected DOS attack alert")
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
	monitor.UpdateTxPoolSize(1000)
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
	monitor.UpdateTxPoolSize(1000)
	monitor.CollectMetrics()

	monitor.UpdateTxPoolSize(2000)
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

	if stats["tx_pool_size"] != 0 {
		t.Errorf("expected 0 tx pool size, got %v", stats["tx_pool_size"])
	}

	// Update and collect
	monitor.UpdateTxPoolSize(5000)
	monitor.UpdateStorageSize(100.0)
	monitor.CollectMetrics()

	stats = monitor.GetStats()
	if stats["tx_pool_size"] != 5000 {
		t.Errorf("expected 5000 tx pool size, got %v", stats["tx_pool_size"])
	}

	if stats["storage_gb"] != 100.0 {
		t.Errorf("expected 100.0 GB storage, got %v", stats["storage_gb"])
	}
}

func TestNormalizeToEvent(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	alert := &Alert{
		ID:       uuid.New(),
		Type:     "spam-txpool-saturation",
		Severity: "high",
		Title:    "Transaction Pool Saturation",
		Description: "TX pool saturated",
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"txpool_percent": 85.0,
		},
	}

	event := monitor.NormalizeToEvent(alert, "tenant-123")

	if event == nil {
		t.Fatal("expected event to be created")
	}

	if event.TenantID != "tenant-123" {
		t.Errorf("expected tenant ID 'tenant-123', got %s", event.TenantID)
	}

	if event.Action != "spam.spam-txpool-saturation" {
		t.Errorf("expected action 'spam.spam-txpool-saturation', got %s", event.Action)
	}

	if event.Severity != 7 {
		t.Errorf("expected severity 7, got %d", event.Severity)
	}

	if event.Metadata["alert_type"] != "spam-txpool-saturation" {
		t.Errorf("expected alert_type 'spam-txpool-saturation', got %v", event.Metadata["alert_type"])
	}
}

func TestCreateCorrelationRules(t *testing.T) {
	rules := CreateCorrelationRules()

	if len(rules) != 4 {
		t.Errorf("expected 4 correlation rules, got %d", len(rules))
	}

	// Check first rule
	if rules[0].ID != "spam-txpool-flooding" {
		t.Errorf("expected first rule ID 'spam-txpool-flooding', got %s", rules[0].ID)
	}

	// Check second rule
	if rules[1].ID != "spam-storage-bloat-attack" {
		t.Errorf("expected second rule ID 'spam-storage-bloat-attack', got %s", rules[1].ID)
	}

	// Verify MITRE mappings
	if rules[0].MITRE == nil {
		t.Error("expected MITRE mapping for txpool flooding rule")
	}

	if rules[2].MITRE == nil {
		t.Error("expected MITRE mapping for DOS attack rule")
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
	monitor.UpdateTxPoolSize(1000)

	time.Sleep(250 * time.Millisecond)

	monitor.Stop()

	// Verify metrics were collected
	metrics := monitor.GetCurrentMetrics()
	if metrics == nil {
		t.Error("expected metrics to be collected during monitoring")
	}
}

func TestCleanupAddressCounts(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record transactions
	monitor.RecordTransaction("0xaddr1", time.Now())
	monitor.RecordTransaction("0xaddr2", time.Now())

	if len(monitor.addressTxCounts) != 2 {
		t.Errorf("expected 2 addresses, got %d", len(monitor.addressTxCounts))
	}

	// Cleanup
	monitor.cleanupAddressCounts()

	if len(monitor.addressTxCounts) != 0 {
		t.Errorf("expected 0 addresses after cleanup, got %d", len(monitor.addressTxCounts))
	}
}

func TestStorageHistoryLimit(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Add more storage samples than the limit (100)
	for i := 0; i < 120; i++ {
		monitor.UpdateStorageSize(float64(i))
	}

	if len(monitor.storageHistory) != 100 {
		t.Errorf("expected storage history limit of 100, got %d", len(monitor.storageHistory))
	}
}

func TestRecentTxCountsLimit(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Add more tx count samples than the limit (60)
	for i := 0; i < 70; i++ {
		monitor.RecordTransactionBatch(100)
	}

	if len(monitor.recentTxCounts) != 60 {
		t.Errorf("expected recent tx counts limit of 60, got %d", len(monitor.recentTxCounts))
	}
}

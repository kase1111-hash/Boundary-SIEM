package resources

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

	if monitor.config.DiskThreshold != 85.0 {
		t.Errorf("expected disk threshold 85.0, got %.1f", monitor.config.DiskThreshold)
	}

	if monitor.config.MemoryThreshold != 90.0 {
		t.Errorf("expected memory threshold 90.0, got %.1f", monitor.config.MemoryThreshold)
	}

	if monitor.config.CPUThreshold != 85.0 {
		t.Errorf("expected CPU threshold 85.0, got %.1f", monitor.config.CPUThreshold)
	}
}

func TestDefaultMonitorConfig(t *testing.T) {
	config := DefaultMonitorConfig()

	// Verify disk settings
	if config.DiskThreshold != 85.0 {
		t.Errorf("expected disk threshold 85.0, got %.1f", config.DiskThreshold)
	}
	if config.DiskCritical != 95.0 {
		t.Errorf("expected disk critical 95.0, got %.1f", config.DiskCritical)
	}
	if config.DiskAlertLeadDays != 7 {
		t.Errorf("expected disk alert lead days 7, got %d", config.DiskAlertLeadDays)
	}

	// Verify memory settings
	if config.MemoryThreshold != 90.0 {
		t.Errorf("expected memory threshold 90.0, got %.1f", config.MemoryThreshold)
	}
	if config.MemoryLeakThreshold != 1000.0 {
		t.Errorf("expected memory leak threshold 1000.0, got %.1f", config.MemoryLeakThreshold)
	}

	// Verify CPU settings
	if config.CPUThreshold != 85.0 {
		t.Errorf("expected CPU threshold 85.0, got %.1f", config.CPUThreshold)
	}
	if config.CPUPersistencePeriod != 15*time.Minute {
		t.Errorf("expected CPU persistence 15m, got %v", config.CPUPersistencePeriod)
	}

	// Verify connection pool settings
	if config.MaxDBConnections != 100 {
		t.Errorf("expected max DB connections 100, got %d", config.MaxDBConnections)
	}
	if config.MaxPeerConnections != 150 {
		t.Errorf("expected max peer connections 150, got %d", config.MaxPeerConnections)
	}
}

func TestCollectDiskMetrics(t *testing.T) {
	config := DefaultMonitorConfig()
	config.DataDirPath = "/tmp" // Use /tmp for testing
	monitor := NewMonitor(config)

	metrics := &ResourceMetrics{
		Timestamp: time.Now(),
	}

	err := monitor.collectDiskMetrics(metrics)
	if err != nil {
		t.Fatalf("failed to collect disk metrics: %v", err)
	}

	if metrics.DiskTotalBytes == 0 {
		t.Error("expected disk total bytes to be set")
	}

	if metrics.DiskUsedPercent < 0 || metrics.DiskUsedPercent > 100 {
		t.Errorf("expected disk used percent between 0-100, got %.1f", metrics.DiskUsedPercent)
	}

	if metrics.DiskAvailableBytes > metrics.DiskTotalBytes {
		t.Error("available bytes should not exceed total bytes")
	}
}

func TestCollectMemoryMetrics(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	metrics := &ResourceMetrics{
		Timestamp: time.Now(),
	}

	monitor.collectMemoryMetrics(metrics)

	if metrics.MemoryTotalBytes == 0 {
		t.Error("expected memory total bytes to be set")
	}

	if metrics.MemoryUsedPercent < 0 || metrics.MemoryUsedPercent > 100 {
		t.Errorf("expected memory used percent between 0-100, got %.1f", metrics.MemoryUsedPercent)
	}
}

func TestCollectCPUMetrics(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	metrics := &ResourceMetrics{
		Timestamp: time.Now(),
	}

	monitor.collectCPUMetrics(metrics)

	if metrics.CPUCores == 0 {
		t.Error("expected CPU cores to be set")
	}

	if metrics.CPUCores < 1 {
		t.Errorf("expected at least 1 CPU core, got %d", metrics.CPUCores)
	}
}

func TestCollectConnectionMetrics(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	metrics := &ResourceMetrics{
		Timestamp: time.Now(),
	}

	monitor.collectConnectionMetrics(metrics)

	if metrics.DBConnectionsMax != config.MaxDBConnections {
		t.Errorf("expected DB max %d, got %d", config.MaxDBConnections, metrics.DBConnectionsMax)
	}

	if metrics.PeerConnectionsMax != config.MaxPeerConnections {
		t.Errorf("expected peer max %d, got %d", config.MaxPeerConnections, metrics.PeerConnectionsMax)
	}
}

func TestMemoryLeakDetection(t *testing.T) {
	config := DefaultMonitorConfig()
	config.MemoryLeakSampleCount = 3
	config.MemoryLeakThreshold = 100.0 // 100 MB/hour
	monitor := NewMonitor(config)

	// Simulate increasing memory usage
	for i := 0; i < 3; i++ {
		metrics := &ResourceMetrics{
			Timestamp:        time.Now(),
			MemoryUsedBytes:  uint64((1000 + i*200) * 1024 * 1024), // Increase by 200 MB each time
			MemoryTotalBytes: 8 * 1024 * 1024 * 1024,               // 8 GB total
		}
		monitor.detectMemoryLeak(metrics)
	}

	// Last sample should detect leak
	metrics := &ResourceMetrics{
		Timestamp:        time.Now(),
		MemoryUsedBytes:  2000 * 1024 * 1024, // 2000 MB
		MemoryTotalBytes: 8 * 1024 * 1024 * 1024,
	}
	monitor.detectMemoryLeak(metrics)

	if !metrics.MemoryLeakDetected {
		t.Error("expected memory leak to be detected")
	}

	if metrics.MemoryGrowthRate == 0 {
		t.Error("expected memory growth rate to be calculated")
	}
}

func TestCheckDiskAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.DiskThreshold = 85.0
	config.DiskCritical = 95.0
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertCalled := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertCalled = true
		if alert.Resource != ResourceDisk {
			t.Errorf("expected disk resource, got %s", alert.Resource)
		}
		if alert.Severity != SeverityCritical {
			t.Errorf("expected critical severity, got %s", alert.Severity)
		}
		done <- true
		return nil
	})

	metrics := &ResourceMetrics{
		Timestamp:         time.Now(),
		DiskUsedPercent:   96.0,
		DiskUsedBytes:     960 * 1024 * 1024 * 1024,
		DiskTotalBytes:    1000 * 1024 * 1024 * 1024,
		DiskDaysUntilFull: 2,
	}

	monitor.checkDiskAlerts(ctx, metrics)

	// Wait for alert handler to complete
	select {
	case <-done:
		// Handler called
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert handler")
	}

	if !alertCalled {
		t.Error("expected alert to be called for critical disk usage")
	}
}

func TestCheckMemoryAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.MemoryCritical = 95.0
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertCalled := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertCalled = true
		if alert.Resource != ResourceMemory {
			t.Errorf("expected memory resource, got %s", alert.Resource)
		}
		if alert.Type != "resource-memory-critical" {
			t.Errorf("expected memory-critical alert, got %s", alert.Type)
		}
		done <- true
		return nil
	})

	metrics := &ResourceMetrics{
		Timestamp:         time.Now(),
		MemoryUsedPercent: 96.0,
		MemoryUsedBytes:   7680 * 1024 * 1024,
		MemoryTotalBytes:  8 * 1024 * 1024 * 1024,
	}

	monitor.checkMemoryAlerts(ctx, metrics)

	// Wait for alert handler
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert handler")
	}

	if !alertCalled {
		t.Error("expected alert to be called for critical memory usage")
	}
}

func TestCheckCPUAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.CPUThreshold = 85.0
	config.CPUPersistencePeriod = 1 * time.Second // Short for testing
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertCalled := false
	done := make(chan bool, 1)

	// Simulate high CPU
	monitor.cpuHighStartTime = time.Now().Add(-2 * time.Second)

	metrics := &ResourceMetrics{
		Timestamp:        time.Now(),
		CPUUsedPercent:   90.0,
		CPUSustainedHigh: true,
		CPUHighDuration:  2 * time.Second,
	}

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertCalled = true
		if alert.Resource != ResourceCPU {
			t.Errorf("expected CPU resource, got %s", alert.Resource)
		}
		done <- true
		return nil
	})

	monitor.checkCPUAlerts(ctx, metrics)

	// Wait for alert handler
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert handler")
	}

	if !alertCalled {
		t.Error("expected alert to be called for sustained high CPU")
	}
}

func TestCheckConnectionAlerts(t *testing.T) {
	config := DefaultMonitorConfig()
	config.MaxDBConnections = 100
	config.DBConnectionCritical = 90.0
	monitor := NewMonitor(config)

	ctx := context.Background()
	alertCalled := false
	done := make(chan bool, 1)

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertCalled = true
		if alert.Resource != ResourceDBConnPool {
			t.Errorf("expected DB connection pool resource, got %s", alert.Resource)
		}
		if alert.Severity != SeverityCritical {
			t.Errorf("expected critical severity, got %s", alert.Severity)
		}
		done <- true
		return nil
	})

	metrics := &ResourceMetrics{
		Timestamp:            time.Now(),
		DBConnectionsUsed:    95,
		DBConnectionsMax:     100,
		DBConnectionsPercent: 95.0,
	}

	monitor.checkConnectionAlerts(ctx, metrics)

	// Wait for alert handler
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert handler")
	}

	if !alertCalled {
		t.Error("expected alert to be called for critical DB connections")
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

	// Set some metrics
	testMetrics := &ResourceMetrics{
		Timestamp:       time.Now(),
		DiskUsedPercent: 50.0,
	}
	monitor.mu.Lock()
	monitor.lastMetrics = testMetrics
	monitor.mu.Unlock()

	// Get metrics
	metrics = monitor.GetCurrentMetrics()
	if metrics == nil {
		t.Fatal("expected metrics to be returned")
	}

	if metrics.DiskUsedPercent != 50.0 {
		t.Errorf("expected disk used 50.0%%, got %.1f%%", metrics.DiskUsedPercent)
	}
}

func TestGetMetricsHistory(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Add some historical metrics
	for i := 0; i < 10; i++ {
		monitor.metricsHistory = append(monitor.metricsHistory, ResourceMetrics{
			Timestamp:       time.Now().Add(-time.Duration(i) * time.Minute),
			DiskUsedPercent: float64(50 + i),
		})
	}

	// Get last 5
	history := monitor.GetMetricsHistory(5)
	if len(history) != 5 {
		t.Errorf("expected 5 metrics, got %d", len(history))
	}

	// Get all
	history = monitor.GetMetricsHistory(0)
	if len(history) != 10 {
		t.Errorf("expected 10 metrics, got %d", len(history))
	}
}

func TestGetStats(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Set some metrics
	testMetrics := &ResourceMetrics{
		Timestamp:         time.Now(),
		DiskUsedPercent:   75.0,
		MemoryUsedPercent: 60.0,
		CPUUsedPercent:    45.0,
		DiskDaysUntilFull: 30,
	}
	monitor.mu.Lock()
	monitor.lastMetrics = testMetrics
	monitor.metricsHistory = append(monitor.metricsHistory, *testMetrics)
	monitor.mu.Unlock()

	stats := monitor.GetStats()

	if stats["metrics_count"] != 1 {
		t.Errorf("expected metrics_count 1, got %v", stats["metrics_count"])
	}

	if stats["disk_used_percent"] != 75.0 {
		t.Errorf("expected disk_used_percent 75.0, got %v", stats["disk_used_percent"])
	}

	if stats["memory_used_percent"] != 60.0 {
		t.Errorf("expected memory_used_percent 60.0, got %v", stats["memory_used_percent"])
	}

	if stats["disk_days_until_full"] != 30 {
		t.Errorf("expected disk_days_until_full 30, got %v", stats["disk_days_until_full"])
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
		Severity:  SeverityWarning,
		Resource:  ResourceDisk,
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

func TestNormalizeToEvent(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	alert := &Alert{
		ID:          uuid.New(),
		Type:        "resource-disk-space-critical",
		Severity:    SeverityCritical,
		Resource:    ResourceDisk,
		Title:       "Disk Space Critical",
		Description: "Disk usage at 95%",
		Timestamp:   time.Now(),
		Metrics: &ResourceMetrics{
			DiskUsedPercent:   95.0,
			MemoryUsedPercent: 50.0,
			CPUUsedPercent:    30.0,
			DiskDaysUntilFull: 2,
		},
		Metadata: map[string]interface{}{
			"available_gb": 50.0,
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

	if event.Source.Product != "resource-monitor" {
		t.Errorf("expected product 'resource-monitor', got %s", event.Source.Product)
	}

	if event.Target != string(ResourceDisk) {
		t.Errorf("expected target 'disk', got %s", event.Target)
	}

	// Check metadata
	if event.Metadata["disk_used_percent"] != 95.0 {
		t.Errorf("expected disk_used_percent in metadata, got %v", event.Metadata["disk_used_percent"])
	}

	if event.Metadata["available_gb"] != 50.0 {
		t.Errorf("expected available_gb in metadata, got %v", event.Metadata["available_gb"])
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{1073741824, "1.0 GiB"},
		{1099511627776, "1.0 TiB"},
	}

	for _, tt := range tests {
		result := formatBytes(tt.bytes)
		if result != tt.expected {
			t.Errorf("formatBytes(%d) = %s, want %s", tt.bytes, result, tt.expected)
		}
	}
}

func TestCreateCorrelationRules(t *testing.T) {
	rules := CreateCorrelationRules()

	if len(rules) != 3 {
		t.Errorf("expected 3 correlation rules, got %d", len(rules))
	}

	// Check first rule (disk exhaustion)
	if rules[0].ID != "resource-disk-exhaustion-imminent" {
		t.Errorf("expected first rule ID 'resource-disk-exhaustion-imminent', got %s", rules[0].ID)
	}

	if !rules[0].Enabled {
		t.Error("expected disk exhaustion rule to be enabled")
	}

	// Check second rule (memory leak)
	if rules[1].ID != "resource-memory-leak-sustained" {
		t.Errorf("expected second rule ID 'resource-memory-leak-sustained', got %s", rules[1].ID)
	}

	// Check third rule (multiple exhaustion)
	if rules[2].ID != "resource-multiple-exhaustion" {
		t.Errorf("expected third rule ID 'resource-multiple-exhaustion', got %s", rules[2].ID)
	}

	// Verify all rules have MITRE mappings (first rule)
	if rules[0].MITRE == nil {
		t.Error("expected MITRE mapping for disk exhaustion rule")
	}
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

func TestMonitorStartStop(t *testing.T) {
	config := DefaultMonitorConfig()
	config.DataDirPath = "/tmp"
	config.CheckInterval = 100 * time.Millisecond
	monitor := NewMonitor(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitor
	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("failed to start monitor: %v", err)
	}

	// Wait for a few checks
	time.Sleep(350 * time.Millisecond)

	// Should have some metrics
	metrics := monitor.GetCurrentMetrics()
	if metrics == nil {
		t.Error("expected metrics to be collected after start")
	}

	// Stop monitor
	monitor.Stop()
}

// Benchmark tests
func BenchmarkCollectDiskMetrics(b *testing.B) {
	config := DefaultMonitorConfig()
	config.DataDirPath = "/tmp"
	monitor := NewMonitor(config)

	metrics := &ResourceMetrics{
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		monitor.collectDiskMetrics(metrics)
	}
}

func BenchmarkCollectMemoryMetrics(b *testing.B) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	metrics := &ResourceMetrics{
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		monitor.collectMemoryMetrics(metrics)
	}
}

func BenchmarkCheck(b *testing.B) {
	config := DefaultMonitorConfig()
	config.DataDirPath = "/tmp"
	monitor := NewMonitor(config)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		monitor.check(ctx)
	}
}

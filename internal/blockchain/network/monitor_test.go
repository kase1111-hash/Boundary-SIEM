package network

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

	if monitor.config.MinPeerCount != 50 {
		t.Errorf("expected min peer count 50, got %d", monitor.config.MinPeerCount)
	}

	if monitor.config.OptimalPeerCount != 100 {
		t.Errorf("expected optimal peer count 100, got %d", monitor.config.OptimalPeerCount)
	}
}

func TestDefaultMonitorConfig(t *testing.T) {
	config := DefaultMonitorConfig()

	// Verify peer count settings
	if config.MinPeerCount != 50 {
		t.Errorf("expected min peer count 50, got %d", config.MinPeerCount)
	}
	if config.OptimalPeerCount != 100 {
		t.Errorf("expected optimal peer count 100, got %d", config.OptimalPeerCount)
	}
	if config.LowPeerCritical != 20 {
		t.Errorf("expected critical peer count 20, got %d", config.LowPeerCritical)
	}

	// Verify peer ratio settings
	if config.MinInboundPercent != 20.0 {
		t.Errorf("expected min inbound 20%%, got %.1f%%", config.MinInboundPercent)
	}

	// Verify geographic diversity settings
	if config.MaxASNPercent != 50.0 {
		t.Errorf("expected max ASN 50%%, got %.1f%%", config.MaxASNPercent)
	}
	if config.EclipseASNThreshold != 70.0 {
		t.Errorf("expected eclipse threshold 70%%, got %.1f%%", config.EclipseASNThreshold)
	}

	// Verify bandwidth settings
	if config.BandwidthLimit != 10*1000*1000*1000 {
		t.Errorf("expected bandwidth limit 10 Gbps, got %d", config.BandwidthLimit)
	}
}

func TestAddPeer(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	peer := &PeerInfo{
		ID:        "peer1",
		IPAddress: "192.168.1.1",
		Direction: "outbound",
		QualityScore: 0.9,
	}

	monitor.AddPeer(peer)

	// Verify peer was added
	retrieved, ok := monitor.GetPeer("peer1")
	if !ok {
		t.Fatal("expected peer to be found")
	}

	if retrieved.IPAddress != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", retrieved.IPAddress)
	}

	if retrieved.QualityScore != 0.9 {
		t.Errorf("expected quality score 0.9, got %.1f", retrieved.QualityScore)
	}
}

func TestRemovePeer(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	peer := &PeerInfo{
		ID:        "peer1",
		IPAddress: "192.168.1.1",
	}

	monitor.AddPeer(peer)
	monitor.RemovePeer("peer1")

	// Verify peer was removed
	_, ok := monitor.GetPeer("peer1")
	if ok {
		t.Error("expected peer to be removed")
	}
}

func TestUpdatePeerQuality(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	peer := &PeerInfo{
		ID:           "peer1",
		QualityScore: 0.5,
	}

	monitor.AddPeer(peer)
	monitor.UpdatePeerQuality("peer1", 0.9)

	// Verify quality was updated
	updated, _ := monitor.GetPeer("peer1")
	if updated.QualityScore != 0.9 {
		t.Errorf("expected quality score 0.9, got %.1f", updated.QualityScore)
	}
}

func TestCollectMetrics(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Add some peers
	monitor.AddPeer(&PeerInfo{
		ID:           "peer1",
		Direction:    "inbound",
		Country:      "US",
		ASN:          12345,
		QualityScore: 0.8,
		BytesSent:    1000,
		BytesReceived: 2000,
	})

	monitor.AddPeer(&PeerInfo{
		ID:           "peer2",
		Direction:    "outbound",
		Country:      "US",
		ASN:          12345,
		QualityScore: 0.9,
		BytesSent:    3000,
		BytesReceived: 4000,
	})

	monitor.AddPeer(&PeerInfo{
		ID:           "peer3",
		Direction:    "outbound",
		Country:      "DE",
		ASN:          67890,
		QualityScore: 0.7,
	})

	metrics := monitor.collectMetrics()

	if metrics.TotalPeers != 3 {
		t.Errorf("expected 3 total peers, got %d", metrics.TotalPeers)
	}

	if metrics.InboundPeers != 1 {
		t.Errorf("expected 1 inbound peer, got %d", metrics.InboundPeers)
	}

	if metrics.OutboundPeers != 2 {
		t.Errorf("expected 2 outbound peers, got %d", metrics.OutboundPeers)
	}

	expectedInbound := (1.0 / 3.0) * 100.0
	if metrics.InboundPercent < expectedInbound-1 || metrics.InboundPercent > expectedInbound+1 {
		t.Errorf("expected inbound percent ~%.1f%%, got %.1f%%", expectedInbound, metrics.InboundPercent)
	}

	// Check geographic data
	if metrics.PeersByCountry["US"] != 2 {
		t.Errorf("expected 2 US peers, got %d", metrics.PeersByCountry["US"])
	}

	if metrics.PeersByCountry["DE"] != 1 {
		t.Errorf("expected 1 DE peer, got %d", metrics.PeersByCountry["DE"])
	}

	// Check ASN data
	if metrics.PeersByASN[12345] != 2 {
		t.Errorf("expected 2 peers from ASN 12345, got %d", metrics.PeersByASN[12345])
	}

	// Check quality
	expectedAvg := (0.8 + 0.9 + 0.7) / 3.0
	if metrics.AvgQualityScore < expectedAvg-0.1 || metrics.AvgQualityScore > expectedAvg+0.1 {
		t.Errorf("expected avg quality ~%.2f, got %.2f", expectedAvg, metrics.AvgQualityScore)
	}
}

func TestCheckPeerCount(t *testing.T) {
	config := DefaultMonitorConfig()
	config.LowPeerCritical = 20
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertReceived = true
		if alert.Type != "network-peer-count-critical" {
			t.Errorf("expected peer-count-critical, got %s", alert.Type)
		}
		if alert.Severity != "critical" {
			t.Errorf("expected critical severity, got %s", alert.Severity)
		}
		done <- true
		return nil
	})

	metrics := &NetworkMetrics{
		Timestamp:   time.Now(),
		TotalPeers:  15, // Below critical threshold of 20
	}

	monitor.checkPeerCount(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for critical peer count")
	}
}

func TestCheckPeerRatio(t *testing.T) {
	config := DefaultMonitorConfig()
	config.MinInboundPercent = 20.0
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertReceived = true
		if alert.Type != "network-inbound-imbalance" {
			t.Errorf("expected inbound-imbalance, got %s", alert.Type)
		}
		done <- true
		return nil
	})

	metrics := &NetworkMetrics{
		Timestamp:       time.Now(),
		TotalPeers:      100,
		InboundPeers:    10,  // 10%
		OutboundPeers:   90,  // 90%
		InboundPercent:  10.0, // Below 20% threshold
	}

	monitor.checkPeerRatio(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for inbound imbalance")
	}
}

func TestCheckGeographicDiversity_EclipseAttack(t *testing.T) {
	config := DefaultMonitorConfig()
	config.EclipseASNThreshold = 70.0
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertReceived = true
		if alert.Type != "network-eclipse-attack-risk" {
			t.Errorf("expected eclipse-attack-risk, got %s", alert.Type)
		}
		if alert.Severity != "critical" {
			t.Errorf("expected critical severity, got %s", alert.Severity)
		}
		done <- true
		return nil
	})

	metrics := &NetworkMetrics{
		Timestamp:      time.Now(),
		TotalPeers:     100,
		TopASN:         12345,
		TopASNCount:    75,  // 75% from single ASN
		TopASNPercent:  75.0, // Above eclipse threshold
	}

	monitor.checkGeographicDiversity(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for eclipse attack risk")
	}
}

func TestCheckGeographicDiversity_ASNConcentration(t *testing.T) {
	config := DefaultMonitorConfig()
	config.MaxASNPercent = 50.0
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "network-asn-concentration" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	metrics := &NetworkMetrics{
		Timestamp:     time.Now(),
		TotalPeers:    100,
		TopASN:        12345,
		TopASNCount:   60,   // 60% from single ASN
		TopASNPercent: 60.0, // Above max but below eclipse threshold
	}

	monitor.checkGeographicDiversity(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for ASN concentration")
	}
}

func TestCheckPeerQuality(t *testing.T) {
	config := DefaultMonitorConfig()
	config.MaxLowQualityPercent = 30.0
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertReceived = true
		if alert.Type != "network-low-quality-peers" {
			t.Errorf("expected low-quality-peers, got %s", alert.Type)
		}
		done <- true
		return nil
	})

	metrics := &NetworkMetrics{
		Timestamp:         time.Now(),
		TotalPeers:        100,
		LowQualityCount:   40,   // 40 low quality peers
		LowQualityPercent: 40.0, // Above 30% threshold
	}

	monitor.checkPeerQuality(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for low quality peers")
	}
}

func TestCheckBandwidth(t *testing.T) {
	config := DefaultMonitorConfig()
	config.BandwidthCritical = 90.0
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertReceived = true
		if alert.Type != "network-bandwidth-critical" {
			t.Errorf("expected bandwidth-critical, got %s", alert.Type)
		}
		done <- true
		return nil
	})

	metrics := &NetworkMetrics{
		Timestamp:        time.Now(),
		BandwidthLimit:   10000000000, // 10 Gbps
		BandwidthUsedBps: 9500000000,  // 9.5 Gbps
		BandwidthPercent: 95.0,        // Above critical threshold
	}

	monitor.checkBandwidth(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for critical bandwidth")
	}
}

func TestCheckConnectionFailures(t *testing.T) {
	config := DefaultMonitorConfig()
	config.MaxConnectionFailures = 10
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		alertReceived = true
		if alert.Type != "network-connection-failures" {
			t.Errorf("expected connection-failures, got %s", alert.Type)
		}
		done <- true
		return nil
	})

	metrics := &NetworkMetrics{
		Timestamp:          time.Now(),
		ConnectionFailures: 15, // Above threshold of 10
	}

	monitor.checkConnectionFailures(ctx, metrics)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for connection failures")
	}
}

func TestCheckChurn(t *testing.T) {
	config := DefaultMonitorConfig()
	config.ChurnRateThreshold = 50.0
	monitor := NewMonitor(config)

	ctx := context.Background()
	done := make(chan bool, 1)
	alertReceived := false

	monitor.AddHandler(func(ctx context.Context, alert *Alert) error {
		if alert.Type == "network-peer-churn-high" {
			alertReceived = true
			done <- true
		}
		return nil
	})

	// Create initial snapshot with 10 peers
	for i := 0; i < 10; i++ {
		monitor.peerSnapshot[fmt.Sprintf("peer%d", i)] = true
	}

	// Now have 10 different peers (100% churn)
	for i := 10; i < 20; i++ {
		monitor.peers[fmt.Sprintf("peer%d", i)] = &PeerInfo{
			ID: fmt.Sprintf("peer%d", i),
		}
	}

	monitor.checkChurn(ctx)

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for alert")
	}

	if !alertReceived {
		t.Error("expected alert for high peer churn")
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
	testMetrics := &NetworkMetrics{
		Timestamp:  time.Now(),
		TotalPeers: 75,
	}
	monitor.mu.Lock()
	monitor.lastMetrics = testMetrics
	monitor.mu.Unlock()

	// Get metrics
	metrics = monitor.GetCurrentMetrics()
	if metrics == nil {
		t.Fatal("expected metrics to be returned")
	}

	if metrics.TotalPeers != 75 {
		t.Errorf("expected 75 total peers, got %d", metrics.TotalPeers)
	}
}

func TestGetMetricsHistory(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Add some historical metrics
	for i := 0; i < 10; i++ {
		monitor.metricsHistory = append(monitor.metricsHistory, NetworkMetrics{
			Timestamp:  time.Now().Add(-time.Duration(i) * time.Minute),
			TotalPeers: i + 50,
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

func TestGetPeers(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	monitor.AddPeer(&PeerInfo{ID: "peer1"})
	monitor.AddPeer(&PeerInfo{ID: "peer2"})
	monitor.AddPeer(&PeerInfo{ID: "peer3"})

	peers := monitor.GetPeers()
	if len(peers) != 3 {
		t.Errorf("expected 3 peers, got %d", len(peers))
	}
}

func TestGetStats(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Add some peers
	monitor.AddPeer(&PeerInfo{ID: "peer1", Direction: "inbound"})
	monitor.AddPeer(&PeerInfo{ID: "peer2", Direction: "outbound"})

	// Set metrics
	testMetrics := &NetworkMetrics{
		Timestamp:        time.Now(),
		TotalPeers:       2,
		InboundPeers:     1,
		OutboundPeers:    1,
		AvgQualityScore:  0.75,
		BandwidthPercent: 45.0,
	}
	monitor.mu.Lock()
	monitor.lastMetrics = testMetrics
	monitor.mu.Unlock()

	stats := monitor.GetStats()

	if stats["total_peers"] != 2 {
		t.Errorf("expected 2 total peers, got %v", stats["total_peers"])
	}

	if stats["inbound_peers"] != 1 {
		t.Errorf("expected 1 inbound peer, got %v", stats["inbound_peers"])
	}

	if stats["avg_quality_score"] != 0.75 {
		t.Errorf("expected avg quality 0.75, got %v", stats["avg_quality_score"])
	}
}

func TestNormalizeToEvent(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	alert := &Alert{
		ID:       uuid.New(),
		Type:     "network-eclipse-attack-risk",
		Severity: "critical",
		Title:    "Eclipse Attack Risk",
		Description: "75% of peers from single ASN",
		Timestamp: time.Now(),
		Metrics: &NetworkMetrics{
			TotalPeers:    100,
			InboundPeers:  30,
			OutboundPeers: 70,
			AvgQualityScore: 0.8,
			BandwidthPercent: 65.0,
		},
		Metadata: map[string]interface{}{
			"top_asn": 12345,
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

	if event.Source.Product != "network-monitor" {
		t.Errorf("expected product 'network-monitor', got %s", event.Source.Product)
	}

	// Check metadata
	if event.Metadata["total_peers"] != 100 {
		t.Errorf("expected total_peers in metadata, got %v", event.Metadata["total_peers"])
	}

	if event.Metadata["top_asn"] != 12345 {
		t.Errorf("expected top_asn in metadata, got %v", event.Metadata["top_asn"])
	}
}

func TestFormatBandwidth(t *testing.T) {
	tests := []struct {
		bps      uint64
		expected string
	}{
		{500, "500 bps"},
		{1500, "1.5 Kbps"},
		{1500000, "1.5 Mbps"},
		{1500000000, "1.5 Gbps"},
	}

	for _, tt := range tests {
		result := formatBandwidth(tt.bps)
		if result != tt.expected {
			t.Errorf("formatBandwidth(%d) = %s, want %s", tt.bps, result, tt.expected)
		}
	}
}

func TestCreateCorrelationRules(t *testing.T) {
	rules := CreateCorrelationRules()

	if len(rules) != 4 {
		t.Errorf("expected 4 correlation rules, got %d", len(rules))
	}

	// Check first rule (eclipse attack)
	if rules[0].ID != "network-eclipse-attack" {
		t.Errorf("expected first rule ID 'network-eclipse-attack', got %s", rules[0].ID)
	}

	if !rules[0].Enabled {
		t.Error("expected eclipse attack rule to be enabled")
	}

	// Check second rule (isolation)
	if rules[1].ID != "network-isolation" {
		t.Errorf("expected second rule ID 'network-isolation', got %s", rules[1].ID)
	}

	// Check third rule (bandwidth)
	if rules[2].ID != "network-bandwidth-saturation" {
		t.Errorf("expected third rule ID 'network-bandwidth-saturation', got %s", rules[2].ID)
	}

	// Check fourth rule (connection storm)
	if rules[3].ID != "network-connection-storm" {
		t.Errorf("expected fourth rule ID 'network-connection-storm', got %s", rules[3].ID)
	}

	// Verify MITRE mappings for rules that have them
	if rules[0].MITRE == nil {
		t.Error("expected MITRE mapping for eclipse attack rule")
	}

	if rules[2].MITRE == nil {
		t.Error("expected MITRE mapping for bandwidth saturation rule")
	}
}

func TestRecordConnectionFailure(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Record some failures
	for i := 0; i < 5; i++ {
		monitor.RecordConnectionFailure()
	}

	monitor.mu.RLock()
	failCount := len(monitor.connectionFails)
	monitor.mu.RUnlock()

	if failCount != 5 {
		t.Errorf("expected 5 connection failures, got %d", failCount)
	}
}

func TestCleanup(t *testing.T) {
	config := DefaultMonitorConfig()
	monitor := NewMonitor(config)

	// Add some old connection failures
	monitor.mu.Lock()
	monitor.connectionFails = append(monitor.connectionFails, time.Now().Add(-20*time.Minute))
	monitor.connectionFails = append(monitor.connectionFails, time.Now())
	monitor.mu.Unlock()

	// Add some old alerts
	monitor.recentAlerts["old-alert"] = time.Now().Add(-1 * time.Hour)
	monitor.recentAlerts["recent-alert"] = time.Now()

	// Run cleanup
	monitor.cleanup()

	// Old connection failure should be removed
	monitor.mu.RLock()
	failCount := len(monitor.connectionFails)
	monitor.mu.RUnlock()

	if failCount != 1 {
		t.Errorf("expected 1 recent connection failure, got %d", failCount)
	}

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

// Add missing import at the top
func init() {
	// Ensure fmt is available for tests that need it
	_ = fmt.Sprintf
}

// Package network provides blockchain network health monitoring capabilities.
package network

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// PeerInfo represents information about a connected peer.
type PeerInfo struct {
	ID              string `json:"id"`
	IPAddress       string `json:"ip_address"`
	Port            int    `json:"port"`
	Country         string `json:"country,omitempty"`
	ASN             int    `json:"asn,omitempty"`
	ASNOrg          string `json:"asn_org,omitempty"`
	UserAgent       string `json:"user_agent,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`

	// Connection info
	Direction   string    `json:"direction"` // "inbound" or "outbound"
	ConnectedAt time.Time `json:"connected_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`

	// Quality metrics
	QualityScore    float64 `json:"quality_score"` // 0.0 to 1.0
	Latency         int     `json:"latency_ms"`
	FailedRequests  int     `json:"failed_requests"`
	SuccessRequests int     `json:"success_requests"`

	// Bandwidth
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
}

// NetworkMetrics contains current network health metrics.
type NetworkMetrics struct {
	Timestamp time.Time `json:"timestamp"`

	// Peer counts
	TotalPeers     int     `json:"total_peers"`
	InboundPeers   int     `json:"inbound_peers"`
	OutboundPeers  int     `json:"outbound_peers"`
	InboundPercent float64 `json:"inbound_percent"`

	// Geographic diversity
	PeersByCountry    map[string]int `json:"peers_by_country"`
	PeersByASN        map[int]int    `json:"peers_by_asn"`
	TopCountry        string         `json:"top_country"`
	TopCountryCount   int            `json:"top_country_count"`
	TopCountryPercent float64        `json:"top_country_percent"`
	TopASN            int            `json:"top_asn"`
	TopASNCount       int            `json:"top_asn_count"`
	TopASNPercent     float64        `json:"top_asn_percent"`

	// Peer quality
	AvgQualityScore   float64 `json:"avg_quality_score"`
	LowQualityCount   int     `json:"low_quality_count"`
	LowQualityPercent float64 `json:"low_quality_percent"`

	// Bandwidth
	TotalBytesSent     uint64  `json:"total_bytes_sent"`
	TotalBytesReceived uint64  `json:"total_bytes_received"`
	BandwidthLimit     uint64  `json:"bandwidth_limit_bps"`
	BandwidthUsedBps   uint64  `json:"bandwidth_used_bps"`
	BandwidthPercent   float64 `json:"bandwidth_percent"`

	// Connection churn
	PeerChurnRate      float64 `json:"peer_churn_rate"` // Percentage turnover
	ConnectionFailures int     `json:"connection_failures"`
}

// Alert represents a network health alert.
type Alert struct {
	ID          uuid.UUID              `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Metrics     *NetworkMetrics        `json:"metrics,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertHandler processes network alerts.
type AlertHandler func(context.Context, *Alert) error

// MonitorConfig configures the network monitor.
type MonitorConfig struct {
	// Peer count thresholds
	MinPeerCount     int // Minimum peers (default: 50 for Ethereum)
	OptimalPeerCount int // Optimal peers (default: 100)
	MaxPeerCount     int // Maximum peers (default: 150)
	LowPeerCritical  int // Critical low peer count (default: 20)

	// Peer ratio
	MinInboundPercent float64 // Min inbound peers % (default: 20%)
	MaxInboundPercent float64 // Max inbound peers % (default: 80%)

	// Geographic diversity (eclipse attack detection)
	MaxCountryPercent   float64 // Max peers from single country (default: 50%)
	MaxASNPercent       float64 // Max peers from single ASN (default: 50%)
	EclipseASNThreshold float64 // ASN concentration = eclipse risk (default: 70%)

	// Peer quality
	LowQualityThreshold  float64 // Quality score threshold (default: 0.5)
	MaxLowQualityPercent float64 // Max % low quality peers (default: 30%)

	// Bandwidth
	BandwidthLimit    uint64  // Bandwidth limit in bps (default: 10 Gbps)
	BandwidthWarning  float64 // % for warning (default: 80%)
	BandwidthCritical float64 // % for critical (default: 90%)

	// Connection churn
	ChurnRateThreshold    float64       // % turnover to alert (default: 50%)
	ChurnCheckWindow      time.Duration // Window for churn calculation (default: 10 min)
	MaxConnectionFailures int           // Max failures per minute (default: 10)

	// Monitoring intervals
	CheckInterval    time.Duration // How often to check (default: 30s)
	MetricsRetention int           // Historical metrics to keep (default: 2880 = 24h)
	CleanupInterval  time.Duration // Cleanup old data (default: 5 min)
}

// DefaultMonitorConfig returns default configuration.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		MinPeerCount:     50,
		OptimalPeerCount: 100,
		MaxPeerCount:     150,
		LowPeerCritical:  20,

		MinInboundPercent: 20.0,
		MaxInboundPercent: 80.0,

		MaxCountryPercent:   50.0,
		MaxASNPercent:       50.0,
		EclipseASNThreshold: 70.0,

		LowQualityThreshold:  0.5,
		MaxLowQualityPercent: 30.0,

		BandwidthLimit:    10 * 1000 * 1000 * 1000, // 10 Gbps
		BandwidthWarning:  80.0,
		BandwidthCritical: 90.0,

		ChurnRateThreshold:    50.0,
		ChurnCheckWindow:      10 * time.Minute,
		MaxConnectionFailures: 10,

		CheckInterval:    30 * time.Second,
		MetricsRetention: 2880,
		CleanupInterval:  5 * time.Minute,
	}
}

// Monitor monitors network health and connectivity.
type Monitor struct {
	config   MonitorConfig
	handlers []AlertHandler
	mu       sync.RWMutex

	// Peer tracking
	peers          map[string]*PeerInfo
	metricsHistory []NetworkMetrics
	lastMetrics    *NetworkMetrics

	// Churn tracking
	peerSnapshot    map[string]bool // Snapshot for churn calculation
	snapshotTime    time.Time
	connectionFails []time.Time

	// Alert deduplication
	recentAlerts map[string]time.Time

	// Lifecycle
	stopCh chan struct{}
	wg     sync.WaitGroup
	logger *slog.Logger
}

// NewMonitor creates a new network monitor.
func NewMonitor(config MonitorConfig) *Monitor {
	return &Monitor{
		config:          config,
		peers:           make(map[string]*PeerInfo),
		metricsHistory:  make([]NetworkMetrics, 0, config.MetricsRetention),
		peerSnapshot:    make(map[string]bool),
		connectionFails: make([]time.Time, 0, 100),
		recentAlerts:    make(map[string]time.Time),
		stopCh:          make(chan struct{}),
		logger:          slog.Default(),
	}
}

// AddHandler adds an alert handler.
func (m *Monitor) AddHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// Start starts the network monitor.
func (m *Monitor) Start(ctx context.Context) error {
	m.logger.Info("starting network monitor",
		"check_interval", m.config.CheckInterval,
		"min_peers", m.config.MinPeerCount)

	// Initial snapshot
	m.takeSnapshot()

	// Start monitoring loop
	m.wg.Add(1)
	go m.monitorLoop(ctx)

	// Start cleanup loop
	m.wg.Add(1)
	go m.cleanupLoop(ctx)

	return nil
}

// Stop stops the network monitor.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	m.logger.Info("network monitor stopped")
}

// AddPeer adds or updates a peer.
func (m *Monitor) AddPeer(peer *PeerInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer.LastSeenAt = time.Now()
	if existing, ok := m.peers[peer.ID]; ok {
		// Update existing peer
		peer.ConnectedAt = existing.ConnectedAt
	} else {
		// New peer
		if peer.ConnectedAt.IsZero() {
			peer.ConnectedAt = time.Now()
		}
	}

	m.peers[peer.ID] = peer
}

// RemovePeer removes a peer.
func (m *Monitor) RemovePeer(peerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.peers, peerID)
}

// UpdatePeerQuality updates a peer's quality score.
func (m *Monitor) UpdatePeerQuality(peerID string, score float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if peer, ok := m.peers[peerID]; ok {
		peer.QualityScore = score
		peer.LastSeenAt = time.Now()
	}
}

// RecordConnectionFailure records a connection failure.
func (m *Monitor) RecordConnectionFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.connectionFails = append(m.connectionFails, time.Now())
}

// monitorLoop runs the main monitoring loop.
func (m *Monitor) monitorLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	churnTicker := time.NewTicker(m.config.ChurnCheckWindow)
	defer churnTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			if err := m.check(ctx); err != nil {
				m.logger.Error("network check failed", "error", err)
			}
		case <-churnTicker.C:
			m.checkChurn(ctx)
			m.takeSnapshot()
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

// check performs a network health check.
func (m *Monitor) check(ctx context.Context) error {
	metrics := m.collectMetrics()

	// Store metrics
	m.mu.Lock()
	m.lastMetrics = metrics
	m.metricsHistory = append(m.metricsHistory, *metrics)
	if len(m.metricsHistory) > m.config.MetricsRetention {
		m.metricsHistory = m.metricsHistory[1:]
	}
	m.mu.Unlock()

	// Analyze and generate alerts
	m.analyzeMetrics(ctx, metrics)

	return nil
}

// collectMetrics collects current network metrics.
func (m *Monitor) collectMetrics() *NetworkMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	metrics := &NetworkMetrics{
		Timestamp:      time.Now(),
		PeersByCountry: make(map[string]int),
		PeersByASN:     make(map[int]int),
	}

	var totalQuality float64
	var lowQualityCount int

	// Aggregate peer metrics
	for _, peer := range m.peers {
		metrics.TotalPeers++

		if peer.Direction == "inbound" {
			metrics.InboundPeers++
		} else {
			metrics.OutboundPeers++
		}

		if peer.Country != "" {
			metrics.PeersByCountry[peer.Country]++
		}

		if peer.ASN > 0 {
			metrics.PeersByASN[peer.ASN]++
		}

		totalQuality += peer.QualityScore
		if peer.QualityScore < m.config.LowQualityThreshold {
			lowQualityCount++
		}

		metrics.TotalBytesSent += peer.BytesSent
		metrics.TotalBytesReceived += peer.BytesReceived
	}

	// Calculate percentages
	if metrics.TotalPeers > 0 {
		metrics.InboundPercent = float64(metrics.InboundPeers) / float64(metrics.TotalPeers) * 100.0
		metrics.AvgQualityScore = totalQuality / float64(metrics.TotalPeers)
		metrics.LowQualityCount = lowQualityCount
		metrics.LowQualityPercent = float64(lowQualityCount) / float64(metrics.TotalPeers) * 100.0
	}

	// Find top country and ASN
	m.findTopCountryASN(metrics)

	// Calculate bandwidth
	metrics.BandwidthLimit = m.config.BandwidthLimit
	if len(m.metricsHistory) > 0 {
		prev := m.metricsHistory[len(m.metricsHistory)-1]
		timeDiff := metrics.Timestamp.Sub(prev.Timestamp).Seconds()
		if timeDiff > 0 {
			bytesSent := metrics.TotalBytesSent - prev.TotalBytesSent
			bytesRecv := metrics.TotalBytesReceived - prev.TotalBytesReceived
			metrics.BandwidthUsedBps = uint64((float64(bytesSent+bytesRecv) * 8) / timeDiff)
		}
	}
	if metrics.BandwidthLimit > 0 {
		metrics.BandwidthPercent = float64(metrics.BandwidthUsedBps) / float64(metrics.BandwidthLimit) * 100.0
	}

	// Count recent connection failures
	cutoff := time.Now().Add(-1 * time.Minute)
	failCount := 0
	for _, failTime := range m.connectionFails {
		if failTime.After(cutoff) {
			failCount++
		}
	}
	metrics.ConnectionFailures = failCount

	return metrics
}

// findTopCountryASN finds the top country and ASN by peer count.
func (m *Monitor) findTopCountryASN(metrics *NetworkMetrics) {
	for country, count := range metrics.PeersByCountry {
		if count > metrics.TopCountryCount {
			metrics.TopCountry = country
			metrics.TopCountryCount = count
		}
	}

	for asn, count := range metrics.PeersByASN {
		if count > metrics.TopASNCount {
			metrics.TopASN = asn
			metrics.TopASNCount = count
		}
	}

	if metrics.TotalPeers > 0 {
		metrics.TopCountryPercent = float64(metrics.TopCountryCount) / float64(metrics.TotalPeers) * 100.0
		metrics.TopASNPercent = float64(metrics.TopASNCount) / float64(metrics.TotalPeers) * 100.0
	}
}

// analyzeMetrics analyzes metrics and generates alerts.
func (m *Monitor) analyzeMetrics(ctx context.Context, metrics *NetworkMetrics) {
	m.checkPeerCount(ctx, metrics)
	m.checkPeerRatio(ctx, metrics)
	m.checkGeographicDiversity(ctx, metrics)
	m.checkPeerQuality(ctx, metrics)
	m.checkBandwidth(ctx, metrics)
	m.checkConnectionFailures(ctx, metrics)
}

// checkPeerCount checks peer count thresholds.
func (m *Monitor) checkPeerCount(ctx context.Context, metrics *NetworkMetrics) {
	if metrics.TotalPeers < m.config.LowPeerCritical {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "network-peer-count-critical",
			Severity: "critical",
			Title:    "CRITICAL: Very Low Peer Count",
			Description: fmt.Sprintf("Only %d peers connected (minimum: %d, critical: %d)",
				metrics.TotalPeers, m.config.MinPeerCount, m.config.LowPeerCritical),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
		})
	} else if metrics.TotalPeers < m.config.MinPeerCount {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "network-low-peer-count",
			Severity: "high",
			Title:    "Low Peer Count",
			Description: fmt.Sprintf("%d peers connected (minimum: %d, optimal: %d)",
				metrics.TotalPeers, m.config.MinPeerCount, m.config.OptimalPeerCount),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
		})
	}
}

// checkPeerRatio checks inbound/outbound peer ratio.
func (m *Monitor) checkPeerRatio(ctx context.Context, metrics *NetworkMetrics) {
	if metrics.TotalPeers == 0 {
		return
	}

	if metrics.InboundPercent < m.config.MinInboundPercent {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "network-inbound-imbalance",
			Severity: "medium",
			Title:    "Low Inbound Peer Ratio",
			Description: fmt.Sprintf("Only %.1f%% inbound peers (minimum: %.1f%%). Possible firewall issue.",
				metrics.InboundPercent, m.config.MinInboundPercent),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
			Metadata: map[string]interface{}{
				"inbound_peers":  metrics.InboundPeers,
				"outbound_peers": metrics.OutboundPeers,
			},
		})
	}
}

// checkGeographicDiversity checks for geographic concentration (eclipse attacks).
func (m *Monitor) checkGeographicDiversity(ctx context.Context, metrics *NetworkMetrics) {
	if metrics.TotalPeers == 0 {
		return
	}

	// Check ASN concentration (eclipse attack risk)
	if metrics.TopASNPercent >= m.config.EclipseASNThreshold {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "network-eclipse-attack-risk",
			Severity: "critical",
			Title:    "CRITICAL: Eclipse Attack Risk",
			Description: fmt.Sprintf("%.1f%% of peers from single ASN %d. High risk of eclipse attack!",
				metrics.TopASNPercent, metrics.TopASN),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
			Metadata: map[string]interface{}{
				"top_asn":        metrics.TopASN,
				"asn_percent":    metrics.TopASNPercent,
				"peers_from_asn": metrics.TopASNCount,
			},
		})
	} else if metrics.TopASNPercent >= m.config.MaxASNPercent {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "network-asn-concentration",
			Severity: "high",
			Title:    "High ASN Concentration",
			Description: fmt.Sprintf("%.1f%% of peers from ASN %d (threshold: %.1f%%)",
				metrics.TopASNPercent, metrics.TopASN, m.config.MaxASNPercent),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
			Metadata: map[string]interface{}{
				"top_asn":     metrics.TopASN,
				"asn_percent": metrics.TopASNPercent,
			},
		})
	}

	// Check country concentration
	if metrics.TopCountryPercent >= m.config.MaxCountryPercent {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "network-geographic-concentration",
			Severity: "medium",
			Title:    "Geographic Concentration",
			Description: fmt.Sprintf("%.1f%% of peers from %s (threshold: %.1f%%)",
				metrics.TopCountryPercent, metrics.TopCountry, m.config.MaxCountryPercent),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
			Metadata: map[string]interface{}{
				"top_country":     metrics.TopCountry,
				"country_percent": metrics.TopCountryPercent,
			},
		})
	}
}

// checkPeerQuality checks peer quality metrics.
func (m *Monitor) checkPeerQuality(ctx context.Context, metrics *NetworkMetrics) {
	if metrics.TotalPeers == 0 {
		return
	}

	if metrics.LowQualityPercent >= m.config.MaxLowQualityPercent {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "network-low-quality-peers",
			Severity: "medium",
			Title:    "High Percentage of Low-Quality Peers",
			Description: fmt.Sprintf("%.1f%% of peers have quality score <%.1f (threshold: %.1f%%)",
				metrics.LowQualityPercent,
				m.config.LowQualityThreshold,
				m.config.MaxLowQualityPercent),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
			Metadata: map[string]interface{}{
				"low_quality_count": metrics.LowQualityCount,
				"avg_quality_score": metrics.AvgQualityScore,
			},
		})
	}
}

// checkBandwidth checks bandwidth utilization.
func (m *Monitor) checkBandwidth(ctx context.Context, metrics *NetworkMetrics) {
	if metrics.BandwidthPercent >= m.config.BandwidthCritical {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "network-bandwidth-critical",
			Severity: "critical",
			Title:    "Bandwidth Saturation",
			Description: fmt.Sprintf("Bandwidth at %.1f%% of limit (%s of %s)",
				metrics.BandwidthPercent,
				formatBandwidth(metrics.BandwidthUsedBps),
				formatBandwidth(metrics.BandwidthLimit)),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
		})
	} else if metrics.BandwidthPercent >= m.config.BandwidthWarning {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "network-bandwidth-warning",
			Severity: "medium",
			Title:    "High Bandwidth Usage",
			Description: fmt.Sprintf("Bandwidth at %.1f%% of limit",
				metrics.BandwidthPercent),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
		})
	}
}

// checkConnectionFailures checks for excessive connection failures.
func (m *Monitor) checkConnectionFailures(ctx context.Context, metrics *NetworkMetrics) {
	if metrics.ConnectionFailures >= m.config.MaxConnectionFailures {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "network-connection-failures",
			Severity: "high",
			Title:    "Excessive Connection Failures",
			Description: fmt.Sprintf("%d connection failures in last minute (threshold: %d)",
				metrics.ConnectionFailures,
				m.config.MaxConnectionFailures),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
		})
	}
}

// checkChurn calculates and checks peer churn rate.
func (m *Monitor) checkChurn(ctx context.Context) {
	m.mu.Lock()

	if len(m.peerSnapshot) == 0 {
		m.mu.Unlock()
		return
	}

	// Count peers that left and joined
	left := 0
	for peerID := range m.peerSnapshot {
		if _, exists := m.peers[peerID]; !exists {
			left++
		}
	}

	joined := 0
	for peerID := range m.peers {
		if _, existed := m.peerSnapshot[peerID]; !existed {
			joined++
		}
	}

	totalChange := left + joined
	avgPeerCount := (len(m.peerSnapshot) + len(m.peers)) / 2
	if avgPeerCount == 0 {
		m.mu.Unlock()
		return
	}

	churnRate := float64(totalChange) / float64(avgPeerCount) * 100.0
	threshold := m.config.ChurnRateThreshold
	checkWindow := m.config.ChurnCheckWindow

	// Unlock before emitting alert to avoid deadlock
	m.mu.Unlock()

	if churnRate >= threshold {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "network-peer-churn-high",
			Severity: "high",
			Title:    "High Peer Churn Rate",
			Description: fmt.Sprintf("%.1f%% peer turnover in last %s (threshold: %.1f%%)",
				churnRate,
				checkWindow,
				threshold),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"churn_rate":   churnRate,
				"peers_left":   left,
				"peers_joined": joined,
			},
		})
	}
}

// takeSnapshot takes a snapshot of current peers for churn calculation.
func (m *Monitor) takeSnapshot() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.peerSnapshot = make(map[string]bool)
	for peerID := range m.peers {
		m.peerSnapshot[peerID] = true
	}
	m.snapshotTime = time.Now()
}

// emitAlert emits an alert with deduplication.
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

	m.logger.Warn("network alert generated",
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

// cleanup removes old data.
func (m *Monitor) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clean old connection failures
	cutoff := time.Now().Add(-10 * time.Minute)
	var recent []time.Time
	for _, failTime := range m.connectionFails {
		if failTime.After(cutoff) {
			recent = append(recent, failTime)
		}
	}
	m.connectionFails = recent

	// Clean old alerts
	alertCutoff := time.Now().Add(-30 * time.Minute)
	for alertType, lastTime := range m.recentAlerts {
		if lastTime.Before(alertCutoff) {
			delete(m.recentAlerts, alertType)
		}
	}
}

// GetCurrentMetrics returns current network metrics.
func (m *Monitor) GetCurrentMetrics() *NetworkMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.lastMetrics != nil {
		metrics := *m.lastMetrics
		return &metrics
	}
	return nil
}

// GetMetricsHistory returns historical metrics.
func (m *Monitor) GetMetricsHistory(limit int) []NetworkMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.metricsHistory) {
		limit = len(m.metricsHistory)
	}

	start := len(m.metricsHistory) - limit
	if start < 0 {
		start = 0
	}

	result := make([]NetworkMetrics, limit)
	copy(result, m.metricsHistory[start:])
	return result
}

// GetPeers returns all connected peers.
func (m *Monitor) GetPeers() []*PeerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peers := make([]*PeerInfo, 0, len(m.peers))
	for _, peer := range m.peers {
		peerCopy := *peer
		peers = append(peers, &peerCopy)
	}
	return peers
}

// GetPeer returns information about a specific peer.
func (m *Monitor) GetPeer(peerID string) (*PeerInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peer, ok := m.peers[peerID]
	if !ok {
		return nil, false
	}
	peerCopy := *peer
	return &peerCopy, true
}

// GetStats returns monitor statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"total_peers":    len(m.peers),
		"metrics_count":  len(m.metricsHistory),
		"check_interval": m.config.CheckInterval.String(),
	}

	if m.lastMetrics != nil {
		stats["inbound_peers"] = m.lastMetrics.InboundPeers
		stats["outbound_peers"] = m.lastMetrics.OutboundPeers
		stats["avg_quality_score"] = m.lastMetrics.AvgQualityScore
		stats["bandwidth_percent"] = m.lastMetrics.BandwidthPercent
	}

	return stats
}

// NormalizeToEvent converts a network alert to a schema.Event.
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
		metadata["total_peers"] = alert.Metrics.TotalPeers
		metadata["inbound_peers"] = alert.Metrics.InboundPeers
		metadata["outbound_peers"] = alert.Metrics.OutboundPeers
		metadata["avg_quality_score"] = alert.Metrics.AvgQualityScore
		metadata["bandwidth_percent"] = alert.Metrics.BandwidthPercent
	}

	return &schema.Event{
		EventID:   alert.ID,
		Timestamp: alert.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: "network-monitor",
			Host:    getHostname(),
			Version: "1.0",
		},
		Action:   fmt.Sprintf("network.%s", alert.Type),
		Outcome:  outcome,
		Severity: severity,
		Metadata: metadata,
	}
}

// formatBandwidth formats bandwidth into human-readable format.
func formatBandwidth(bps uint64) string {
	const unit = 1000
	if bps < unit {
		return fmt.Sprintf("%d bps", bps)
	}

	kbps := float64(bps) / unit
	if kbps < unit {
		return fmt.Sprintf("%.1f Kbps", kbps)
	}

	mbps := kbps / unit
	if mbps < unit {
		return fmt.Sprintf("%.1f Mbps", mbps)
	}

	gbps := mbps / unit
	return fmt.Sprintf("%.1f Gbps", gbps)
}

// getHostname returns the system hostname.
func getHostname() string {
	hostname, err := net.LookupAddr("127.0.0.1")
	if err != nil || len(hostname) == 0 {
		return "blockchain-node"
	}
	return hostname[0]
}

// CreateCorrelationRules creates network-related correlation rules.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "network-eclipse-attack",
			Name:        "Eclipse Attack Detected",
			Description: "Majority of peers concentrated in single ASN - eclipse attack risk",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"network", "eclipse", "attack"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0005",
				TacticName:  "Defense Evasion",
				TechniqueID: "T1562",
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "network.network-eclipse-attack-risk"},
			},
			GroupBy: []string{"source.host"},
			Window:  10 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "network-isolation",
			Name:        "Network Isolation",
			Description: "Node has very few peers and may be isolated from network",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"network", "isolation", "peers"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "network.network-peer-count-critical"},
			},
			GroupBy: []string{"source.host"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    2,
				Operator: "gte",
			},
		},
		{
			ID:          "network-bandwidth-saturation",
			Name:        "Bandwidth Saturation",
			Description: "Network bandwidth saturated - performance degradation likely",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"network", "bandwidth", "performance"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1499",
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "network.network-bandwidth-critical"},
			},
			GroupBy: []string{"source.host"},
			Window:  15 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    3,
				Operator: "gte",
			},
		},
		{
			ID:          "network-connection-storm",
			Name:        "Connection Failure Storm",
			Description: "High rate of connection failures indicates network or attack issues",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"network", "connections", "failures"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "network.network-connection-failures"},
			},
			GroupBy: []string{"source.host"},
			Window:  10 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    5,
				Operator: "gte",
			},
		},
	}
}

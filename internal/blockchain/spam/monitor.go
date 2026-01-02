package spam

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"
	"github.com/google/uuid"
)

// TransactionSpam represents a spam transaction pattern.
type TransactionSpam struct {
	Timestamp     time.Time
	SourceAddress string
	TxCount       int
	TxRate        float64 // Transactions per second
	PatternType   string  // "rate", "size", "duplicate"
}

// StorageMetrics contains storage bloat metrics.
type StorageMetrics struct {
	Timestamp time.Time

	// Storage size
	TotalStorageBytes  uint64
	StorageGrowthRate  float64 // GB/day
	StorageDaysToLimit int

	// Transaction pool
	TxPoolSize         int
	TxPoolSizePercent  float64
	TxPoolMaxSize      int

	// Spam detection
	SpamTxCount1h      int
	SpamTxRate         float64
	TopSpammerAddress  string
	TopSpammerTxCount  int

	// DOS indicators
	DOSPatternDetected bool
	DOSAttackType      string
}

// MonitorConfig contains configuration for the spam monitor.
type MonitorConfig struct {
	// Transaction spam thresholds
	TxRateThreshold       float64       // Tx/sec from single address
	TxPoolFullThreshold   float64       // Percentage
	SpamWindowDuration    time.Duration

	// Storage bloat thresholds
	StorageGrowthThreshold float64       // GB/day
	StorageAlertLeadDays   int          // Alert N days before limit
	MaxStorageGB           float64

	// DOS detection
	DOSTxRateThreshold    float64       // Global tx/sec
	DOSBurstSize          int          // Burst transaction count
	DOSBurstWindow        time.Duration

	// Monitoring
	CheckInterval    time.Duration
	MetricsRetention time.Duration
}

// DefaultMonitorConfig returns default configuration.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		TxRateThreshold:        10.0,             // 10 tx/sec from single address
		TxPoolFullThreshold:    80.0,             // 80% full
		SpamWindowDuration:     1 * time.Minute,

		StorageGrowthThreshold: 50.0,             // 50 GB/day
		StorageAlertLeadDays:   7,               // 7 days before limit
		MaxStorageGB:           1000.0,          // 1 TB limit

		DOSTxRateThreshold:     1000.0,          // 1000 tx/sec globally
		DOSBurstSize:           10000,           // 10k transactions
		DOSBurstWindow:         1 * time.Minute,

		CheckInterval:          30 * time.Second,
		MetricsRetention:       24 * time.Hour,
	}
}

// Alert represents a spam/bloat alert.
type Alert struct {
	ID          uuid.UUID
	Type        string
	Severity    string
	Title       string
	Description string
	Timestamp   time.Time
	Metadata    map[string]interface{}
	Metrics     *StorageMetrics
}

// AlertHandler is a function that handles alerts.
type AlertHandler func(ctx context.Context, alert *Alert) error

// Monitor monitors spam and storage bloat.
type Monitor struct {
	config MonitorConfig
	logger *slog.Logger

	mu                sync.RWMutex
	spamPatterns      []TransactionSpam
	addressTxCounts   map[string]int
	storageHistory    []uint64
	metricsHistory    []StorageMetrics
	lastMetrics       *StorageMetrics
	handlers          []AlertHandler
	recentAlerts      map[string]time.Time
	currentTxPoolSize int
	currentStorageGB  float64
	recentTxCounts    []int
	lastTxCountTime   time.Time

	running bool
	stopCh  chan struct{}
}

// NewMonitor creates a new spam monitor.
func NewMonitor(config MonitorConfig) *Monitor {
	return &Monitor{
		config:          config,
		logger:          slog.Default(),
		spamPatterns:    make([]TransactionSpam, 0),
		addressTxCounts: make(map[string]int),
		storageHistory:  make([]uint64, 0),
		metricsHistory:  make([]StorageMetrics, 0),
		handlers:        make([]AlertHandler, 0),
		recentAlerts:    make(map[string]time.Time),
		recentTxCounts:  make([]int, 0),
		stopCh:          make(chan struct{}),
	}
}

// AddHandler adds an alert handler.
func (m *Monitor) AddHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// RecordTransaction records a transaction from an address.
func (m *Monitor) RecordTransaction(address string, timestamp time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.addressTxCounts[address]++
	m.lastTxCountTime = timestamp
}

// RecordTransactionBatch records multiple transactions at once.
func (m *Monitor) RecordTransactionBatch(count int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.recentTxCounts = append(m.recentTxCounts, count)
	if len(m.recentTxCounts) > 60 { // Keep last 60 samples
		m.recentTxCounts = m.recentTxCounts[1:]
	}
}

// UpdateTxPoolSize updates the current transaction pool size.
func (m *Monitor) UpdateTxPoolSize(size int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.currentTxPoolSize = size
}

// UpdateStorageSize updates the current storage size in GB.
func (m *Monitor) UpdateStorageSize(sizeGB float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.currentStorageGB = sizeGB
	sizeBytes := uint64(sizeGB * 1024 * 1024 * 1024)
	m.storageHistory = append(m.storageHistory, sizeBytes)

	// Keep only last 100 samples for growth rate calculation
	if len(m.storageHistory) > 100 {
		m.storageHistory = m.storageHistory[1:]
	}
}

// CollectMetrics collects current spam and storage metrics.
func (m *Monitor) CollectMetrics() *StorageMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()

	metrics := &StorageMetrics{
		Timestamp:     time.Now(),
		TxPoolSize:    m.currentTxPoolSize,
		TxPoolMaxSize: 50000, // Default max
	}

	// Calculate transaction pool percentage
	if metrics.TxPoolMaxSize > 0 {
		metrics.TxPoolSizePercent = float64(m.currentTxPoolSize) / float64(metrics.TxPoolMaxSize) * 100.0
	}

	// Calculate storage metrics
	if len(m.storageHistory) > 0 {
		metrics.TotalStorageBytes = m.storageHistory[len(m.storageHistory)-1]

		// Calculate growth rate if we have enough history
		if len(m.storageHistory) >= 2 {
			oldest := m.storageHistory[0]
			newest := m.storageHistory[len(m.storageHistory)-1]
			bytesGrowth := int64(newest) - int64(oldest)

			// Assume samples are taken at check interval
			timeDiff := time.Duration(len(m.storageHistory)-1) * m.config.CheckInterval
			if timeDiff > 0 {
				gbPerDay := float64(bytesGrowth) / (1024*1024*1024) / timeDiff.Hours() * 24
				metrics.StorageGrowthRate = gbPerDay

				// Calculate days to limit
				if gbPerDay > 0 {
					currentGB := float64(newest) / (1024 * 1024 * 1024)
					remainingGB := m.config.MaxStorageGB - currentGB
					if remainingGB > 0 {
						metrics.StorageDaysToLimit = int(remainingGB / gbPerDay)
					}
				}
			}
		}
	}

	// Calculate spam metrics
	spamCount := 0
	maxTxCount := 0
	var topSpammer string

	for addr, count := range m.addressTxCounts {
		spamCount += count
		if count > maxTxCount {
			maxTxCount = count
			topSpammer = addr
		}
	}

	metrics.SpamTxCount1h = spamCount
	metrics.TopSpammerAddress = topSpammer
	metrics.TopSpammerTxCount = maxTxCount

	if spamCount > 0 {
		metrics.SpamTxRate = float64(spamCount) / 3600.0 // tx/sec
	}

	// Detect DOS patterns
	if len(m.recentTxCounts) > 0 {
		totalTx := 0
		for _, count := range m.recentTxCounts {
			totalTx += count
			if count >= m.config.DOSBurstSize {
				metrics.DOSPatternDetected = true
				metrics.DOSAttackType = "burst"
			}
		}

		avgTxRate := float64(totalTx) / float64(len(m.recentTxCounts)) / m.config.CheckInterval.Seconds()
		if avgTxRate >= m.config.DOSTxRateThreshold {
			metrics.DOSPatternDetected = true
			if metrics.DOSAttackType == "" {
				metrics.DOSAttackType = "sustained"
			}
		}
	}

	// Store metrics
	m.lastMetrics = metrics
	m.metricsHistory = append(m.metricsHistory, *metrics)

	// Clean old metrics
	cutoffTime := time.Now().Add(-m.config.MetricsRetention)
	for len(m.metricsHistory) > 0 && m.metricsHistory[0].Timestamp.Before(cutoffTime) {
		m.metricsHistory = m.metricsHistory[1:]
	}

	return metrics
}

// Start starts the monitoring loop.
func (m *Monitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("monitor already running")
	}
	m.running = true
	m.mu.Unlock()

	m.logger.Info("starting spam & storage bloat monitor",
		"check_interval", m.config.CheckInterval,
		"tx_rate_threshold", m.config.TxRateThreshold)

	go m.monitorLoop(ctx)
	return nil
}

// Stop stops the monitoring loop.
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return
	}

	close(m.stopCh)
	m.running = false
	m.logger.Info("spam & storage bloat monitor stopped")
}

// monitorLoop is the main monitoring loop.
func (m *Monitor) monitorLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	// Cleanup ticker for address counts
	cleanupTicker := time.NewTicker(m.config.SpamWindowDuration)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			metrics := m.CollectMetrics()
			if metrics != nil {
				m.checkAlerts(ctx, metrics)
			}
		case <-cleanupTicker.C:
			m.cleanupAddressCounts()
		}
	}
}

// checkAlerts checks for alert conditions.
func (m *Monitor) checkAlerts(ctx context.Context, metrics *StorageMetrics) {
	m.checkTxPoolAlerts(ctx, metrics)
	m.checkStorageAlerts(ctx, metrics)
	m.checkSpamAlerts(ctx, metrics)
	m.checkDOSAlerts(ctx, metrics)
}

// checkTxPoolAlerts checks for transaction pool saturation.
func (m *Monitor) checkTxPoolAlerts(ctx context.Context, metrics *StorageMetrics) {
	if metrics.TxPoolSizePercent >= m.config.TxPoolFullThreshold {
		severity := "medium"
		if metrics.TxPoolSizePercent >= 90.0 {
			severity = "high"
		}

		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "spam-txpool-saturation",
			Severity: severity,
			Title:    "Transaction Pool Saturation",
			Description: fmt.Sprintf("Transaction pool is %.1f%% full (%d/%d transactions). "+
				"May indicate spam attack or processing bottleneck.",
				metrics.TxPoolSizePercent, metrics.TxPoolSize, metrics.TxPoolMaxSize),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"txpool_percent": metrics.TxPoolSizePercent,
				"txpool_size":    metrics.TxPoolSize,
				"txpool_max":     metrics.TxPoolMaxSize,
			},
			Metrics: metrics,
		})
	}
}

// checkStorageAlerts checks for storage bloat.
func (m *Monitor) checkStorageAlerts(ctx context.Context, metrics *StorageMetrics) {
	// High growth rate alert
	if metrics.StorageGrowthRate >= m.config.StorageGrowthThreshold {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "spam-storage-bloat",
			Severity: "high",
			Title:    "Excessive Storage Growth",
			Description: fmt.Sprintf("Storage growing at %.1f GB/day (threshold: %.1f GB/day). "+
				"Rapid growth may indicate bloat or spam.",
				metrics.StorageGrowthRate, m.config.StorageGrowthThreshold),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"growth_rate_gb_per_day": metrics.StorageGrowthRate,
				"threshold_gb_per_day":   m.config.StorageGrowthThreshold,
				"days_to_limit":          metrics.StorageDaysToLimit,
			},
			Metrics: metrics,
		})
	}

	// Approaching storage limit alert
	if metrics.StorageDaysToLimit > 0 && metrics.StorageDaysToLimit <= m.config.StorageAlertLeadDays {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "spam-storage-limit-approaching",
			Severity: "critical",
			Title:    "CRITICAL: Storage Limit Approaching",
			Description: fmt.Sprintf("Storage will reach limit in %d days at current growth rate (%.1f GB/day). "+
				"Immediate action required.",
				metrics.StorageDaysToLimit, metrics.StorageGrowthRate),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"days_to_limit":          metrics.StorageDaysToLimit,
				"growth_rate_gb_per_day": metrics.StorageGrowthRate,
				"alert_lead_days":        m.config.StorageAlertLeadDays,
			},
			Metrics: metrics,
		})
	}
}

// checkSpamAlerts checks for spam patterns.
func (m *Monitor) checkSpamAlerts(ctx context.Context, metrics *StorageMetrics) {
	// Check for high-volume spammer
	if metrics.TopSpammerTxCount > 0 {
		txPerSec := float64(metrics.TopSpammerTxCount) / 3600.0
		if txPerSec >= m.config.TxRateThreshold {
			m.emitAlert(ctx, &Alert{
				ID:       uuid.New(),
				Type:     "spam-high-volume-address",
				Severity: "high",
				Title:    "High-Volume Spam Address Detected",
				Description: fmt.Sprintf("Address %s sent %d transactions in 1 hour (%.2f tx/sec, threshold: %.2f). "+
					"Possible spam or attack.",
					metrics.TopSpammerAddress[:10]+"...", metrics.TopSpammerTxCount, txPerSec, m.config.TxRateThreshold),
				Timestamp: time.Now(),
				Metadata: map[string]interface{}{
					"address":         metrics.TopSpammerAddress,
					"tx_count":        metrics.TopSpammerTxCount,
					"tx_rate":         txPerSec,
					"threshold":       m.config.TxRateThreshold,
				},
				Metrics: metrics,
			})
		}
	}
}

// checkDOSAlerts checks for DOS attack patterns.
func (m *Monitor) checkDOSAlerts(ctx context.Context, metrics *StorageMetrics) {
	if metrics.DOSPatternDetected {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "spam-dos-attack",
			Severity: "critical",
			Title:    "CRITICAL: DOS Attack Pattern Detected",
			Description: fmt.Sprintf("DOS attack pattern detected (type: %s). "+
				"Transaction rate or burst size exceeds normal thresholds.",
				metrics.DOSAttackType),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"attack_type": metrics.DOSAttackType,
				"tx_rate":     metrics.SpamTxRate,
			},
			Metrics: metrics,
		})
	}
}

// emitAlert emits an alert to all handlers.
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

	m.logger.Warn("spam alert generated",
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

// cleanupAddressCounts resets address transaction counts.
func (m *Monitor) cleanupAddressCounts() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Reset counts after spam window
	m.addressTxCounts = make(map[string]int)
}

// GetCurrentMetrics returns the most recent metrics.
func (m *Monitor) GetCurrentMetrics() *StorageMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastMetrics
}

// GetMetricsHistory returns historical metrics.
func (m *Monitor) GetMetricsHistory() []StorageMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]StorageMetrics{}, m.metricsHistory...)
}

// GetStats returns monitor statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"storage_samples":  len(m.storageHistory),
		"metrics_count":    len(m.metricsHistory),
		"tx_pool_size":     m.currentTxPoolSize,
		"storage_gb":       m.currentStorageGB,
	}

	if m.lastMetrics != nil {
		stats["storage_growth_gb_per_day"] = m.lastMetrics.StorageGrowthRate
		stats["txpool_percent"] = m.lastMetrics.TxPoolSizePercent
		stats["spam_tx_count_1h"] = m.lastMetrics.SpamTxCount1h
	}

	return stats
}

// NormalizeToEvent converts a spam alert to a schema.Event.
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
		metadata["storage_growth_gb_per_day"] = alert.Metrics.StorageGrowthRate
		metadata["txpool_percent"] = alert.Metrics.TxPoolSizePercent
		metadata["spam_tx_count"] = alert.Metrics.SpamTxCount1h
		metadata["dos_detected"] = alert.Metrics.DOSPatternDetected
	}

	return &schema.Event{
		EventID:   alert.ID,
		Timestamp: alert.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: "spam-monitor",
			Host:    getHostname(),
			Version: "1.0",
		},
		Action:   fmt.Sprintf("spam.%s", alert.Type),
		Outcome:  outcome,
		Severity: severity,
		Metadata: metadata,
	}
}

// getHostname returns the system hostname.
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// CreateCorrelationRules creates correlation rules for spam monitoring.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "spam-txpool-flooding",
			Name:        "Transaction Pool Flooding Attack",
			Description: "Sustained transaction pool saturation indicating spam or DOS attack",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "spam", "dos"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1498", // Network Denial of Service
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "spam.spam-txpool-saturation"},
			},
			GroupBy: []string{"source.host"},
			Window:  15 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    3,
				Operator: "gte",
			},
		},
		{
			ID:          "spam-storage-bloat-attack",
			Name:        "Storage Bloat Attack",
			Description: "Excessive storage growth indicating spam or bloat attack",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "spam", "storage"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1499", // Endpoint Denial of Service
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "spam.spam-storage-bloat"},
			},
			GroupBy: []string{"source.host"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    2,
				Operator: "gte",
			},
		},
		{
			ID:          "spam-dos-attack-critical",
			Name:        "Critical DOS Attack Pattern",
			Description: "DOS attack pattern detected with burst or sustained high transaction rate",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"blockchain", "spam", "dos", "attack"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1498", // Network Denial of Service
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "spam.spam-dos-attack"},
			},
			GroupBy: []string{"source.host"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "spam-high-volume-spammer",
			Name:        "High-Volume Spam Address",
			Description: "Single address generating excessive transaction volume",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "spam", "address"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "spam.spam-high-volume-address"},
			},
			GroupBy: []string{"source.host"},
			Window:  30 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    2,
				Operator: "gte",
			},
		},
	}
}

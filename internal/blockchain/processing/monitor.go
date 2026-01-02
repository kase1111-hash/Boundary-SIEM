package processing

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"
	"github.com/google/uuid"
)

// BlockInfo contains information about a processed block.
type BlockInfo struct {
	Slot          uint64
	Hash          string
	ParentHash    string
	StartTime     time.Time
	EndTime       time.Time
	ProcessingMS  int64
	Attestations  int
	Transactions  int
	StateRootMS   int64
	Success       bool
	ErrorMessage  string
}

// ProcessingMetrics contains aggregated block processing metrics.
type ProcessingMetrics struct {
	Timestamp time.Time

	// Block import latency
	AvgBlockProcessingMS int64
	P50BlockProcessingMS int64
	P95BlockProcessingMS int64
	P99BlockProcessingMS int64
	MaxBlockProcessingMS int64

	// Stuck block detection
	StuckBlock     bool
	StuckSlot      uint64
	StuckDuration  time.Duration

	// Throughput
	BlocksProcessed1m   int
	BlocksProcessed5m   int
	BlocksProcessed15m  int
	AvgThroughputBPS    float64 // Blocks per second

	// Attestation performance
	AvgAttestationsPerBlock int
	TotalAttestations       int

	// State root performance
	AvgStateRootMS int64
	P95StateRootMS int64

	// Error tracking
	FailedBlocks1m  int
	FailureRate     float64
}

// MonitorConfig contains configuration for the processing monitor.
type MonitorConfig struct {
	// Thresholds
	SlowBlockThresholdMS   int64         // Alert if block takes longer than this
	StuckBlockTimeout      time.Duration // Alert if no blocks processed in this time
	LowThroughputThreshold float64       // Blocks per second threshold
	HighFailureRate        float64       // Percentage threshold for failures

	// Performance targets
	TargetBlockProcessingMS int64
	TargetStateRootMS       int64

	// Monitoring
	CheckInterval    time.Duration
	MetricsRetention time.Duration
	SampleSize       int // Number of recent blocks to keep for percentile calculations
}

// DefaultMonitorConfig returns default configuration.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		SlowBlockThresholdMS:    5000,              // 5 seconds
		StuckBlockTimeout:       10 * time.Minute,  // 10 minutes
		LowThroughputThreshold:  0.05,              // Less than 1 block per 20 seconds
		HighFailureRate:         5.0,               // 5% failure rate
		TargetBlockProcessingMS: 1000,              // 1 second target
		TargetStateRootMS:       500,               // 500ms target
		CheckInterval:           30 * time.Second,
		MetricsRetention:        24 * time.Hour,
		SampleSize:              1000,
	}
}

// Alert represents a processing alert.
type Alert struct {
	ID          uuid.UUID
	Type        string
	Severity    string
	Title       string
	Description string
	Timestamp   time.Time
	Metadata    map[string]interface{}
	Metrics     *ProcessingMetrics
}

// AlertHandler is a function that handles alerts.
type AlertHandler func(ctx context.Context, alert *Alert) error

// Monitor monitors block processing performance.
type Monitor struct {
	config MonitorConfig
	logger *slog.Logger

	mu                sync.RWMutex
	recentBlocks      []BlockInfo
	currentBlock      *BlockInfo
	lastBlockTime     time.Time
	metricsHistory    []ProcessingMetrics
	lastMetrics       *ProcessingMetrics
	handlers          []AlertHandler
	recentAlerts      map[string]time.Time

	// Throughput tracking
	blocks1m          []time.Time
	blocks5m          []time.Time
	blocks15m         []time.Time

	running bool
	stopCh  chan struct{}
}

// NewMonitor creates a new processing monitor.
func NewMonitor(config MonitorConfig) *Monitor {
	return &Monitor{
		config:         config,
		logger:         slog.Default(),
		recentBlocks:   make([]BlockInfo, 0, config.SampleSize),
		metricsHistory: make([]ProcessingMetrics, 0),
		handlers:       make([]AlertHandler, 0),
		recentAlerts:   make(map[string]time.Time),
		blocks1m:       make([]time.Time, 0),
		blocks5m:       make([]time.Time, 0),
		blocks15m:      make([]time.Time, 0),
		stopCh:         make(chan struct{}),
	}
}

// AddHandler adds an alert handler.
func (m *Monitor) AddHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// StartBlock marks the start of processing a new block.
func (m *Monitor) StartBlock(slot uint64, hash, parentHash string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.currentBlock = &BlockInfo{
		Slot:       slot,
		Hash:       hash,
		ParentHash: parentHash,
		StartTime:  time.Now(),
	}
}

// EndBlock marks the end of processing a block.
func (m *Monitor) EndBlock(success bool, attestations, transactions int, stateRootMS int64, errorMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.currentBlock == nil {
		return
	}

	m.currentBlock.EndTime = time.Now()
	m.currentBlock.ProcessingMS = m.currentBlock.EndTime.Sub(m.currentBlock.StartTime).Milliseconds()
	m.currentBlock.Success = success
	m.currentBlock.Attestations = attestations
	m.currentBlock.Transactions = transactions
	m.currentBlock.StateRootMS = stateRootMS
	m.currentBlock.ErrorMessage = errorMsg

	// Add to recent blocks
	m.recentBlocks = append(m.recentBlocks, *m.currentBlock)
	if len(m.recentBlocks) > m.config.SampleSize {
		m.recentBlocks = m.recentBlocks[1:]
	}

	// Update throughput tracking
	now := time.Now()
	m.blocks1m = append(m.blocks1m, now)
	m.blocks5m = append(m.blocks5m, now)
	m.blocks15m = append(m.blocks15m, now)

	m.lastBlockTime = now
	m.currentBlock = nil
}

// RecordBlockProcessing is a convenience method to record a complete block processing event.
func (m *Monitor) RecordBlockProcessing(slot uint64, hash, parentHash string, processingMS, stateRootMS int64,
	attestations, transactions int, success bool, errorMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	blockInfo := BlockInfo{
		Slot:         slot,
		Hash:         hash,
		ParentHash:   parentHash,
		StartTime:    time.Now().Add(-time.Duration(processingMS) * time.Millisecond),
		EndTime:      time.Now(),
		ProcessingMS: processingMS,
		StateRootMS:  stateRootMS,
		Attestations: attestations,
		Transactions: transactions,
		Success:      success,
		ErrorMessage: errorMsg,
	}

	m.recentBlocks = append(m.recentBlocks, blockInfo)
	if len(m.recentBlocks) > m.config.SampleSize {
		m.recentBlocks = m.recentBlocks[1:]
	}

	now := time.Now()
	m.blocks1m = append(m.blocks1m, now)
	m.blocks5m = append(m.blocks5m, now)
	m.blocks15m = append(m.blocks15m, now)

	m.lastBlockTime = now
}

// CollectMetrics collects current processing metrics.
func (m *Monitor) CollectMetrics() *ProcessingMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.recentBlocks) == 0 {
		return nil
	}

	metrics := &ProcessingMetrics{
		Timestamp: time.Now(),
	}

	// Calculate block processing latency metrics
	processingTimes := make([]int64, 0, len(m.recentBlocks))
	stateRootTimes := make([]int64, 0, len(m.recentBlocks))
	totalAttestations := 0
	failedBlocks1m := 0
	totalProcessingMS := int64(0)

	cutoff1m := time.Now().Add(-1 * time.Minute)

	for _, block := range m.recentBlocks {
		processingTimes = append(processingTimes, block.ProcessingMS)
		if block.StateRootMS > 0 {
			stateRootTimes = append(stateRootTimes, block.StateRootMS)
		}
		totalAttestations += block.Attestations
		totalProcessingMS += block.ProcessingMS

		if !block.Success && block.EndTime.After(cutoff1m) {
			failedBlocks1m++
		}
	}

	// Calculate percentiles
	sort.Slice(processingTimes, func(i, j int) bool {
		return processingTimes[i] < processingTimes[j]
	})

	metrics.AvgBlockProcessingMS = totalProcessingMS / int64(len(m.recentBlocks))
	metrics.P50BlockProcessingMS = percentile(processingTimes, 50)
	metrics.P95BlockProcessingMS = percentile(processingTimes, 95)
	metrics.P99BlockProcessingMS = percentile(processingTimes, 99)
	metrics.MaxBlockProcessingMS = processingTimes[len(processingTimes)-1]

	// State root metrics
	if len(stateRootTimes) > 0 {
		sort.Slice(stateRootTimes, func(i, j int) bool {
			return stateRootTimes[i] < stateRootTimes[j]
		})
		totalStateRoot := int64(0)
		for _, t := range stateRootTimes {
			totalStateRoot += t
		}
		metrics.AvgStateRootMS = totalStateRoot / int64(len(stateRootTimes))
		metrics.P95StateRootMS = percentile(stateRootTimes, 95)
	}

	// Attestation metrics
	metrics.TotalAttestations = totalAttestations
	metrics.AvgAttestationsPerBlock = totalAttestations / len(m.recentBlocks)

	// Throughput metrics
	metrics.BlocksProcessed1m = m.countBlocksSince(m.blocks1m, 1*time.Minute)
	metrics.BlocksProcessed5m = m.countBlocksSince(m.blocks5m, 5*time.Minute)
	metrics.BlocksProcessed15m = m.countBlocksSince(m.blocks15m, 15*time.Minute)

	if metrics.BlocksProcessed1m > 0 {
		metrics.AvgThroughputBPS = float64(metrics.BlocksProcessed1m) / 60.0
	}

	// Failure rate
	metrics.FailedBlocks1m = failedBlocks1m
	if metrics.BlocksProcessed1m > 0 {
		metrics.FailureRate = float64(failedBlocks1m) / float64(metrics.BlocksProcessed1m) * 100.0
	}

	// Stuck block detection
	if !m.lastBlockTime.IsZero() {
		timeSinceLastBlock := time.Since(m.lastBlockTime)
		if timeSinceLastBlock > m.config.StuckBlockTimeout {
			metrics.StuckBlock = true
			metrics.StuckDuration = timeSinceLastBlock
			if m.currentBlock != nil {
				metrics.StuckSlot = m.currentBlock.Slot
			}
		}
	}

	// Store metrics
	m.lastMetrics = metrics
	m.metricsHistory = append(m.metricsHistory, *metrics)

	// Clean old metrics
	cutoff := time.Now().Add(-m.config.MetricsRetention)
	for len(m.metricsHistory) > 0 && m.metricsHistory[0].Timestamp.Before(cutoff) {
		m.metricsHistory = m.metricsHistory[1:]
	}

	return metrics
}

// countBlocksSince counts blocks processed since the given duration.
func (m *Monitor) countBlocksSince(blocks []time.Time, duration time.Duration) int {
	cutoff := time.Now().Add(-duration)
	count := 0
	for i := len(blocks) - 1; i >= 0; i-- {
		if blocks[i].After(cutoff) {
			count++
		} else {
			break
		}
	}
	return count
}

// percentile calculates the percentile of a sorted slice.
func percentile(sorted []int64, p int) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := (len(sorted) * p) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
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

	m.logger.Info("starting block processing monitor",
		"check_interval", m.config.CheckInterval,
		"slow_threshold_ms", m.config.SlowBlockThresholdMS)

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
	m.logger.Info("block processing monitor stopped")
}

// monitorLoop is the main monitoring loop.
func (m *Monitor) monitorLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

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
			m.cleanup()
		}
	}
}

// checkAlerts checks for alert conditions.
func (m *Monitor) checkAlerts(ctx context.Context, metrics *ProcessingMetrics) {
	m.checkSlowBlockAlerts(ctx, metrics)
	m.checkStuckBlockAlerts(ctx, metrics)
	m.checkThroughputAlerts(ctx, metrics)
	m.checkFailureRateAlerts(ctx, metrics)
}

// checkSlowBlockAlerts checks for slow block processing.
func (m *Monitor) checkSlowBlockAlerts(ctx context.Context, metrics *ProcessingMetrics) {
	if metrics.P95BlockProcessingMS >= m.config.SlowBlockThresholdMS {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "processing-slow-blocks",
			Severity: "high",
			Title:    "Slow Block Processing",
			Description: fmt.Sprintf("P95 block processing time is %dms (threshold: %dms). "+
				"This may cause validator penalties or sync issues.",
				metrics.P95BlockProcessingMS, m.config.SlowBlockThresholdMS),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"p95_ms":        metrics.P95BlockProcessingMS,
				"p99_ms":        metrics.P99BlockProcessingMS,
				"max_ms":        metrics.MaxBlockProcessingMS,
				"avg_ms":        metrics.AvgBlockProcessingMS,
				"threshold_ms":  m.config.SlowBlockThresholdMS,
			},
			Metrics: metrics,
		})
	}
}

// checkStuckBlockAlerts checks for stuck block processing.
func (m *Monitor) checkStuckBlockAlerts(ctx context.Context, metrics *ProcessingMetrics) {
	if metrics.StuckBlock {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "processing-stuck-block",
			Severity: "critical",
			Title:    "CRITICAL: Block Processing Stuck",
			Description: fmt.Sprintf("No blocks processed in %s. "+
				"Node may be stuck or experiencing critical issues.",
				metrics.StuckDuration.Round(time.Second)),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"stuck_duration_seconds": metrics.StuckDuration.Seconds(),
				"stuck_slot":             metrics.StuckSlot,
				"timeout_seconds":        m.config.StuckBlockTimeout.Seconds(),
			},
			Metrics: metrics,
		})
	}
}

// checkThroughputAlerts checks for low throughput.
func (m *Monitor) checkThroughputAlerts(ctx context.Context, metrics *ProcessingMetrics) {
	if metrics.AvgThroughputBPS < m.config.LowThroughputThreshold && metrics.AvgThroughputBPS > 0 {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "processing-low-throughput",
			Severity: "medium",
			Title:    "Low Block Processing Throughput",
			Description: fmt.Sprintf("Block processing throughput is %.3f blocks/sec (threshold: %.3f blocks/sec). "+
				"Node is processing blocks slower than expected.",
				metrics.AvgThroughputBPS, m.config.LowThroughputThreshold),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"throughput_bps": metrics.AvgThroughputBPS,
				"threshold_bps":  m.config.LowThroughputThreshold,
				"blocks_1m":      metrics.BlocksProcessed1m,
			},
			Metrics: metrics,
		})
	}
}

// checkFailureRateAlerts checks for high failure rate.
func (m *Monitor) checkFailureRateAlerts(ctx context.Context, metrics *ProcessingMetrics) {
	if metrics.FailureRate >= m.config.HighFailureRate && metrics.FailedBlocks1m > 0 {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "processing-high-failure-rate",
			Severity: "high",
			Title:    "High Block Processing Failure Rate",
			Description: fmt.Sprintf("%.1f%% of blocks failed to process in last minute (threshold: %.1f%%). "+
				"%d blocks failed.",
				metrics.FailureRate, m.config.HighFailureRate, metrics.FailedBlocks1m),
			Timestamp: time.Now(),
			Metadata: map[string]interface{}{
				"failure_rate":    metrics.FailureRate,
				"failed_blocks":   metrics.FailedBlocks1m,
				"threshold":       m.config.HighFailureRate,
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

	m.logger.Warn("processing alert generated",
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

	// Clean old throughput tracking
	cutoff1m := time.Now().Add(-1 * time.Minute)
	cutoff5m := time.Now().Add(-5 * time.Minute)
	cutoff15m := time.Now().Add(-15 * time.Minute)

	m.blocks1m = filterTimeSlice(m.blocks1m, cutoff1m)
	m.blocks5m = filterTimeSlice(m.blocks5m, cutoff5m)
	m.blocks15m = filterTimeSlice(m.blocks15m, cutoff15m)
}

// filterTimeSlice filters a time slice to only include times after the cutoff.
func filterTimeSlice(times []time.Time, cutoff time.Time) []time.Time {
	filtered := make([]time.Time, 0)
	for _, t := range times {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

// GetCurrentMetrics returns the most recent metrics.
func (m *Monitor) GetCurrentMetrics() *ProcessingMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastMetrics
}

// GetMetricsHistory returns historical metrics.
func (m *Monitor) GetMetricsHistory() []ProcessingMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]ProcessingMetrics{}, m.metricsHistory...)
}

// GetRecentBlocks returns recent block processing info.
func (m *Monitor) GetRecentBlocks() []BlockInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]BlockInfo{}, m.recentBlocks...)
}

// GetStats returns monitor statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"total_blocks_tracked": len(m.recentBlocks),
		"metrics_count":        len(m.metricsHistory),
		"check_interval":       m.config.CheckInterval.String(),
	}

	if m.lastMetrics != nil {
		stats["avg_processing_ms"] = m.lastMetrics.AvgBlockProcessingMS
		stats["p95_processing_ms"] = m.lastMetrics.P95BlockProcessingMS
		stats["throughput_bps"] = m.lastMetrics.AvgThroughputBPS
		stats["failure_rate"] = m.lastMetrics.FailureRate
	}

	return stats
}

// NormalizeToEvent converts a processing alert to a schema.Event.
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
		metadata["avg_processing_ms"] = alert.Metrics.AvgBlockProcessingMS
		metadata["p95_processing_ms"] = alert.Metrics.P95BlockProcessingMS
		metadata["throughput_bps"] = alert.Metrics.AvgThroughputBPS
		metadata["failure_rate"] = alert.Metrics.FailureRate
	}

	return &schema.Event{
		EventID:   alert.ID,
		Timestamp: alert.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: "processing-monitor",
			Host:    getHostname(),
			Version: "1.0",
		},
		Action:   fmt.Sprintf("processing.%s", alert.Type),
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

// CreateCorrelationRules creates correlation rules for processing monitoring.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "processing-performance-degradation",
			Name:        "Block Processing Performance Degradation",
			Description: "Detects sustained slow block processing that may impact validator duties",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "processing", "performance"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1498",
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "processing.processing-slow-blocks"},
			},
			GroupBy: []string{"source.host"},
			Window:  15 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    3,
				Operator: "gte",
			},
		},
		{
			ID:          "processing-stuck-critical",
			Name:        "Critical Block Processing Stuck",
			Description: "Block processing has completely halted - immediate attention required",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"blockchain", "processing", "critical"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1499",
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "processing.processing-stuck-block"},
			},
			GroupBy: []string{"source.host"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "processing-throughput-decline",
			Name:        "Block Processing Throughput Decline",
			Description: "Block processing throughput has fallen below acceptable levels",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityMedium),
			Tags:        []string{"blockchain", "processing", "throughput"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "processing.processing-low-throughput"},
			},
			GroupBy: []string{"source.host"},
			Window:  10 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    2,
				Operator: "gte",
			},
		},
		{
			ID:          "processing-high-failures",
			Name:        "High Block Processing Failure Rate",
			Description: "Excessive block processing failures may indicate data corruption or bugs",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "processing", "failures"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1499",
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "processing.processing-high-failure-rate"},
			},
			GroupBy: []string{"source.host"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    2,
				Operator: "gte",
			},
		},
	}
}

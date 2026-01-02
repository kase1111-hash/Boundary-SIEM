// Package resources provides resource exhaustion monitoring for blockchain nodes.
package resources

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// ResourceType categorizes different resource types.
type ResourceType string

const (
	ResourceDisk        ResourceType = "disk"
	ResourceMemory      ResourceType = "memory"
	ResourceCPU         ResourceType = "cpu"
	ResourceDBConnPool  ResourceType = "db_connections"
	ResourcePeerConnPool ResourceType = "peer_connections"
)

// AlertSeverity defines alert severity levels.
type AlertSeverity string

const (
	SeverityWarning  AlertSeverity = "warning"
	SeverityHigh     AlertSeverity = "high"
	SeverityCritical AlertSeverity = "critical"
)

// ResourceMetrics contains current resource usage metrics.
type ResourceMetrics struct {
	Timestamp time.Time `json:"timestamp"`

	// Disk metrics
	DiskUsedBytes      uint64  `json:"disk_used_bytes"`
	DiskTotalBytes     uint64  `json:"disk_total_bytes"`
	DiskUsedPercent    float64 `json:"disk_used_percent"`
	DiskAvailableBytes uint64  `json:"disk_available_bytes"`
	DiskGrowthRate     float64 `json:"disk_growth_rate_gb_per_day"`
	DiskDaysUntilFull  int     `json:"disk_days_until_full"`

	// Memory metrics
	MemoryUsedBytes    uint64  `json:"memory_used_bytes"`
	MemoryTotalBytes   uint64  `json:"memory_total_bytes"`
	MemoryUsedPercent  float64 `json:"memory_used_percent"`
	MemoryGrowthRate   float64 `json:"memory_growth_rate_mb_per_hour"`
	MemoryLeakDetected bool    `json:"memory_leak_detected"`

	// CPU metrics
	CPUUsedPercent     float64       `json:"cpu_used_percent"`
	CPUCores           int           `json:"cpu_cores"`
	CPUSustainedHigh   bool          `json:"cpu_sustained_high"`
	CPUHighDuration    time.Duration `json:"cpu_high_duration"`

	// Connection pool metrics
	DBConnectionsUsed  int     `json:"db_connections_used"`
	DBConnectionsMax   int     `json:"db_connections_max"`
	DBConnectionsPercent float64 `json:"db_connections_percent"`

	PeerConnectionsUsed int     `json:"peer_connections_used"`
	PeerConnectionsMax  int     `json:"peer_connections_max"`
	PeerConnectionsPercent float64 `json:"peer_connections_percent"`
}

// Alert represents a resource exhaustion alert.
type Alert struct {
	ID          uuid.UUID              `json:"id"`
	Type        string                 `json:"type"`
	Severity    AlertSeverity          `json:"severity"`
	Resource    ResourceType           `json:"resource"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Metrics     *ResourceMetrics       `json:"metrics"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertHandler processes resource alerts.
type AlertHandler func(context.Context, *Alert) error

// MonitorConfig configures the resource monitor.
type MonitorConfig struct {
	// Disk monitoring
	DataDirPath        string  // Path to monitor for disk usage
	DiskThreshold      float64 // Percent (default: 85%)
	DiskCritical       float64 // Percent (default: 95%)
	DiskAlertLeadDays  int     // Days before full to alert (default: 7)

	// Memory monitoring
	MemoryThreshold       float64       // Percent (default: 90%)
	MemoryCritical        float64       // Percent (default: 95%)
	MemoryLeakDetection   bool          // Enable leak detection
	MemoryLeakThreshold   float64       // MB/hour growth to trigger leak alert (default: 1000)
	MemoryLeakSampleCount int           // Samples needed to confirm leak (default: 6)

	// CPU monitoring
	CPUThreshold         float64       // Percent (default: 85%)
	CPUCritical          float64       // Percent (default: 95%)
	CPUPersistencePeriod time.Duration // Duration of high CPU before alert (default: 15 min)

	// Connection pool monitoring
	MaxDBConnections         int     // Maximum DB connections
	DBConnectionWarning      float64 // Percent (default: 80%)
	DBConnectionCritical     float64 // Percent (default: 90%)
	MaxPeerConnections       int     // Maximum peer connections
	PeerConnectionWarning    float64 // Percent (default: 90%)
	PeerConnectionCritical   float64 // Percent (default: 95%)

	// Monitoring intervals
	CheckInterval        time.Duration // How often to check resources (default: 1 min)
	MetricsRetention     int           // Number of historical metrics to keep (default: 1440 = 24h at 1min)
	CleanupInterval      time.Duration // How often to clean old data (default: 1 hour)
}

// DefaultMonitorConfig returns default configuration.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		DataDirPath:       "/var/lib/blockchain",
		DiskThreshold:     85.0,
		DiskCritical:      95.0,
		DiskAlertLeadDays: 7,

		MemoryThreshold:       90.0,
		MemoryCritical:        95.0,
		MemoryLeakDetection:   true,
		MemoryLeakThreshold:   1000.0, // 1GB/hour
		MemoryLeakSampleCount: 6,      // 6 samples = 6 minutes at 1min interval

		CPUThreshold:         85.0,
		CPUCritical:          95.0,
		CPUPersistencePeriod: 15 * time.Minute,

		MaxDBConnections:       100,
		DBConnectionWarning:    80.0,
		DBConnectionCritical:   90.0,
		MaxPeerConnections:     150,
		PeerConnectionWarning:  90.0,
		PeerConnectionCritical: 95.0,

		CheckInterval:    1 * time.Minute,
		MetricsRetention: 1440, // 24 hours
		CleanupInterval:  1 * time.Hour,
	}
}

// Monitor monitors system resource usage and degradation.
type Monitor struct {
	config   MonitorConfig
	handlers []AlertHandler
	mu       sync.RWMutex

	// Historical metrics for trend analysis
	metricsHistory []ResourceMetrics

	// State tracking
	lastMetrics       *ResourceMetrics
	cpuHighStartTime  time.Time
	memoryLeakSamples []float64 // Recent memory usage samples for leak detection

	// Alert tracking (deduplication)
	recentAlerts map[string]time.Time // alert type -> last alert time

	// Lifecycle management
	stopCh chan struct{}
	wg     sync.WaitGroup
	logger *slog.Logger
}

// NewMonitor creates a new resource monitor.
func NewMonitor(config MonitorConfig) *Monitor {
	return &Monitor{
		config:            config,
		metricsHistory:    make([]ResourceMetrics, 0, config.MetricsRetention),
		memoryLeakSamples: make([]float64, 0, config.MemoryLeakSampleCount),
		recentAlerts:      make(map[string]time.Time),
		stopCh:            make(chan struct{}),
		logger:            slog.Default(),
	}
}

// AddHandler adds an alert handler.
func (m *Monitor) AddHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// Start starts the resource monitor.
func (m *Monitor) Start(ctx context.Context) error {
	m.logger.Info("starting resource monitor",
		"check_interval", m.config.CheckInterval,
		"data_dir", m.config.DataDirPath)

	// Initial check
	if err := m.check(ctx); err != nil {
		m.logger.Error("initial resource check failed", "error", err)
	}

	// Start monitoring loop
	m.wg.Add(1)
	go m.monitorLoop(ctx)

	// Start cleanup loop
	m.wg.Add(1)
	go m.cleanupLoop(ctx)

	return nil
}

// Stop stops the resource monitor.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	m.logger.Info("resource monitor stopped")
}

// monitorLoop runs the main monitoring loop.
func (m *Monitor) monitorLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			if err := m.check(ctx); err != nil {
				m.logger.Error("resource check failed", "error", err)
			}
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

// check performs a resource check and generates alerts if needed.
func (m *Monitor) check(ctx context.Context) error {
	metrics := &ResourceMetrics{
		Timestamp: time.Now(),
	}

	// Collect disk metrics
	if err := m.collectDiskMetrics(metrics); err != nil {
		m.logger.Error("failed to collect disk metrics", "error", err)
	}

	// Collect memory metrics
	m.collectMemoryMetrics(metrics)

	// Collect CPU metrics
	m.collectCPUMetrics(metrics)

	// Collect connection pool metrics (would need DB/peer connection tracking)
	m.collectConnectionMetrics(metrics)

	// Store metrics
	m.mu.Lock()
	m.metricsHistory = append(m.metricsHistory, *metrics)
	if len(m.metricsHistory) > m.config.MetricsRetention {
		m.metricsHistory = m.metricsHistory[1:]
	}
	m.lastMetrics = metrics
	m.mu.Unlock()

	// Analyze and generate alerts
	m.analyzeMetrics(ctx, metrics)

	return nil
}

// collectDiskMetrics collects disk usage metrics.
func (m *Monitor) collectDiskMetrics(metrics *ResourceMetrics) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(m.config.DataDirPath, &stat); err != nil {
		return fmt.Errorf("failed to stat filesystem: %w", err)
	}

	// Calculate disk usage
	totalBytes := stat.Blocks * uint64(stat.Bsize)
	availableBytes := stat.Bavail * uint64(stat.Bsize)
	usedBytes := totalBytes - availableBytes
	usedPercent := float64(usedBytes) / float64(totalBytes) * 100.0

	metrics.DiskTotalBytes = totalBytes
	metrics.DiskUsedBytes = usedBytes
	metrics.DiskAvailableBytes = availableBytes
	metrics.DiskUsedPercent = usedPercent

	// Calculate growth rate and days until full
	m.mu.RLock()
	if len(m.metricsHistory) > 0 {
		oldestMetric := m.metricsHistory[0]
		timeDiff := metrics.Timestamp.Sub(oldestMetric.Timestamp)
		if timeDiff > 0 {
			bytesGrowth := int64(metrics.DiskUsedBytes) - int64(oldestMetric.DiskUsedBytes)
			// Convert to GB/day
			gbPerDay := float64(bytesGrowth) / (1024 * 1024 * 1024) / timeDiff.Hours() * 24
			metrics.DiskGrowthRate = gbPerDay

			// Calculate days until full
			if gbPerDay > 0 {
				availableGB := float64(availableBytes) / (1024 * 1024 * 1024)
				metrics.DiskDaysUntilFull = int(availableGB / gbPerDay)
			} else {
				metrics.DiskDaysUntilFull = -1 // Not growing
			}
		}
	}
	m.mu.RUnlock()

	return nil
}

// collectMemoryMetrics collects memory usage metrics.
func (m *Monitor) collectMemoryMetrics(metrics *ResourceMetrics) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Get system memory info
	var sysInfo syscall.Sysinfo_t
	if err := syscall.Sysinfo(&sysInfo); err == nil {
		totalMemory := sysInfo.Totalram * uint64(sysInfo.Unit)
		freeMemory := sysInfo.Freeram * uint64(sysInfo.Unit)
		usedMemory := totalMemory - freeMemory

		metrics.MemoryTotalBytes = totalMemory
		metrics.MemoryUsedBytes = usedMemory
		metrics.MemoryUsedPercent = float64(usedMemory) / float64(totalMemory) * 100.0

		// Memory leak detection
		if m.config.MemoryLeakDetection {
			m.detectMemoryLeak(metrics)
		}
	}
}

// detectMemoryLeak detects memory leaks based on sustained growth.
func (m *Monitor) detectMemoryLeak(metrics *ResourceMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Add current memory usage to samples
	usedMB := float64(metrics.MemoryUsedBytes) / (1024 * 1024)
	m.memoryLeakSamples = append(m.memoryLeakSamples, usedMB)

	// Keep only recent samples
	if len(m.memoryLeakSamples) > m.config.MemoryLeakSampleCount {
		m.memoryLeakSamples = m.memoryLeakSamples[1:]
	}

	// Need enough samples to detect trend
	if len(m.memoryLeakSamples) < m.config.MemoryLeakSampleCount {
		return
	}

	// Calculate growth rate (MB per hour)
	first := m.memoryLeakSamples[0]
	last := m.memoryLeakSamples[len(m.memoryLeakSamples)-1]
	timeDiff := time.Duration(len(m.memoryLeakSamples)) * m.config.CheckInterval
	mbGrowth := last - first
	mbPerHour := mbGrowth / timeDiff.Hours()

	metrics.MemoryGrowthRate = mbPerHour

	// Check if leak detected
	if mbPerHour > m.config.MemoryLeakThreshold {
		metrics.MemoryLeakDetected = true
	}
}

// collectCPUMetrics collects CPU usage metrics.
func (m *Monitor) collectCPUMetrics(metrics *ResourceMetrics) {
	// Get CPU count
	metrics.CPUCores = runtime.NumCPU()

	// For CPU usage, we would need to track /proc/stat or use a library
	// For now, we'll use a simplified approach
	// In production, you'd read /proc/stat and calculate usage

	// Placeholder: In real implementation, calculate from /proc/stat
	// This would require reading twice with a small delay to calculate percentage
	metrics.CPUUsedPercent = 0 // To be implemented with proper /proc/stat reading

	// Track sustained high CPU
	m.mu.Lock()
	if metrics.CPUUsedPercent > m.config.CPUThreshold {
		if m.cpuHighStartTime.IsZero() {
			m.cpuHighStartTime = time.Now()
		}
		duration := time.Since(m.cpuHighStartTime)
		metrics.CPUHighDuration = duration
		if duration > m.config.CPUPersistencePeriod {
			metrics.CPUSustainedHigh = true
		}
	} else {
		m.cpuHighStartTime = time.Time{} // Reset
		metrics.CPUHighDuration = 0
	}
	m.mu.Unlock()
}

// collectConnectionMetrics collects connection pool metrics.
func (m *Monitor) collectConnectionMetrics(metrics *ResourceMetrics) {
	// These would be populated by external sources (DB client, peer manager)
	// For now, set to configured maximums
	metrics.DBConnectionsMax = m.config.MaxDBConnections
	metrics.PeerConnectionsMax = m.config.MaxPeerConnections

	// In real implementation, these would come from:
	// - Database client connection pool stats
	// - P2P network peer manager stats
	metrics.DBConnectionsUsed = 0
	metrics.PeerConnectionsUsed = 0

	if metrics.DBConnectionsMax > 0 {
		metrics.DBConnectionsPercent = float64(metrics.DBConnectionsUsed) / float64(metrics.DBConnectionsMax) * 100.0
	}
	if metrics.PeerConnectionsMax > 0 {
		metrics.PeerConnectionsPercent = float64(metrics.PeerConnectionsUsed) / float64(metrics.PeerConnectionsMax) * 100.0
	}
}

// analyzeMetrics analyzes metrics and generates alerts.
func (m *Monitor) analyzeMetrics(ctx context.Context, metrics *ResourceMetrics) {
	// Check disk usage
	m.checkDiskAlerts(ctx, metrics)

	// Check memory usage
	m.checkMemoryAlerts(ctx, metrics)

	// Check CPU usage
	m.checkCPUAlerts(ctx, metrics)

	// Check connection pools
	m.checkConnectionAlerts(ctx, metrics)
}

// checkDiskAlerts checks disk usage and generates alerts.
func (m *Monitor) checkDiskAlerts(ctx context.Context, metrics *ResourceMetrics) {
	// Critical: >95% or <3 days until full
	if metrics.DiskUsedPercent >= m.config.DiskCritical ||
		(metrics.DiskDaysUntilFull >= 0 && metrics.DiskDaysUntilFull < 3) {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "resource-disk-space-critical",
			Severity: SeverityCritical,
			Resource: ResourceDisk,
			Title:    "CRITICAL: Disk Space Exhaustion Imminent",
			Description: fmt.Sprintf("Disk usage at %.1f%% (%s used of %s). Estimated %d days until full.",
				metrics.DiskUsedPercent,
				formatBytes(metrics.DiskUsedBytes),
				formatBytes(metrics.DiskTotalBytes),
				metrics.DiskDaysUntilFull),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
			Metadata: map[string]interface{}{
				"available_gb": float64(metrics.DiskAvailableBytes) / (1024 * 1024 * 1024),
				"growth_rate":  metrics.DiskGrowthRate,
			},
		})
	} else if metrics.DiskUsedPercent >= m.config.DiskThreshold ||
		(metrics.DiskDaysUntilFull >= 0 && metrics.DiskDaysUntilFull < m.config.DiskAlertLeadDays) {
		// Warning: >85% or <7 days until full
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "resource-disk-space-warning",
			Severity: SeverityWarning,
			Resource: ResourceDisk,
			Title:    "Disk Space Running Low",
			Description: fmt.Sprintf("Disk usage at %.1f%% (%s used of %s). Estimated %d days until full.",
				metrics.DiskUsedPercent,
				formatBytes(metrics.DiskUsedBytes),
				formatBytes(metrics.DiskTotalBytes),
				metrics.DiskDaysUntilFull),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
			Metadata: map[string]interface{}{
				"available_gb": float64(metrics.DiskAvailableBytes) / (1024 * 1024 * 1024),
				"growth_rate":  metrics.DiskGrowthRate,
			},
		})
	}
}

// checkMemoryAlerts checks memory usage and generates alerts.
func (m *Monitor) checkMemoryAlerts(ctx context.Context, metrics *ResourceMetrics) {
	// Memory leak detected
	if metrics.MemoryLeakDetected {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "resource-memory-leak-detected",
			Severity: SeverityHigh,
			Resource: ResourceMemory,
			Title:    "Memory Leak Detected",
			Description: fmt.Sprintf("Memory growing at %.1f MB/hour. Current usage: %.1f%%",
				metrics.MemoryGrowthRate,
				metrics.MemoryUsedPercent),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
			Metadata: map[string]interface{}{
				"growth_rate_mb_per_hour": metrics.MemoryGrowthRate,
			},
		})
	}

	// Critical memory usage
	if metrics.MemoryUsedPercent >= m.config.MemoryCritical {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "resource-memory-critical",
			Severity: SeverityCritical,
			Resource: ResourceMemory,
			Title:    "CRITICAL: Memory Exhaustion",
			Description: fmt.Sprintf("Memory usage at %.1f%% (%s used of %s)",
				metrics.MemoryUsedPercent,
				formatBytes(metrics.MemoryUsedBytes),
				formatBytes(metrics.MemoryTotalBytes)),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
		})
	} else if metrics.MemoryUsedPercent >= m.config.MemoryThreshold {
		// Warning
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "resource-memory-warning",
			Severity: SeverityWarning,
			Resource: ResourceMemory,
			Title:    "Memory Usage High",
			Description: fmt.Sprintf("Memory usage at %.1f%% (%s used of %s)",
				metrics.MemoryUsedPercent,
				formatBytes(metrics.MemoryUsedBytes),
				formatBytes(metrics.MemoryTotalBytes)),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
		})
	}
}

// checkCPUAlerts checks CPU usage and generates alerts.
func (m *Monitor) checkCPUAlerts(ctx context.Context, metrics *ResourceMetrics) {
	if metrics.CPUSustainedHigh {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "resource-cpu-sustained-high",
			Severity: SeverityHigh,
			Resource: ResourceCPU,
			Title:    "Sustained High CPU Usage",
			Description: fmt.Sprintf("CPU usage at %.1f%% for %s (threshold: %.1f%% for %s)",
				metrics.CPUUsedPercent,
				metrics.CPUHighDuration,
				m.config.CPUThreshold,
				m.config.CPUPersistencePeriod),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
		})
	}
}

// checkConnectionAlerts checks connection pool usage and generates alerts.
func (m *Monitor) checkConnectionAlerts(ctx context.Context, metrics *ResourceMetrics) {
	// DB connection pool
	if metrics.DBConnectionsPercent >= m.config.DBConnectionCritical {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "resource-db-connections-critical",
			Severity: SeverityCritical,
			Resource: ResourceDBConnPool,
			Title:    "Database Connection Pool Near Limit",
			Description: fmt.Sprintf("DB connections at %.1f%% (%d of %d used)",
				metrics.DBConnectionsPercent,
				metrics.DBConnectionsUsed,
				metrics.DBConnectionsMax),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
		})
	} else if metrics.DBConnectionsPercent >= m.config.DBConnectionWarning {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "resource-db-connections-warning",
			Severity: SeverityWarning,
			Resource: ResourceDBConnPool,
			Title:    "Database Connection Pool High",
			Description: fmt.Sprintf("DB connections at %.1f%% (%d of %d used)",
				metrics.DBConnectionsPercent,
				metrics.DBConnectionsUsed,
				metrics.DBConnectionsMax),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
		})
	}

	// Peer connection pool
	if metrics.PeerConnectionsPercent >= m.config.PeerConnectionCritical {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "resource-peer-connections-critical",
			Severity: SeverityCritical,
			Resource: ResourcePeerConnPool,
			Title:    "Peer Connection Pool Near Limit",
			Description: fmt.Sprintf("Peer connections at %.1f%% (%d of %d used)",
				metrics.PeerConnectionsPercent,
				metrics.PeerConnectionsUsed,
				metrics.PeerConnectionsMax),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
		})
	} else if metrics.PeerConnectionsPercent >= m.config.PeerConnectionWarning {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "resource-peer-connections-warning",
			Severity: SeverityWarning,
			Resource: ResourcePeerConnPool,
			Title:    "Peer Connection Pool High",
			Description: fmt.Sprintf("Peer connections at %.1f%% (%d of %d used)",
				metrics.PeerConnectionsPercent,
				metrics.PeerConnectionsUsed,
				metrics.PeerConnectionsMax),
			Timestamp: metrics.Timestamp,
			Metrics:   metrics,
		})
	}
}

// emitAlert emits an alert with deduplication.
func (m *Monitor) emitAlert(ctx context.Context, alert *Alert) {
	// Deduplicate alerts (don't send same alert within 5 minutes)
	m.mu.Lock()
	lastAlert, exists := m.recentAlerts[alert.Type]
	if exists && time.Since(lastAlert) < 5*time.Minute {
		m.mu.Unlock()
		return
	}
	m.recentAlerts[alert.Type] = time.Now()
	handlers := m.handlers
	m.mu.Unlock()

	m.logger.Warn("resource alert generated",
		"type", alert.Type,
		"severity", alert.Severity,
		"resource", alert.Resource,
		"title", alert.Title)

	// Dispatch to handlers
	for _, handler := range handlers {
		go func(h AlertHandler) {
			if err := h(ctx, alert); err != nil {
				m.logger.Error("alert handler failed", "error", err)
			}
		}(handler)
	}
}

// cleanup removes old metrics and alerts.
func (m *Monitor) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clean old alert tracking
	cutoff := time.Now().Add(-30 * time.Minute)
	for alertType, lastTime := range m.recentAlerts {
		if lastTime.Before(cutoff) {
			delete(m.recentAlerts, alertType)
		}
	}

	m.logger.Debug("cleanup completed",
		"metrics_count", len(m.metricsHistory),
		"tracked_alerts", len(m.recentAlerts))
}

// GetCurrentMetrics returns the latest resource metrics.
func (m *Monitor) GetCurrentMetrics() *ResourceMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.lastMetrics != nil {
		// Return a copy
		metrics := *m.lastMetrics
		return &metrics
	}
	return nil
}

// GetMetricsHistory returns historical metrics.
func (m *Monitor) GetMetricsHistory(limit int) []ResourceMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.metricsHistory) {
		limit = len(m.metricsHistory)
	}

	start := len(m.metricsHistory) - limit
	if start < 0 {
		start = 0
	}

	// Return a copy
	result := make([]ResourceMetrics, limit)
	copy(result, m.metricsHistory[start:])
	return result
}

// GetStats returns monitor statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := map[string]interface{}{
		"metrics_count": len(m.metricsHistory),
		"check_interval": m.config.CheckInterval.String(),
	}

	if m.lastMetrics != nil {
		stats["last_check"] = m.lastMetrics.Timestamp
		stats["disk_used_percent"] = m.lastMetrics.DiskUsedPercent
		stats["memory_used_percent"] = m.lastMetrics.MemoryUsedPercent
		stats["cpu_used_percent"] = m.lastMetrics.CPUUsedPercent
		stats["disk_days_until_full"] = m.lastMetrics.DiskDaysUntilFull
	}

	return stats
}

// NormalizeToEvent converts a resource alert to a schema.Event.
func (m *Monitor) NormalizeToEvent(alert *Alert, tenantID string) *schema.Event {
	outcome := schema.OutcomeFailure
	severity := 6

	switch alert.Severity {
	case SeverityCritical:
		severity = 9
	case SeverityHigh:
		severity = 7
	case SeverityWarning:
		severity = 5
	}

	metadata := map[string]interface{}{
		"resource_type": string(alert.Resource),
		"alert_type":    alert.Type,
	}

	if alert.Metadata != nil {
		for k, v := range alert.Metadata {
			metadata[k] = v
		}
	}

	if alert.Metrics != nil {
		metadata["disk_used_percent"] = alert.Metrics.DiskUsedPercent
		metadata["memory_used_percent"] = alert.Metrics.MemoryUsedPercent
		metadata["cpu_used_percent"] = alert.Metrics.CPUUsedPercent
		metadata["disk_days_until_full"] = alert.Metrics.DiskDaysUntilFull
	}

	return &schema.Event{
		EventID:   alert.ID,
		Timestamp: alert.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: "resource-monitor",
			Host:    getHostname(),
			Version: "1.0",
		},
		Action:   fmt.Sprintf("resource.%s", alert.Type),
		Outcome:  outcome,
		Severity: severity,
		Target:   string(alert.Resource),
		Metadata: metadata,
	}
}

// formatBytes formats bytes into human-readable format.
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// getHostname returns the system hostname.
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// CreateCorrelationRules creates resource-related correlation rules.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "resource-disk-exhaustion-imminent",
			Name:        "Disk Exhaustion Imminent",
			Description: "Disk space critically low or will be full within 3 days",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"resource", "disk", "critical"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1499",
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "resource.resource-disk-space-critical"},
			},
			GroupBy: []string{"source.host"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "resource-memory-leak-sustained",
			Name:        "Sustained Memory Leak",
			Description: "Memory leak detected with sustained growth",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"resource", "memory", "leak"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "resource.resource-memory-leak-detected"},
			},
			GroupBy: []string{"source.host"},
			Window:  30 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    3,
				Operator: "gte",
			},
		},
		{
			ID:          "resource-multiple-exhaustion",
			Name:        "Multiple Resource Exhaustion",
			Description: "Multiple resources approaching limits simultaneously",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"resource", "multiple", "exhaustion"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "resource.resource-"},
				{Field: "severity", Operator: "gte", Value: 7},
			},
			GroupBy: []string{"source.host"},
			Window:  15 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    2,
				Operator: "gte",
			},
		},
	}
}

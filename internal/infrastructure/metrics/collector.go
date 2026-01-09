// Package metrics provides system and node metrics collection.
package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// MetricType categorizes metric types.
type MetricType string

const (
	MetricCPU        MetricType = "cpu"
	MetricMemory     MetricType = "memory"
	MetricDisk       MetricType = "disk"
	MetricNetwork    MetricType = "network"
	MetricProcess    MetricType = "process"
	MetricConnection MetricType = "connection"
	MetricLatency    MetricType = "latency"
)

// Metric represents a collected metric.
type Metric struct {
	Type      MetricType             `json:"type"`
	Name      string                 `json:"name"`
	Value     float64                `json:"value"`
	Unit      string                 `json:"unit"`
	Host      string                 `json:"host"`
	Timestamp time.Time              `json:"timestamp"`
	Tags      map[string]string      `json:"tags,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Threshold defines an alerting threshold.
type Threshold struct {
	Metric   string        `json:"metric"`
	Operator string        `json:"operator"` // gt, gte, lt, lte, eq
	Value    float64       `json:"value"`
	Severity string        `json:"severity"`
	Duration time.Duration `json:"duration"` // How long threshold must be exceeded
}

// Alert represents a metrics alert.
type Alert struct {
	ID          uuid.UUID `json:"id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Host        string    `json:"host"`
	Metric      string    `json:"metric"`
	Value       float64   `json:"value"`
	Threshold   float64   `json:"threshold"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// AlertHandler processes metric alerts.
type AlertHandler func(context.Context, *Alert) error

// CollectorConfig configures the metrics collector.
type CollectorConfig struct {
	CollectionInterval time.Duration
	RetentionPeriod    time.Duration
	Thresholds         []Threshold
	EnabledMetrics     []MetricType
}

// DefaultCollectorConfig returns default configuration.
func DefaultCollectorConfig() CollectorConfig {
	return CollectorConfig{
		CollectionInterval: 30 * time.Second,
		RetentionPeriod:    1 * time.Hour,
		Thresholds: []Threshold{
			{Metric: "cpu.usage", Operator: "gte", Value: 90, Severity: "high", Duration: 5 * time.Minute},
			{Metric: "memory.usage", Operator: "gte", Value: 90, Severity: "high", Duration: 5 * time.Minute},
			{Metric: "disk.usage", Operator: "gte", Value: 95, Severity: "critical", Duration: 0},
			{Metric: "network.errors", Operator: "gte", Value: 100, Severity: "medium", Duration: 1 * time.Minute},
			{Metric: "connections.count", Operator: "gte", Value: 10000, Severity: "high", Duration: 0},
		},
		EnabledMetrics: []MetricType{MetricCPU, MetricMemory, MetricDisk, MetricNetwork, MetricConnection},
	}
}

// Collector collects and monitors system metrics.
type Collector struct {
	config   CollectorConfig
	metrics  map[string][]*Metric
	handlers []AlertHandler
	mu       sync.RWMutex
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// Threshold state tracking
	thresholdBreaches map[string]time.Time // metric -> first breach time
}

// NewCollector creates a new metrics collector.
func NewCollector(config CollectorConfig) *Collector {
	return &Collector{
		config:            config,
		metrics:           make(map[string][]*Metric),
		stopCh:            make(chan struct{}),
		thresholdBreaches: make(map[string]time.Time),
	}
}

// AddHandler adds an alert handler.
func (c *Collector) AddHandler(handler AlertHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers = append(c.handlers, handler)
}

// RecordMetric records a metric value.
func (c *Collector) RecordMetric(metric *Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := fmt.Sprintf("%s.%s", metric.Type, metric.Name)
	c.metrics[key] = append(c.metrics[key], metric)

	// Check thresholds
	go c.checkThresholds(metric)
}

// RecordMetrics records multiple metrics.
func (c *Collector) RecordMetrics(metrics []*Metric) {
	for _, m := range metrics {
		c.RecordMetric(m)
	}
}

func (c *Collector) checkThresholds(metric *Metric) {
	ctx := context.Background()
	metricKey := fmt.Sprintf("%s.%s", metric.Type, metric.Name)

	for _, threshold := range c.config.Thresholds {
		if threshold.Metric != metricKey {
			continue
		}

		breached := false
		switch threshold.Operator {
		case "gt", ">":
			breached = metric.Value > threshold.Value
		case "gte", ">=":
			breached = metric.Value >= threshold.Value
		case "lt", "<":
			breached = metric.Value < threshold.Value
		case "lte", "<=":
			breached = metric.Value <= threshold.Value
		case "eq", "=":
			breached = metric.Value == threshold.Value
		}

		if breached {
			c.mu.Lock()
			firstBreach, exists := c.thresholdBreaches[metricKey]
			if !exists {
				c.thresholdBreaches[metricKey] = metric.Timestamp
				firstBreach = metric.Timestamp
			}
			c.mu.Unlock()

			// Check if duration requirement is met
			if threshold.Duration == 0 || metric.Timestamp.Sub(firstBreach) >= threshold.Duration {
				c.emitAlert(ctx, &Alert{
					ID:        uuid.New(),
					Type:      "threshold_breach",
					Severity:  threshold.Severity,
					Host:      metric.Host,
					Metric:    metricKey,
					Value:     metric.Value,
					Threshold: threshold.Value,
					Title:     fmt.Sprintf("Threshold breach: %s", metricKey),
					Description: fmt.Sprintf("%s on %s is %.2f (threshold: %.2f)",
						metricKey, metric.Host, metric.Value, threshold.Value),
					Timestamp: metric.Timestamp,
				})
			}
		} else {
			// Clear breach tracking
			c.mu.Lock()
			delete(c.thresholdBreaches, metricKey)
			c.mu.Unlock()
		}
	}
}

func (c *Collector) emitAlert(ctx context.Context, alert *Alert) {
	c.mu.RLock()
	handlers := c.handlers
	c.mu.RUnlock()

	for _, handler := range handlers {
		go func(h AlertHandler) {
			if err := h(ctx, alert); err != nil {
				slog.Error("metrics alert handler failed", "error", err)
			}
		}(handler)
	}
}

// GetMetrics returns metrics for a given key.
func (c *Collector) GetMetrics(metricType MetricType, name string, since time.Time) []*Metric {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := fmt.Sprintf("%s.%s", metricType, name)
	var result []*Metric
	for _, m := range c.metrics[key] {
		if m.Timestamp.After(since) {
			result = append(result, m)
		}
	}
	return result
}

// GetStats returns collector statistics.
func (c *Collector) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalMetrics := 0
	for _, v := range c.metrics {
		totalMetrics += len(v)
	}

	return map[string]interface{}{
		"metric_types":          len(c.metrics),
		"total_data_points":     totalMetrics,
		"active_breaches":       len(c.thresholdBreaches),
		"configured_thresholds": len(c.config.Thresholds),
	}
}

// Cleanup removes old metrics.
func (c *Collector) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := time.Now().Add(-c.config.RetentionPeriod)
	for key, metrics := range c.metrics {
		var kept []*Metric
		for _, m := range metrics {
			if m.Timestamp.After(cutoff) {
				kept = append(kept, m)
			}
		}
		c.metrics[key] = kept
	}
}

// NormalizeToEvent converts a metric to a schema.Event.
func (c *Collector) NormalizeToEvent(metric *Metric, tenantID string) *schema.Event {
	action := fmt.Sprintf("metric.%s.%s", metric.Type, metric.Name)

	severity := 1
	if metric.Value > 80 {
		severity = 3
	}
	if metric.Value > 90 {
		severity = 5
	}
	if metric.Value > 95 {
		severity = 7
	}

	metadata := map[string]interface{}{
		"value": metric.Value,
		"unit":  metric.Unit,
	}
	for k, v := range metric.Tags {
		metadata["tag_"+k] = v
	}
	for k, v := range metric.Metadata {
		metadata[k] = v
	}

	return &schema.Event{
		EventID:   uuid.New(),
		Timestamp: metric.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: "metrics-collector",
			Host:    metric.Host,
			Version: "1.0",
		},
		Action:   action,
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,
		Target:   metric.Host,
		Metadata: metadata,
	}
}

// ParsePrometheusMetric parses a Prometheus-format metric line.
func ParsePrometheusMetric(line string) (*Metric, error) {
	// Basic Prometheus format: metric_name{labels} value timestamp
	// This is a simplified parser
	var name string
	var value float64

	_, err := fmt.Sscanf(line, "%s %f", &name, &value)
	if err != nil {
		return nil, fmt.Errorf("failed to parse prometheus metric: %w", err)
	}

	metricType := MetricCPU
	if name[:3] == "mem" {
		metricType = MetricMemory
	} else if name[:4] == "disk" {
		metricType = MetricDisk
	} else if name[:3] == "net" {
		metricType = MetricNetwork
	}

	return &Metric{
		Type:      metricType,
		Name:      name,
		Value:     value,
		Timestamp: time.Now(),
	}, nil
}

// CreateCorrelationRules creates infrastructure-related correlation rules.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "infra-high-cpu",
			Name:        "Sustained High CPU Usage",
			Description: "CPU usage above 90% for extended period",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"infrastructure", "cpu", "performance"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "metric.cpu.usage"},
				{Field: "metadata.value", Operator: "gte", Value: float64(90)},
			},
			GroupBy: []string{"source.host"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    10,
				Operator: "gte",
			},
		},
		{
			ID:          "infra-memory-exhaustion",
			Name:        "Memory Exhaustion Warning",
			Description: "Memory usage critically high",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"infrastructure", "memory", "critical"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "metric.memory.usage"},
				{Field: "metadata.value", Operator: "gte", Value: float64(95)},
			},
			GroupBy: []string{"source.host"},
			Window:  2 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    4,
				Operator: "gte",
			},
		},
		{
			ID:          "infra-disk-full",
			Name:        "Disk Space Critical",
			Description: "Disk usage above 95%",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"infrastructure", "disk", "critical"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "metric.disk.usage"},
				{Field: "metadata.value", Operator: "gte", Value: float64(95)},
			},
			GroupBy: []string{"source.host"},
			Window:  1 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "infra-network-errors",
			Name:        "Network Error Spike",
			Description: "High rate of network errors detected",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityMedium),
			Tags:        []string{"infrastructure", "network", "errors"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "metric.network.error"},
			},
			GroupBy: []string{"source.host"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    50,
				Operator: "gte",
			},
		},
		{
			ID:          "infra-connection-flood",
			Name:        "Connection Flood Detected",
			Description: "Abnormally high number of connections",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"infrastructure", "network", "ddos"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1498",
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "metric.connection.count"},
				{Field: "metadata.value", Operator: "gte", Value: float64(10000)},
			},
			GroupBy: []string{"source.host"},
			Window:  1 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
	}
}

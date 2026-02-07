package correlation

import (
	"fmt"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"
)

// BaselineWindow defines the time window for a baseline calculation.
type BaselineWindow string

const (
	Baseline1h  BaselineWindow = "1h"
	Baseline24h BaselineWindow = "24h"
	Baseline7d  BaselineWindow = "7d"
)

// BaselineStats holds computed statistics for a metric.
type BaselineStats struct {
	P50     float64   `json:"p50"`
	P95     float64   `json:"p95"`
	P99     float64   `json:"p99"`
	Mean    float64   `json:"mean"`
	StdDev  float64   `json:"std_dev"`
	Min     float64   `json:"min"`
	Max     float64   `json:"max"`
	Samples int       `json:"samples"`
	Updated time.Time `json:"updated"`
}

// BaselineConfig configures adaptive threshold behavior for a rule.
type BaselineConfig struct {
	Metric     string         `yaml:"metric" json:"metric"`           // metric key (e.g., "event_count")
	Window     BaselineWindow `yaml:"window" json:"window"`           // 1h, 24h, 7d
	Multiplier float64        `yaml:"multiplier" json:"multiplier"`   // e.g., 1.5
	Percentile string         `yaml:"percentile" json:"percentile"`   // p50, p95, p99
	MinSamples int            `yaml:"min_samples" json:"min_samples"` // min data points before active
	WarmupDays int            `yaml:"warmup_days" json:"warmup_days"` // days in learning mode (default 7)
}

// BaselineEngine computes rolling statistics for rule metrics.
type BaselineEngine struct {
	mu       sync.RWMutex
	metrics  map[string]*metricStore // key: ruleID:groupKey:metric
	started  time.Time
}

type metricStore struct {
	mu       sync.Mutex
	samples  []timedSample
	maxAge   time.Duration
}

type timedSample struct {
	value float64
	ts    time.Time
}

// NewBaselineEngine creates a new baseline engine.
func NewBaselineEngine() *BaselineEngine {
	return &BaselineEngine{
		metrics: make(map[string]*metricStore),
		started: time.Now(),
	}
}

// Record adds a metric sample for a rule+group.
func (b *BaselineEngine) Record(ruleID, groupKey, metric string, value float64) {
	key := fmt.Sprintf("%s:%s:%s", ruleID, groupKey, metric)

	b.mu.RLock()
	store, ok := b.metrics[key]
	b.mu.RUnlock()

	if !ok {
		b.mu.Lock()
		store, ok = b.metrics[key]
		if !ok {
			store = &metricStore{
				maxAge: 7 * 24 * time.Hour, // keep 7 days of samples
			}
			b.metrics[key] = store
		}
		b.mu.Unlock()
	}

	store.mu.Lock()
	store.samples = append(store.samples, timedSample{value: value, ts: time.Now()})
	store.mu.Unlock()
}

// Stats computes baseline statistics for a metric within the given window.
func (b *BaselineEngine) Stats(ruleID, groupKey, metric string, window BaselineWindow) *BaselineStats {
	key := fmt.Sprintf("%s:%s:%s", ruleID, groupKey, metric)

	b.mu.RLock()
	store, ok := b.metrics[key]
	b.mu.RUnlock()

	if !ok {
		return nil
	}

	dur := windowDuration(window)
	cutoff := time.Now().Add(-dur)

	store.mu.Lock()
	// Trim old samples beyond max retention
	trimCutoff := time.Now().Add(-store.maxAge)
	trimmed := make([]timedSample, 0, len(store.samples))
	for _, s := range store.samples {
		if s.ts.After(trimCutoff) {
			trimmed = append(trimmed, s)
		}
	}
	store.samples = trimmed

	// Collect values within window
	var values []float64
	for _, s := range store.samples {
		if s.ts.After(cutoff) {
			values = append(values, s.value)
		}
	}
	store.mu.Unlock()

	if len(values) == 0 {
		return nil
	}

	sort.Float64s(values)

	stats := &BaselineStats{
		P50:     percentile(values, 0.50),
		P95:     percentile(values, 0.95),
		P99:     percentile(values, 0.99),
		Min:     values[0],
		Max:     values[len(values)-1],
		Samples: len(values),
		Updated: time.Now(),
	}

	// Mean
	var sum float64
	for _, v := range values {
		sum += v
	}
	stats.Mean = sum / float64(len(values))

	// Standard deviation
	var variance float64
	for _, v := range values {
		diff := v - stats.Mean
		variance += diff * diff
	}
	stats.StdDev = math.Sqrt(variance / float64(len(values)))

	return stats
}

// AdaptiveThreshold computes the threshold for a rule using its BaselineConfig.
// Returns the threshold value and whether the baseline is active (past warmup).
func (b *BaselineEngine) AdaptiveThreshold(ruleID, groupKey string, cfg *BaselineConfig) (float64, bool) {
	warmupDays := cfg.WarmupDays
	if warmupDays <= 0 {
		warmupDays = 7
	}
	warmupEnd := b.started.Add(time.Duration(warmupDays) * 24 * time.Hour)
	isWarmedUp := time.Now().After(warmupEnd)

	stats := b.Stats(ruleID, groupKey, cfg.Metric, cfg.Window)
	if stats == nil || stats.Samples < cfg.MinSamples {
		return 0, false
	}

	var baseValue float64
	switch cfg.Percentile {
	case "p50":
		baseValue = stats.P50
	case "p99":
		baseValue = stats.P99
	default:
		baseValue = stats.P95
	}

	multiplier := cfg.Multiplier
	if multiplier <= 0 {
		multiplier = 1.5
	}

	threshold := baseValue * multiplier

	if !isWarmedUp {
		slog.Debug("baseline in warmup mode",
			"rule_id", ruleID,
			"group_key", groupKey,
			"threshold", threshold,
			"warmup_remaining", time.Until(warmupEnd),
		)
	}

	return threshold, isWarmedUp
}

// Cleanup removes stale metric stores with no recent samples.
func (b *BaselineEngine) Cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	for key, store := range b.metrics {
		store.mu.Lock()
		if len(store.samples) == 0 {
			store.mu.Unlock()
			delete(b.metrics, key)
			continue
		}
		lastSample := store.samples[len(store.samples)-1]
		store.mu.Unlock()
		if lastSample.ts.Before(cutoff) {
			delete(b.metrics, key)
		}
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	idx := p * float64(len(sorted)-1)
	lower := int(math.Floor(idx))
	upper := int(math.Ceil(idx))
	if lower == upper {
		return sorted[lower]
	}
	weight := idx - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}

func windowDuration(w BaselineWindow) time.Duration {
	switch w {
	case Baseline1h:
		return time.Hour
	case Baseline24h:
		return 24 * time.Hour
	case Baseline7d:
		return 7 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}

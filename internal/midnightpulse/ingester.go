package midnightpulse

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"boundary-siem/internal/schema"
)

// EventHandler is called for each normalized event.
type EventHandler func(ctx context.Context, event *schema.Event) error

// Ingester polls Midnight Pulse for events and normalizes them.
type Ingester struct {
	client     *Client
	normalizer *Normalizer
	handler    EventHandler
	config     IngesterConfig
	logger     *slog.Logger

	mu           sync.RWMutex
	lastPollTime time.Time
	running      bool
	stopCh       chan struct{}
}

// IngesterConfig holds configuration for the ingester.
type IngesterConfig struct {
	// Polling configuration
	PollInterval time.Duration `yaml:"poll_interval"`
	BatchSize    int           `yaml:"batch_size"`

	// Feature toggles - log all important info
	IngestSessions      bool `yaml:"ingest_sessions"`
	IngestCrashes       bool `yaml:"ingest_crashes"`
	IngestMultiplayer   bool `yaml:"ingest_multiplayer"`
	IngestInputAnomalies bool `yaml:"ingest_input_anomalies"`
	IngestSaveLoad      bool `yaml:"ingest_save_load"`
	IngestPerformance   bool `yaml:"ingest_performance"`
	IngestLeaderboard   bool `yaml:"ingest_leaderboard"`
	IngestDifficulty    bool `yaml:"ingest_difficulty"`

	// Filtering
	MinAnomalySeverity string `yaml:"min_anomaly_severity"`
}

// DefaultIngesterConfig returns the default ingester configuration with all logging enabled.
func DefaultIngesterConfig() IngesterConfig {
	return IngesterConfig{
		PollInterval:         30 * time.Second,
		BatchSize:            100,
		IngestSessions:       true,
		IngestCrashes:        true,
		IngestMultiplayer:    true,
		IngestInputAnomalies: true,
		IngestSaveLoad:       true,
		IngestPerformance:    true,
		IngestLeaderboard:    true,
		IngestDifficulty:     true,
		MinAnomalySeverity:   "low", // Log all anomalies
	}
}

// NewIngester creates a new Midnight Pulse ingester.
func NewIngester(client *Client, normalizer *Normalizer, handler EventHandler, cfg IngesterConfig, logger *slog.Logger) *Ingester {
	if logger == nil {
		logger = slog.Default()
	}
	return &Ingester{
		client:     client,
		normalizer: normalizer,
		handler:    handler,
		config:     cfg,
		logger:     logger,
		stopCh:     make(chan struct{}),
	}
}

// Start begins polling Midnight Pulse for events.
func (i *Ingester) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return fmt.Errorf("ingester already running")
	}
	i.running = true
	i.lastPollTime = time.Now().Add(-i.config.PollInterval)
	i.mu.Unlock()

	i.logger.Info("starting Midnight Pulse ingester",
		"poll_interval", i.config.PollInterval,
		"ingest_sessions", i.config.IngestSessions,
		"ingest_crashes", i.config.IngestCrashes,
		"ingest_multiplayer", i.config.IngestMultiplayer,
		"ingest_input_anomalies", i.config.IngestInputAnomalies,
		"ingest_save_load", i.config.IngestSaveLoad,
		"ingest_performance", i.config.IngestPerformance,
		"ingest_leaderboard", i.config.IngestLeaderboard,
	)

	// Initial health check
	health, err := i.client.GetHealth(ctx)
	if err != nil {
		i.logger.Warn("Midnight Pulse health check failed", "error", err)
	} else {
		i.logger.Info("Midnight Pulse connection established",
			"status", health.Status,
			"version", health.Version,
			"active_sessions", health.ActiveSessions,
		)
	}

	go i.pollLoop(ctx)
	return nil
}

// Stop stops the ingester.
func (i *Ingester) Stop() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.running {
		close(i.stopCh)
		i.running = false
	}
}

// pollLoop continuously polls for new events.
func (i *Ingester) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(i.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			i.logger.Info("ingester context cancelled")
			return
		case <-i.stopCh:
			i.logger.Info("ingester stopped")
			return
		case <-ticker.C:
			i.poll(ctx)
		}
	}
}

// poll fetches new events from Midnight Pulse.
func (i *Ingester) poll(ctx context.Context) {
	i.mu.Lock()
	lastPoll := i.lastPollTime
	i.mu.Unlock()

	pollStart := time.Now()
	var eventCount int

	if i.config.IngestSessions {
		count := i.pollSessions(ctx)
		eventCount += count
	}

	if i.config.IngestCrashes {
		count := i.pollCrashes(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestMultiplayer {
		count := i.pollMultiplayer(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestInputAnomalies {
		count := i.pollInputAnomalies(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestSaveLoad {
		count := i.pollSaveLoad(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestPerformance {
		count := i.pollPerformance(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestLeaderboard {
		count := i.pollLeaderboard(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestDifficulty {
		count := i.pollDifficulty(ctx, lastPoll)
		eventCount += count
	}

	i.mu.Lock()
	i.lastPollTime = pollStart
	i.mu.Unlock()

	if eventCount > 0 {
		i.logger.Info("poll completed",
			"events_ingested", eventCount,
			"duration", time.Since(pollStart),
		)
	}
}

func (i *Ingester) pollSessions(ctx context.Context) int {
	sessions, err := i.client.GetSessions(ctx, "", i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch sessions", "error", err)
		return 0
	}

	var eventCount int
	for _, session := range sessions {
		eventType := "session." + session.Status
		sessionCopy := session
		event, err := i.normalizer.NormalizeSession(&sessionCopy, eventType)
		if err != nil {
			i.logger.Error("failed to normalize session", "session", session.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle session event", "session", session.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollCrashes(ctx context.Context, since time.Time) int {
	crashes, err := i.client.GetCrashEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch crashes", "error", err)
		return 0
	}

	var eventCount int
	for _, crash := range crashes {
		crashCopy := crash
		event, err := i.normalizer.NormalizeCrash(&crashCopy)
		if err != nil {
			i.logger.Error("failed to normalize crash", "crash", crash.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle crash event", "crash", crash.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollMultiplayer(ctx context.Context, since time.Time) int {
	events, err := i.client.GetMultiplayerEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch multiplayer events", "error", err)
		return 0
	}

	var eventCount int
	for _, mp := range events {
		mpCopy := mp
		event, err := i.normalizer.NormalizeMultiplayer(&mpCopy)
		if err != nil {
			i.logger.Error("failed to normalize multiplayer", "event", mp.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle multiplayer event", "event", mp.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollInputAnomalies(ctx context.Context, since time.Time) int {
	anomalies, err := i.client.GetInputAnomalies(ctx, since, i.config.MinAnomalySeverity)
	if err != nil {
		i.logger.Error("failed to fetch input anomalies", "error", err)
		return 0
	}

	var eventCount int
	for _, anomaly := range anomalies {
		anomalyCopy := anomaly
		event, err := i.normalizer.NormalizeInputAnomaly(&anomalyCopy)
		if err != nil {
			i.logger.Error("failed to normalize anomaly", "anomaly", anomaly.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle anomaly event", "anomaly", anomaly.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollSaveLoad(ctx context.Context, since time.Time) int {
	events, err := i.client.GetSaveLoadEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch save/load events", "error", err)
		return 0
	}

	var eventCount int
	for _, sl := range events {
		slCopy := sl
		event, err := i.normalizer.NormalizeSaveLoad(&slCopy)
		if err != nil {
			i.logger.Error("failed to normalize save/load", "event", sl.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle save/load event", "event", sl.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollPerformance(ctx context.Context, since time.Time) int {
	metrics, err := i.client.GetPerformanceMetrics(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch performance metrics", "error", err)
		return 0
	}

	var eventCount int
	for _, perf := range metrics {
		perfCopy := perf
		event, err := i.normalizer.NormalizePerformance(&perfCopy)
		if err != nil {
			i.logger.Error("failed to normalize performance", "metric", perf.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle performance event", "metric", perf.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollLeaderboard(ctx context.Context, since time.Time) int {
	submissions, err := i.client.GetLeaderboardSubmissions(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch leaderboard submissions", "error", err)
		return 0
	}

	var eventCount int
	for _, lb := range submissions {
		lbCopy := lb
		event, err := i.normalizer.NormalizeLeaderboard(&lbCopy)
		if err != nil {
			i.logger.Error("failed to normalize leaderboard", "submission", lb.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle leaderboard event", "submission", lb.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollDifficulty(ctx context.Context, since time.Time) int {
	events, err := i.client.GetDifficultyEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch difficulty events", "error", err)
		return 0
	}

	var eventCount int
	for _, diff := range events {
		diffCopy := diff
		event, err := i.normalizer.NormalizeDifficulty(&diffCopy)
		if err != nil {
			i.logger.Error("failed to normalize difficulty", "event", diff.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle difficulty event", "event", diff.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

// Stats returns current ingester statistics.
func (i *Ingester) Stats() IngesterStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return IngesterStats{
		Running:      i.running,
		LastPollTime: i.lastPollTime,
	}
}

// IngesterStats holds ingester statistics.
type IngesterStats struct {
	Running      bool      `json:"running"`
	LastPollTime time.Time `json:"last_poll_time"`
}

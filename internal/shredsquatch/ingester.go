package shredsquatch

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

// Ingester polls Shredsquatch for events and normalizes them.
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
	IngestRuns          bool `yaml:"ingest_runs"`
	IngestTricks        bool `yaml:"ingest_tricks"`
	IngestAnomalies     bool `yaml:"ingest_anomalies"`
	IngestLeaderboard   bool `yaml:"ingest_leaderboard"`
	IngestPerformance   bool `yaml:"ingest_performance"`
	IngestAssets        bool `yaml:"ingest_assets"`
	IngestPowerups      bool `yaml:"ingest_powerups"`
	IngestSasquatch     bool `yaml:"ingest_sasquatch"`
	IngestCollisions    bool `yaml:"ingest_collisions"`

	// Filtering
	MinAnomalySeverity string `yaml:"min_anomaly_severity"`
}

// DefaultIngesterConfig returns the default ingester configuration with all logging enabled.
func DefaultIngesterConfig() IngesterConfig {
	return IngesterConfig{
		PollInterval:       30 * time.Second,
		BatchSize:          100,
		IngestSessions:     true,
		IngestRuns:         true,
		IngestTricks:       true,
		IngestAnomalies:    true,
		IngestLeaderboard:  true,
		IngestPerformance:  true,
		IngestAssets:       true,
		IngestPowerups:     true,
		IngestSasquatch:    true,
		IngestCollisions:   true,
		MinAnomalySeverity: "low", // Log all anomalies
	}
}

// NewIngester creates a new Shredsquatch ingester.
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

// Start begins polling Shredsquatch for events.
func (i *Ingester) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return fmt.Errorf("ingester already running")
	}
	i.running = true
	i.lastPollTime = time.Now().Add(-i.config.PollInterval)
	i.mu.Unlock()

	i.logger.Info("starting Shredsquatch ingester",
		"poll_interval", i.config.PollInterval,
		"ingest_sessions", i.config.IngestSessions,
		"ingest_runs", i.config.IngestRuns,
		"ingest_tricks", i.config.IngestTricks,
		"ingest_anomalies", i.config.IngestAnomalies,
		"ingest_leaderboard", i.config.IngestLeaderboard,
	)

	// Initial health check
	health, err := i.client.GetHealth(ctx)
	if err != nil {
		i.logger.Warn("Shredsquatch health check failed", "error", err)
	} else {
		i.logger.Info("Shredsquatch connection established",
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

// poll fetches new events from Shredsquatch.
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

	if i.config.IngestRuns {
		count := i.pollRuns(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestTricks {
		count := i.pollTricks(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestAnomalies {
		count := i.pollAnomalies(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestLeaderboard {
		count := i.pollLeaderboard(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestPerformance {
		count := i.pollPerformance(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestAssets {
		count := i.pollAssets(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestPowerups {
		count := i.pollPowerups(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestSasquatch {
		count := i.pollSasquatch(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestCollisions {
		count := i.pollCollisions(ctx, lastPoll)
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

func (i *Ingester) pollRuns(ctx context.Context, since time.Time) int {
	runs, err := i.client.GetRunEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch runs", "error", err)
		return 0
	}

	var eventCount int
	for _, run := range runs {
		runCopy := run
		event, err := i.normalizer.NormalizeRun(&runCopy)
		if err != nil {
			i.logger.Error("failed to normalize run", "run", run.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle run event", "run", run.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollTricks(ctx context.Context, since time.Time) int {
	tricks, err := i.client.GetTrickEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch tricks", "error", err)
		return 0
	}

	var eventCount int
	for _, trick := range tricks {
		trickCopy := trick
		event, err := i.normalizer.NormalizeTrick(&trickCopy)
		if err != nil {
			i.logger.Error("failed to normalize trick", "trick", trick.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle trick event", "trick", trick.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollAnomalies(ctx context.Context, since time.Time) int {
	anomalies, err := i.client.GetInputAnomalies(ctx, since, i.config.MinAnomalySeverity)
	if err != nil {
		i.logger.Error("failed to fetch anomalies", "error", err)
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

func (i *Ingester) pollLeaderboard(ctx context.Context, since time.Time) int {
	submissions, err := i.client.GetLeaderboardSubmissions(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch leaderboard", "error", err)
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

func (i *Ingester) pollPerformance(ctx context.Context, since time.Time) int {
	metrics, err := i.client.GetPerformanceMetrics(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch performance", "error", err)
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

func (i *Ingester) pollAssets(ctx context.Context, since time.Time) int {
	assets, err := i.client.GetAssetEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch assets", "error", err)
		return 0
	}

	var eventCount int
	for _, asset := range assets {
		assetCopy := asset
		event, err := i.normalizer.NormalizeAsset(&assetCopy)
		if err != nil {
			i.logger.Error("failed to normalize asset", "asset", asset.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle asset event", "asset", asset.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollPowerups(ctx context.Context, since time.Time) int {
	powerups, err := i.client.GetPowerupEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch powerups", "error", err)
		return 0
	}

	var eventCount int
	for _, powerup := range powerups {
		powerupCopy := powerup
		event, err := i.normalizer.NormalizePowerup(&powerupCopy)
		if err != nil {
			i.logger.Error("failed to normalize powerup", "powerup", powerup.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle powerup event", "powerup", powerup.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollSasquatch(ctx context.Context, since time.Time) int {
	events, err := i.client.GetSasquatchEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch sasquatch events", "error", err)
		return 0
	}

	var eventCount int
	for _, sq := range events {
		sqCopy := sq
		event, err := i.normalizer.NormalizeSasquatch(&sqCopy)
		if err != nil {
			i.logger.Error("failed to normalize sasquatch", "event", sq.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle sasquatch event", "event", sq.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollCollisions(ctx context.Context, since time.Time) int {
	collisions, err := i.client.GetCollisionEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch collisions", "error", err)
		return 0
	}

	var eventCount int
	for _, col := range collisions {
		colCopy := col
		event, err := i.normalizer.NormalizeCollision(&colCopy)
		if err != nil {
			i.logger.Error("failed to normalize collision", "collision", col.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle collision event", "collision", col.ID, "error", err)
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

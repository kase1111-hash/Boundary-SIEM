package medicagent

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

// Ingester polls Medic-Agent for events and normalizes them.
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
	IngestKillNotifications   bool `yaml:"ingest_kill_notifications"`
	IngestRiskAssessments     bool `yaml:"ingest_risk_assessments"`
	IngestResurrections       bool `yaml:"ingest_resurrections"`
	IngestAnomalies           bool `yaml:"ingest_anomalies"`
	IngestThresholdAdjustments bool `yaml:"ingest_threshold_adjustments"`
	IngestRollbacks           bool `yaml:"ingest_rollbacks"`
	IngestApprovals           bool `yaml:"ingest_approvals"`
	IngestSmithIntegration    bool `yaml:"ingest_smith_integration"`

	// Filtering
	MinAnomalySeverity string `yaml:"min_anomaly_severity"`
}

// DefaultIngesterConfig returns the default ingester configuration with all logging enabled.
func DefaultIngesterConfig() IngesterConfig {
	return IngesterConfig{
		PollInterval:              30 * time.Second,
		BatchSize:                 100,
		IngestKillNotifications:   true,
		IngestRiskAssessments:     true,
		IngestResurrections:       true,
		IngestAnomalies:           true,
		IngestThresholdAdjustments: true,
		IngestRollbacks:           true,
		IngestApprovals:           true,
		IngestSmithIntegration:    true,
		MinAnomalySeverity:        "low", // Log all anomalies
	}
}

// NewIngester creates a new Medic-Agent ingester.
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

// Start begins polling Medic-Agent for events.
func (i *Ingester) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return fmt.Errorf("ingester already running")
	}
	i.running = true
	i.lastPollTime = time.Now().Add(-i.config.PollInterval)
	i.mu.Unlock()

	i.logger.Info("starting Medic-Agent ingester",
		"poll_interval", i.config.PollInterval,
		"ingest_kills", i.config.IngestKillNotifications,
		"ingest_assessments", i.config.IngestRiskAssessments,
		"ingest_resurrections", i.config.IngestResurrections,
		"ingest_anomalies", i.config.IngestAnomalies,
		"ingest_thresholds", i.config.IngestThresholdAdjustments,
		"ingest_rollbacks", i.config.IngestRollbacks,
		"ingest_approvals", i.config.IngestApprovals,
		"ingest_smith", i.config.IngestSmithIntegration,
	)

	// Initial health check
	health, err := i.client.GetHealth(ctx)
	if err != nil {
		i.logger.Warn("Medic-Agent health check failed", "error", err)
	} else {
		i.logger.Info("Medic-Agent connection established",
			"status", health.Status,
			"version", health.Version,
			"active_monitors", health.ActiveMonitors,
			"pending_approvals", health.PendingApprovals,
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

// poll fetches new events from Medic-Agent.
func (i *Ingester) poll(ctx context.Context) {
	i.mu.Lock()
	lastPoll := i.lastPollTime
	i.mu.Unlock()

	pollStart := time.Now()
	var eventCount int

	if i.config.IngestKillNotifications {
		count := i.pollKillNotifications(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestRiskAssessments {
		count := i.pollRiskAssessments(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestResurrections {
		count := i.pollResurrections(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestAnomalies {
		count := i.pollAnomalies(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestThresholdAdjustments {
		count := i.pollThresholdAdjustments(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestRollbacks {
		count := i.pollRollbacks(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestApprovals {
		count := i.pollApprovals(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestSmithIntegration {
		count := i.pollSmithIntegration(ctx, lastPoll)
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

func (i *Ingester) pollKillNotifications(ctx context.Context, since time.Time) int {
	kills, err := i.client.GetKillNotifications(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch kill notifications", "error", err)
		return 0
	}

	var eventCount int
	for _, kill := range kills {
		killCopy := kill
		event, err := i.normalizer.NormalizeKillNotification(&killCopy)
		if err != nil {
			i.logger.Error("failed to normalize kill notification", "kill", kill.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle kill notification event", "kill", kill.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollRiskAssessments(ctx context.Context, since time.Time) int {
	assessments, err := i.client.GetRiskAssessments(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch risk assessments", "error", err)
		return 0
	}

	var eventCount int
	for _, assessment := range assessments {
		assessmentCopy := assessment
		event, err := i.normalizer.NormalizeRiskAssessment(&assessmentCopy)
		if err != nil {
			i.logger.Error("failed to normalize risk assessment", "assessment", assessment.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle risk assessment event", "assessment", assessment.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollResurrections(ctx context.Context, since time.Time) int {
	resurrections, err := i.client.GetResurrectionEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch resurrection events", "error", err)
		return 0
	}

	var eventCount int
	for _, resurrection := range resurrections {
		resCopy := resurrection
		event, err := i.normalizer.NormalizeResurrection(&resCopy)
		if err != nil {
			i.logger.Error("failed to normalize resurrection", "resurrection", resurrection.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle resurrection event", "resurrection", resurrection.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollAnomalies(ctx context.Context, since time.Time) int {
	anomalies, err := i.client.GetAnomalyEvents(ctx, since, i.config.MinAnomalySeverity)
	if err != nil {
		i.logger.Error("failed to fetch anomalies", "error", err)
		return 0
	}

	var eventCount int
	for _, anomaly := range anomalies {
		anomalyCopy := anomaly
		event, err := i.normalizer.NormalizeAnomaly(&anomalyCopy)
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

func (i *Ingester) pollThresholdAdjustments(ctx context.Context, since time.Time) int {
	adjustments, err := i.client.GetThresholdAdjustments(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch threshold adjustments", "error", err)
		return 0
	}

	var eventCount int
	for _, adjustment := range adjustments {
		adjCopy := adjustment
		event, err := i.normalizer.NormalizeThresholdAdjustment(&adjCopy)
		if err != nil {
			i.logger.Error("failed to normalize threshold adjustment", "adjustment", adjustment.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle threshold adjustment event", "adjustment", adjustment.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollRollbacks(ctx context.Context, since time.Time) int {
	rollbacks, err := i.client.GetRollbackEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch rollback events", "error", err)
		return 0
	}

	var eventCount int
	for _, rollback := range rollbacks {
		rollbackCopy := rollback
		event, err := i.normalizer.NormalizeRollback(&rollbackCopy)
		if err != nil {
			i.logger.Error("failed to normalize rollback", "rollback", rollback.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle rollback event", "rollback", rollback.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollApprovals(ctx context.Context, since time.Time) int {
	approvals, err := i.client.GetApprovalEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch approval events", "error", err)
		return 0
	}

	var eventCount int
	for _, approval := range approvals {
		approvalCopy := approval
		event, err := i.normalizer.NormalizeApproval(&approvalCopy)
		if err != nil {
			i.logger.Error("failed to normalize approval", "approval", approval.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle approval event", "approval", approval.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollSmithIntegration(ctx context.Context, since time.Time) int {
	events, err := i.client.GetSmithIntegrationEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch Smith integration events", "error", err)
		return 0
	}

	var eventCount int
	for _, event := range events {
		eventCopy := event
		normalizedEvent, err := i.normalizer.NormalizeSmithIntegration(&eventCopy)
		if err != nil {
			i.logger.Error("failed to normalize Smith integration event", "event", event.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, normalizedEvent); err != nil {
			i.logger.Error("failed to handle Smith integration event", "event", event.ID, "error", err)
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

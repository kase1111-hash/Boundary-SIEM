package finiteintent

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

// Ingester polls Finite Intent Executor for events and normalizes them.
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

	// Feature toggles - log all important info by default
	IngestIntents    bool `yaml:"ingest_intents"`
	IngestTriggers   bool `yaml:"ingest_triggers"`
	IngestExecutions bool `yaml:"ingest_executions"`
	IngestIPTokens   bool `yaml:"ingest_ip_tokens"`
	IngestSunset     bool `yaml:"ingest_sunset"`
	IngestOracles    bool `yaml:"ingest_oracles"`
	IngestSecurity   bool `yaml:"ingest_security"`

	// Filtering
	MinSecuritySeverity string `yaml:"min_security_severity"`
}

// DefaultIngesterConfig returns the default ingester configuration with all logging enabled.
func DefaultIngesterConfig() IngesterConfig {
	return IngesterConfig{
		PollInterval:        30 * time.Second,
		BatchSize:           100,
		IngestIntents:       true,
		IngestTriggers:      true,
		IngestExecutions:    true,
		IngestIPTokens:      true,
		IngestSunset:        true,
		IngestOracles:       true,
		IngestSecurity:      true,
		MinSecuritySeverity: "low", // Log all security events
	}
}

// NewIngester creates a new FIE ingester.
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

// Start begins polling FIE for events.
func (i *Ingester) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return fmt.Errorf("ingester already running")
	}
	i.running = true
	i.lastPollTime = time.Now().Add(-i.config.PollInterval)
	i.mu.Unlock()

	i.logger.Info("starting Finite Intent Executor ingester",
		"poll_interval", i.config.PollInterval,
		"ingest_intents", i.config.IngestIntents,
		"ingest_triggers", i.config.IngestTriggers,
		"ingest_executions", i.config.IngestExecutions,
		"ingest_ip_tokens", i.config.IngestIPTokens,
		"ingest_sunset", i.config.IngestSunset,
		"ingest_oracles", i.config.IngestOracles,
		"ingest_security", i.config.IngestSecurity,
	)

	// Initial health check
	health, err := i.client.GetHealth(ctx)
	if err != nil {
		i.logger.Warn("FIE health check failed", "error", err)
	} else {
		i.logger.Info("FIE connection established",
			"status", health.Status,
			"version", health.Version,
			"active_intents", health.ActiveIntents,
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

// pollLoop continuously polls FIE for new events.
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

// poll fetches new events from FIE.
func (i *Ingester) poll(ctx context.Context) {
	i.mu.Lock()
	lastPoll := i.lastPollTime
	i.mu.Unlock()

	pollStart := time.Now()
	var eventCount int

	// Poll intents
	if i.config.IngestIntents {
		count := i.pollIntents(ctx)
		eventCount += count
	}

	// Poll trigger events
	if i.config.IngestTriggers {
		count := i.pollTriggers(ctx, lastPoll)
		eventCount += count
	}

	// Poll execution events
	if i.config.IngestExecutions {
		count := i.pollExecutions(ctx, lastPoll)
		eventCount += count
	}

	// Poll IP tokens
	if i.config.IngestIPTokens {
		count := i.pollIPTokens(ctx)
		eventCount += count
	}

	// Poll sunset events
	if i.config.IngestSunset {
		count := i.pollSunset(ctx, lastPoll)
		eventCount += count
	}

	// Poll oracle events
	if i.config.IngestOracles {
		count := i.pollOracles(ctx, lastPoll)
		eventCount += count
	}

	// Poll security events
	if i.config.IngestSecurity {
		count := i.pollSecurity(ctx, lastPoll)
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

// pollIntents fetches recent intents.
func (i *Ingester) pollIntents(ctx context.Context) int {
	intents, err := i.client.GetIntents(ctx, "", i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch intents", "error", err)
		return 0
	}

	var eventCount int
	for _, intent := range intents {
		eventType := "intent." + intent.Status
		if _, ok := ActionMappings[eventType]; !ok {
			eventType = "intent.captured"
		}

		intentCopy := intent
		event, err := i.normalizer.NormalizeIntent(&intentCopy, eventType)
		if err != nil {
			i.logger.Error("failed to normalize intent", "intent", intent.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle intent event", "intent", intent.ID, "error", err)
		} else {
			eventCount++
		}
	}

	return eventCount
}

// pollTriggers fetches trigger activation events.
func (i *Ingester) pollTriggers(ctx context.Context, since time.Time) int {
	triggers, err := i.client.GetTriggerEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch triggers", "error", err)
		return 0
	}

	var eventCount int
	for _, trigger := range triggers {
		eventType := fmt.Sprintf("trigger.%s.activated", trigger.TriggerType)
		if trigger.Status != "pending" {
			eventType = "trigger." + trigger.Status
		}

		triggerCopy := trigger
		event, err := i.normalizer.NormalizeTrigger(&triggerCopy, eventType)
		if err != nil {
			i.logger.Error("failed to normalize trigger", "trigger", trigger.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle trigger event", "trigger", trigger.ID, "error", err)
		} else {
			eventCount++
		}
	}

	return eventCount
}

// pollExecutions fetches execution agent events.
func (i *Ingester) pollExecutions(ctx context.Context, since time.Time) int {
	executions, err := i.client.GetExecutionEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch executions", "error", err)
		return 0
	}

	var eventCount int
	for _, exec := range executions {
		execCopy := exec
		event, err := i.normalizer.NormalizeExecution(&execCopy)
		if err != nil {
			i.logger.Error("failed to normalize execution", "execution", exec.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle execution event", "execution", exec.ID, "error", err)
		} else {
			eventCount++
		}
	}

	return eventCount
}

// pollIPTokens fetches IP token events.
func (i *Ingester) pollIPTokens(ctx context.Context) int {
	tokens, err := i.client.GetIPTokens(ctx, "", i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch IP tokens", "error", err)
		return 0
	}

	var eventCount int
	for _, token := range tokens {
		eventType := "ip.token." + token.Status
		if _, ok := ActionMappings[eventType]; !ok {
			eventType = "ip.token.created"
		}

		tokenCopy := token
		event, err := i.normalizer.NormalizeIPToken(&tokenCopy, eventType)
		if err != nil {
			i.logger.Error("failed to normalize IP token", "token", token.TokenID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle IP token event", "token", token.TokenID, "error", err)
		} else {
			eventCount++
		}
	}

	return eventCount
}

// pollSunset fetches sunset transition events.
func (i *Ingester) pollSunset(ctx context.Context, since time.Time) int {
	sunsets, err := i.client.GetSunsetEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch sunset events", "error", err)
		return 0
	}

	var eventCount int
	for _, sunset := range sunsets {
		sunsetCopy := sunset
		event, err := i.normalizer.NormalizeSunset(&sunsetCopy)
		if err != nil {
			i.logger.Error("failed to normalize sunset", "sunset", sunset.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle sunset event", "sunset", sunset.ID, "error", err)
		} else {
			eventCount++
		}
	}

	return eventCount
}

// pollOracles fetches oracle verification events.
func (i *Ingester) pollOracles(ctx context.Context, since time.Time) int {
	oracles, err := i.client.GetOracleEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch oracle events", "error", err)
		return 0
	}

	var eventCount int
	for _, oracle := range oracles {
		oracleCopy := oracle
		event, err := i.normalizer.NormalizeOracle(&oracleCopy)
		if err != nil {
			i.logger.Error("failed to normalize oracle", "oracle", oracle.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle oracle event", "oracle", oracle.ID, "error", err)
		} else {
			eventCount++
		}
	}

	return eventCount
}

// pollSecurity fetches security events.
func (i *Ingester) pollSecurity(ctx context.Context, since time.Time) int {
	events, err := i.client.GetSecurityEvents(ctx, since, i.config.MinSecuritySeverity)
	if err != nil {
		i.logger.Error("failed to fetch security events", "error", err)
		return 0
	}

	var eventCount int
	for _, sec := range events {
		secCopy := sec
		event, err := i.normalizer.NormalizeSecurity(&secCopy)
		if err != nil {
			i.logger.Error("failed to normalize security event", "security", sec.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle security event", "security", sec.ID, "error", err)
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

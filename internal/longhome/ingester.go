package longhome

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

// Ingester polls Long-Home for events and normalizes them.
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
	IngestSessions       bool `yaml:"ingest_sessions"`
	IngestTransitions    bool `yaml:"ingest_transitions"`
	IngestFatals         bool `yaml:"ingest_fatals"`
	IngestSlides         bool `yaml:"ingest_slides"`
	IngestRopes          bool `yaml:"ingest_ropes"`
	IngestBodyConditions bool `yaml:"ingest_body_conditions"`
	IngestInputs         bool `yaml:"ingest_inputs"`
	IngestSaves          bool `yaml:"ingest_saves"`
	IngestPhysics        bool `yaml:"ingest_physics"`
	IngestSignals        bool `yaml:"ingest_signals"`

	// Filtering
	CriticalBodyOnly     bool   `yaml:"critical_body_only"`
	UnusualSignalsOnly   bool   `yaml:"unusual_signals_only"`
	MinPhysicsSeverity   string `yaml:"min_physics_severity"`
}

// DefaultIngesterConfig returns the default ingester configuration with all logging enabled.
func DefaultIngesterConfig() IngesterConfig {
	return IngesterConfig{
		PollInterval:         30 * time.Second,
		BatchSize:            100,
		IngestSessions:       true,
		IngestTransitions:    true,
		IngestFatals:         true,
		IngestSlides:         true,
		IngestRopes:          true,
		IngestBodyConditions: true,
		IngestInputs:         true,
		IngestSaves:          true,
		IngestPhysics:        true,
		IngestSignals:        true,
		CriticalBodyOnly:     false, // Log all body conditions
		UnusualSignalsOnly:   false, // Log all signals
		MinPhysicsSeverity:   "low", // Log all physics anomalies
	}
}

// NewIngester creates a new Long-Home ingester.
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

// Start begins polling Long-Home for events.
func (i *Ingester) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return fmt.Errorf("ingester already running")
	}
	i.running = true
	i.lastPollTime = time.Now().Add(-i.config.PollInterval)
	i.mu.Unlock()

	i.logger.Info("starting Long-Home ingester",
		"poll_interval", i.config.PollInterval,
		"ingest_sessions", i.config.IngestSessions,
		"ingest_fatals", i.config.IngestFatals,
		"ingest_slides", i.config.IngestSlides,
		"ingest_ropes", i.config.IngestRopes,
		"ingest_physics", i.config.IngestPhysics,
	)

	// Initial health check
	health, err := i.client.GetHealth(ctx)
	if err != nil {
		i.logger.Warn("Long-Home health check failed", "error", err)
	} else {
		i.logger.Info("Long-Home connection established",
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

// poll fetches new events from Long-Home.
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

	if i.config.IngestTransitions {
		count := i.pollTransitions(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestFatals {
		count := i.pollFatals(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestSlides {
		count := i.pollSlides(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestRopes {
		count := i.pollRopes(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestBodyConditions {
		count := i.pollBodyConditions(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestInputs {
		count := i.pollInputs(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestSaves {
		count := i.pollSaves(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestPhysics {
		count := i.pollPhysics(ctx, lastPoll)
		eventCount += count
	}

	if i.config.IngestSignals {
		count := i.pollSignals(ctx, lastPoll)
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
		eventType := "session." + session.GameState
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

func (i *Ingester) pollTransitions(ctx context.Context, since time.Time) int {
	transitions, err := i.client.GetStateTransitions(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch transitions", "error", err)
		return 0
	}

	var eventCount int
	for _, trans := range transitions {
		transCopy := trans
		event, err := i.normalizer.NormalizeStateTransition(&transCopy)
		if err != nil {
			i.logger.Error("failed to normalize transition", "transition", trans.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle transition event", "transition", trans.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollFatals(ctx context.Context, since time.Time) int {
	fatals, err := i.client.GetFatalEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch fatals", "error", err)
		return 0
	}

	var eventCount int
	for _, fatal := range fatals {
		fatalCopy := fatal
		event, err := i.normalizer.NormalizeFatal(&fatalCopy)
		if err != nil {
			i.logger.Error("failed to normalize fatal", "fatal", fatal.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle fatal event", "fatal", fatal.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollSlides(ctx context.Context, since time.Time) int {
	slides, err := i.client.GetSlideEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch slides", "error", err)
		return 0
	}

	var eventCount int
	for _, slide := range slides {
		slideCopy := slide
		event, err := i.normalizer.NormalizeSlide(&slideCopy)
		if err != nil {
			i.logger.Error("failed to normalize slide", "slide", slide.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle slide event", "slide", slide.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollRopes(ctx context.Context, since time.Time) int {
	ropes, err := i.client.GetRopeEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch ropes", "error", err)
		return 0
	}

	var eventCount int
	for _, rope := range ropes {
		ropeCopy := rope
		event, err := i.normalizer.NormalizeRope(&ropeCopy)
		if err != nil {
			i.logger.Error("failed to normalize rope", "rope", rope.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle rope event", "rope", rope.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollBodyConditions(ctx context.Context, since time.Time) int {
	conditions, err := i.client.GetBodyConditions(ctx, since, i.config.CriticalBodyOnly)
	if err != nil {
		i.logger.Error("failed to fetch body conditions", "error", err)
		return 0
	}

	var eventCount int
	for _, body := range conditions {
		bodyCopy := body
		event, err := i.normalizer.NormalizeBodyCondition(&bodyCopy)
		if err != nil {
			i.logger.Error("failed to normalize body condition", "body", body.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle body event", "body", body.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollInputs(ctx context.Context, since time.Time) int {
	inputs, err := i.client.GetInputValidations(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch inputs", "error", err)
		return 0
	}

	var eventCount int
	for _, input := range inputs {
		inputCopy := input
		event, err := i.normalizer.NormalizeInput(&inputCopy)
		if err != nil {
			i.logger.Error("failed to normalize input", "input", input.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle input event", "input", input.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollSaves(ctx context.Context, since time.Time) int {
	saves, err := i.client.GetSaveEvents(ctx, since, i.config.BatchSize)
	if err != nil {
		i.logger.Error("failed to fetch saves", "error", err)
		return 0
	}

	var eventCount int
	for _, save := range saves {
		saveCopy := save
		event, err := i.normalizer.NormalizeSave(&saveCopy)
		if err != nil {
			i.logger.Error("failed to normalize save", "save", save.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle save event", "save", save.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollPhysics(ctx context.Context, since time.Time) int {
	anomalies, err := i.client.GetPhysicsAnomalies(ctx, since, i.config.MinPhysicsSeverity)
	if err != nil {
		i.logger.Error("failed to fetch physics anomalies", "error", err)
		return 0
	}

	var eventCount int
	for _, anomaly := range anomalies {
		anomalyCopy := anomaly
		event, err := i.normalizer.NormalizePhysicsAnomaly(&anomalyCopy)
		if err != nil {
			i.logger.Error("failed to normalize physics anomaly", "anomaly", anomaly.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle physics event", "anomaly", anomaly.ID, "error", err)
		} else {
			eventCount++
		}
	}
	return eventCount
}

func (i *Ingester) pollSignals(ctx context.Context, since time.Time) int {
	signals, err := i.client.GetEventBusSignals(ctx, since, i.config.UnusualSignalsOnly)
	if err != nil {
		i.logger.Error("failed to fetch signals", "error", err)
		return 0
	}

	var eventCount int
	for _, signal := range signals {
		signalCopy := signal
		event, err := i.normalizer.NormalizeSignal(&signalCopy)
		if err != nil {
			i.logger.Error("failed to normalize signal", "signal", signal.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle signal event", "signal", signal.ID, "error", err)
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

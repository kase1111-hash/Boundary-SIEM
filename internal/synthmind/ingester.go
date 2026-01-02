package synthmind

import (
	"boundary-siem/internal/schema"
	"context"
	"log/slog"
	"sync"
	"time"
)

// Ingester polls Synth Mind for events and normalizes them.
type Ingester struct {
	client       *Client
	normalizer   *Normalizer
	pollInterval time.Duration
	batchSize    int
	eventChan    chan *schema.Event
	lastPoll     time.Time
	mu           sync.Mutex
	running      bool
	stopChan     chan struct{}
	logger       *slog.Logger
}

// IngesterConfig holds configuration for the ingester.
type IngesterConfig struct {
	PollInterval     time.Duration    `yaml:"poll_interval"`
	BatchSize        int              `yaml:"batch_size"`
	NormalizerConfig NormalizerConfig `yaml:"normalizer"`
}

// DefaultIngesterConfig returns the default ingester configuration.
func DefaultIngesterConfig() IngesterConfig {
	return IngesterConfig{
		PollInterval: 30 * time.Second,
		BatchSize:    100,
		NormalizerConfig: NormalizerConfig{
			SourceProduct: "synthmind",
		},
	}
}

// NewIngester creates a new Synth Mind ingester.
func NewIngester(client *Client, cfg IngesterConfig, logger *slog.Logger) *Ingester {
	if logger == nil {
		logger = slog.Default()
	}
	return &Ingester{
		client:       client,
		normalizer:   NewNormalizer(cfg.NormalizerConfig),
		pollInterval: cfg.PollInterval,
		batchSize:    cfg.BatchSize,
		eventChan:    make(chan *schema.Event, 1000),
		lastPoll:     time.Now().Add(-cfg.PollInterval),
		stopChan:     make(chan struct{}),
		logger:       logger,
	}
}

// Start begins polling for events.
func (i *Ingester) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return nil
	}
	i.running = true
	i.mu.Unlock()

	i.logger.Info("starting synthmind ingester", "poll_interval", i.pollInterval)
	go i.pollLoop(ctx)
	return nil
}

// Stop stops the ingester.
func (i *Ingester) Stop() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.running {
		close(i.stopChan)
		i.running = false
		i.logger.Info("synthmind ingester stopped")
	}
}

// Events returns the channel of normalized events.
func (i *Ingester) Events() <-chan *schema.Event {
	return i.eventChan
}

func (i *Ingester) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(i.pollInterval)
	defer ticker.Stop()

	// Initial poll
	i.poll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-i.stopChan:
			return
		case <-ticker.C:
			i.poll(ctx)
		}
	}
}

func (i *Ingester) poll(ctx context.Context) {
	i.mu.Lock()
	since := i.lastPoll
	i.lastPoll = time.Now()
	i.mu.Unlock()

	var eventCount int

	// Poll emotional states
	states, err := i.client.GetEmotionalStates(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get emotional states", "error", err)
	} else {
		for _, state := range states {
			stateCopy := state
			event, err := i.normalizer.NormalizeEmotionalState(&stateCopy)
			if err != nil {
				i.logger.Error("failed to normalize emotional state", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll module events
	moduleEvents, err := i.client.GetModuleEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get module events", "error", err)
	} else {
		for _, evt := range moduleEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeModuleEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize module event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll dreaming events
	dreamingEvents, err := i.client.GetDreamingEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get dreaming events", "error", err)
	} else {
		for _, evt := range dreamingEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeDreamingEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize dreaming event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll reflection events
	reflectionEvents, err := i.client.GetReflectionEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get reflection events", "error", err)
	} else {
		for _, evt := range reflectionEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeReflectionEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize reflection event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll social events
	socialEvents, err := i.client.GetSocialEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get social events", "error", err)
	} else {
		for _, evt := range socialEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeSocialEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize social event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll tool usage events
	toolEvents, err := i.client.GetToolUsageEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get tool usage events", "error", err)
	} else {
		for _, evt := range toolEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeToolUsageEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize tool usage event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll safety events
	safetyEvents, err := i.client.GetSafetyEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get safety events", "error", err)
	} else {
		for _, evt := range safetyEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeSafetyEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize safety event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	if eventCount > 0 {
		i.logger.Info("poll completed", "events_ingested", eventCount)
	}
}

func (i *Ingester) sendEvent(event *schema.Event) bool {
	select {
	case i.eventChan <- event:
		return true
	default:
		i.logger.Warn("event channel full, dropping event", "event_id", event.EventID)
		return false
	}
}

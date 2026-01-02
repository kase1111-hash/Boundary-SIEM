package rramodule

import (
	"boundary-siem/internal/schema"
	"context"
	"log/slog"
	"sync"
	"time"
)

// Ingester polls RRA-Module for events and normalizes them.
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
			SourceProduct: "rramodule",
		},
	}
}

// NewIngester creates a new RRA-Module ingester.
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

	i.logger.Info("starting rramodule ingester", "poll_interval", i.pollInterval)
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
		i.logger.Info("rramodule ingester stopped")
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

	// Poll ingestion events
	ingestionEvents, err := i.client.GetIngestionEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get ingestion events", "error", err)
	} else {
		for _, evt := range ingestionEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeIngestionEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize ingestion event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll negotiation events
	negotiationEvents, err := i.client.GetNegotiationEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get negotiation events", "error", err)
	} else {
		for _, evt := range negotiationEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeNegotiationEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize negotiation event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll contract events
	contractEvents, err := i.client.GetContractEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get contract events", "error", err)
	} else {
		for _, evt := range contractEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeContractEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize contract event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll revenue events
	revenueEvents, err := i.client.GetRevenueEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get revenue events", "error", err)
	} else {
		for _, evt := range revenueEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeRevenueEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize revenue event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll security events
	securityEvents, err := i.client.GetSecurityEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get security events", "error", err)
	} else {
		for _, evt := range securityEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeSecurityEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize security event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll governance events
	governanceEvents, err := i.client.GetGovernanceEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get governance events", "error", err)
	} else {
		for _, evt := range governanceEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeGovernanceEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize governance event", "error", err)
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

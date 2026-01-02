package mediatornode

import (
	"boundary-siem/internal/schema"
	"context"
	"log/slog"
	"sync"
	"time"
)

// Ingester polls Mediator Node for events and normalizes them.
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
		PollInterval:     30 * time.Second,
		BatchSize:        100,
		NormalizerConfig: DefaultNormalizerConfig(),
	}
}

// NewIngester creates a new Mediator Node ingester.
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

	i.logger.Info("starting mediatornode ingester", "poll_interval", i.pollInterval)
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
		i.logger.Info("mediatornode ingester stopped")
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

	// Poll alignment events
	alignments, err := i.client.GetAlignments(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get alignments", "error", err)
	} else {
		for _, alignment := range alignments {
			alignmentCopy := alignment
			event, err := i.normalizer.NormalizeAlignment(&alignmentCopy)
			if err != nil {
				i.logger.Error("failed to normalize alignment", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll negotiation sessions
	negotiations, err := i.client.GetNegotiations(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get negotiations", "error", err)
	} else {
		for _, negotiation := range negotiations {
			negotiationCopy := negotiation
			event, err := i.normalizer.NormalizeNegotiation(&negotiationCopy)
			if err != nil {
				i.logger.Error("failed to normalize negotiation", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll settlements
	settlements, err := i.client.GetSettlements(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get settlements", "error", err)
	} else {
		for _, settlement := range settlements {
			settlementCopy := settlement
			event, err := i.normalizer.NormalizeSettlement(&settlementCopy)
			if err != nil {
				i.logger.Error("failed to normalize settlement", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll flag events
	flags, err := i.client.GetFlagEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get flag events", "error", err)
	} else {
		for _, flag := range flags {
			flagCopy := flag
			event, err := i.normalizer.NormalizeFlagEvent(&flagCopy)
			if err != nil {
				i.logger.Error("failed to normalize flag event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll reputation events
	reputations, err := i.client.GetReputationEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get reputation events", "error", err)
	} else {
		for _, reputation := range reputations {
			reputationCopy := reputation
			event, err := i.normalizer.NormalizeReputationEvent(&reputationCopy)
			if err != nil {
				i.logger.Error("failed to normalize reputation event", "error", err)
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

package intentlog

import (
	"boundary-siem/internal/schema"
	"context"
	"log/slog"
	"sync"
	"time"
)

// Ingester polls IntentLog for events and normalizes them.
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

// NewIngester creates a new IntentLog ingester.
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

	i.logger.Info("starting intentlog ingester", "poll_interval", i.pollInterval)
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
		i.logger.Info("intentlog ingester stopped")
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

	// Poll prose commits
	commits, err := i.client.GetCommits(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get commits", "error", err)
	} else {
		for _, commit := range commits {
			commitCopy := commit
			event, err := i.normalizer.NormalizeProseCommit(&commitCopy)
			if err != nil {
				i.logger.Error("failed to normalize commit", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll semantic diffs
	diffs, err := i.client.GetSemanticDiffs(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get semantic diffs", "error", err)
	} else {
		for _, diff := range diffs {
			diffCopy := diff
			event, err := i.normalizer.NormalizeSemanticDiff(&diffCopy)
			if err != nil {
				i.logger.Error("failed to normalize semantic diff", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll branch events
	branchEvents, err := i.client.GetBranchEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get branch events", "error", err)
	} else {
		for _, evt := range branchEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeBranchEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize branch event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll chain integrity events
	chainEvents, err := i.client.GetChainEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get chain events", "error", err)
	} else {
		for _, evt := range chainEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeChainEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize chain event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll export events
	exportEvents, err := i.client.GetExportEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get export events", "error", err)
	} else {
		for _, evt := range exportEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeExportEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize export event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll key events
	keyEvents, err := i.client.GetKeyEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get key events", "error", err)
	} else {
		for _, evt := range keyEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeKeyEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize key event", "error", err)
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

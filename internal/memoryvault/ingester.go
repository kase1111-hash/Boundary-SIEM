package memoryvault

import (
	"boundary-siem/internal/schema"
	"context"
	"log/slog"
	"sync"
	"time"
)

// Ingester polls Memory Vault for events and normalizes them.
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

// NewIngester creates a new Memory Vault ingester.
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

	i.logger.Info("starting memoryvault ingester", "poll_interval", i.pollInterval)
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
		i.logger.Info("memoryvault ingester stopped")
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

	// Poll access events
	accessEvents, err := i.client.GetAccessEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get access events", "error", err)
	} else {
		for _, evt := range accessEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeAccessEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize access event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll integrity events
	integrityEvents, err := i.client.GetIntegrityEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get integrity events", "error", err)
	} else {
		for _, evt := range integrityEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeIntegrityEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize integrity event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll lockdown events
	lockdownEvents, err := i.client.GetLockdownEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get lockdown events", "error", err)
	} else {
		for _, evt := range lockdownEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeLockdownEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize lockdown event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll succession events
	successionEvents, err := i.client.GetSuccessionEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get succession events", "error", err)
	} else {
		for _, evt := range successionEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeSuccessionEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize succession event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll backup events
	backupEvents, err := i.client.GetBackupEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get backup events", "error", err)
	} else {
		for _, evt := range backupEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizeBackupEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize backup event", "error", err)
				continue
			}
			if i.sendEvent(event) {
				eventCount++
			}
		}
	}

	// Poll physical token events
	tokenEvents, err := i.client.GetPhysicalTokenEvents(ctx, since, i.batchSize)
	if err != nil {
		i.logger.Error("failed to get physical token events", "error", err)
	} else {
		for _, evt := range tokenEvents {
			evtCopy := evt
			event, err := i.normalizer.NormalizePhysicalTokenEvent(&evtCopy)
			if err != nil {
				i.logger.Error("failed to normalize physical token event", "error", err)
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

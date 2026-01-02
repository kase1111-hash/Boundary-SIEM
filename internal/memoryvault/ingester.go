package memoryvault

import (
	"boundary-siem/internal/schema"
	"context"
	"log"
	"sync"
	"time"
)

// Ingester polls Memory Vault for events and normalizes them.
type Ingester struct {
	client       *Client
	normalizer   *Normalizer
	pollInterval time.Duration
	eventChan    chan schema.CanonicalEvent
	lastPoll     time.Time
	mu           sync.Mutex
	running      bool
	stopChan     chan struct{}
}

// IngesterConfig holds configuration for the ingester.
type IngesterConfig struct {
	PollInterval time.Duration `yaml:"poll_interval"`
	BatchSize    int           `yaml:"batch_size"`
}

// DefaultIngesterConfig returns the default ingester configuration.
func DefaultIngesterConfig() IngesterConfig {
	return IngesterConfig{
		PollInterval: 30 * time.Second,
		BatchSize:    100,
	}
}

// NewIngester creates a new Memory Vault ingester.
func NewIngester(client *Client, cfg IngesterConfig) *Ingester {
	return &Ingester{
		client:       client,
		normalizer:   NewNormalizer(),
		pollInterval: cfg.PollInterval,
		eventChan:    make(chan schema.CanonicalEvent, 1000),
		lastPoll:     time.Now().Add(-cfg.PollInterval),
		stopChan:     make(chan struct{}),
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
	}
}

// Events returns the channel of normalized events.
func (i *Ingester) Events() <-chan schema.CanonicalEvent {
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

	// Poll access events
	accessEvents, err := i.client.GetAccessEvents(ctx, since, 100)
	if err != nil {
		log.Printf("memoryvault: failed to get access events: %v", err)
	} else {
		for _, event := range accessEvents {
			normalized := i.normalizer.NormalizeAccessEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("memoryvault: event channel full, dropping event")
			}
		}
	}

	// Poll integrity events
	integrityEvents, err := i.client.GetIntegrityEvents(ctx, since, 100)
	if err != nil {
		log.Printf("memoryvault: failed to get integrity events: %v", err)
	} else {
		for _, event := range integrityEvents {
			normalized := i.normalizer.NormalizeIntegrityEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("memoryvault: event channel full, dropping event")
			}
		}
	}

	// Poll lockdown events
	lockdownEvents, err := i.client.GetLockdownEvents(ctx, since, 100)
	if err != nil {
		log.Printf("memoryvault: failed to get lockdown events: %v", err)
	} else {
		for _, event := range lockdownEvents {
			normalized := i.normalizer.NormalizeLockdownEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("memoryvault: event channel full, dropping event")
			}
		}
	}

	// Poll succession events
	successionEvents, err := i.client.GetSuccessionEvents(ctx, since, 100)
	if err != nil {
		log.Printf("memoryvault: failed to get succession events: %v", err)
	} else {
		for _, event := range successionEvents {
			normalized := i.normalizer.NormalizeSuccessionEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("memoryvault: event channel full, dropping event")
			}
		}
	}

	// Poll backup events
	backupEvents, err := i.client.GetBackupEvents(ctx, since, 100)
	if err != nil {
		log.Printf("memoryvault: failed to get backup events: %v", err)
	} else {
		for _, event := range backupEvents {
			normalized := i.normalizer.NormalizeBackupEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("memoryvault: event channel full, dropping event")
			}
		}
	}

	// Poll physical token events
	tokenEvents, err := i.client.GetPhysicalTokenEvents(ctx, since, 100)
	if err != nil {
		log.Printf("memoryvault: failed to get physical token events: %v", err)
	} else {
		for _, event := range tokenEvents {
			normalized := i.normalizer.NormalizePhysicalTokenEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("memoryvault: event channel full, dropping event")
			}
		}
	}
}

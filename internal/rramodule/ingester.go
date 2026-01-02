package rramodule

import (
	"boundary-siem/internal/core/schema"
	"context"
	"log"
	"sync"
	"time"
)

// Ingester polls RRA-Module for events and normalizes them.
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

// NewIngester creates a new RRA-Module ingester.
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

	// Poll ingestion events
	ingestionEvents, err := i.client.GetIngestionEvents(ctx, since, 100)
	if err != nil {
		log.Printf("rramodule: failed to get ingestion events: %v", err)
	} else {
		for _, event := range ingestionEvents {
			normalized := i.normalizer.NormalizeIngestionEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("rramodule: event channel full, dropping event")
			}
		}
	}

	// Poll negotiation events
	negotiationEvents, err := i.client.GetNegotiationEvents(ctx, since, 100)
	if err != nil {
		log.Printf("rramodule: failed to get negotiation events: %v", err)
	} else {
		for _, event := range negotiationEvents {
			normalized := i.normalizer.NormalizeNegotiationEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("rramodule: event channel full, dropping event")
			}
		}
	}

	// Poll contract events
	contractEvents, err := i.client.GetContractEvents(ctx, since, 100)
	if err != nil {
		log.Printf("rramodule: failed to get contract events: %v", err)
	} else {
		for _, event := range contractEvents {
			normalized := i.normalizer.NormalizeContractEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("rramodule: event channel full, dropping event")
			}
		}
	}

	// Poll revenue events
	revenueEvents, err := i.client.GetRevenueEvents(ctx, since, 100)
	if err != nil {
		log.Printf("rramodule: failed to get revenue events: %v", err)
	} else {
		for _, event := range revenueEvents {
			normalized := i.normalizer.NormalizeRevenueEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("rramodule: event channel full, dropping event")
			}
		}
	}

	// Poll security events
	securityEvents, err := i.client.GetSecurityEvents(ctx, since, 100)
	if err != nil {
		log.Printf("rramodule: failed to get security events: %v", err)
	} else {
		for _, event := range securityEvents {
			normalized := i.normalizer.NormalizeSecurityEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("rramodule: event channel full, dropping event")
			}
		}
	}

	// Poll governance events
	governanceEvents, err := i.client.GetGovernanceEvents(ctx, since, 100)
	if err != nil {
		log.Printf("rramodule: failed to get governance events: %v", err)
	} else {
		for _, event := range governanceEvents {
			normalized := i.normalizer.NormalizeGovernanceEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("rramodule: event channel full, dropping event")
			}
		}
	}
}

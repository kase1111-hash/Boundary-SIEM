package mediatornode

import (
	"boundary-siem/internal/schema"
	"context"
	"log"
	"sync"
	"time"
)

// Ingester polls Mediator Node for events and normalizes them.
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

// NewIngester creates a new Mediator Node ingester.
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

	// Poll alignment events
	alignments, err := i.client.GetAlignments(ctx, since, 100)
	if err != nil {
		log.Printf("mediatornode: failed to get alignments: %v", err)
	} else {
		for _, alignment := range alignments {
			event := i.normalizer.NormalizeAlignment(alignment)
			select {
			case i.eventChan <- event:
			default:
				log.Printf("mediatornode: event channel full, dropping event")
			}
		}
	}

	// Poll negotiation sessions
	negotiations, err := i.client.GetNegotiations(ctx, since, 100)
	if err != nil {
		log.Printf("mediatornode: failed to get negotiations: %v", err)
	} else {
		for _, negotiation := range negotiations {
			event := i.normalizer.NormalizeNegotiation(negotiation)
			select {
			case i.eventChan <- event:
			default:
				log.Printf("mediatornode: event channel full, dropping event")
			}
		}
	}

	// Poll settlements
	settlements, err := i.client.GetSettlements(ctx, since, 100)
	if err != nil {
		log.Printf("mediatornode: failed to get settlements: %v", err)
	} else {
		for _, settlement := range settlements {
			event := i.normalizer.NormalizeSettlement(settlement)
			select {
			case i.eventChan <- event:
			default:
				log.Printf("mediatornode: event channel full, dropping event")
			}
		}
	}

	// Poll flag events
	flags, err := i.client.GetFlagEvents(ctx, since, 100)
	if err != nil {
		log.Printf("mediatornode: failed to get flag events: %v", err)
	} else {
		for _, flag := range flags {
			event := i.normalizer.NormalizeFlagEvent(flag)
			select {
			case i.eventChan <- event:
			default:
				log.Printf("mediatornode: event channel full, dropping event")
			}
		}
	}

	// Poll reputation events
	reputations, err := i.client.GetReputationEvents(ctx, since, 100)
	if err != nil {
		log.Printf("mediatornode: failed to get reputation events: %v", err)
	} else {
		for _, reputation := range reputations {
			event := i.normalizer.NormalizeReputationEvent(reputation)
			select {
			case i.eventChan <- event:
			default:
				log.Printf("mediatornode: event channel full, dropping event")
			}
		}
	}
}

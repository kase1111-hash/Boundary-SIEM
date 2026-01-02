package synthmind

import (
	"boundary-siem/internal/core/schema"
	"context"
	"log"
	"sync"
	"time"
)

// Ingester polls Synth Mind for events and normalizes them.
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

// NewIngester creates a new Synth Mind ingester.
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

	// Poll emotional states
	states, err := i.client.GetEmotionalStates(ctx, since, 100)
	if err != nil {
		log.Printf("synthmind: failed to get emotional states: %v", err)
	} else {
		for _, state := range states {
			event := i.normalizer.NormalizeEmotionalState(state)
			select {
			case i.eventChan <- event:
			default:
				log.Printf("synthmind: event channel full, dropping event")
			}
		}
	}

	// Poll module events
	moduleEvents, err := i.client.GetModuleEvents(ctx, since, 100)
	if err != nil {
		log.Printf("synthmind: failed to get module events: %v", err)
	} else {
		for _, event := range moduleEvents {
			normalized := i.normalizer.NormalizeModuleEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("synthmind: event channel full, dropping event")
			}
		}
	}

	// Poll dreaming events
	dreamingEvents, err := i.client.GetDreamingEvents(ctx, since, 100)
	if err != nil {
		log.Printf("synthmind: failed to get dreaming events: %v", err)
	} else {
		for _, event := range dreamingEvents {
			normalized := i.normalizer.NormalizeDreamingEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("synthmind: event channel full, dropping event")
			}
		}
	}

	// Poll reflection events
	reflectionEvents, err := i.client.GetReflectionEvents(ctx, since, 100)
	if err != nil {
		log.Printf("synthmind: failed to get reflection events: %v", err)
	} else {
		for _, event := range reflectionEvents {
			normalized := i.normalizer.NormalizeReflectionEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("synthmind: event channel full, dropping event")
			}
		}
	}

	// Poll social events
	socialEvents, err := i.client.GetSocialEvents(ctx, since, 100)
	if err != nil {
		log.Printf("synthmind: failed to get social events: %v", err)
	} else {
		for _, event := range socialEvents {
			normalized := i.normalizer.NormalizeSocialEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("synthmind: event channel full, dropping event")
			}
		}
	}

	// Poll tool usage events
	toolEvents, err := i.client.GetToolUsageEvents(ctx, since, 100)
	if err != nil {
		log.Printf("synthmind: failed to get tool usage events: %v", err)
	} else {
		for _, event := range toolEvents {
			normalized := i.normalizer.NormalizeToolUsageEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("synthmind: event channel full, dropping event")
			}
		}
	}

	// Poll safety events
	safetyEvents, err := i.client.GetSafetyEvents(ctx, since, 100)
	if err != nil {
		log.Printf("synthmind: failed to get safety events: %v", err)
	} else {
		for _, event := range safetyEvents {
			normalized := i.normalizer.NormalizeSafetyEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("synthmind: event channel full, dropping event")
			}
		}
	}
}

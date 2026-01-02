package intentlog

import (
	"boundary-siem/internal/core/schema"
	"context"
	"log"
	"sync"
	"time"
)

// Ingester polls IntentLog for events and normalizes them.
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

// NewIngester creates a new IntentLog ingester.
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

	// Poll prose commits
	commits, err := i.client.GetCommits(ctx, since, 100)
	if err != nil {
		log.Printf("intentlog: failed to get commits: %v", err)
	} else {
		for _, commit := range commits {
			event := i.normalizer.NormalizeProseCommit(commit)
			select {
			case i.eventChan <- event:
			default:
				log.Printf("intentlog: event channel full, dropping event")
			}
		}
	}

	// Poll semantic diffs
	diffs, err := i.client.GetSemanticDiffs(ctx, since, 100)
	if err != nil {
		log.Printf("intentlog: failed to get semantic diffs: %v", err)
	} else {
		for _, diff := range diffs {
			event := i.normalizer.NormalizeSemanticDiff(diff)
			select {
			case i.eventChan <- event:
			default:
				log.Printf("intentlog: event channel full, dropping event")
			}
		}
	}

	// Poll branch events
	branchEvents, err := i.client.GetBranchEvents(ctx, since, 100)
	if err != nil {
		log.Printf("intentlog: failed to get branch events: %v", err)
	} else {
		for _, event := range branchEvents {
			normalized := i.normalizer.NormalizeBranchEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("intentlog: event channel full, dropping event")
			}
		}
	}

	// Poll chain integrity events
	chainEvents, err := i.client.GetChainEvents(ctx, since, 100)
	if err != nil {
		log.Printf("intentlog: failed to get chain events: %v", err)
	} else {
		for _, event := range chainEvents {
			normalized := i.normalizer.NormalizeChainEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("intentlog: event channel full, dropping event")
			}
		}
	}

	// Poll export events
	exportEvents, err := i.client.GetExportEvents(ctx, since, 100)
	if err != nil {
		log.Printf("intentlog: failed to get export events: %v", err)
	} else {
		for _, event := range exportEvents {
			normalized := i.normalizer.NormalizeExportEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("intentlog: event channel full, dropping event")
			}
		}
	}

	// Poll key events
	keyEvents, err := i.client.GetKeyEvents(ctx, since, 100)
	if err != nil {
		log.Printf("intentlog: failed to get key events: %v", err)
	} else {
		for _, event := range keyEvents {
			normalized := i.normalizer.NormalizeKeyEvent(event)
			select {
			case i.eventChan <- normalized:
			default:
				log.Printf("intentlog: event channel full, dropping event")
			}
		}
	}
}

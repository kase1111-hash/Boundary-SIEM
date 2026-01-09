package natlangchain

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"boundary-siem/internal/schema"
)

// EventHandler is called for each normalized event.
type EventHandler func(ctx context.Context, event *schema.Event) error

// Ingester polls NatLangChain for events and normalizes them.
type Ingester struct {
	client     *Client
	normalizer *Normalizer
	handler    EventHandler
	config     IngesterConfig
	logger     *slog.Logger

	mu              sync.RWMutex
	lastBlockNumber int64
	lastPollTime    time.Time
	running         bool
	stopCh          chan struct{}
}

// IngesterConfig holds configuration for the ingester.
type IngesterConfig struct {
	// Polling configuration
	PollInterval   time.Duration `yaml:"poll_interval"`
	BlockBatchSize int           `yaml:"block_batch_size"`
	EntryBatchSize int           `yaml:"entry_batch_size"`

	// Feature toggles
	IngestEntries       bool `yaml:"ingest_entries"`
	IngestBlocks        bool `yaml:"ingest_blocks"`
	IngestDisputes      bool `yaml:"ingest_disputes"`
	IngestContracts     bool `yaml:"ingest_contracts"`
	IngestNegotiations  bool `yaml:"ingest_negotiations"`
	IngestValidation    bool `yaml:"ingest_validation"`
	IngestSemanticDrift bool `yaml:"ingest_semantic_drift"`

	// Filtering
	MinDriftSeverity string `yaml:"min_drift_severity"`
}

// DefaultIngesterConfig returns the default ingester configuration.
func DefaultIngesterConfig() IngesterConfig {
	return IngesterConfig{
		PollInterval:        30 * time.Second,
		BlockBatchSize:      100,
		EntryBatchSize:      500,
		IngestEntries:       true,
		IngestBlocks:        true,
		IngestDisputes:      true,
		IngestContracts:     true,
		IngestNegotiations:  true,
		IngestValidation:    true,
		IngestSemanticDrift: true,
		MinDriftSeverity:    "low",
	}
}

// NewIngester creates a new NatLangChain ingester.
func NewIngester(client *Client, normalizer *Normalizer, handler EventHandler, cfg IngesterConfig, logger *slog.Logger) *Ingester {
	if logger == nil {
		logger = slog.Default()
	}
	return &Ingester{
		client:     client,
		normalizer: normalizer,
		handler:    handler,
		config:     cfg,
		logger:     logger,
		stopCh:     make(chan struct{}),
	}
}

// Start begins polling NatLangChain for events.
func (i *Ingester) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return fmt.Errorf("ingester already running")
	}
	i.running = true
	i.lastPollTime = time.Now().Add(-i.config.PollInterval)
	i.mu.Unlock()

	i.logger.Info("starting NatLangChain ingester",
		"poll_interval", i.config.PollInterval,
		"ingest_entries", i.config.IngestEntries,
		"ingest_blocks", i.config.IngestBlocks,
	)

	// Initial health check
	health, err := i.client.GetHealth(ctx)
	if err != nil {
		i.logger.Warn("NatLangChain health check failed", "error", err)
	} else {
		i.logger.Info("NatLangChain connection established",
			"status", health.Status,
			"version", health.Version,
		)
	}

	// Get initial chain stats
	stats, err := i.client.GetChainStats(ctx)
	if err != nil {
		i.logger.Warn("failed to get chain stats", "error", err)
	} else {
		i.mu.Lock()
		i.lastBlockNumber = stats.BlockHeight
		i.mu.Unlock()
		i.logger.Info("starting from block",
			"block_height", stats.BlockHeight,
			"total_entries", stats.TotalEntries,
		)
	}

	go i.pollLoop(ctx)
	return nil
}

// Stop stops the ingester.
func (i *Ingester) Stop() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.running {
		close(i.stopCh)
		i.running = false
	}
}

// pollLoop continuously polls NatLangChain for new events.
func (i *Ingester) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(i.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			i.logger.Info("ingester context cancelled")
			return
		case <-i.stopCh:
			i.logger.Info("ingester stopped")
			return
		case <-ticker.C:
			i.poll(ctx)
		}
	}
}

// poll fetches new events from NatLangChain.
func (i *Ingester) poll(ctx context.Context) {
	i.mu.Lock()
	lastBlock := i.lastBlockNumber
	lastPoll := i.lastPollTime
	i.mu.Unlock()

	pollStart := time.Now()
	var eventCount int

	// Poll blocks and entries
	if i.config.IngestBlocks || i.config.IngestEntries {
		count, newBlock := i.pollBlocks(ctx, lastBlock)
		eventCount += count
		if newBlock > lastBlock {
			i.mu.Lock()
			i.lastBlockNumber = newBlock
			i.mu.Unlock()
		}
	}

	// Poll disputes
	if i.config.IngestDisputes {
		count := i.pollDisputes(ctx)
		eventCount += count
	}

	// Poll contracts
	if i.config.IngestContracts {
		count := i.pollContracts(ctx)
		eventCount += count
	}

	// Poll negotiations
	if i.config.IngestNegotiations {
		count := i.pollNegotiations(ctx)
		eventCount += count
	}

	// Poll validation events
	if i.config.IngestValidation {
		count := i.pollValidation(ctx, lastPoll)
		eventCount += count
	}

	// Poll semantic drift
	if i.config.IngestSemanticDrift {
		count := i.pollSemanticDrift(ctx, lastPoll)
		eventCount += count
	}

	i.mu.Lock()
	i.lastPollTime = pollStart
	i.mu.Unlock()

	if eventCount > 0 {
		i.logger.Info("poll completed",
			"events_ingested", eventCount,
			"duration", time.Since(pollStart),
		)
	}
}

// pollBlocks fetches new blocks and their entries.
func (i *Ingester) pollBlocks(ctx context.Context, sinceBlock int64) (int, int64) {
	blocks, err := i.client.GetBlocksSince(ctx, sinceBlock, i.config.BlockBatchSize)
	if err != nil {
		i.logger.Error("failed to fetch blocks", "error", err)
		return 0, sinceBlock
	}

	var eventCount int
	var maxBlock int64 = sinceBlock

	for _, block := range blocks {
		if block.Number <= sinceBlock {
			continue
		}
		if block.Number > maxBlock {
			maxBlock = block.Number
		}

		// Emit block event
		if i.config.IngestBlocks {
			event, err := i.normalizer.NormalizeBlock(&block, "block.mined")
			if err != nil {
				i.logger.Error("failed to normalize block", "block", block.Number, "error", err)
				continue
			}
			if err := i.handler(ctx, event); err != nil {
				i.logger.Error("failed to handle block event", "block", block.Number, "error", err)
			} else {
				eventCount++
			}
		}

		// Emit entry events
		if i.config.IngestEntries {
			for _, entry := range block.Entries {
				eventType := "entry.created"
				if entry.Validated {
					eventType = "entry.validated"
				}

				entryCopy := entry // Avoid closure capture issue
				event, err := i.normalizer.NormalizeEntry(&entryCopy, eventType)
				if err != nil {
					i.logger.Error("failed to normalize entry", "entry", entry.ID, "error", err)
					continue
				}
				if err := i.handler(ctx, event); err != nil {
					i.logger.Error("failed to handle entry event", "entry", entry.ID, "error", err)
				} else {
					eventCount++
				}
			}
		}
	}

	return eventCount, maxBlock
}

// pollDisputes fetches recent disputes.
func (i *Ingester) pollDisputes(ctx context.Context) int {
	disputes, err := i.client.GetDisputes(ctx, "", 100)
	if err != nil {
		i.logger.Error("failed to fetch disputes", "error", err)
		return 0
	}

	var eventCount int
	for _, dispute := range disputes {
		eventType := "dispute." + dispute.Status
		if _, ok := ActionMappings[eventType]; !ok {
			eventType = "dispute.filed"
		}

		disputeCopy := dispute
		event, err := i.normalizer.NormalizeDispute(&disputeCopy, eventType)
		if err != nil {
			i.logger.Error("failed to normalize dispute", "dispute", dispute.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle dispute event", "dispute", dispute.ID, "error", err)
		} else {
			eventCount++
		}
	}

	return eventCount
}

// pollContracts fetches recent contracts.
func (i *Ingester) pollContracts(ctx context.Context) int {
	contracts, err := i.client.GetContracts(ctx, "", 100)
	if err != nil {
		i.logger.Error("failed to fetch contracts", "error", err)
		return 0
	}

	var eventCount int
	for _, contract := range contracts {
		eventType := "contract." + contract.Status
		if _, ok := ActionMappings[eventType]; !ok {
			eventType = "contract.created"
		}

		contractCopy := contract
		event, err := i.normalizer.NormalizeContract(&contractCopy, eventType)
		if err != nil {
			i.logger.Error("failed to normalize contract", "contract", contract.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle contract event", "contract", contract.ID, "error", err)
		} else {
			eventCount++
		}
	}

	return eventCount
}

// pollNegotiations fetches recent negotiations.
func (i *Ingester) pollNegotiations(ctx context.Context) int {
	negotiations, err := i.client.GetNegotiations(ctx, "", 100)
	if err != nil {
		i.logger.Error("failed to fetch negotiations", "error", err)
		return 0
	}

	var eventCount int
	for _, neg := range negotiations {
		eventType := "negotiation." + neg.Status
		if _, ok := ActionMappings[eventType]; !ok {
			eventType = "negotiation.started"
		}

		negCopy := neg
		event, err := i.normalizer.NormalizeNegotiation(&negCopy, eventType)
		if err != nil {
			i.logger.Error("failed to normalize negotiation", "negotiation", neg.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle negotiation event", "negotiation", neg.ID, "error", err)
		} else {
			eventCount++
		}
	}

	return eventCount
}

// pollValidation fetches validation events.
func (i *Ingester) pollValidation(ctx context.Context, since time.Time) int {
	events, err := i.client.GetValidationEvents(ctx, since, 500)
	if err != nil {
		i.logger.Error("failed to fetch validation events", "error", err)
		return 0
	}

	var eventCount int
	for _, ve := range events {
		veCopy := ve
		event, err := i.normalizer.NormalizeValidationEvent(&veCopy)
		if err != nil {
			i.logger.Error("failed to normalize validation event", "event", ve.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle validation event", "event", ve.ID, "error", err)
		} else {
			eventCount++
		}
	}

	return eventCount
}

// pollSemanticDrift fetches semantic drift events.
func (i *Ingester) pollSemanticDrift(ctx context.Context, since time.Time) int {
	drifts, err := i.client.GetSemanticDrifts(ctx, since, i.config.MinDriftSeverity)
	if err != nil {
		i.logger.Error("failed to fetch semantic drifts", "error", err)
		return 0
	}

	var eventCount int
	for _, drift := range drifts {
		driftCopy := drift
		event, err := i.normalizer.NormalizeSemanticDrift(&driftCopy)
		if err != nil {
			i.logger.Error("failed to normalize semantic drift", "drift", drift.ID, "error", err)
			continue
		}
		if err := i.handler(ctx, event); err != nil {
			i.logger.Error("failed to handle semantic drift event", "drift", drift.ID, "error", err)
		} else {
			eventCount++
		}
	}

	return eventCount
}

// Stats returns current ingester statistics.
func (i *Ingester) Stats() IngesterStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return IngesterStats{
		Running:         i.running,
		LastBlockNumber: i.lastBlockNumber,
		LastPollTime:    i.lastPollTime,
	}
}

// IngesterStats holds ingester statistics.
type IngesterStats struct {
	Running         bool      `json:"running"`
	LastBlockNumber int64     `json:"last_block_number"`
	LastPollTime    time.Time `json:"last_poll_time"`
}

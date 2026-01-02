package ilrmodule

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
)

// IngesterConfig holds configuration for the ILR-Module ingester.
type IngesterConfig struct {
	PollInterval       time.Duration `yaml:"poll_interval"`
	DisputeBatchSize   int           `yaml:"dispute_batch_size"`
	ProposalBatchSize  int           `yaml:"proposal_batch_size"`
	IngestDisputes     bool          `yaml:"ingest_disputes"`
	IngestProposals    bool          `yaml:"ingest_proposals"`
	IngestCompliance   bool          `yaml:"ingest_compliance"`
	IngestL3Batches    bool          `yaml:"ingest_l3_batches"`
	IngestOracleEvents bool          `yaml:"ingest_oracle_events"`
}

// DefaultIngesterConfig returns the default ingester configuration.
func DefaultIngesterConfig() IngesterConfig {
	return IngesterConfig{
		PollInterval:       30 * time.Second,
		DisputeBatchSize:   100,
		ProposalBatchSize:  200,
		IngestDisputes:     true,
		IngestProposals:    true,
		IngestCompliance:   true,
		IngestL3Batches:    true,
		IngestOracleEvents: true,
	}
}

// Ingester polls ILR-Module for events and normalizes them for SIEM ingestion.
type Ingester struct {
	client     *Client
	normalizer *Normalizer
	queue      *queue.RingBuffer
	config     IngesterConfig

	lastDisputeTime    time.Time
	lastProposalTime   time.Time
	lastComplianceTime time.Time
	lastL3Time         time.Time
	lastOracleTime     time.Time

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

// NewIngester creates a new ILR-Module ingester.
func NewIngester(client *Client, normalizer *Normalizer, q *queue.RingBuffer, cfg IngesterConfig) *Ingester {
	return &Ingester{
		client:             client,
		normalizer:         normalizer,
		queue:              q,
		config:             cfg,
		lastDisputeTime:    time.Now().Add(-1 * time.Hour),
		lastProposalTime:   time.Now().Add(-1 * time.Hour),
		lastComplianceTime: time.Now().Add(-1 * time.Hour),
		lastL3Time:         time.Now().Add(-1 * time.Hour),
		lastOracleTime:     time.Now().Add(-1 * time.Hour),
		stopCh:             make(chan struct{}),
	}
}

// Start begins polling the ILR-Module for events.
func (i *Ingester) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return nil
	}
	i.running = true
	i.mu.Unlock()

	slog.Info("starting ilr-module ingester",
		"poll_interval", i.config.PollInterval,
		"ingest_disputes", i.config.IngestDisputes,
		"ingest_proposals", i.config.IngestProposals,
	)

	ticker := time.NewTicker(i.config.PollInterval)
	defer ticker.Stop()

	// Initial poll
	i.poll(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-i.stopCh:
			return nil
		case <-ticker.C:
			i.poll(ctx)
		}
	}
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

// poll fetches and processes events from ILR-Module.
func (i *Ingester) poll(ctx context.Context) {
	var wg sync.WaitGroup

	if i.config.IngestDisputes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollDisputes(ctx)
		}()
	}

	if i.config.IngestProposals {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollProposals(ctx)
		}()
	}

	if i.config.IngestCompliance {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollCompliance(ctx)
		}()
	}

	if i.config.IngestL3Batches {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollL3Batches(ctx)
		}()
	}

	if i.config.IngestOracleEvents {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollOracleEvents(ctx)
		}()
	}

	wg.Wait()
}

// pollDisputes fetches and processes disputes.
func (i *Ingester) pollDisputes(ctx context.Context) {
	disputes, err := i.client.GetDisputes(ctx, "", i.lastDisputeTime, i.config.DisputeBatchSize)
	if err != nil {
		slog.Error("failed to get ilr-module disputes", "error", err)
		return
	}

	if len(disputes) == 0 {
		return
	}

	slog.Debug("fetched ilr-module disputes", "count", len(disputes))

	var latestTime time.Time
	for _, dispute := range disputes {
		event, err := i.normalizer.NormalizeDispute(&dispute)
		if err != nil {
			slog.Warn("failed to normalize ilr-module dispute",
				"dispute_id", dispute.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if dispute.FiledAt.After(latestTime) {
			latestTime = dispute.FiledAt
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastDisputeTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollProposals fetches and processes proposals.
func (i *Ingester) pollProposals(ctx context.Context) {
	proposals, err := i.client.GetProposals(ctx, i.lastProposalTime, i.config.ProposalBatchSize)
	if err != nil {
		slog.Error("failed to get ilr-module proposals", "error", err)
		return
	}

	if len(proposals) == 0 {
		return
	}

	slog.Debug("fetched ilr-module proposals", "count", len(proposals))

	var latestTime time.Time
	for _, proposal := range proposals {
		event, err := i.normalizer.NormalizeProposal(&proposal)
		if err != nil {
			slog.Warn("failed to normalize ilr-module proposal",
				"proposal_id", proposal.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if proposal.ProposedAt.After(latestTime) {
			latestTime = proposal.ProposedAt
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastProposalTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollCompliance fetches and processes compliance events.
func (i *Ingester) pollCompliance(ctx context.Context) {
	events, err := i.client.GetComplianceEvents(ctx, i.lastComplianceTime, 100)
	if err != nil {
		slog.Error("failed to get ilr-module compliance events", "error", err)
		return
	}

	if len(events) == 0 {
		return
	}

	slog.Debug("fetched ilr-module compliance events", "count", len(events))

	var latestTime time.Time
	for _, compEvent := range events {
		event, err := i.normalizer.NormalizeComplianceEvent(&compEvent)
		if err != nil {
			slog.Warn("failed to normalize ilr-module compliance event",
				"event_id", compEvent.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if compEvent.Timestamp.After(latestTime) {
			latestTime = compEvent.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastComplianceTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollL3Batches fetches and processes L3 batch events.
func (i *Ingester) pollL3Batches(ctx context.Context) {
	batches, err := i.client.GetL3BatchEvents(ctx, i.lastL3Time, 50)
	if err != nil {
		slog.Error("failed to get ilr-module L3 batch events", "error", err)
		return
	}

	if len(batches) == 0 {
		return
	}

	slog.Debug("fetched ilr-module L3 batch events", "count", len(batches))

	var latestTime time.Time
	for _, batch := range batches {
		event, err := i.normalizer.NormalizeL3BatchEvent(&batch)
		if err != nil {
			slog.Warn("failed to normalize ilr-module L3 batch event",
				"batch_id", batch.BatchID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if batch.Timestamp.After(latestTime) {
			latestTime = batch.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastL3Time = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollOracleEvents fetches and processes oracle events.
func (i *Ingester) pollOracleEvents(ctx context.Context) {
	events, err := i.client.GetOracleEvents(ctx, i.lastOracleTime, 100)
	if err != nil {
		slog.Error("failed to get ilr-module oracle events", "error", err)
		return
	}

	if len(events) == 0 {
		return
	}

	slog.Debug("fetched ilr-module oracle events", "count", len(events))

	var latestTime time.Time
	for _, oracle := range events {
		event, err := i.normalizer.NormalizeOracleEvent(&oracle)
		if err != nil {
			slog.Warn("failed to normalize ilr-module oracle event",
				"oracle_id", oracle.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if oracle.Timestamp.After(latestTime) {
			latestTime = oracle.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastOracleTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// enqueueEvent adds an event to the queue.
func (i *Ingester) enqueueEvent(event *schema.Event) {
	if err := i.queue.Enqueue(event); err != nil {
		slog.Warn("failed to enqueue ilr-module event",
			"event_id", event.EventID,
			"error", err,
		)
	}
}

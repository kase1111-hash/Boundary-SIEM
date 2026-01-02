package valueledger

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
)

// IngesterConfig holds configuration for the Value Ledger ingester.
type IngesterConfig struct {
	PollInterval      time.Duration `yaml:"poll_interval"`
	EntryBatchSize    int           `yaml:"entry_batch_size"`
	SecurityBatchSize int           `yaml:"security_batch_size"`
	IngestEntries     bool          `yaml:"ingest_entries"`
	IngestSecurity    bool          `yaml:"ingest_security"`
	IngestRevocations bool          `yaml:"ingest_revocations"`
	IngestProofs      bool          `yaml:"ingest_proofs"`
}

// DefaultIngesterConfig returns the default ingester configuration.
func DefaultIngesterConfig() IngesterConfig {
	return IngesterConfig{
		PollInterval:      30 * time.Second,
		EntryBatchSize:    500,
		SecurityBatchSize: 100,
		IngestEntries:     true,
		IngestSecurity:    true,
		IngestRevocations: true,
		IngestProofs:      true,
	}
}

// Ingester polls Value Ledger for events and normalizes them for SIEM ingestion.
type Ingester struct {
	client     *Client
	normalizer *Normalizer
	queue      *queue.RingBuffer
	config     IngesterConfig

	lastEntryTime    time.Time
	lastSecurityTime time.Time
	lastRevokeTime   time.Time

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

// NewIngester creates a new Value Ledger ingester.
func NewIngester(client *Client, normalizer *Normalizer, q *queue.RingBuffer, cfg IngesterConfig) *Ingester {
	return &Ingester{
		client:           client,
		normalizer:       normalizer,
		queue:            q,
		config:           cfg,
		lastEntryTime:    time.Now().Add(-1 * time.Hour),
		lastSecurityTime: time.Now().Add(-1 * time.Hour),
		lastRevokeTime:   time.Now().Add(-1 * time.Hour),
		stopCh:           make(chan struct{}),
	}
}

// Start begins polling the Value Ledger for events.
func (i *Ingester) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return nil
	}
	i.running = true
	i.mu.Unlock()

	slog.Info("starting value-ledger ingester",
		"poll_interval", i.config.PollInterval,
		"ingest_entries", i.config.IngestEntries,
		"ingest_security", i.config.IngestSecurity,
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

// poll fetches and processes events from Value Ledger.
func (i *Ingester) poll(ctx context.Context) {
	var wg sync.WaitGroup

	if i.config.IngestEntries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollEntries(ctx)
		}()
	}

	if i.config.IngestSecurity {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollSecurityEvents(ctx)
		}()
	}

	if i.config.IngestRevocations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollRevocations(ctx)
		}()
	}

	wg.Wait()
}

// pollEntries fetches and processes ledger entries.
func (i *Ingester) pollEntries(ctx context.Context) {
	entries, err := i.client.GetRecentEntries(ctx, i.lastEntryTime, i.config.EntryBatchSize)
	if err != nil {
		slog.Error("failed to get value-ledger entries", "error", err)
		return
	}

	if len(entries) == 0 {
		return
	}

	slog.Debug("fetched value-ledger entries", "count", len(entries))

	var latestTime time.Time
	for _, entry := range entries {
		event, err := i.normalizer.NormalizeLedgerEntry(&entry)
		if err != nil {
			slog.Warn("failed to normalize value-ledger entry",
				"entry_id", entry.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if entry.Timestamp.After(latestTime) {
			latestTime = entry.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastEntryTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollSecurityEvents fetches and processes security events.
func (i *Ingester) pollSecurityEvents(ctx context.Context) {
	events, err := i.client.GetSecurityEvents(ctx, i.lastSecurityTime, i.config.SecurityBatchSize)
	if err != nil {
		slog.Error("failed to get value-ledger security events", "error", err)
		return
	}

	if len(events) == 0 {
		return
	}

	slog.Debug("fetched value-ledger security events", "count", len(events))

	var latestTime time.Time
	for _, secEvent := range events {
		event, err := i.normalizer.NormalizeSecurityEvent(&secEvent)
		if err != nil {
			slog.Warn("failed to normalize value-ledger security event",
				"event_id", secEvent.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if secEvent.Timestamp.After(latestTime) {
			latestTime = secEvent.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastSecurityTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollRevocations fetches and processes revoked entries.
func (i *Ingester) pollRevocations(ctx context.Context) {
	entries, err := i.client.GetRevokedEntries(ctx, i.lastRevokeTime, i.config.EntryBatchSize)
	if err != nil {
		slog.Error("failed to get value-ledger revoked entries", "error", err)
		return
	}

	if len(entries) == 0 {
		return
	}

	slog.Debug("fetched value-ledger revoked entries", "count", len(entries))

	var latestTime time.Time
	for _, entry := range entries {
		event, err := i.normalizer.NormalizeLedgerEntry(&entry)
		if err != nil {
			slog.Warn("failed to normalize value-ledger revoked entry",
				"entry_id", entry.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if entry.RevokedAt != nil && entry.RevokedAt.After(latestTime) {
			latestTime = *entry.RevokedAt
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastRevokeTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// enqueueEvent adds an event to the queue.
func (i *Ingester) enqueueEvent(event *schema.Event) {
	if err := i.queue.Push(event); err != nil {
		slog.Warn("failed to enqueue value-ledger event",
			"event_id", event.EventID,
			"error", err,
		)
	}
}

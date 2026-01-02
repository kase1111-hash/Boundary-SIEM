package learningcontracts

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
)

// IngesterConfig holds configuration for the Learning Contracts ingester.
type IngesterConfig struct {
	PollInterval       time.Duration `yaml:"poll_interval"`
	ContractBatchSize  int           `yaml:"contract_batch_size"`
	EventBatchSize     int           `yaml:"event_batch_size"`
	IngestContracts    bool          `yaml:"ingest_contracts"`
	IngestEnforcement  bool          `yaml:"ingest_enforcement"`
	IngestStateChanges bool          `yaml:"ingest_state_changes"`
	IngestViolations   bool          `yaml:"ingest_violations"`
}

// DefaultIngesterConfig returns the default ingester configuration.
func DefaultIngesterConfig() IngesterConfig {
	return IngesterConfig{
		PollInterval:       30 * time.Second,
		ContractBatchSize:  100,
		EventBatchSize:     500,
		IngestContracts:    true,
		IngestEnforcement:  true,
		IngestStateChanges: true,
		IngestViolations:   true,
	}
}

// Ingester polls Learning Contracts for events and normalizes them for SIEM ingestion.
type Ingester struct {
	client     *Client
	normalizer *Normalizer
	queue      *queue.RingBuffer
	config     IngesterConfig

	lastContractTime    time.Time
	lastEnforcementTime time.Time
	lastStateChangeTime time.Time
	lastViolationTime   time.Time

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

// NewIngester creates a new Learning Contracts ingester.
func NewIngester(client *Client, normalizer *Normalizer, q *queue.RingBuffer, cfg IngesterConfig) *Ingester {
	return &Ingester{
		client:              client,
		normalizer:          normalizer,
		queue:               q,
		config:              cfg,
		lastContractTime:    time.Now().Add(-1 * time.Hour),
		lastEnforcementTime: time.Now().Add(-1 * time.Hour),
		lastStateChangeTime: time.Now().Add(-1 * time.Hour),
		lastViolationTime:   time.Now().Add(-1 * time.Hour),
		stopCh:              make(chan struct{}),
	}
}

// Start begins polling the Learning Contracts module for events.
func (i *Ingester) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return nil
	}
	i.running = true
	i.mu.Unlock()

	slog.Info("starting learning-contracts ingester",
		"poll_interval", i.config.PollInterval,
		"ingest_contracts", i.config.IngestContracts,
		"ingest_enforcement", i.config.IngestEnforcement,
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

// poll fetches and processes events from Learning Contracts.
func (i *Ingester) poll(ctx context.Context) {
	var wg sync.WaitGroup

	if i.config.IngestContracts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollContracts(ctx)
		}()
	}

	if i.config.IngestEnforcement {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollEnforcement(ctx)
		}()
	}

	if i.config.IngestStateChanges {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollStateChanges(ctx)
		}()
	}

	if i.config.IngestViolations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollViolations(ctx)
		}()
	}

	wg.Wait()
}

// pollContracts fetches and processes contracts.
func (i *Ingester) pollContracts(ctx context.Context) {
	contracts, err := i.client.GetContracts(ctx, "", i.lastContractTime, i.config.ContractBatchSize)
	if err != nil {
		slog.Error("failed to get learning-contracts contracts", "error", err)
		return
	}

	if len(contracts) == 0 {
		return
	}

	slog.Debug("fetched learning-contracts contracts", "count", len(contracts))

	var latestTime time.Time
	for _, contract := range contracts {
		event, err := i.normalizer.NormalizeContract(&contract)
		if err != nil {
			slog.Warn("failed to normalize learning-contracts contract",
				"contract_id", contract.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		timestamp := contract.CreatedAt
		if contract.ActivatedAt != nil && contract.ActivatedAt.After(timestamp) {
			timestamp = *contract.ActivatedAt
		}
		if contract.RevokedAt != nil && contract.RevokedAt.After(timestamp) {
			timestamp = *contract.RevokedAt
		}

		if timestamp.After(latestTime) {
			latestTime = timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastContractTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollEnforcement fetches and processes enforcement events.
func (i *Ingester) pollEnforcement(ctx context.Context) {
	events, err := i.client.GetEnforcementEvents(ctx, i.lastEnforcementTime, i.config.EventBatchSize)
	if err != nil {
		slog.Error("failed to get learning-contracts enforcement events", "error", err)
		return
	}

	if len(events) == 0 {
		return
	}

	slog.Debug("fetched learning-contracts enforcement events", "count", len(events))

	var latestTime time.Time
	for _, enforcement := range events {
		event, err := i.normalizer.NormalizeEnforcementEvent(&enforcement)
		if err != nil {
			slog.Warn("failed to normalize learning-contracts enforcement event",
				"event_id", enforcement.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if enforcement.Timestamp.After(latestTime) {
			latestTime = enforcement.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastEnforcementTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollStateChanges fetches and processes state changes.
func (i *Ingester) pollStateChanges(ctx context.Context) {
	changes, err := i.client.GetStateChanges(ctx, i.lastStateChangeTime, i.config.EventBatchSize)
	if err != nil {
		slog.Error("failed to get learning-contracts state changes", "error", err)
		return
	}

	if len(changes) == 0 {
		return
	}

	slog.Debug("fetched learning-contracts state changes", "count", len(changes))

	var latestTime time.Time
	for _, change := range changes {
		event, err := i.normalizer.NormalizeStateChange(&change)
		if err != nil {
			slog.Warn("failed to normalize learning-contracts state change",
				"change_id", change.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if change.Timestamp.After(latestTime) {
			latestTime = change.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastStateChangeTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollViolations fetches and processes violations.
func (i *Ingester) pollViolations(ctx context.Context) {
	violations, err := i.client.GetViolations(ctx, i.lastViolationTime, i.config.EventBatchSize)
	if err != nil {
		slog.Error("failed to get learning-contracts violations", "error", err)
		return
	}

	if len(violations) == 0 {
		return
	}

	slog.Debug("fetched learning-contracts violations", "count", len(violations))

	var latestTime time.Time
	for _, violation := range violations {
		event, err := i.normalizer.NormalizeViolation(&violation)
		if err != nil {
			slog.Warn("failed to normalize learning-contracts violation",
				"violation_id", violation.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if violation.Timestamp.After(latestTime) {
			latestTime = violation.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastViolationTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// enqueueEvent adds an event to the queue.
func (i *Ingester) enqueueEvent(event *schema.Event) {
	if err := i.queue.Push(event); err != nil {
		slog.Warn("failed to enqueue learning-contracts event",
			"event_id", event.EventID,
			"error", err,
		)
	}
}

package alerting

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DeliveryStatus represents the delivery state of a notification.
type DeliveryStatus string

const (
	DeliveryPending   DeliveryStatus = "pending"
	DeliverySent      DeliveryStatus = "sent"
	DeliveryFailed    DeliveryStatus = "failed"
	DeliveryRetrying  DeliveryStatus = "retrying"
	DeliveryDeadLetter DeliveryStatus = "dead_letter"
)

// DeliveryRecord tracks the delivery of a notification to a specific channel.
type DeliveryRecord struct {
	ID          uuid.UUID      `json:"id"`
	AlertID     uuid.UUID      `json:"alert_id"`
	ChannelName string         `json:"channel_name"`
	Status      DeliveryStatus `json:"status"`
	Attempts    int            `json:"attempts"`
	LastAttempt time.Time      `json:"last_attempt"`
	LastError   string         `json:"last_error,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	DeliveredAt *time.Time     `json:"delivered_at,omitempty"`
}

// DeliveryConfig configures the reliable delivery system.
type DeliveryConfig struct {
	MaxRetries     int           // Maximum retry attempts (default 5)
	InitialBackoff time.Duration // First retry delay (default 1s)
	MaxBackoff     time.Duration // Maximum backoff duration (default 30s)
	BackoffFactor  float64       // Backoff multiplier (default 2.0)
	RetryTimeout   time.Duration // Per-attempt timeout (default 10s)
}

// DefaultDeliveryConfig returns sensible delivery defaults.
func DefaultDeliveryConfig() DeliveryConfig {
	return DeliveryConfig{
		MaxRetries:     5,
		InitialBackoff: 1 * time.Second,
		MaxBackoff:     30 * time.Second,
		BackoffFactor:  2.0,
		RetryTimeout:   10 * time.Second,
	}
}

// ReliableDispatcher handles notification delivery with retries and dead-letter support.
type ReliableDispatcher struct {
	config     DeliveryConfig
	channels   []NotificationChannel
	records    map[uuid.UUID]*DeliveryRecord
	deadLetter []*DeliveryRecord
	mu         sync.RWMutex
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// NewReliableDispatcher creates a new reliable notification dispatcher.
func NewReliableDispatcher(cfg DeliveryConfig, channels []NotificationChannel) *ReliableDispatcher {
	return &ReliableDispatcher{
		config:   cfg,
		channels: channels,
		records:  make(map[uuid.UUID]*DeliveryRecord),
		stopCh:   make(chan struct{}),
	}
}

// Dispatch sends an alert to all channels with retry logic.
func (d *ReliableDispatcher) Dispatch(ctx context.Context, alert *Alert) {
	for _, ch := range d.channels {
		record := &DeliveryRecord{
			ID:          uuid.New(),
			AlertID:     alert.ID,
			ChannelName: ch.Name(),
			Status:      DeliveryPending,
			CreatedAt:   time.Now(),
		}

		d.mu.Lock()
		d.records[record.ID] = record
		d.mu.Unlock()

		d.wg.Add(1)
		go d.deliverWithRetry(ctx, ch, alert, record)
	}
}

// deliverWithRetry attempts delivery with exponential backoff.
func (d *ReliableDispatcher) deliverWithRetry(ctx context.Context, ch NotificationChannel, alert *Alert, record *DeliveryRecord) {
	defer d.wg.Done()

	backoff := d.config.InitialBackoff
	maxRetries := d.config.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 5
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		d.mu.Lock()
		record.Attempts = attempt
		record.LastAttempt = time.Now()
		if attempt > 1 {
			record.Status = DeliveryRetrying
		}
		d.mu.Unlock()

		// Create a per-attempt context with timeout
		attemptCtx, cancel := context.WithTimeout(ctx, d.config.RetryTimeout)
		err := ch.Send(attemptCtx, alert)
		cancel()

		if err == nil {
			now := time.Now()
			d.mu.Lock()
			record.Status = DeliverySent
			record.DeliveredAt = &now
			d.mu.Unlock()

			slog.Debug("notification delivered",
				"channel", ch.Name(),
				"alert_id", alert.ID,
				"attempts", attempt,
			)
			return
		}

		d.mu.Lock()
		record.LastError = err.Error()
		d.mu.Unlock()

		slog.Warn("notification delivery failed",
			"channel", ch.Name(),
			"alert_id", alert.ID,
			"attempt", attempt,
			"max_retries", maxRetries,
			"error", err,
		)

		// Don't sleep after the last attempt
		if attempt < maxRetries {
			select {
			case <-ctx.Done():
				d.moveToDeadLetter(record, "context cancelled")
				return
			case <-d.stopCh:
				d.moveToDeadLetter(record, "dispatcher stopped")
				return
			case <-time.After(backoff):
			}

			// Increase backoff
			backoff = time.Duration(float64(backoff) * d.config.BackoffFactor)
			if backoff > d.config.MaxBackoff {
				backoff = d.config.MaxBackoff
			}
		}
	}

	// Exhausted all retries — move to dead letter queue
	d.moveToDeadLetter(record, record.LastError)
}

func (d *ReliableDispatcher) moveToDeadLetter(record *DeliveryRecord, reason string) {
	d.mu.Lock()
	record.Status = DeliveryDeadLetter
	record.LastError = reason
	d.deadLetter = append(d.deadLetter, record)
	d.mu.Unlock()

	slog.Error("notification moved to dead letter queue",
		"alert_id", record.AlertID,
		"channel", record.ChannelName,
		"attempts", record.Attempts,
		"reason", reason,
	)
}

// DeadLetterQueue returns all failed delivery records.
func (d *ReliableDispatcher) DeadLetterQueue() []*DeliveryRecord {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]*DeliveryRecord, len(d.deadLetter))
	copy(result, d.deadLetter)
	return result
}

// RetryDeadLetter retries a specific dead letter delivery.
func (d *ReliableDispatcher) RetryDeadLetter(ctx context.Context, recordID uuid.UUID, alert *Alert) error {
	d.mu.Lock()
	var target *DeliveryRecord
	var targetIdx int
	for i, rec := range d.deadLetter {
		if rec.ID == recordID {
			target = rec
			targetIdx = i
			break
		}
	}
	if target == nil {
		d.mu.Unlock()
		return fmt.Errorf("dead letter record not found: %s", recordID)
	}

	// Remove from dead letter queue
	d.deadLetter = append(d.deadLetter[:targetIdx], d.deadLetter[targetIdx+1:]...)

	// Reset for retry
	target.Status = DeliveryPending
	target.Attempts = 0
	target.LastError = ""
	d.mu.Unlock()

	// Find channel
	var ch NotificationChannel
	for _, c := range d.channels {
		if c.Name() == target.ChannelName {
			ch = c
			break
		}
	}
	if ch == nil {
		d.moveToDeadLetter(target, "channel not found: "+target.ChannelName)
		return fmt.Errorf("channel not found: %s", target.ChannelName)
	}

	d.wg.Add(1)
	go d.deliverWithRetry(ctx, ch, alert, target)
	return nil
}

// GetDeliveryRecords returns delivery records for a given alert.
func (d *ReliableDispatcher) GetDeliveryRecords(alertID uuid.UUID) []*DeliveryRecord {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var records []*DeliveryRecord
	for _, rec := range d.records {
		if rec.AlertID == alertID {
			records = append(records, rec)
		}
	}
	return records
}

// Stats returns delivery statistics.
func (d *ReliableDispatcher) Stats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	statusCounts := make(map[string]int)
	channelCounts := make(map[string]map[string]int)

	for _, rec := range d.records {
		statusCounts[string(rec.Status)]++

		if _, ok := channelCounts[rec.ChannelName]; !ok {
			channelCounts[rec.ChannelName] = make(map[string]int)
		}
		channelCounts[rec.ChannelName][string(rec.Status)]++
	}

	return map[string]interface{}{
		"total_deliveries":  len(d.records),
		"dead_letter_count": len(d.deadLetter),
		"by_status":         statusCounts,
		"by_channel":        channelCounts,
	}
}

// Stop waits for all pending deliveries to complete.
func (d *ReliableDispatcher) Stop() {
	close(d.stopCh)
	d.wg.Wait()
}

package boundarydaemon

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
)

// IngesterConfig holds configuration for the Boundary Daemon ingester.
type IngesterConfig struct {
	PollInterval      time.Duration `yaml:"poll_interval"`
	SessionBatchSize  int           `yaml:"session_batch_size"`
	AuthBatchSize     int           `yaml:"auth_batch_size"`
	AccessBatchSize   int           `yaml:"access_batch_size"`
	ThreatBatchSize   int           `yaml:"threat_batch_size"`
	PolicyBatchSize   int           `yaml:"policy_batch_size"`
	AuditBatchSize    int           `yaml:"audit_batch_size"`
	IngestSessions    bool          `yaml:"ingest_sessions"`
	IngestAuth        bool          `yaml:"ingest_auth"`
	IngestAccess      bool          `yaml:"ingest_access"`
	IngestThreats     bool          `yaml:"ingest_threats"`
	IngestPolicies    bool          `yaml:"ingest_policies"`
	IngestAuditLogs   bool          `yaml:"ingest_audit_logs"`
	VerifyAuditLogs   bool          `yaml:"verify_audit_logs"`
	MinThreatSeverity string        `yaml:"min_threat_severity"`
}

// DefaultIngesterConfig returns the default ingester configuration.
func DefaultIngesterConfig() IngesterConfig {
	return IngesterConfig{
		PollInterval:      30 * time.Second,
		SessionBatchSize:  500,
		AuthBatchSize:     500,
		AccessBatchSize:   500,
		ThreatBatchSize:   100,
		PolicyBatchSize:   200,
		AuditBatchSize:    500,
		IngestSessions:    true,
		IngestAuth:        true,
		IngestAccess:      true,
		IngestThreats:     true,
		IngestPolicies:    true,
		IngestAuditLogs:   true,
		VerifyAuditLogs:   false, // Disabled by default for performance
		MinThreatSeverity: "low",
	}
}

// Ingester polls Boundary Daemon for events and normalizes them for SIEM ingestion.
type Ingester struct {
	client     *Client
	normalizer *Normalizer
	queue      *queue.RingBuffer
	config     IngesterConfig

	lastSessionTime time.Time
	lastAuthTime    time.Time
	lastAccessTime  time.Time
	lastThreatTime  time.Time
	lastPolicyTime  time.Time
	lastAuditTime   time.Time

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

// NewIngester creates a new Boundary Daemon ingester.
func NewIngester(client *Client, normalizer *Normalizer, q *queue.RingBuffer, cfg IngesterConfig) *Ingester {
	return &Ingester{
		client:          client,
		normalizer:      normalizer,
		queue:           q,
		config:          cfg,
		lastSessionTime: time.Now().Add(-1 * time.Hour),
		lastAuthTime:    time.Now().Add(-1 * time.Hour),
		lastAccessTime:  time.Now().Add(-1 * time.Hour),
		lastThreatTime:  time.Now().Add(-1 * time.Hour),
		lastPolicyTime:  time.Now().Add(-1 * time.Hour),
		lastAuditTime:   time.Now().Add(-1 * time.Hour),
		stopCh:          make(chan struct{}),
	}
}

// Start begins polling the Boundary Daemon for events.
func (i *Ingester) Start(ctx context.Context) error {
	i.mu.Lock()
	if i.running {
		i.mu.Unlock()
		return nil
	}
	i.running = true
	i.mu.Unlock()

	slog.Info("starting boundary-daemon ingester",
		"poll_interval", i.config.PollInterval,
		"ingest_sessions", i.config.IngestSessions,
		"ingest_auth", i.config.IngestAuth,
		"ingest_access", i.config.IngestAccess,
		"ingest_threats", i.config.IngestThreats,
		"ingest_policies", i.config.IngestPolicies,
		"ingest_audit_logs", i.config.IngestAuditLogs,
	)

	// Initial health check
	health, err := i.client.GetHealth(ctx)
	if err != nil {
		slog.Warn("boundary-daemon health check failed", "error", err)
	} else {
		slog.Info("boundary-daemon connection established",
			"status", health.Status,
			"version", health.Version,
			"mode", health.Mode,
			"active_sessions", health.ActiveSessions,
		)
	}

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

// poll fetches and processes events from Boundary Daemon.
func (i *Ingester) poll(ctx context.Context) {
	var wg sync.WaitGroup

	if i.config.IngestSessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollSessionEvents(ctx)
		}()
	}

	if i.config.IngestAuth {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollAuthEvents(ctx)
		}()
	}

	if i.config.IngestAccess {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollAccessEvents(ctx)
		}()
	}

	if i.config.IngestThreats {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollThreatEvents(ctx)
		}()
	}

	if i.config.IngestPolicies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollPolicyEvents(ctx)
		}()
	}

	if i.config.IngestAuditLogs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i.pollAuditLogs(ctx)
		}()
	}

	wg.Wait()
}

// pollSessionEvents fetches and processes session events.
func (i *Ingester) pollSessionEvents(ctx context.Context) {
	i.mu.RLock()
	since := i.lastSessionTime
	i.mu.RUnlock()

	events, err := i.client.GetSessionEvents(ctx, since, i.config.SessionBatchSize)
	if err != nil {
		slog.Error("failed to get boundary-daemon session events", "error", err)
		return
	}

	if len(events) == 0 {
		return
	}

	slog.Debug("fetched boundary-daemon session events", "count", len(events))

	var latestTime time.Time
	for _, ev := range events {
		event, err := i.normalizer.NormalizeSessionEvent(&ev)
		if err != nil {
			slog.Warn("failed to normalize boundary-daemon session event",
				"event_id", ev.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if ev.Timestamp.After(latestTime) {
			latestTime = ev.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastSessionTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollAuthEvents fetches and processes authentication events.
func (i *Ingester) pollAuthEvents(ctx context.Context) {
	i.mu.RLock()
	since := i.lastAuthTime
	i.mu.RUnlock()

	events, err := i.client.GetAuthEvents(ctx, since, i.config.AuthBatchSize)
	if err != nil {
		slog.Error("failed to get boundary-daemon auth events", "error", err)
		return
	}

	if len(events) == 0 {
		return
	}

	slog.Debug("fetched boundary-daemon auth events", "count", len(events))

	var latestTime time.Time
	for _, ev := range events {
		event, err := i.normalizer.NormalizeAuthEvent(&ev)
		if err != nil {
			slog.Warn("failed to normalize boundary-daemon auth event",
				"event_id", ev.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if ev.Timestamp.After(latestTime) {
			latestTime = ev.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastAuthTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollAccessEvents fetches and processes access control events.
func (i *Ingester) pollAccessEvents(ctx context.Context) {
	i.mu.RLock()
	since := i.lastAccessTime
	i.mu.RUnlock()

	events, err := i.client.GetAccessEvents(ctx, since, i.config.AccessBatchSize)
	if err != nil {
		slog.Error("failed to get boundary-daemon access events", "error", err)
		return
	}

	if len(events) == 0 {
		return
	}

	slog.Debug("fetched boundary-daemon access events", "count", len(events))

	var latestTime time.Time
	for _, ev := range events {
		event, err := i.normalizer.NormalizeAccessEvent(&ev)
		if err != nil {
			slog.Warn("failed to normalize boundary-daemon access event",
				"event_id", ev.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if ev.Timestamp.After(latestTime) {
			latestTime = ev.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastAccessTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollThreatEvents fetches and processes threat detection events.
func (i *Ingester) pollThreatEvents(ctx context.Context) {
	i.mu.RLock()
	since := i.lastThreatTime
	i.mu.RUnlock()

	events, err := i.client.GetThreatEvents(ctx, since, i.config.ThreatBatchSize)
	if err != nil {
		slog.Error("failed to get boundary-daemon threat events", "error", err)
		return
	}

	if len(events) == 0 {
		return
	}

	slog.Debug("fetched boundary-daemon threat events", "count", len(events))

	var latestTime time.Time
	for _, ev := range events {
		// Filter by minimum severity
		if !i.meetsMinSeverity(ev.Severity) {
			continue
		}

		event, err := i.normalizer.NormalizeThreatEvent(&ev)
		if err != nil {
			slog.Warn("failed to normalize boundary-daemon threat event",
				"event_id", ev.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if ev.Timestamp.After(latestTime) {
			latestTime = ev.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastThreatTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollPolicyEvents fetches and processes policy enforcement events.
func (i *Ingester) pollPolicyEvents(ctx context.Context) {
	i.mu.RLock()
	since := i.lastPolicyTime
	i.mu.RUnlock()

	events, err := i.client.GetPolicyEvents(ctx, since, i.config.PolicyBatchSize)
	if err != nil {
		slog.Error("failed to get boundary-daemon policy events", "error", err)
		return
	}

	if len(events) == 0 {
		return
	}

	slog.Debug("fetched boundary-daemon policy events", "count", len(events))

	var latestTime time.Time
	for _, ev := range events {
		event, err := i.normalizer.NormalizePolicyEvent(&ev)
		if err != nil {
			slog.Warn("failed to normalize boundary-daemon policy event",
				"event_id", ev.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if ev.Timestamp.After(latestTime) {
			latestTime = ev.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastPolicyTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// pollAuditLogs fetches and processes cryptographically signed audit logs.
func (i *Ingester) pollAuditLogs(ctx context.Context) {
	i.mu.RLock()
	since := i.lastAuditTime
	i.mu.RUnlock()

	logs, err := i.client.GetAuditLogs(ctx, since, i.config.AuditBatchSize)
	if err != nil {
		slog.Error("failed to get boundary-daemon audit logs", "error", err)
		return
	}

	if len(logs) == 0 {
		return
	}

	slog.Debug("fetched boundary-daemon audit logs", "count", len(logs))

	var latestTime time.Time
	for _, log := range logs {
		// Optionally verify signature
		if i.config.VerifyAuditLogs && !log.Verified {
			verified, err := i.client.VerifyAuditLog(ctx, log.ID)
			if err != nil {
				slog.Warn("failed to verify boundary-daemon audit log",
					"log_id", log.ID,
					"error", err,
				)
			} else {
				log = *verified
			}
		}

		event, err := i.normalizer.NormalizeAuditLog(&log)
		if err != nil {
			slog.Warn("failed to normalize boundary-daemon audit log",
				"log_id", log.ID,
				"error", err,
			)
			continue
		}

		i.enqueueEvent(event)

		if log.Timestamp.After(latestTime) {
			latestTime = log.Timestamp
		}
	}

	if !latestTime.IsZero() {
		i.mu.Lock()
		i.lastAuditTime = latestTime.Add(time.Millisecond)
		i.mu.Unlock()
	}
}

// enqueueEvent adds an event to the queue.
func (i *Ingester) enqueueEvent(event *schema.Event) {
	if err := i.queue.Push(event); err != nil {
		slog.Warn("failed to enqueue boundary-daemon event",
			"event_id", event.EventID,
			"error", err,
		)
	}
}

// meetsMinSeverity checks if a severity level meets the minimum threshold.
func (i *Ingester) meetsMinSeverity(severity string) bool {
	severityLevels := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	eventLevel, ok := severityLevels[severity]
	if !ok {
		return true // Unknown severity passes through
	}

	minLevel, ok := severityLevels[i.config.MinThreatSeverity]
	if !ok {
		return true // Unknown min severity allows all
	}

	return eventLevel >= minLevel
}

// Stats returns current ingester statistics.
func (i *Ingester) Stats() IngesterStats {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return IngesterStats{
		Running:         i.running,
		LastSessionTime: i.lastSessionTime,
		LastAuthTime:    i.lastAuthTime,
		LastAccessTime:  i.lastAccessTime,
		LastThreatTime:  i.lastThreatTime,
		LastPolicyTime:  i.lastPolicyTime,
		LastAuditTime:   i.lastAuditTime,
	}
}

// IngesterStats holds ingester statistics.
type IngesterStats struct {
	Running         bool      `json:"running"`
	LastSessionTime time.Time `json:"last_session_time"`
	LastAuthTime    time.Time `json:"last_auth_time"`
	LastAccessTime  time.Time `json:"last_access_time"`
	LastThreatTime  time.Time `json:"last_threat_time"`
	LastPolicyTime  time.Time `json:"last_policy_time"`
	LastAuditTime   time.Time `json:"last_audit_time"`
}

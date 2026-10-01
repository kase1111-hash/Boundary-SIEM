// Package ingest handles HTTP ingestion of events.
package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
	"boundary-siem/internal/storage"
)

// Component status values reported by /health and used by /ready.
const (
	StatusUp       = "up"
	StatusDegraded = "degraded"
	StatusDown     = "down"
	StatusDisabled = "disabled"
)

// ComponentStatus describes one subsystem in the /health response. /health
// is unauthenticated, so it carries no secrets: only state and the listen
// address.
type ComponentStatus struct {
	Status  string `json:"status"`
	Enabled bool   `json:"enabled"`
	Address string `json:"address,omitempty"`
	Message string `json:"message,omitempty"`
}

// SourceMetrics holds the counters of a non-HTTP ingest transport (CEF over
// UDP, TCP or DTLS). Queued events count towards siem_events_total.
type SourceMetrics struct {
	Transport        string
	Received         uint64
	Queued           uint64
	Errors           uint64
	ParseErrors      uint64
	ValidationErrors uint64
	OversizedLines   uint64
}

// Metric is an additional Prometheus sample exported on /metrics.
type Metric struct {
	Name   string
	Help   string
	Type   string // "counter" or "gauge"
	Labels map[string]string
	Value  float64
}

// Handler handles HTTP event ingestion.
type Handler struct {
	validator     *schema.Validator
	queue         *queue.RingBuffer
	maxPayload    int
	maxBatch      int
	startTime     time.Time
	defaultTenant string
	quarantine    *Quarantiner
	components    func() map[string]ComponentStatus
	sources       func() []SourceMetrics
	extraMetrics  func() []Metric

	httpAccepted uint64
	shuttingDown atomic.Bool
}

// NewHandler creates a new ingest Handler.
func NewHandler(validator *schema.Validator, q *queue.RingBuffer) *Handler {
	return &Handler{
		validator:  validator,
		queue:      q,
		maxPayload: 10 * 1024 * 1024, // 10MB default
		maxBatch:   1000,
		startTime:  time.Now(),
	}
}

// WithMaxPayload sets the maximum payload size.
func (h *Handler) WithMaxPayload(size int) *Handler {
	h.maxPayload = size
	return h
}

// WithMaxBatch sets the maximum batch size.
func (h *Handler) WithMaxBatch(size int) *Handler {
	h.maxBatch = size
	return h
}

// WithDefaultTenant sets the tenant given to events ingested without one,
// so JSON events land in the same tenant as CEF events and the tenant the
// search API defaults to.
func (h *Handler) WithDefaultTenant(tenantID string) *Handler {
	h.defaultTenant = tenantID
	return h
}

// WithQuarantine stores rejected events (malformed JSON, failed validation)
// in the quarantine table through q. Quarantine is best effort and never
// changes the response.
func (h *Handler) WithQuarantine(q *Quarantiner) *Handler {
	h.quarantine = q
	return h
}

// WithComponents sets the function reporting subsystem status for /health
// and /ready.
func (h *Handler) WithComponents(fn func() map[string]ComponentStatus) *Handler {
	h.components = fn
	return h
}

// WithSources sets the function reporting the counters of the non-HTTP
// ingest transports for /metrics and siem_events_total.
func (h *Handler) WithSources(fn func() []SourceMetrics) *Handler {
	h.sources = fn
	return h
}

// WithMetrics sets a function returning additional samples for /metrics.
func (h *Handler) WithMetrics(fn func() []Metric) *Handler {
	h.extraMetrics = fn
	return h
}

// SetShuttingDown makes /ready report not ready, so load balancers stop
// sending traffic while the service drains.
func (h *Handler) SetShuttingDown() {
	h.shuttingDown.Store(true)
}

// IngestRequest is the request body for event ingestion.
type IngestRequest struct {
	Events []EventInput `json:"events"`
}

// EventInput is the input format for events.
type EventInput struct {
	EventID   *uuid.UUID      `json:"event_id,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
	Source    schema.Source   `json:"source"`
	Action    string          `json:"action"`
	Outcome   schema.Outcome  `json:"outcome"`
	Severity  int             `json:"severity"`
	Actor     *schema.Actor   `json:"actor,omitempty"`
	Network   *schema.Network `json:"network,omitempty"`
	Target    string          `json:"target,omitempty"`
	Raw       string          `json:"raw,omitempty"`
	Metadata  map[string]any  `json:"metadata,omitempty"`
}

// IngestResponse is the response for event ingestion.
type IngestResponse struct {
	Success   bool     `json:"success"`
	Accepted  int      `json:"accepted"`
	Rejected  int      `json:"rejected"`
	Errors    []string `json:"errors,omitempty"`
	RequestID string   `json:"request_id"`
}

// parseEvents decodes a request body. Three shapes are accepted: the
// canonical {"events":[...]} wrapper, a JSON array of events, and a single
// bare event object.
func parseEvents(body []byte) ([]EventInput, error) {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var events []EventInput
		err := json.Unmarshal(body, &events)
		return events, err
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, err
	}
	if _, ok := probe["events"]; ok {
		var req IngestRequest
		err := json.Unmarshal(body, &req)
		return req.Events, err
	}
	if len(probe) == 0 {
		return nil, nil
	}
	var event EventInput
	if err := json.Unmarshal(body, &event); err != nil {
		return nil, err
	}
	return []EventInput{event}, nil
}

// clientIP returns the host part of the request's remote address.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// HandleEvents handles POST /v1/events.
func (h *Handler) HandleEvents(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, int64(h.maxPayload))

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// MaxBytesReader returns a MaxBytesError when the body exceeds the limit
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			respondError(w, http.StatusRequestEntityTooLarge, "payload too large", requestID)
			return
		}
		respondError(w, http.StatusBadRequest, "failed to read request body", requestID)
		return
	}

	inputs, err := parseEvents(body)
	if err != nil {
		if h.quarantine != nil {
			h.quarantine.Submit(storage.NewQuarantineEntry(string(body), clientIP(r),
				storage.QuarantineFormatJSON, storage.QuarantineCodeParseFailed, err.Error()))
		}
		respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err), requestID)
		return
	}

	// Check batch size
	if len(inputs) == 0 {
		respondError(w, http.StatusBadRequest, "no events provided", requestID)
		return
	}

	if len(inputs) > h.maxBatch {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("batch size exceeds maximum of %d", h.maxBatch), requestID)
		return
	}

	// Process events
	var accepted, rejected, unavailable int
	var errs []string
	var quarantined []*storage.QuarantineEntry

	for i, input := range inputs {
		event := h.convertInput(input)
		event.RequestID = requestID

		// Validate event
		if err := h.validator.Validate(event); err != nil {
			rejected++
			errs = append(errs, fmt.Sprintf("event[%d]: %s", i, err.Error()))
			if h.quarantine != nil {
				quarantined = append(quarantined, storage.QuarantineEntryForEvent(event, clientIP(r),
					storage.QuarantineFormatJSON, storage.QuarantineCodeValidationFailed, err.Error()))
			}
			continue
		}

		// Enqueue event
		if err := h.queue.Push(event); err != nil {
			rejected++
			unavailable++
			switch {
			case errors.Is(err, queue.ErrQueueFull):
				errs = append(errs, fmt.Sprintf("event[%d]: queue full", i))
			case errors.Is(err, queue.ErrQueueClosed):
				errs = append(errs, fmt.Sprintf("event[%d]: server shutting down", i))
			default:
				errs = append(errs, fmt.Sprintf("event[%d]: %s", i, err.Error()))
			}
			continue
		}

		accepted++
		atomic.AddUint64(&h.httpAccepted, 1)
	}

	if len(quarantined) > 0 {
		h.quarantine.Submit(quarantined...)
	}

	// Build response
	resp := IngestResponse{
		Success:   rejected == 0,
		Accepted:  accepted,
		Rejected:  rejected,
		RequestID: requestID,
	}

	if len(errs) > 0 {
		resp.Errors = errs
	}

	status := http.StatusOK
	switch {
	case accepted == 0 && rejected > 0 && unavailable == rejected:
		// Nothing was wrong with the events: the server cannot take them
		// right now. 503 tells clients to retry.
		status = http.StatusServiceUnavailable
		w.Header().Set("Retry-After", "1")
	case accepted == 0 && rejected > 0:
		status = http.StatusBadRequest
	case rejected > 0:
		status = http.StatusMultiStatus // 207 for partial success
	}

	respondJSON(w, status, resp)
}

// convertInput converts an EventInput to a canonical Event.
func (h *Handler) convertInput(input EventInput) *schema.Event {
	event := &schema.Event{
		TenantID:      h.defaultTenant,
		Timestamp:     input.Timestamp,
		Source:        input.Source,
		Action:        input.Action,
		Outcome:       input.Outcome,
		Severity:      input.Severity,
		Actor:         input.Actor,
		Network:       input.Network,
		Target:        input.Target,
		Raw:           input.Raw,
		Metadata:      input.Metadata,
		SchemaVersion: schema.SchemaVersionCurrent,
		ReceivedAt:    time.Now().UTC(),
	}

	// Generate event ID if not provided
	if input.EventID != nil {
		event.EventID = *input.EventID
	} else {
		event.EventID = uuid.New()
	}

	return event
}

// queueBacklogged reports whether the queue is more than 90% full.
func queueBacklogged(m queue.QueueMetrics) bool {
	return m.Depth > int(float64(m.Capacity)*0.9)
}

// componentStatus returns the subsystem status, or nil without a reporter.
func (h *Handler) componentStatus() map[string]ComponentStatus {
	if h.components == nil {
		return nil
	}
	return h.components()
}

// HealthCheck handles GET /health. It always answers 200 while the process
// runs; "status" is "degraded" when the queue is backlogged or a subsystem
// (for example storage) is degraded or down, and "components" says which.
// Use /ready for load-balancer decisions.
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	metrics := h.queue.Metrics()
	components := h.componentStatus()

	status := "healthy"
	if queueBacklogged(metrics) {
		status = "degraded"
	}
	for _, c := range components {
		if c.Enabled && (c.Status == StatusDown || c.Status == StatusDegraded) {
			status = "degraded"
		}
	}

	resp := map[string]any{
		"status":         status,
		"queue_depth":    metrics.Depth,
		"queue_capacity": metrics.Capacity,
		"uptime_seconds": int(time.Since(h.startTime).Seconds()),
	}
	if components != nil {
		resp["components"] = components
	}

	respondJSON(w, http.StatusOK, resp)
}

// Ready handles GET /ready: 200 when the service should receive traffic,
// 503 with the reasons when it is shutting down, its queue is backlogged or
// an enabled subsystem is down.
func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	var reasons []string
	if h.shuttingDown.Load() {
		reasons = append(reasons, "shutting down")
	}
	if m := h.queue.Metrics(); queueBacklogged(m) {
		reasons = append(reasons, fmt.Sprintf("queue backlogged (%d/%d)", m.Depth, m.Capacity))
	}
	components := h.componentStatus()
	names := make([]string, 0, len(components))
	for name := range components {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if c := components[name]; c.Enabled && c.Status == StatusDown {
			reason := name + " down"
			if c.Message != "" {
				reason += ": " + c.Message
			}
			reasons = append(reasons, reason)
		}
	}

	if len(reasons) > 0 {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status":  "not_ready",
			"reasons": reasons,
		})
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

// eventsTotal returns the events accepted into the queue over every
// transport: HTTP plus the CEF servers.
func (h *Handler) eventsTotal() uint64 {
	total := atomic.LoadUint64(&h.httpAccepted)
	if h.sources != nil {
		for _, s := range h.sources() {
			total += s.Queued
		}
	}
	return total
}

// Metrics handles GET /metrics (Prometheus format).
func (h *Handler) Metrics(w http.ResponseWriter, r *http.Request) {
	metrics := h.queue.Metrics()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	var sources []SourceMetrics
	if h.sources != nil {
		sources = h.sources()
	}

	httpAccepted := atomic.LoadUint64(&h.httpAccepted)
	total := httpAccepted
	for _, s := range sources {
		total += s.Queued
	}

	var b strings.Builder
	writeSample := func(name, help, typ string, value string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %s\n\n", name, help, name, typ, name, value)
	}

	writeSample("siem_events_total", "Total number of events ingested (HTTP and CEF)", "counter", strconv.FormatUint(total, 10))

	fmt.Fprintf(&b, "# HELP siem_events_ingested_total Events accepted into the queue by transport\n")
	fmt.Fprintf(&b, "# TYPE siem_events_ingested_total counter\n")
	fmt.Fprintf(&b, "siem_events_ingested_total{transport=\"http\"} %d\n", httpAccepted)
	for _, s := range sources {
		fmt.Fprintf(&b, "siem_events_ingested_total{transport=%q} %d\n", labelValue(s.Transport), s.Queued)
	}
	b.WriteString("\n")

	if len(sources) > 0 {
		for _, series := range []struct {
			name, help string
			value      func(SourceMetrics) uint64
			tcpOnly    bool
		}{
			{"siem_cef_received_total", "CEF messages received", func(s SourceMetrics) uint64 { return s.Received }, false},
			{"siem_cef_queued_total", "CEF events accepted into the queue", func(s SourceMetrics) uint64 { return s.Queued }, false},
			{"siem_cef_errors_total", "CEF messages dropped", func(s SourceMetrics) uint64 { return s.Errors }, false},
			{"siem_cef_parse_errors_total", "CEF messages that are not valid CEF", func(s SourceMetrics) uint64 { return s.ParseErrors }, false},
			{"siem_cef_validation_errors_total", "CEF events that failed normalization or validation", func(s SourceMetrics) uint64 { return s.ValidationErrors }, false},
			{"siem_cef_oversized_lines_total", "CEF TCP lines longer than max_line_length", func(s SourceMetrics) uint64 { return s.OversizedLines }, true},
		} {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", series.name, series.help, series.name)
			for _, s := range sources {
				if series.tcpOnly && s.Transport != "tcp" {
					continue
				}
				fmt.Fprintf(&b, "%s{transport=%q} %d\n", series.name, labelValue(s.Transport), series.value(s))
			}
			b.WriteString("\n")
		}
	}

	writeSample("siem_queue_pushed_total", "Total events pushed to queue", "counter", strconv.FormatUint(metrics.Pushed, 10))
	writeSample("siem_queue_popped_total", "Total events popped from queue", "counter", strconv.FormatUint(metrics.Popped, 10))
	writeSample("siem_queue_dropped_total", "Total events dropped due to full queue", "counter", strconv.FormatUint(metrics.Dropped, 10))
	writeSample("siem_queue_depth", "Current queue depth", "gauge", strconv.Itoa(metrics.Depth))
	writeSample("siem_queue_capacity", "Queue capacity", "gauge", strconv.Itoa(metrics.Capacity))

	if h.quarantine != nil {
		qm := h.quarantine.Metrics()
		writeSample("siem_quarantine_written_total", "Rejected events stored in events_quarantine", "counter", strconv.FormatUint(qm.Written, 10))
		writeSample("siem_quarantine_dropped_total", "Rejected events not quarantined (buffer full or write failed)", "counter", strconv.FormatUint(qm.Dropped+qm.Failed, 10))
	}

	if h.extraMetrics != nil {
		writeMetrics(&b, h.extraMetrics())
	}

	fmt.Fprintf(&b, "# HELP siem_uptime_seconds Uptime in seconds\n")
	fmt.Fprintf(&b, "# TYPE siem_uptime_seconds gauge\n")
	fmt.Fprintf(&b, "siem_uptime_seconds %d\n", int(time.Since(h.startTime).Seconds()))

	if _, err := io.WriteString(w, b.String()); err != nil {
		slog.Debug("failed to write metrics", "error", err)
	}
}

// writeMetrics writes samples in Prometheus text format, emitting HELP and
// TYPE once per metric name (samples of one name must be adjacent).
func writeMetrics(b *strings.Builder, metrics []Metric) {
	seen := make(map[string]bool)
	for i, m := range metrics {
		if !seen[m.Name] {
			seen[m.Name] = true
			typ := m.Type
			if typ == "" {
				typ = "gauge"
			}
			fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", m.Name, m.Help, m.Name, typ)
		}
		b.WriteString(m.Name)
		if len(m.Labels) > 0 {
			keys := make([]string, 0, len(m.Labels))
			for k := range m.Labels {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteString("{")
			for j, k := range keys {
				if j > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(b, "%s=%q", k, labelValue(m.Labels[k]))
			}
			b.WriteString("}")
		}
		fmt.Fprintf(b, " %s\n", strconv.FormatFloat(m.Value, 'f', -1, 64))
		if i+1 == len(metrics) || metrics[i+1].Name != m.Name {
			b.WriteString("\n")
		}
	}
}

// labelValue strips characters that %q would escape differently from the
// Prometheus text format (only backslash, quote and newline are escaped
// there); label values here are fixed identifiers anyway.
func labelValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r > 0x7e {
			return -1
		}
		return r
	}, s)
}

// respondJSON writes a JSON response.
func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to write response", "error", err)
	}
}

// respondError writes a JSON error response.
func respondError(w http.ResponseWriter, status int, message string, requestID string) {
	resp := map[string]any{
		"success":    false,
		"error":      message,
		"request_id": requestID,
	}
	respondJSON(w, status, resp)
}

// DreamingResponse represents the system's current activity state.
type DreamingResponse struct {
	Status      string          `json:"status"`
	Activity    string          `json:"activity"`
	Description string          `json:"description"`
	Metrics     DreamingMetrics `json:"metrics"`
	Timestamp   time.Time       `json:"timestamp"`
}

// DreamingMetrics contains the system's current operational metrics.
type DreamingMetrics struct {
	EventsTotal   uint64  `json:"events_total"`
	QueueDepth    int     `json:"queue_depth"`
	QueueCapacity int     `json:"queue_capacity"`
	QueueUsage    float64 `json:"queue_usage_percent"`
	UptimeSeconds int     `json:"uptime_seconds"`
	EventsPerSec  float64 `json:"events_per_second"`
}

// Dreaming handles GET /api/system/dreaming.
// Reports the current system activity for Agent OS integration.
func (h *Handler) Dreaming(w http.ResponseWriter, r *http.Request) {
	queueMetrics := h.queue.Metrics()
	uptime := time.Since(h.startTime)
	eventsTotal := h.eventsTotal()

	// Calculate events per second
	var eventsPerSec float64
	if uptime.Seconds() > 0 {
		eventsPerSec = float64(eventsTotal) / uptime.Seconds()
	}

	// Calculate queue usage percentage
	var queueUsage float64
	if queueMetrics.Capacity > 0 {
		queueUsage = (float64(queueMetrics.Depth) / float64(queueMetrics.Capacity)) * 100
	}

	// Determine current activity status
	status, activity, description := h.determineActivity(queueMetrics, eventsPerSec)

	resp := DreamingResponse{
		Status:      status,
		Activity:    activity,
		Description: description,
		Metrics: DreamingMetrics{
			EventsTotal:   eventsTotal,
			QueueDepth:    queueMetrics.Depth,
			QueueCapacity: queueMetrics.Capacity,
			QueueUsage:    queueUsage,
			UptimeSeconds: int(uptime.Seconds()),
			EventsPerSec:  eventsPerSec,
		},
		Timestamp: time.Now().UTC(),
	}

	// Log to CLI so operators can see the status
	slog.Info("system dreaming status",
		"status", resp.Status,
		"activity", resp.Activity,
		"description", resp.Description,
		"queue_depth", queueMetrics.Depth,
		"events_total", eventsTotal,
		"events_per_sec", fmt.Sprintf("%.2f", eventsPerSec),
	)

	respondJSON(w, http.StatusOK, resp)
}

// determineActivity analyzes system state and returns human-readable status.
func (h *Handler) determineActivity(metrics queue.QueueMetrics, eventsPerSec float64) (status, activity, description string) {
	queueUsage := float64(metrics.Depth) / float64(metrics.Capacity) * 100

	switch {
	case queueUsage > 90:
		return "busy", "processing_backlog",
			fmt.Sprintf("Processing event backlog - queue at %.1f%% capacity with %d events pending", queueUsage, metrics.Depth)

	case queueUsage > 50:
		return "active", "processing_events",
			fmt.Sprintf("Actively processing events - %.1f events/sec, %d in queue", eventsPerSec, metrics.Depth)

	case eventsPerSec > 10:
		return "active", "high_throughput",
			fmt.Sprintf("High throughput ingestion - %.1f events/sec", eventsPerSec)

	case eventsPerSec > 1:
		return "active", "ingesting",
			fmt.Sprintf("Ingesting events at %.1f events/sec", eventsPerSec)

	case eventsPerSec > 0:
		return "idle", "low_activity",
			fmt.Sprintf("Low activity - %.2f events/sec, monitoring for new events", eventsPerSec)

	default:
		return "idle", "waiting",
			"Waiting for events - all systems ready, listening on configured ports"
	}
}

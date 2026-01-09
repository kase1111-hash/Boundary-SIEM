// Package ingest handles HTTP ingestion of events.
package ingest

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
)

// Handler handles HTTP event ingestion.
type Handler struct {
	validator   *schema.Validator
	queue       *queue.RingBuffer
	maxPayload  int
	maxBatch    int
	startTime   time.Time
	eventsTotal uint64
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

// IngestRequest is the request body for event ingestion.
type IngestRequest struct {
	Events []EventInput `json:"events"`
}

// EventInput is the input format for events.
type EventInput struct {
	EventID   *uuid.UUID     `json:"event_id,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
	Source    schema.Source  `json:"source"`
	Action    string         `json:"action"`
	Outcome   schema.Outcome `json:"outcome"`
	Severity  int            `json:"severity"`
	Actor     *schema.Actor  `json:"actor,omitempty"`
	Target    string         `json:"target,omitempty"`
	Raw       string         `json:"raw,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// IngestResponse is the response for event ingestion.
type IngestResponse struct {
	Success   bool     `json:"success"`
	Accepted  int      `json:"accepted"`
	Rejected  int      `json:"rejected"`
	Errors    []string `json:"errors,omitempty"`
	RequestID string   `json:"request_id"`
}

// HandleEvents handles POST /v1/events.
func (h *Handler) HandleEvents(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, int64(h.maxPayload))

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if err.Error() == "http: request body too large" {
			respondError(w, http.StatusRequestEntityTooLarge, "payload too large", requestID)
			return
		}
		respondError(w, http.StatusBadRequest, "failed to read request body", requestID)
		return
	}

	var req IngestRequest
	if err := json.Unmarshal(body, &req); err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err), requestID)
		return
	}

	// Check batch size
	if len(req.Events) == 0 {
		respondError(w, http.StatusBadRequest, "no events provided", requestID)
		return
	}

	if len(req.Events) > h.maxBatch {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("batch size exceeds maximum of %d", h.maxBatch), requestID)
		return
	}

	// Process events
	var accepted, rejected int
	var errors []string

	for i, input := range req.Events {
		event := h.convertInput(input)

		// Validate event
		if err := h.validator.Validate(event); err != nil {
			rejected++
			errors = append(errors, fmt.Sprintf("event[%d]: %s", i, err.Error()))
			continue
		}

		// Enqueue event
		if err := h.queue.Push(event); err != nil {
			rejected++
			if err == queue.ErrQueueFull {
				errors = append(errors, fmt.Sprintf("event[%d]: queue full", i))
			} else {
				errors = append(errors, fmt.Sprintf("event[%d]: %s", i, err.Error()))
			}
			continue
		}

		accepted++
		atomic.AddUint64(&h.eventsTotal, 1)
	}

	// Build response
	resp := IngestResponse{
		Success:   rejected == 0,
		Accepted:  accepted,
		Rejected:  rejected,
		RequestID: requestID,
	}

	if len(errors) > 0 {
		resp.Errors = errors
	}

	status := http.StatusOK
	if accepted == 0 && rejected > 0 {
		status = http.StatusBadRequest
	} else if rejected > 0 {
		status = http.StatusMultiStatus // 207 for partial success
	}

	respondJSON(w, status, resp)
}

// convertInput converts an EventInput to a canonical Event.
func (h *Handler) convertInput(input EventInput) *schema.Event {
	event := &schema.Event{
		Timestamp:     input.Timestamp,
		Source:        input.Source,
		Action:        input.Action,
		Outcome:       input.Outcome,
		Severity:      input.Severity,
		Actor:         input.Actor,
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

// HealthCheck handles GET /health.
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	metrics := h.queue.Metrics()

	status := "healthy"
	if metrics.Depth > int(float64(metrics.Capacity)*0.9) {
		status = "degraded"
	}

	resp := map[string]any{
		"status":         status,
		"queue_depth":    metrics.Depth,
		"queue_capacity": metrics.Capacity,
		"uptime_seconds": int(time.Since(h.startTime).Seconds()),
	}

	respondJSON(w, http.StatusOK, resp)
}

// Metrics handles GET /metrics (Prometheus format).
func (h *Handler) Metrics(w http.ResponseWriter, r *http.Request) {
	metrics := h.queue.Metrics()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	fmt.Fprintf(w, "# HELP siem_events_total Total number of events ingested\n")
	fmt.Fprintf(w, "# TYPE siem_events_total counter\n")
	fmt.Fprintf(w, "siem_events_total %d\n\n", atomic.LoadUint64(&h.eventsTotal))

	fmt.Fprintf(w, "# HELP siem_queue_pushed_total Total events pushed to queue\n")
	fmt.Fprintf(w, "# TYPE siem_queue_pushed_total counter\n")
	fmt.Fprintf(w, "siem_queue_pushed_total %d\n\n", metrics.Pushed)

	fmt.Fprintf(w, "# HELP siem_queue_popped_total Total events popped from queue\n")
	fmt.Fprintf(w, "# TYPE siem_queue_popped_total counter\n")
	fmt.Fprintf(w, "siem_queue_popped_total %d\n\n", metrics.Popped)

	fmt.Fprintf(w, "# HELP siem_queue_dropped_total Total events dropped due to full queue\n")
	fmt.Fprintf(w, "# TYPE siem_queue_dropped_total counter\n")
	fmt.Fprintf(w, "siem_queue_dropped_total %d\n\n", metrics.Dropped)

	fmt.Fprintf(w, "# HELP siem_queue_depth Current queue depth\n")
	fmt.Fprintf(w, "# TYPE siem_queue_depth gauge\n")
	fmt.Fprintf(w, "siem_queue_depth %d\n\n", metrics.Depth)

	fmt.Fprintf(w, "# HELP siem_queue_capacity Queue capacity\n")
	fmt.Fprintf(w, "# TYPE siem_queue_capacity gauge\n")
	fmt.Fprintf(w, "siem_queue_capacity %d\n\n", metrics.Capacity)

	fmt.Fprintf(w, "# HELP siem_uptime_seconds Uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE siem_uptime_seconds gauge\n")
	fmt.Fprintf(w, "siem_uptime_seconds %d\n", int(time.Since(h.startTime).Seconds()))
}

// respondJSON writes a JSON response.
func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
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
	eventsTotal := atomic.LoadUint64(&h.eventsTotal)

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

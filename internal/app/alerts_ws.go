package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/alerting"
	"boundary-siem/internal/search"
	"boundary-siem/internal/ws"
)

// wsAlertChannel is a notification channel that pushes every new alert to
// the dashboard's WebSocket clients.
type wsAlertChannel struct {
	hub *ws.Hub
}

func (c *wsAlertChannel) Name() string { return "websocket" }

func (c *wsAlertChannel) Send(_ context.Context, alert *alerting.Alert) error {
	return c.hub.Broadcast(ws.TypeAlert, alert)
}

// broadcastAlertUpdate returns an alerting.Manager.OnRecurrence listener
// that pushes an alert a recurrence was merged into to WebSocket clients,
// as alertChangeNotifier does for lifecycle changes, so open views see its
// new event count. (Merges used to be pushed by nothing: live views kept the
// stale count until their next poll.)
func broadcastAlertUpdate(hub *ws.Hub, logger *slog.Logger) func(*alerting.Alert) {
	return func(alert *alerting.Alert) {
		if err := hub.Broadcast(ws.TypeAlert, alert); err != nil {
			logger.Warn("failed to broadcast alert update", "alert_id", alert.ID, "error", err)
		}
	}
}

// alertActionPath matches the alert lifecycle endpoints.
var alertActionPath = regexp.MustCompile(`^/v1/alerts/([^/]+)/(acknowledge|resolve|notes|assign)$`)

// alertChangeNotifier broadcasts the new state of an alert to WebSocket
// clients after a successful lifecycle call (acknowledge, resolve, note,
// assign), so open dashboards refresh.
func alertChangeNotifier(next http.Handler, mgr *alerting.Manager, hub *ws.Hub) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		m := alertActionPath.FindStringSubmatch(r.URL.Path)
		if m == nil {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if rec.status < 200 || rec.status > 299 {
			return
		}
		id, err := uuid.Parse(m[1])
		if err != nil {
			return
		}
		alert, err := mgr.GetAlert(r.Context(), id)
		if err != nil {
			slog.Debug("cannot broadcast alert change", "alert_id", id, "error", err)
			return
		}
		if err := hub.Broadcast(ws.TypeAlert, alert); err != nil {
			slog.Warn("failed to broadcast alert change", "alert_id", id, "error", err)
		}
	})
}

// statusRecorder captures the response status.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// bufferWriter is an in-memory http.ResponseWriter used to call a handler
// in-process.
type bufferWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferWriter) Header() http.Header         { return b.header }
func (b *bufferWriter) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufferWriter) WriteHeader(code int)        { b.status = code }

// statsFunc returns a function computing exactly the GET /v1/stats response
// (the dashboard replaces its stats cache with the "stats" message, so the
// shapes must match).
func statsFunc(h *search.Handler) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/v1/stats", nil)
		if err != nil {
			return nil, err
		}
		rec := &bufferWriter{header: make(http.Header), status: http.StatusOK}
		h.HandleStats(rec, req)
		if rec.status != http.StatusOK {
			return nil, fmt.Errorf("stats query returned HTTP %d", rec.status)
		}
		return bytes.TrimSpace(rec.body.Bytes()), nil
	}
}

// pushStats broadcasts event statistics to WebSocket clients every interval
// while at least one client is connected.
func pushStats(ctx context.Context, hub *ws.Hub, stats func(context.Context) ([]byte, error), interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if hub.Clients() == 0 {
			continue
		}
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		body, err := stats(qctx)
		cancel()
		if err != nil {
			logger.Debug("skipping WebSocket stats push", "error", err)
			continue
		}
		if err := hub.Broadcast(ws.TypeStats, json.RawMessage(body)); err != nil {
			logger.Warn("failed to broadcast stats", "error", err)
		}
	}
}

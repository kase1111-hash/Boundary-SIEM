package alerting

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/identity"
	"boundary-siem/internal/search"

	"github.com/google/uuid"
)

// Handler provides HTTP handlers for alert management.
type Handler struct {
	manager *Manager
}

// NewHandler creates a new alert handler.
func NewHandler(manager *Manager) *Handler {
	return &Handler{manager: manager}
}

// RegisterRoutes registers alert routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/alerts", h.HandleListAlerts)
	mux.HandleFunc("GET /v1/alerts/{id}", h.HandleGetAlert)
	mux.HandleFunc("POST /v1/alerts/{id}/acknowledge", h.HandleAcknowledge)
	mux.HandleFunc("POST /v1/alerts/{id}/resolve", h.HandleResolve)
	mux.HandleFunc("POST /v1/alerts/{id}/notes", h.HandleAddNote)
	mux.HandleFunc("POST /v1/alerts/{id}/assign", h.HandleAssign)
	mux.HandleFunc("GET /v1/alerts/stats", h.HandleStats)
}

// Pagination of GET /v1/alerts.
const (
	defaultAlertListLimit = 100
	maxAlertListLimit     = 10000
)

// alertStatuses and alertSeverities are the values the status and severity
// filters accept.
var (
	alertStatuses   = []AlertStatus{StatusNew, StatusAcknowledged, StatusInProgress, StatusResolved, StatusSuppressed}
	alertSeverities = []correlation.Severity{
		correlation.SeverityLow, correlation.SeverityMedium, correlation.SeverityHigh, correlation.SeverityCritical,
	}
)

// parseAlertFilter builds the filter of a GET /v1/alerts request. Every
// parameter that is present must be valid: an unparseable time, limit or
// offset, or an unknown status or severity, used to be ignored, so the
// request silently listed every alert (or none, for an unknown status).
// Times take the formats of the search API (search.ParseTime); status and
// severity are case-insensitive.
func parseAlertFilter(q url.Values) (AlertFilter, error) {
	filter := AlertFilter{RuleID: q.Get("rule_id"), Limit: defaultAlertListLimit}

	if v := q.Get("status"); v != "" {
		s := AlertStatus(strings.ToLower(v))
		if !slices.Contains(alertStatuses, s) {
			return filter, fmt.Errorf("status: unknown status %q (want one of %v)", v, alertStatuses)
		}
		filter.Status = &s
	}
	if v := q.Get("severity"); v != "" {
		s := correlation.Severity(strings.ToLower(v))
		if !slices.Contains(alertSeverities, s) {
			return filter, fmt.Errorf("severity: unknown severity %q (want one of %v)", v, alertSeverities)
		}
		filter.Severity = &s
	}
	for _, p := range []struct {
		name string
		dst  **time.Time
	}{{"since", &filter.Since}, {"until", &filter.Until}} {
		v := q.Get(p.name)
		if v == "" {
			continue
		}
		t, err := search.ParseTime(v)
		if err != nil {
			return filter, fmt.Errorf("%s: %w", p.name, err)
		}
		*p.dst = &t
	}
	if filter.Since != nil && filter.Until != nil && filter.Until.Before(*filter.Since) {
		return filter, errors.New("until is before since")
	}
	if v := q.Get("limit"); v != "" {
		l, err := strconv.Atoi(v)
		if err != nil || l < 1 || l > maxAlertListLimit {
			return filter, fmt.Errorf("limit: want an integer from 1 to %d, got %q", maxAlertListLimit, v)
		}
		filter.Limit = l
	}
	if v := q.Get("offset"); v != "" {
		o, err := strconv.Atoi(v)
		if err != nil || o < 0 {
			return filter, fmt.Errorf("offset: want a non-negative integer, got %q", v)
		}
		filter.Offset = o
	}
	return filter, nil
}

// HandleListAlerts handles GET /v1/alerts requests. An invalid filter is
// 400 with the reason in details.
func (h *Handler) HandleListAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	filter, err := parseAlertFilter(r.URL.Query())
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":   "invalid alert filter",
			"code":    "invalid_filter",
			"details": err.Error(),
		})
		return
	}

	alerts, err := h.manager.ListAlerts(ctx, filter)
	if err != nil {
		slog.Error("failed to list alerts", "error", err)
		h.writeError(w, http.StatusInternalServerError, "list_error", "failed to list alerts")
		return
	}
	if alerts == nil {
		alerts = []*Alert{} // [] rather than null
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": alerts,
		"total":  len(alerts),
	})
}

// HandleGetAlert handles GET /v1/alerts/{id} requests.
func (h *Handler) HandleGetAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_id", "invalid alert ID format")
		return
	}

	alert, err := h.manager.GetAlert(ctx, id)
	if err != nil {
		if errors.Is(err, ErrAlertNotFound) {
			h.writeError(w, http.StatusNotFound, "not_found", "alert not found")
			return
		}
		slog.Error("failed to get alert", "alert_id", id, "error", err)
		h.writeError(w, http.StatusInternalServerError, "get_error", "failed to get alert")
		return
	}

	h.writeJSON(w, http.StatusOK, alert)
}

type actionRequest struct {
	User string `json:"user"`
}

// actorOf is who an alert action is recorded as (acknowledged_by,
// resolved_by, a note's author). user is the name the request gives, which
// the client chooses freely, so the authenticated caller (identity.Caller,
// e.g. "api-key-2") is added: "alice (api-key-2)". A request that gives no
// user is recorded as its caller. ok is false when there is neither. (The
// dashboard sent the fixed user "operator", so every action looked alike.)
func actorOf(r *http.Request, user string) (actor string, ok bool) {
	user = strings.TrimSpace(user)
	caller, authenticated := identity.Caller(r.Context())
	switch {
	case user != "" && authenticated:
		return user + " (" + caller + ")", true
	case user != "":
		return user, true
	case authenticated:
		return caller, true
	}
	return "", false
}

// decodeOptionalJSON decodes the JSON body of r into v; an empty body leaves
// v unchanged.
func decodeOptionalJSON(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

type noteRequest struct {
	Author  string `json:"author"`
	Content string `json:"content"`
}

type assignRequest struct {
	Assignee string `json:"assignee"`
}

// HandleAcknowledge handles POST /v1/alerts/{id}/acknowledge requests.
func (h *Handler) HandleAcknowledge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_id", "invalid alert ID format")
		return
	}

	var req actionRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "failed to parse request body")
		return
	}
	actor, ok := actorOf(r, req.User)
	if !ok {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "user field is required")
		return
	}

	if err := h.manager.AcknowledgeAlert(ctx, id, actor); err != nil {
		h.writeManagerError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

// HandleResolve handles POST /v1/alerts/{id}/resolve requests.
func (h *Handler) HandleResolve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_id", "invalid alert ID format")
		return
	}

	var req actionRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "failed to parse request body")
		return
	}
	actor, ok := actorOf(r, req.User)
	if !ok {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "user field is required")
		return
	}

	if err := h.manager.ResolveAlert(ctx, id, actor); err != nil {
		h.writeManagerError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"status": "resolved"})
}

// HandleAddNote handles POST /v1/alerts/{id}/notes requests.
func (h *Handler) HandleAddNote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_id", "invalid alert ID format")
		return
	}

	var req noteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "failed to parse request body")
		return
	}
	author, ok := actorOf(r, req.Author)
	if !ok || req.Content == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "author and content fields are required")
		return
	}

	if err := h.manager.AddNote(ctx, id, author, req.Content); err != nil {
		h.writeManagerError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"status": "note_added"})
}

// HandleAssign handles POST /v1/alerts/{id}/assign requests.
func (h *Handler) HandleAssign(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_id", "invalid alert ID format")
		return
	}

	var req assignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Assignee == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "assignee field is required")
		return
	}

	if err := h.manager.AssignAlert(ctx, id, req.Assignee); err != nil {
		h.writeManagerError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"status": "assigned"})
}

// HandleStats handles GET /v1/alerts/stats requests.
func (h *Handler) HandleStats(w http.ResponseWriter, _ *http.Request) {
	h.writeJSON(w, http.StatusOK, h.manager.Stats())
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to write response", "error", err)
	}
}

// writeManagerError maps an error from a Manager lifecycle method to an HTTP
// response: unknown alert -> 404, invalid status transition -> 409, anything
// else (the alert store failed) -> 500.
func (h *Handler) writeManagerError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrAlertNotFound):
		h.writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, ErrInvalidTransition):
		h.writeError(w, http.StatusConflict, "invalid_transition", err.Error())
	default:
		slog.Error("alert storage error", "error", err)
		h.writeError(w, http.StatusInternalServerError, "storage_error", "alert storage error")
	}
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]string{
		"error": message,
		"code":  code,
	})
}

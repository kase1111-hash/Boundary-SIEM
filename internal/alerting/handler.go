package alerting

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"boundary-siem/internal/correlation"

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

// HandleListAlerts handles GET /v1/alerts requests.
func (h *Handler) HandleListAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	filter := AlertFilter{}

	if status := q.Get("status"); status != "" {
		s := AlertStatus(status)
		filter.Status = &s
	}
	if severity := q.Get("severity"); severity != "" {
		s := correlation.Severity(severity)
		filter.Severity = &s
	}
	if ruleID := q.Get("rule_id"); ruleID != "" {
		filter.RuleID = ruleID
	}
	if since := q.Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			filter.Since = &t
		}
	}
	if until := q.Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			filter.Until = &t
		}
	}
	if limit := q.Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 {
			filter.Limit = l
		}
	}
	if offset := q.Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			filter.Offset = o
		}
	}

	if filter.Limit == 0 {
		filter.Limit = 100
	}

	alerts, err := h.manager.ListAlerts(ctx, filter)
	if err != nil {
		slog.Error("failed to list alerts", "error", err)
		h.writeError(w, http.StatusInternalServerError, "list_error", "failed to list alerts")
		return
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
		h.writeError(w, http.StatusNotFound, "not_found", "alert not found")
		return
	}

	h.writeJSON(w, http.StatusOK, alert)
}

type actionRequest struct {
	User string `json:"user"`
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.User == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "user field is required")
		return
	}

	if err := h.manager.AcknowledgeAlert(ctx, id, req.User); err != nil {
		h.writeError(w, http.StatusNotFound, "not_found", err.Error())
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.User == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "user field is required")
		return
	}

	if err := h.manager.ResolveAlert(ctx, id, req.User); err != nil {
		h.writeError(w, http.StatusNotFound, "not_found", err.Error())
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
	if req.Author == "" || req.Content == "" {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "author and content fields are required")
		return
	}

	if err := h.manager.AddNote(ctx, id, req.Author, req.Content); err != nil {
		h.writeError(w, http.StatusNotFound, "not_found", err.Error())
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
		h.writeError(w, http.StatusNotFound, "not_found", err.Error())
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

func (h *Handler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]string{
		"error": message,
		"code":  code,
	})
}

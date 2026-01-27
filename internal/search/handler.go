package search

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Handler provides HTTP handlers for search operations.
type Handler struct {
	executor *Executor
}

// NewHandler creates a new search handler.
func NewHandler(executor *Executor) *Handler {
	return &Handler{executor: executor}
}

// SearchRequest represents a search API request.
type SearchRequest struct {
	Query     string `json:"query"`
	StartTime string `json:"start_time,omitempty"`
	EndTime   string `json:"end_time,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	Offset    int    `json:"offset,omitempty"`
	OrderBy   string `json:"order_by,omitempty"`
	OrderDesc *bool  `json:"order_desc,omitempty"`
}

// AggregationRequest represents an aggregation API request.
type AggregationRequest struct {
	Query    string `json:"query,omitempty"`
	Field    string `json:"field"`
	Type     string `json:"type"` // count, sum, avg, min, max, terms, histogram
	Interval string `json:"interval,omitempty"`
	TopN     int    `json:"top_n,omitempty"`
}

// ErrorResponse represents an API error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// HandleSearch handles POST /v1/search requests.
func (h *Handler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "failed to parse request body", err.Error())
		return
	}

	// Parse the query
	query, err := ParseQuery(req.Query)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_query", "failed to parse query", err.Error())
		return
	}

	// Apply request parameters
	if req.Limit > 0 && req.Limit <= 10000 {
		query.Limit = req.Limit
	}
	if req.Offset >= 0 {
		query.Offset = req.Offset
	}
	if req.OrderBy != "" {
		query.OrderBy = req.OrderBy
	}
	if req.OrderDesc != nil {
		query.OrderDesc = *req.OrderDesc
	}

	// Parse time range
	if req.StartTime != "" || req.EndTime != "" {
		query.TimeRange = &TimeRange{}
		if req.StartTime != "" {
			if t, err := parseTimeString(req.StartTime); err == nil {
				query.TimeRange.Start = t
			}
		}
		if req.EndTime != "" {
			if t, err := parseTimeString(req.EndTime); err == nil {
				query.TimeRange.End = t
			}
		}
	}

	// Execute search
	result, err := h.executor.Search(ctx, query)
	if err != nil {
		slog.Error("search failed", "error", err, "query", req.Query)
		h.writeError(w, http.StatusInternalServerError, "search_error", "search execution failed", "")
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// HandleSearchGet handles GET /v1/search requests with query parameters.
func (h *Handler) HandleSearchGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	queryStr := r.URL.Query().Get("q")
	if queryStr == "" {
		queryStr = r.URL.Query().Get("query")
	}

	// Parse the query
	query, err := ParseQuery(queryStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_query", "failed to parse query", err.Error())
		return
	}

	// Apply query parameters
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 && limit <= 10000 {
			query.Limit = limit
		}
	}
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			query.Offset = offset
		}
	}
	if orderBy := r.URL.Query().Get("order_by"); orderBy != "" {
		query.OrderBy = orderBy
	}
	if orderDesc := r.URL.Query().Get("order"); orderDesc == "asc" {
		query.OrderDesc = false
	}

	// Parse time range
	startTime := r.URL.Query().Get("start")
	endTime := r.URL.Query().Get("end")
	if startTime != "" || endTime != "" {
		query.TimeRange = &TimeRange{}
		if startTime != "" {
			if t, err := parseTimeString(startTime); err == nil {
				query.TimeRange.Start = t
			}
		}
		if endTime != "" {
			if t, err := parseTimeString(endTime); err == nil {
				query.TimeRange.End = t
			}
		}
	}

	// Execute search
	result, err := h.executor.Search(ctx, query)
	if err != nil {
		slog.Error("search failed", "error", err, "query", queryStr)
		h.writeError(w, http.StatusInternalServerError, "search_error", "search execution failed", "")
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// HandleAggregation handles POST /v1/aggregations requests.
func (h *Handler) HandleAggregation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req AggregationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "failed to parse request body", err.Error())
		return
	}

	if req.Field == "" {
		h.writeError(w, http.StatusBadRequest, "missing_field", "field is required", "")
		return
	}
	if req.Type == "" {
		req.Type = "count"
	}

	// Parse the query
	var query *Query
	var err error
	if req.Query != "" {
		query, err = ParseQuery(req.Query)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "invalid_query", "failed to parse query", err.Error())
			return
		}
	} else {
		query = &Query{}
	}

	// Execute aggregation
	var result *AggregationResult

	switch req.Type {
	case "histogram", "time_histogram":
		interval := req.Interval
		if interval == "" {
			interval = "1h"
		}
		result, err = h.executor.TimeHistogram(ctx, query, interval)

	case "terms", "top":
		n := req.TopN
		if n <= 0 {
			n = 10
		}
		result, err = h.executor.TopN(ctx, query, req.Field, n)

	default:
		result, err = h.executor.Aggregate(ctx, query, req.Field, req.Type)
	}

	if err != nil {
		slog.Error("aggregation failed", "error", err, "type", req.Type, "field", req.Field)
		h.writeError(w, http.StatusInternalServerError, "aggregation_error", "aggregation execution failed", "")
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// HandleGetEvent handles GET /v1/events/{id} requests.
func (h *Handler) HandleGetEvent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract event ID from path
	idStr := r.PathValue("id")
	if idStr == "" {
		h.writeError(w, http.StatusBadRequest, "missing_id", "event ID is required", "")
		return
	}

	eventID, err := uuid.Parse(idStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_id", "invalid event ID format", err.Error())
		return
	}

	// Get the event
	event, err := h.executor.GetEvent(ctx, eventID)
	if err != nil {
		slog.Error("get event failed", "error", err, "event_id", idStr)
		h.writeError(w, http.StatusInternalServerError, "query_error", "failed to get event", "")
		return
	}

	if event == nil {
		h.writeError(w, http.StatusNotFound, "not_found", "event not found", "")
		return
	}

	h.writeJSON(w, http.StatusOK, event)
}

// HandleFieldValues handles GET /v1/fields/{field}/values requests.
func (h *Handler) HandleFieldValues(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	field := r.PathValue("field")
	if field == "" {
		h.writeError(w, http.StatusBadRequest, "missing_field", "field name is required", "")
		return
	}

	// Build query from parameters
	query := &Query{}
	queryStr := r.URL.Query().Get("q")
	if queryStr != "" {
		var err error
		query, err = ParseQuery(queryStr)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "invalid_query", "failed to parse query", err.Error())
			return
		}
	}

	n := 20
	if nStr := r.URL.Query().Get("limit"); nStr != "" {
		if parsed, err := strconv.Atoi(nStr); err == nil && parsed > 0 && parsed <= 100 {
			n = parsed
		}
	}

	result, err := h.executor.TopN(ctx, query, field, n)
	if err != nil {
		slog.Error("field values query failed", "error", err, "field", field)
		h.writeError(w, http.StatusInternalServerError, "query_error", "failed to get field values", "")
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// HandleStats handles GET /v1/stats requests.
func (h *Handler) HandleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Build time range from parameters
	query := &Query{TimeRange: &TimeRange{}}

	startTime := r.URL.Query().Get("start")
	endTime := r.URL.Query().Get("end")

	if startTime != "" {
		if t, err := parseTimeString(startTime); err == nil {
			query.TimeRange.Start = t
		}
	} else {
		// Default to last 24 hours
		query.TimeRange.Start = time.Now().Add(-24 * time.Hour)
	}

	if endTime != "" {
		if t, err := parseTimeString(endTime); err == nil {
			query.TimeRange.End = t
		}
	}

	// Get various stats
	stats := make(map[string]interface{})

	// Total events
	searchResp, err := h.executor.Search(ctx, &Query{
		TimeRange: query.TimeRange,
		Limit:     0,
	})
	if err == nil {
		stats["total_events"] = searchResp.TotalCount
	}

	// Events by severity
	sevResult, err := h.executor.TopN(ctx, query, "severity", 10)
	if err == nil {
		stats["by_severity"] = sevResult.Buckets
	}

	// Events by action
	actionResult, err := h.executor.TopN(ctx, query, "action", 10)
	if err == nil {
		stats["by_action"] = actionResult.Buckets
	}

	// Events by outcome
	outcomeResult, err := h.executor.TopN(ctx, query, "outcome", 5)
	if err == nil {
		stats["by_outcome"] = outcomeResult.Buckets
	}

	// Time histogram
	histResult, err := h.executor.TimeHistogram(ctx, query, "1h")
	if err == nil {
		stats["time_histogram"] = histResult.Buckets
	}

	h.writeJSON(w, http.StatusOK, stats)
}

// RegisterRoutes registers search routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/search", h.HandleSearch)
	mux.HandleFunc("GET /v1/search", h.HandleSearchGet)
	mux.HandleFunc("POST /v1/aggregations", h.HandleAggregation)
	mux.HandleFunc("GET /v1/events/{id}", h.HandleGetEvent)
	mux.HandleFunc("GET /v1/fields/{field}/values", h.HandleFieldValues)
	mux.HandleFunc("GET /v1/stats", h.HandleStats)
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to write response", "error", err)
	}
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, message, details string) {
	h.writeJSON(w, status, ErrorResponse{
		Error:   message,
		Code:    code,
		Details: details,
	})
}

// parseTimeString parses various time formats.
func parseTimeString(s string) (time.Time, error) {
	// Try RFC3339 first
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	// Try RFC3339Nano
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}

	// Try date only
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}

	// Try relative time (now, now-1h, now-24h, etc.)
	if dur, ok := parseDuration(s); ok {
		if s == "now" {
			return time.Now(), nil
		}
		return time.Now().Add(-dur), nil
	}

	// Try Unix timestamp (seconds)
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
		if ts > 1e12 {
			// Milliseconds
			return time.UnixMilli(ts), nil
		}
		return time.Unix(ts, 0), nil
	}

	return time.Time{}, nil
}

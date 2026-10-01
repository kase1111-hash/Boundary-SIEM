package search

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// DefaultTenantID is the tenant searched when a request carries none. It
// matches the tenant the storage layer assigns to events ingested without
// one (storage.DefaultTenantID) and the default of the
// ingest.cef.normalizer.default_tenant_id setting.
const DefaultTenantID = "default"

// Handler provides HTTP handlers for search operations.
//
// Every query is scoped to one tenant, resolved per request in this order:
// the TenantResolver (WithTenantResolver), the tenant stored in the request
// context (ContextWithTenant), and the default tenant (WithDefaultTenant,
// DefaultTenantID unless changed). The tenant is never taken from request
// parameters or headers. A request for which no tenant resolves gets 403.
type Handler struct {
	executor      *Executor
	defaultTenant string
	resolveTenant TenantResolver
}

// TenantResolver returns the tenant an authenticated request may search, or
// "" when the request carries no tenant.
type TenantResolver func(r *http.Request) string

// HandlerOption configures a Handler.
type HandlerOption func(*Handler)

// WithDefaultTenant sets the tenant searched when a request carries no
// tenant. An empty tenant disables the fallback, so such requests get 403.
func WithDefaultTenant(tenantID string) HandlerOption {
	return func(h *Handler) { h.defaultTenant = tenantID }
}

// WithTenantResolver sets a function that extracts the tenant from a request,
// e.g. from the authenticated user an auth middleware stored in its context.
func WithTenantResolver(resolve TenantResolver) HandlerOption {
	return func(h *Handler) { h.resolveTenant = resolve }
}

// NewHandler creates a new search handler.
func NewHandler(executor *Executor, opts ...HandlerOption) *Handler {
	h := &Handler{executor: executor, defaultTenant: DefaultTenantID}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

type tenantContextKey struct{}

// ContextWithTenant returns a context carrying the tenant that search
// requests using it are scoped to. Authentication middleware can call it so
// the Handler picks the tenant up without a TenantResolver.
func ContextWithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantContextKey{}, tenantID)
}

// TenantFromContext returns the tenant stored by ContextWithTenant.
func TenantFromContext(ctx context.Context) (string, bool) {
	tenantID, ok := ctx.Value(tenantContextKey{}).(string)
	return tenantID, ok && tenantID != ""
}

// tenant resolves the tenant r is scoped to.
func (h *Handler) tenant(r *http.Request) (string, bool) {
	if h.resolveTenant != nil {
		if tenantID := h.resolveTenant(r); tenantID != "" {
			return tenantID, true
		}
	}
	if tenantID, ok := TenantFromContext(r.Context()); ok {
		return tenantID, true
	}
	return h.defaultTenant, h.defaultTenant != ""
}

// requireTenant resolves the request's tenant, writing a 403 when there is
// none.
func (h *Handler) requireTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	tenantID, ok := h.tenant(r)
	if !ok {
		h.writeError(w, http.StatusForbidden, "tenant_required", "request is not scoped to a tenant", "")
	}
	return tenantID, ok
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
	if query.TimeRange, err = parseTimeRange("start_time", req.StartTime, "end_time", req.EndTime); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_time", "invalid time range", err.Error())
		return
	}

	tenantID, ok := h.requireTenant(w, r)
	if !ok {
		return
	}
	query.TenantID = tenantID

	// Execute search
	result, err := h.executor.Search(ctx, query)
	if err != nil {
		h.writeExecError(w, err, "search_error", "search execution failed", "query", req.Query)
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
	if query.TimeRange, err = parseTimeRange("start", r.URL.Query().Get("start"), "end", r.URL.Query().Get("end")); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_time", "invalid time range", err.Error())
		return
	}

	tenantID, ok := h.requireTenant(w, r)
	if !ok {
		return
	}
	query.TenantID = tenantID

	// Execute search
	result, err := h.executor.Search(ctx, query)
	if err != nil {
		h.writeExecError(w, err, "search_error", "search execution failed", "query", queryStr)
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

	tenantID, ok := h.requireTenant(w, r)
	if !ok {
		return
	}
	query.TenantID = tenantID

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
		h.writeExecError(w, err, "aggregation_error", "aggregation execution failed", "type", req.Type, "field", req.Field)
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

	tenantID, ok := h.requireTenant(w, r)
	if !ok {
		return
	}

	// Get the event (events of other tenants are reported as not found)
	event, err := h.executor.GetEvent(ctx, tenantID, eventID)
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

	tenantID, ok := h.requireTenant(w, r)
	if !ok {
		return
	}
	query.TenantID = tenantID

	result, err := h.executor.TopN(ctx, query, field, n)
	if err != nil {
		h.writeExecError(w, err, "query_error", "failed to get field values", "field", field)
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// HandleStats handles GET /v1/stats requests.
func (h *Handler) HandleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Build time range from parameters (default: the last 24 hours)
	startTime := r.URL.Query().Get("start")
	if startTime == "" {
		startTime = "now-24h"
	}
	timeRange, err := parseTimeRange("start", startTime, "end", r.URL.Query().Get("end"))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_time", "invalid time range", err.Error())
		return
	}
	query := &Query{TimeRange: timeRange}

	tenantID, ok := h.requireTenant(w, r)
	if !ok {
		return
	}
	query.TenantID = tenantID

	// Get various stats. Any failure is reported: an empty object used to
	// hide errors and looked like "no events".
	stats := make(map[string]interface{})
	fail := func(what string, err error) {
		slog.Error("stats query failed", "stat", what, "error", err)
		h.writeError(w, http.StatusInternalServerError, "stats_error", "failed to compute statistics", "")
	}

	// Total events
	searchResp, err := h.executor.Search(ctx, &Query{
		TenantID:  tenantID,
		TimeRange: query.TimeRange,
		Limit:     0,
	})
	if err != nil {
		fail("total_events", err)
		return
	}
	stats["total_events"] = searchResp.TotalCount

	for _, topN := range []struct {
		key, field string
		n          int
	}{
		{"by_severity", "severity", 10},
		{"by_action", "action", 10},
		{"by_outcome", "outcome", 5},
	} {
		result, err := h.executor.TopN(ctx, query, topN.field, topN.n)
		if err != nil {
			fail(topN.key, err)
			return
		}
		stats[topN.key] = result.Buckets
	}

	// Time histogram
	histResult, err := h.executor.TimeHistogram(ctx, query, "1h")
	if err != nil {
		fail("time_histogram", err)
		return
	}
	stats["time_histogram"] = histResult.Buckets

	h.writeJSON(w, http.StatusOK, stats)
}

// HandleExplain handles POST /v1/search/explain requests.
func (h *Handler) HandleExplain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "failed to parse request body", err.Error())
		return
	}

	query, err := ParseQuery(req.Query)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_query", "failed to parse query", err.Error())
		return
	}

	if req.Limit > 0 && req.Limit <= 10000 {
		query.Limit = req.Limit
	}
	if req.OrderBy != "" {
		query.OrderBy = req.OrderBy
	}
	if req.OrderDesc != nil {
		query.OrderDesc = *req.OrderDesc
	}

	if query.TimeRange, err = parseTimeRange("start_time", req.StartTime, "end_time", req.EndTime); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_time", "invalid time range", err.Error())
		return
	}

	tenantID, ok := h.requireTenant(w, r)
	if !ok {
		return
	}
	query.TenantID = tenantID

	result, err := h.executor.Explain(ctx, query)
	if err != nil {
		h.writeExecError(w, err, "explain_error", "explain execution failed", "query", req.Query)
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// routes maps the search route patterns to their handlers.
func (h *Handler) routes() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"POST /v1/search":               h.HandleSearch,
		"GET /v1/search":                h.HandleSearchGet,
		"POST /v1/aggregations":         h.HandleAggregation,
		"GET /v1/events/{id}":           h.HandleGetEvent,
		"GET /v1/fields/{field}/values": h.HandleFieldValues,
		"GET /v1/stats":                 h.HandleStats,
		"POST /v1/search/explain":       h.HandleExplain,
	}
}

// RegisterRoutes registers search routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	for pattern, handler := range h.routes() {
		mux.HandleFunc(pattern, handler)
	}
}

// RegisterUnavailableRoutes registers the search routes with a handler that
// answers 503 with reason, for a server without the ClickHouse store that
// search needs (storage.enabled: false). Without them, the dashboard's
// POST /v1/search reached the static file handler (GET /) and got 405, and
// the dashboard reported "not found".
func RegisterUnavailableRoutes(mux *http.ServeMux, reason string) {
	unavailable := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		if err := json.NewEncoder(w).Encode(ErrorResponse{Error: reason, Code: "search_unavailable"}); err != nil {
			slog.Error("failed to write response", "error", err)
		}
	}
	for pattern := range (&Handler{}).routes() {
		mux.HandleFunc(pattern, unavailable)
	}
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

// unixTime converts a Unix timestamp in seconds, or in milliseconds when it
// is too large to be seconds, to a time.
func unixTime(ts int64) time.Time {
	if ts > 1e12 {
		return time.UnixMilli(ts)
	}
	return time.Unix(ts, 0)
}

// parseTimeString parses RFC 3339 (with or without fractional seconds), a
// date (YYYY-MM-DD), "now" or a relative time ("now-1h", "now-7d"), or Unix
// seconds or milliseconds. Anything else is an error: an unparseable start or
// end used to be ignored, so the request silently searched all time.
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

	// Try Unix timestamp (seconds or milliseconds)
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
		return unixTime(ts), nil
	}

	return time.Time{}, fmt.Errorf("unrecognised time %q: use RFC 3339, YYYY-MM-DD, now, now-<duration> (e.g. now-1h, now-7d) or Unix seconds",
		truncateForLog(s, 100))
}

// parseTimeRange returns the time range of start and end (either may be
// empty), or nil when both are empty. An unparseable value is an error
// naming the parameter.
func parseTimeRange(startName, start, endName, end string) (*TimeRange, error) {
	if start == "" && end == "" {
		return nil, nil
	}
	tr := &TimeRange{}
	if start != "" {
		t, err := parseTimeString(start)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", startName, err)
		}
		tr.Start = t
	}
	if end != "" {
		t, err := parseTimeString(end)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", endName, err)
		}
		tr.End = t
	}
	return tr, nil
}

// writeExecError answers an executor error: 400 with the reason for an
// invalid query (ErrInvalidQuery), otherwise 500 without details.
func (h *Handler) writeExecError(w http.ResponseWriter, err error, code, message string, logAttrs ...any) {
	if errors.Is(err, ErrInvalidQuery) {
		h.writeError(w, http.StatusBadRequest, "invalid_query", "invalid query",
			strings.TrimPrefix(err.Error(), ErrInvalidQuery.Error()+": "))
		return
	}
	slog.Error(message, append([]any{"error", err}, logAttrs...)...)
	h.writeError(w, http.StatusInternalServerError, code, message, "")
}

package search

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// E2E round 1: requests naming an unknown field, an unsupported aggregation
// or an unparseable time were rewritten (unknown field -> timestamp) or
// ignored, so they failed with 500 in ClickHouse or answered 200 with the
// wrong data. They are client errors and must be refused with 400 before any
// SQL is sent.
func TestHandlersRejectInvalidRequestsWith400(t *testing.T) {
	tests := []handlerRequest{
		{name: "unknown field in search", method: http.MethodGet, path: "/v1/search?q=foo:bar"},
		{name: "unknown field with contains", method: http.MethodGet, path: "/v1/search?q=message~tcp"},
		{name: "unknown field in POST search", method: http.MethodPost, path: "/v1/search", body: `{"query":"foo:bar"}`},
		{name: "text value for a number", method: http.MethodGet, path: "/v1/search?q=severity:high"},
		{name: "contains on a time field", method: http.MethodGet, path: "/v1/search?q=timestamp~2024"},
		{name: "unsortable order_by", method: http.MethodGet, path: "/v1/search?q=*&order_by=raw"},
		{name: "terms on unknown field", method: http.MethodPost, path: "/v1/aggregations", body: `{"field":"bogus","type":"terms"}`},
		{name: "count on unknown field", method: http.MethodPost, path: "/v1/aggregations", body: `{"field":"bogus","type":"count"}`},
		{name: "unsupported aggregation type", method: http.MethodPost, path: "/v1/aggregations", body: `{"field":"x","type":"nope"}`},
		{name: "sum of a text field", method: http.MethodPost, path: "/v1/aggregations", body: `{"field":"action","type":"sum"}`},
		{name: "unsupported histogram interval", method: http.MethodPost, path: "/v1/aggregations", body: `{"field":"timestamp","type":"histogram","interval":"7s"}`},
		{name: "field values of unknown field", method: http.MethodGet, path: "/v1/fields/bogus/values"},
		{name: "explain with unknown field", method: http.MethodPost, path: "/v1/search/explain", body: `{"query":"foo:bar"}`},
		{name: "bad start", method: http.MethodGet, path: "/v1/search?q=*&start=1h"},
		{name: "bad end", method: http.MethodGet, path: "/v1/search?q=*&end=yesterday"},
		{name: "bad start_time", method: http.MethodPost, path: "/v1/search", body: `{"query":"*","start_time":"1h"}`},
		{name: "bad stats start", method: http.MethodGet, path: "/v1/stats?start=1h"},
		{name: "inverted range", method: http.MethodGet, path: "/v1/search?q=*&start=2030-01-02&end=2030-01-01"},
		{name: "inverted start_time/end_time", method: http.MethodPost, path: "/v1/search", body: `{"query":"*","start_time":"now-1h","end_time":"now-2h"}`},
		{name: "inverted stats range", method: http.MethodGet, path: "/v1/stats?start=2030-01-02&end=2030-01-01"},
	}
	for _, hr := range tests {
		t.Run(hr.name, func(t *testing.T) {
			exec, rec := newRecordingExecutor(t)
			w := serve(t, NewHandler(exec), hr, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", w.Code, w.Body.String())
			}
			var resp ErrorResponse
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if resp.Code != "invalid_query" && resp.Code != "invalid_time" {
				t.Errorf("error code = %q, want invalid_query or invalid_time", resp.Code)
			}
			if resp.Details == "" {
				t.Error("error response does not say what is wrong")
			}
			if stmts := rec.recorded(); len(stmts) != 0 {
				t.Errorf("invalid request reached the database: %v", stmts)
			}
		})
	}
}

// Valid requests that the stricter validation must keep accepting.
func TestHandlersAcceptValidFieldsAndTimes(t *testing.T) {
	tests := []handlerRequest{
		{name: "column name", method: http.MethodGet, path: "/v1/search?q=source_product:x"},
		{name: "alias", method: http.MethodGet, path: "/v1/search?q=actor.name:alice"},
		{name: "lucene comparison", method: http.MethodGet, path: "/v1/search?q=severity:>=7"},
		{name: "relative and date times", method: http.MethodGet, path: "/v1/search?q=*&start=now-24h&end=2030-01-01"},
		{name: "time condition", method: http.MethodGet, path: "/v1/search?q=timestamp>now-1h"},
		{name: "sort by alias", method: http.MethodGet, path: "/v1/search?q=*&order_by=severity"},
		{name: "free text", method: http.MethodGet, path: "/v1/search?q=alice"},
		{name: "histogram ignores field", method: http.MethodPost, path: "/v1/aggregations", body: `{"field":"timestamp","type":"histogram","interval":"1h"}`},
		{name: "metadata terms", method: http.MethodPost, path: "/v1/aggregations", body: `{"field":"metadata.chain_id","type":"terms"}`},
		{name: "field values via alias", method: http.MethodGet, path: "/v1/fields/vendor/values"},
	}
	for _, hr := range tests {
		t.Run(hr.name, func(t *testing.T) {
			exec, _ := newRecordingExecutor(t)
			w := serve(t, NewHandler(exec), hr, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
			}
		})
	}
}

// A ClickHouse failure is still a 500 without internals.
func TestHandlersReportBackendFailuresAs500(t *testing.T) {
	db := sql.OpenDB(failingConnector{})
	t.Cleanup(func() { _ = db.Close() })
	w := serve(t, NewHandler(NewExecutor(db)), handlerRequest{method: http.MethodGet, path: "/v1/search?q=action:x"}, nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), "Unknown expression") {
		t.Errorf("500 response leaks the backend error: %s", w.Body.String())
	}
}

// E2E round 1: a word typed without a field ("alice") was dropped, so the
// search returned every event.
func TestFreeTextTermsAreSearched(t *testing.T) {
	tests := []struct {
		query     string
		wantConds int
		check     func(t *testing.T, q *Query)
	}{
		{query: "alice", wantConds: 1, check: func(t *testing.T, q *Query) {
			c := q.Conditions[0]
			if !c.IsFreeText || c.Operator != OpContains || c.Value != "alice" || c.IsRegex {
				t.Errorf("condition = %+v, want a free-text substring for alice", c)
			}
		}},
		{query: `"failed login"`, wantConds: 1, check: func(t *testing.T, q *Query) {
			if c := q.Conditions[0]; !c.IsFreeText || c.Value != "failed login" {
				t.Errorf("condition = %+v, want the phrase", c)
			}
		}},
		{query: "NOT alice", wantConds: 1, check: func(t *testing.T, q *Query) {
			if c := q.Conditions[0]; !c.IsFreeText || c.Operator != OpNotContains {
				t.Errorf("condition = %+v, want a negated free-text term", c)
			}
		}},
		{query: "ali*ce", wantConds: 1, check: func(t *testing.T, q *Query) {
			if c := q.Conditions[0]; !c.IsRegex || c.Value != "(?i)ali.*ce" {
				t.Errorf("condition = %+v, want a case-insensitive wildcard pattern", c)
			}
		}},
		{query: "action:login alice", wantConds: 2, check: func(t *testing.T, q *Query) {
			if len(q.Logic) != 1 || q.Logic[0] != "AND" || !q.Conditions[1].IsFreeText {
				t.Errorf("query = %+v, want action:login AND free text", q)
			}
		}},
		{query: "*", wantConds: 0},
		{query: "", wantConds: 0},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			q, err := ParseQuery(tt.query)
			if err != nil {
				t.Fatalf("ParseQuery() error = %v", err)
			}
			if len(q.Conditions) != tt.wantConds {
				t.Fatalf("conditions = %+v, want %d", q.Conditions, tt.wantConds)
			}
			if tt.check != nil {
				tt.check(t, q)
			}
		})
	}

	q, err := ParseQuery("alice")
	if err != nil {
		t.Fatal(err)
	}
	q.TenantID = "t"
	clause, args := mustBuildWhereClause(t, newTestExecutor(), q)
	for _, column := range freeTextColumns {
		if !strings.Contains(clause, "positionCaseInsensitiveUTF8("+column+", ?) > 0") {
			t.Errorf("clause %q does not search %s", clause, column)
		}
	}
	if len(args) != 1+len(freeTextColumns) {
		t.Errorf("args = %v, want the tenant and the term once per column", args)
	}
	for _, a := range args[1:] {
		if a != "alice" {
			t.Errorf("free-text arg = %v, want alice", a)
		}
	}
	if s := q.String(); s != "alice" {
		t.Errorf("Query.String() = %q, want the term (the response echoed an empty query)", s)
	}

	q, _ = ParseQuery("NOT alice")
	clause, _ = mustBuildWhereClause(t, newTestExecutor(), q)
	if !strings.HasPrefix(clause, "WHERE NOT (positionCaseInsensitiveUTF8(raw, ?) > 0 OR ") {
		t.Errorf("negated free-text clause = %q", clause)
	}
}

// E2E round 1: took_ms reported nanoseconds (5303032 for a 5 ms search).
func TestSearchResponseTookIsMilliseconds(t *testing.T) {
	out, err := json.Marshal(&SearchResponse{Took: 5303032 * time.Nanosecond, TookMs: (5303032 * time.Nanosecond).Milliseconds()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"took_ms":5,`) {
		t.Errorf("JSON = %s, want took_ms 5", out)
	}

	exec, _ := newRecordingExecutor(t)
	resp, err := exec.Search(context.Background(), &Query{TenantID: "t"})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if resp.TookMs != resp.Took.Milliseconds() {
		t.Errorf("TookMs = %d, want Took (%v) in milliseconds", resp.TookMs, resp.Took)
	}
}

func TestParseTimeStringRejectsUnknownFormats(t *testing.T) {
	for _, s := range []string{"1h", "-1h", "yesterday", "now-", "2024-13-45"} {
		if _, err := parseTimeString(s); err == nil {
			t.Errorf("parseTimeString(%q) succeeded, want an error", s)
		}
	}
	if _, err := parseTimeString("now-7d"); err != nil {
		t.Errorf("parseTimeString(now-7d) error = %v", err)
	}
}

// E2E round 3: /v1/aggregations has no time range, and start_time/end_time
// were silently ignored, so a client that meant to filter by time got
// all-time numbers. Unknown request keys are refused before any SQL is sent.
func TestAggregationRejectsUnknownFields(t *testing.T) {
	exec, rec := newRecordingExecutor(t)
	hr := handlerRequest{method: http.MethodPost, path: "/v1/aggregations",
		body: `{"field":"action","type":"terms","start_time":"now-1h"}`}
	w := serve(t, NewHandler(exec), hr, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "start_time") {
		t.Errorf("error does not name the unknown field: %s", w.Body.String())
	}
	if stmts := rec.recorded(); len(stmts) != 0 {
		t.Errorf("invalid request reached the database: %v", stmts)
	}
}

// E2E round 3: empty results were encoded as null instead of [].
func TestEmptyResultsAreJSONArrays(t *testing.T) {
	tests := []struct {
		hr   handlerRequest
		want string
	}{
		{handlerRequest{method: http.MethodGet, path: "/v1/search?q=action:none"}, `"results":[]`},
		{handlerRequest{method: http.MethodPost, path: "/v1/aggregations", body: `{"field":"action","type":"terms"}`}, `"buckets":[]`},
		{handlerRequest{method: http.MethodGet, path: "/v1/fields/action/values"}, `[]`},
	}
	for _, tt := range tests {
		t.Run(tt.hr.path, func(t *testing.T) {
			exec, _ := newRecordingExecutor(t)
			w := serve(t, NewHandler(exec), tt.hr, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", w.Code, w.Body.String())
			}
			if body := w.Body.String(); !strings.Contains(body, tt.want) || strings.Contains(body, "null") {
				t.Errorf("body = %s, want %s and no null", body, tt.want)
			}
		})
	}
}

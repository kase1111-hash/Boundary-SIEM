package search

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// E2E round 2: the parser accepted malformed queries. A lone quote, a bare
// AND or OR, and "()" searched for every event; "action:" kept a nil value
// (echoed as action=<nil>); dangling connectives were dropped; and an
// unterminated quote took the rest of the query as its value.
func TestParseQuery_RejectsMalformedQueries(t *testing.T) {
	for _, q := range []string{
		`'`, `"`, `user:"alice`, `action:login raw:'x`, // unterminated quotes
		`""`, `''`, // empty free-text term
		"AND", "OR", "&&", "||", "AND OR", // bare connectives
		"AND action:a", "action:a OR", "OR action:a", "action:a AND",
		"action:a AND OR action:b", "action:a OR OR action:b", "action:a AND AND action:b",
		"(action:a OR)", "(AND action:a)", "action:a OR ()",
		"()", "(())", "() action:login", "action:login ()",
		"action:", "action=", "severity>", "severity:>=", "action: AND x", "(action:)",
		"=x", ":", "action:a:b", "target:naïve~", "> 5",
	} {
		if parsed, err := ParseQuery(q); err == nil {
			t.Errorf("ParseQuery(%q) = %q, want an error", q, parsed.String())
		}
	}
}

// Errors name the operator as the user wrote it (":" is "=" internally).
func TestParseQuery_ErrorsQuoteTheOperatorAsWritten(t *testing.T) {
	for q, want := range map[string]string{
		"action:":          `after ":"`,
		"severity:>":       `after ":>"`,
		"severity>=":       `after ">="`,
		"target:host:srv1": `unexpected ":"`,
	} {
		_, err := ParseQuery(q)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseQuery(%q) error = %v, want it to contain %s", q, err, want)
		}
	}
}

// The stricter parser keeps accepting well-formed queries.
func TestParseQuery_AcceptsWellFormedEdgeCases(t *testing.T) {
	for _, q := range []string{
		"", "*", "**", "(*)", "* AND action:a", `action:""`, `"a b"`, `'it\'s'`,
		"action:a AND NOT outcome:b", "NOT (action:a OR action:b)", "a && b || c",
		`target:"a:b"`, "severity:>=7", "(action:a) (outcome:b)",
	} {
		if _, err := ParseQuery(q); err != nil {
			t.Errorf("ParseQuery(%q) error = %v, want accepted", q, err)
		}
	}
}

// Every search endpoint answers a malformed query with 400 before any SQL is
// sent, and says what is wrong.
func TestHandlersRejectMalformedQueriesWith400(t *testing.T) {
	var tests []handlerRequest
	for _, q := range []string{`'`, `"`, "AND", "OR", "()", "action:", "action:file.write OR", `user:"alice`} {
		tests = append(tests,
			handlerRequest{name: "GET " + q, method: http.MethodGet, path: "/v1/search?q=" + url.QueryEscape(q)},
			handlerRequest{name: "POST " + q, method: http.MethodPost, path: "/v1/search", body: jsonBody(t, map[string]string{"query": q})},
			handlerRequest{name: "aggregation " + q, method: http.MethodPost, path: "/v1/aggregations", body: jsonBody(t, map[string]string{"query": q, "field": "action", "type": "terms"})},
		)
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
			if resp.Code != "invalid_query" || resp.Details == "" {
				t.Errorf("error = %+v, want invalid_query with details", resp)
			}
			if stmts := rec.recorded(); len(stmts) != 0 {
				t.Errorf("malformed query reached the database: %v", stmts)
			}
		})
	}
}

// E2E round 2: limit=abc, 0, -1 and 100000 were replaced by the default
// without a word.
func TestHandlersRejectInvalidPagingWith400(t *testing.T) {
	tests := []handlerRequest{
		{name: "limit abc", method: http.MethodGet, path: "/v1/search?q=*&limit=abc"},
		{name: "limit 0", method: http.MethodGet, path: "/v1/search?q=*&limit=0"},
		{name: "limit -1", method: http.MethodGet, path: "/v1/search?q=*&limit=-1"},
		{name: "limit 100000", method: http.MethodGet, path: "/v1/search?q=*&limit=100000"},
		{name: "offset -1", method: http.MethodGet, path: "/v1/search?q=*&offset=-1"},
		{name: "offset x", method: http.MethodGet, path: "/v1/search?q=*&offset=x"},
		{name: "order sideways", method: http.MethodGet, path: "/v1/search?q=*&order=sideways"},
		{name: "POST limit -1", method: http.MethodPost, path: "/v1/search", body: `{"query":"*","limit":-1}`},
		{name: "POST limit 100000", method: http.MethodPost, path: "/v1/search", body: `{"query":"*","limit":100000}`},
		{name: "POST offset -5", method: http.MethodPost, path: "/v1/search", body: `{"query":"*","offset":-5}`},
		{name: "explain limit 100000", method: http.MethodPost, path: "/v1/search/explain", body: `{"query":"*","limit":100000}`},
		{name: "field values limit 0", method: http.MethodGet, path: "/v1/fields/action/values?limit=0"},
		{name: "field values limit 101", method: http.MethodGet, path: "/v1/fields/action/values?limit=101"},
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
			if resp.Code != "invalid_parameter" || !strings.Contains(resp.Details, ":") {
				t.Errorf("error = %+v, want invalid_parameter naming the parameter", resp)
			}
			if stmts := rec.recorded(); len(stmts) != 0 {
				t.Errorf("invalid request reached the database: %v", stmts)
			}
		})
	}
}

func jsonBody(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

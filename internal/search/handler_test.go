package search

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// handlerRequest is one call to a search endpoint.
type handlerRequest struct {
	name   string
	method string
	path   string
	body   string
	want   int
}

// allHandlerRequests exercises every endpoint that queries events.
var allHandlerRequests = []handlerRequest{
	{name: "POST search", method: http.MethodPost, path: "/v1/search", body: `{"query":"action:auth.login"}`, want: http.StatusOK},
	{name: "GET search", method: http.MethodGet, path: "/v1/search?q=source_product:rt-single", want: http.StatusOK},
	{name: "terms aggregation", method: http.MethodPost, path: "/v1/aggregations", body: `{"field":"action","type":"terms"}`, want: http.StatusOK},
	{name: "count aggregation", method: http.MethodPost, path: "/v1/aggregations", body: `{"field":"outcome","type":"count","query":"severity>3"}`, want: http.StatusOK},
	{name: "histogram aggregation", method: http.MethodPost, path: "/v1/aggregations", body: `{"field":"timestamp","type":"histogram"}`, want: http.StatusOK},
	{name: "field values", method: http.MethodGet, path: "/v1/fields/action/values?q=outcome:failure", want: http.StatusOK},
	{name: "stats", method: http.MethodGet, path: "/v1/stats", want: http.StatusOK},
	{name: "explain", method: http.MethodPost, path: "/v1/search/explain", body: `{"query":"action:auth.login"}`, want: http.StatusOK},
	{name: "get event", method: http.MethodGet, path: "/v1/events/" + uuid.NewString(), want: http.StatusNotFound},
}

func serve(t *testing.T, h *Handler, hr handlerRequest, prepare func(*http.Request) *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(hr.method, hr.path, strings.NewReader(hr.body))
	if prepare != nil {
		req = prepare(req)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// Regression (R02/H04): no handler set Query.TenantID, and the executor
// rejects queries without one, so every search endpoint answered 500 (and
// /v1/stats an empty object). GetEvent had no tenant filter at all.
func TestHandlersScopeEveryQueryToTheTenant(t *testing.T) {
	for _, hr := range allHandlerRequests {
		t.Run(hr.name, func(t *testing.T) {
			exec, rec := newRecordingExecutor(t)
			w := serve(t, NewHandler(exec), hr, nil)

			if w.Code != hr.want {
				t.Fatalf("status = %d, want %d; body %s", w.Code, hr.want, w.Body.String())
			}
			stmts := rec.recorded()
			if len(stmts) == 0 {
				t.Fatal("no query reached the database")
			}
			for _, s := range stmts {
				assertTenantScoped(t, s.query)
				if len(s.args) == 0 || s.args[0].Value != "default" {
					t.Errorf("first bound argument = %v, want the default tenant: %s", s.args, s.query)
				}
			}
		})
	}
}

func TestHandlerTenantResolution(t *testing.T) {
	withCtxTenant := func(tenant string) func(*http.Request) *http.Request {
		return func(r *http.Request) *http.Request {
			return r.WithContext(ContextWithTenant(r.Context(), tenant))
		}
	}
	fromHeader := func(r *http.Request) string { return r.Header.Get("X-Test-Tenant") }

	tests := []struct {
		name       string
		opts       []HandlerOption
		prepare    func(*http.Request) *http.Request
		wantTenant string // "" means the request must be refused
	}{
		{name: "default tenant", wantTenant: "default"},
		{name: "configured default tenant", opts: []HandlerOption{WithDefaultTenant("acme")}, wantTenant: "acme"},
		{name: "context tenant wins over default", opts: []HandlerOption{WithDefaultTenant("acme")}, prepare: withCtxTenant("t-ctx"), wantTenant: "t-ctx"},
		{
			name: "resolver wins over context",
			opts: []HandlerOption{WithTenantResolver(fromHeader)},
			prepare: func(r *http.Request) *http.Request {
				r.Header.Set("X-Test-Tenant", "t-res")
				return withCtxTenant("t-ctx")(r)
			},
			wantTenant: "t-res",
		},
		{name: "empty resolver result falls back to context", opts: []HandlerOption{WithTenantResolver(fromHeader)}, prepare: withCtxTenant("t-ctx"), wantTenant: "t-ctx"},
		{
			name: "client-supplied tenant parameters are ignored",
			prepare: func(r *http.Request) *http.Request {
				r.Header.Set("X-Tenant-ID", "victim")
				r.URL.RawQuery = "tenant_id=victim"
				return r
			},
			wantTenant: "default",
		},
		{name: "no tenant and fallback disabled", opts: []HandlerOption{WithDefaultTenant("")}},
		{name: "empty context tenant and fallback disabled", opts: []HandlerOption{WithDefaultTenant("")}, prepare: withCtxTenant("")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, hr := range allHandlerRequests {
				exec, rec := newRecordingExecutor(t)
				w := serve(t, NewHandler(exec, tt.opts...), hr, tt.prepare)
				stmts := rec.recorded()

				if tt.wantTenant == "" {
					if w.Code != http.StatusForbidden || len(stmts) != 0 {
						t.Errorf("%s: status = %d with %d statements, want 403 and no query", hr.name, w.Code, len(stmts))
					}
					continue
				}
				if w.Code != hr.want {
					t.Errorf("%s: status = %d, want %d", hr.name, w.Code, hr.want)
				}
				for _, s := range stmts {
					if len(s.args) == 0 || s.args[0].Value != tt.wantTenant {
						t.Errorf("%s: tenant argument = %v, want %q", hr.name, s.args, tt.wantTenant)
					}
				}
			}
		})
	}
}

func TestContextWithTenant(t *testing.T) {
	ctx := ContextWithTenant(context.Background(), "t1")
	if got, ok := TenantFromContext(ctx); !ok || got != "t1" {
		t.Errorf("TenantFromContext = %q, %v", got, ok)
	}
	if _, ok := TenantFromContext(context.Background()); ok {
		t.Error("TenantFromContext on a bare context reported a tenant")
	}
}

func TestExecutorGetEventIsTenantScoped(t *testing.T) {
	exec, rec := newRecordingExecutor(t)
	id := uuid.New()

	ev, err := exec.GetEvent(context.Background(), "tenant-a", id)
	if err != nil || ev != nil {
		t.Fatalf("GetEvent() = %v, %v, want nil, nil for a missing event", ev, err)
	}
	stmts := rec.recorded()
	if len(stmts) != 1 {
		t.Fatalf("statements = %v", stmts)
	}
	if !strings.Contains(stmts[0].query, "WHERE tenant_id = ? AND event_id = ? LIMIT 1") {
		t.Errorf("query = %q", stmts[0].query)
	}
	if len(stmts[0].args) != 2 || stmts[0].args[0].Value != "tenant-a" || stmts[0].args[1].Value != id.String() {
		t.Errorf("args = %v", stmts[0].args)
	}

	if _, err := exec.GetEvent(context.Background(), "", id); err == nil {
		t.Error("GetEvent() without a tenant succeeded, want error")
	}
	if len(rec.recorded()) != 1 {
		t.Error("GetEvent() without a tenant reached the database")
	}
}

// ---------------------------------------------------------------------------
// Failing database
// ---------------------------------------------------------------------------

type failingConnector struct{}

func (failingConnector) Connect(context.Context) (driver.Conn, error) { return failingConn{}, nil }
func (failingConnector) Driver() driver.Driver                        { return recordingDriver{} }

type failingConn struct{}

func (failingConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not supported") }
func (failingConn) Close() error                        { return nil }
func (failingConn) Begin() (driver.Tx, error)           { return nil, errors.New("not supported") }
func (failingConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return nil, errors.New("code: 47, Unknown expression identifier")
}

// /v1/stats used to swallow every error and answer 200 {} (R02).
func TestHandleStatsReportsQueryFailures(t *testing.T) {
	db := sql.OpenDB(failingConnector{})
	t.Cleanup(func() { _ = db.Close() })

	w := serve(t, NewHandler(NewExecutor(db)), handlerRequest{method: http.MethodGet, path: "/v1/stats"}, nil)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "stats_error") {
		t.Errorf("status = %d body %s, want 500 stats_error", w.Code, w.Body.String())
	}
}

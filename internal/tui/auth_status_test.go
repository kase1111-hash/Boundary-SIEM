package tui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"boundary-siem/internal/tui/api"
	"boundary-siem/internal/tui/scenes"

	tea "github.com/charmbracelet/bubbletea"
)

// ---------------------------------------------------------------------------
// Regression tests for R19: the TUI could not authenticate against an
// auth-enabled siem-ingest and showed hardcoded service status.
// ---------------------------------------------------------------------------

const testAPIKey = "sk_test_tui_key"

// authServer is a stub siem-ingest that mimics internal/ingest/middleware.go:
// /health and /metrics are public, everything else requires header == key.
type authServer struct {
	*httptest.Server

	header string
	key    string
	health map[string]any

	mu   sync.Mutex
	seen map[string]string // path -> API key header value received
}

func newAuthServer(t *testing.T, header, key string) *authServer {
	t.Helper()
	s := &authServer{
		header: header,
		key:    key,
		seen:   make(map[string]string),
		health: map[string]any{
			"status":         "healthy",
			"queue_depth":    500,
			"queue_capacity": 1000,
			"uptime_seconds": 90,
		},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen[r.URL.Path] = r.Header.Get(s.header)
		health := s.health
		s.mu.Unlock()

		if r.URL.Path != "/health" && r.URL.Path != "/metrics" {
			got := r.Header.Get(s.header)
			if got == "" {
				http.Error(w, `{"success":false,"error":"missing API key"}`, http.StatusUnauthorized)
				return
			}
			if got != s.key {
				http.Error(w, `{"success":false,"error":"invalid API key"}`, http.StatusUnauthorized)
				return
			}
		}

		switch r.URL.Path {
		case "/health":
			encodeJSON(t, w, health)
		case "/metrics":
			writeBody(t, w, "siem_events_total 7\nsiem_queue_pushed_total 7\nsiem_uptime_seconds 90\n")
		case "/api/system/dreaming":
			encodeJSON(t, w, api.DreamingResponse{
				Status:      "active",
				Activity:    "ingesting",
				Description: "Ingesting events",
				Metrics: api.DreamingMetrics{
					EventsTotal:  7,
					QueueUsage:   50,
					EventsPerSec: 0.1,
				},
			})
		case "/v1/search":
			encodeJSON(t, w, api.SearchResponse{
				Results:    []api.SearchResult{{EventID: "evt-1", Action: "login", Outcome: "success"}},
				TotalCount: 1,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *authServer) headerFor(path string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.seen[path]
	return v, ok
}

func (s *authServer) setHealth(h map[string]any) {
	s.mu.Lock()
	s.health = h
	s.mu.Unlock()
}

// runCmd executes a tea.Cmd synchronously and returns its message.
func runCmd(t *testing.T, cmd tea.Cmd) tea.Msg {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected a command, got nil")
	}
	return cmd()
}

func TestAPIClientSendsAPIKeyOnEveryRequest(t *testing.T) {
	tests := []struct {
		name   string
		header string // header configured on the server
		opts   func(key string) []api.Option
		call   func(c *api.Client) error
		paths  []string
	}{
		{
			name:   "health",
			header: api.DefaultAuthHeader,
			opts:   func(k string) []api.Option { return []api.Option{api.WithAPIKey(k)} },
			call:   func(c *api.Client) error { _, err := c.GetHealth(); return err },
			paths:  []string{"/health"},
		},
		{
			name:   "dreaming",
			header: api.DefaultAuthHeader,
			opts:   func(k string) []api.Option { return []api.Option{api.WithAPIKey(k)} },
			call:   func(c *api.Client) error { _, err := c.GetDreaming(); return err },
			paths:  []string{"/api/system/dreaming"},
		},
		{
			name:   "stats",
			header: api.DefaultAuthHeader,
			opts:   func(k string) []api.Option { return []api.Option{api.WithAPIKey(k)} },
			call:   func(c *api.Client) error { _, err := c.GetStats(); return err },
			paths:  []string{"/health", "/api/system/dreaming", "/metrics"},
		},
		{
			name:   "events",
			header: api.DefaultAuthHeader,
			opts:   func(k string) []api.Option { return []api.Option{api.WithAPIKey(k)} },
			call: func(c *api.Client) error {
				resp, err := c.GetEvents(10)
				if err == nil && resp.Error != "" {
					t.Errorf("GetEvents returned API error with a valid key: %s", resp.Error)
				}
				return err
			},
			paths: []string{"/v1/search"},
		},
		{
			name:   "custom header name",
			header: "X-Custom-Key",
			opts: func(k string) []api.Option {
				return []api.Option{api.WithAPIKey(k), api.WithAPIKeyHeader("X-Custom-Key")}
			},
			call: func(c *api.Client) error {
				resp, err := c.GetEvents(10)
				if err == nil && resp.Error != "" {
					t.Errorf("GetEvents returned API error with a valid key: %s", resp.Error)
				}
				return err
			},
			paths: []string{"/v1/search"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newAuthServer(t, tt.header, testAPIKey)
			client := api.NewClient(srv.URL, tt.opts(testAPIKey)...)
			if err := tt.call(client); err != nil {
				t.Fatalf("call failed: %v", err)
			}
			for _, p := range tt.paths {
				got, ok := srv.headerFor(p)
				if !ok {
					t.Errorf("%s was not requested", p)
					continue
				}
				if got != testAPIKey {
					t.Errorf("%s: header %s = %q, want %q", p, tt.header, got, testAPIKey)
				}
			}
		})
	}
}

func TestAPIClientWithoutKeySendsNoHeader(t *testing.T) {
	srv := newAuthServer(t, api.DefaultAuthHeader, testAPIKey)
	client := api.NewClient(srv.URL)
	if _, err := client.GetHealth(); err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	if got, _ := srv.headerFor("/health"); got != "" {
		t.Errorf("expected no API key header without a key, got %q", got)
	}
}

func TestAPIClientTrimsTrailingSlashFromBaseURL(t *testing.T) {
	srv := newAuthServer(t, api.DefaultAuthHeader, testAPIKey)
	client := api.NewClient(srv.URL+"/", api.WithAPIKey(testAPIKey))
	if _, err := client.GetHealth(); err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	if _, ok := srv.headerFor("/health"); !ok {
		t.Error("expected /health to be requested (no double slash)")
	}
}

func TestGetStatsAuthStatus(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		wantAuth   string
		wantDetail string
	}{
		{name: "valid key", key: testAPIKey, wantAuth: api.AuthAccepted},
		{name: "missing key", key: "", wantAuth: api.AuthRejected, wantDetail: "missing API key"},
		{name: "wrong key", key: "nope", wantAuth: api.AuthRejected, wantDetail: "invalid API key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newAuthServer(t, api.DefaultAuthHeader, testAPIKey)
			var opts []api.Option
			if tt.key != "" {
				opts = append(opts, api.WithAPIKey(tt.key))
			}
			stats, err := api.NewClient(srv.URL, opts...).GetStats()
			if err != nil {
				t.Fatalf("GetStats: %v", err)
			}
			if !stats.Connected {
				t.Error("expected Connected=true when /health answers")
			}
			if stats.AuthStatus != tt.wantAuth {
				t.Errorf("AuthStatus = %q, want %q", stats.AuthStatus, tt.wantAuth)
			}
			if tt.wantDetail != "" && !strings.Contains(stats.AuthDetail, tt.wantDetail) {
				t.Errorf("AuthDetail = %q, want it to contain %q", stats.AuthDetail, tt.wantDetail)
			}
		})
	}
}

// A 401 from /api/system/dreaming used to be decoded as an empty dreaming
// response, which zeroed the queue usage computed from /health.
func TestGetStatsUnauthorizedDreamingKeepsHealthMetrics(t *testing.T) {
	srv := newAuthServer(t, api.DefaultAuthHeader, testAPIKey)
	stats, err := api.NewClient(srv.URL).GetStats() // no key -> dreaming is 401
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.QueueUsage != 50 {
		t.Errorf("QueueUsage = %.1f, want 50 (from /health 500/1000)", stats.QueueUsage)
	}
	if stats.EventsTotal != 7 {
		t.Errorf("EventsTotal = %d, want 7 (from /metrics fallback)", stats.EventsTotal)
	}
}

func TestGetHealthNon200IsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"boom"}`, http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	if _, err := api.NewClient(ts.URL).GetHealth(); err == nil {
		t.Fatal("expected an error for HTTP 503 from /health")
	}
}

func TestGetStatsParsesHealthComponents(t *testing.T) {
	srv := newAuthServer(t, api.DefaultAuthHeader, testAPIKey)
	srv.setHealth(map[string]any{
		"status":         "healthy",
		"queue_depth":    0,
		"queue_capacity": 1000,
		"uptime_seconds": 5,
		"components": map[string]any{
			"cef_udp": map[string]any{"status": "up", "address": ":5514"},
			"storage": "down",
		},
	})
	stats, err := api.NewClient(srv.URL, api.WithAPIKey(testAPIKey)).GetStats()
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if got := stats.Components["cef_udp"]; got.Status != "up" || got.Address != ":5514" {
		t.Errorf("cef_udp component = %+v", got)
	}
	if got := stats.Components["storage"]; got.Status != "down" {
		t.Errorf("storage component = %+v (string form must be accepted)", got)
	}
}

func TestGetEventsErrorHints(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantInErr   []string
		wantHint    string
		notWantHint string
	}{
		{
			name:        "unauthorized",
			status:      http.StatusUnauthorized,
			body:        `{"success":false,"error":"missing API key"}`,
			wantInErr:   []string{"401", "missing API key"},
			wantHint:    "SIEM_API_KEY",
			notWantHint: "storage",
		},
		{
			name:      "not found means search API not registered",
			status:    http.StatusNotFound,
			body:      "404 page not found",
			wantInErr: []string{"404"},
			wantHint:  "storage",
		},
		{
			name:        "server error",
			status:      http.StatusInternalServerError,
			body:        `{"error":"search execution failed","code":"search_error"}`,
			wantInErr:   []string{"500", "search execution failed"},
			wantHint:    "logs",
			notWantHint: "API key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, tt.body, tt.status)
			}))
			defer ts.Close()

			resp, err := api.NewClient(ts.URL).GetEvents(10)
			if err != nil {
				t.Fatalf("GetEvents: %v", err)
			}
			if resp.StatusCode != tt.status {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.status)
			}
			for _, s := range tt.wantInErr {
				if !strings.Contains(resp.Error, s) {
					t.Errorf("Error = %q, want it to contain %q", resp.Error, s)
				}
			}
			if !strings.Contains(resp.Hint, tt.wantHint) {
				t.Errorf("Hint = %q, want it to contain %q", resp.Hint, tt.wantHint)
			}
			if tt.notWantHint != "" && strings.Contains(resp.Hint, tt.notWantHint) {
				t.Errorf("Hint = %q, must not mention %q", resp.Hint, tt.notWantHint)
			}
		})
	}
}

func TestEventsSceneUnauthorizedShowsAuthHint(t *testing.T) {
	srv := newAuthServer(t, api.DefaultAuthHeader, testAPIKey)
	e := scenes.NewEventsScene(api.NewClient(srv.URL)) // no key
	e, _ = e.Update(runCmd(t, e.Init()))
	view := e.View()
	if strings.Contains(view, "Make sure storage is enabled") {
		t.Errorf("401 must not be explained as a storage problem:\n%s", view)
	}
	if !strings.Contains(view, "SIEM_API_KEY") {
		t.Errorf("401 view should tell the user how to supply an API key:\n%s", view)
	}
}

func TestEventsSceneWithKeyShowsEvents(t *testing.T) {
	srv := newAuthServer(t, api.DefaultAuthHeader, testAPIKey)
	e := scenes.NewEventsScene(api.NewClient(srv.URL, api.WithAPIKey(testAPIKey)))
	e, _ = e.Update(runCmd(t, e.Init()))
	view := e.View()
	if strings.Contains(view, "Error") {
		t.Errorf("unexpected error with a valid key:\n%s", view)
	}
	if !strings.Contains(view, "login (success)") {
		t.Errorf("expected the event row in the view:\n%s", view)
	}
}

// fakeStatusPhrases are the hardcoded claims the scenes used to print no
// matter what the server reported.
var fakeStatusPhrases = []string{"(disabled)", "Disabled (insecure)", "configure certs"}

func TestDashboardServiceStatusIsNotHardcoded(t *testing.T) {
	tests := []struct {
		name       string
		components map[string]any
		want       []string
		notWant    []string
	}{
		{
			name:    "server does not report components",
			want:    []string{"CEF UDP", "Storage", "unknown", "accepted"},
			notWant: fakeStatusPhrases,
		},
		{
			name: "server reports components",
			components: map[string]any{
				"cef_udp":  map[string]any{"status": "up", "address": ":5514"},
				"storage":  map[string]any{"status": "up"},
				"cef_dtls": map[string]any{"status": "disabled"},
			},
			want:    []string{"CEF UDP", ":5514", "Storage", "up", "disabled"},
			notWant: []string{"Disabled (insecure)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newAuthServer(t, api.DefaultAuthHeader, testAPIKey)
			if tt.components != nil {
				srv.setHealth(map[string]any{
					"status": "healthy", "queue_depth": 0, "queue_capacity": 1000,
					"uptime_seconds": 1, "components": tt.components,
				})
			}
			d := scenes.NewDashboardScene(api.NewClient(srv.URL, api.WithAPIKey(testAPIKey)))
			d, _ = d.Update(runCmd(t, d.Init()))
			view := d.View()
			for _, s := range tt.want {
				if !strings.Contains(view, s) {
					t.Errorf("dashboard view should contain %q:\n%s", s, view)
				}
			}
			for _, s := range tt.notWant {
				if strings.Contains(view, s) {
					t.Errorf("dashboard view must not contain %q:\n%s", s, view)
				}
			}
		})
	}
}

func TestDashboardUnreachableServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close()

	d := scenes.NewDashboardScene(api.NewClient(ts.URL))
	d, _ = d.Update(runCmd(t, d.Init()))
	view := d.View()
	if !strings.Contains(view, "unreachable") {
		t.Errorf("dashboard should report the API as unreachable:\n%s", view)
	}
	if strings.Contains(view, "HEALTHY") && !strings.Contains(view, "UNHEALTHY") {
		t.Errorf("dashboard must not claim HEALTHY for an unreachable server:\n%s", view)
	}
}

func TestSystemSceneStatusIsNotHardcoded(t *testing.T) {
	srv := newAuthServer(t, api.DefaultAuthHeader, testAPIKey)
	srv.setHealth(map[string]any{
		"status": "degraded", "queue_depth": 950, "queue_capacity": 1000, "uptime_seconds": 1,
	})
	s := scenes.NewSystemScene(api.NewClient(srv.URL, api.WithAPIKey(testAPIKey)))
	s, _ = s.Update(runCmd(t, s.Init()))
	view := s.View()

	for _, p := range fakeStatusPhrases {
		if strings.Contains(view, p) {
			t.Errorf("system view must not contain hardcoded %q:\n%s", p, view)
		}
	}
	if !strings.Contains(view, "unknown") {
		t.Errorf("system view should show unreported modules as unknown:\n%s", view)
	}
	// A degraded server is still reachable; it used to be shown as "Not connected".
	if strings.Contains(view, "Not connected") {
		t.Errorf("degraded but reachable server shown as not connected:\n%s", view)
	}
	if !strings.Contains(view, "degraded") {
		t.Errorf("system view should show the degraded status:\n%s", view)
	}
}

func TestNewModelPassesClientOptions(t *testing.T) {
	srv := newAuthServer(t, api.DefaultAuthHeader, testAPIKey)
	m := New(srv.URL, api.WithAPIKey(testAPIKey))
	m.Update(keyMsg("2"))
	e, _ := m.events.Update(runCmd(t, m.events.Init()))
	if view := e.View(); strings.Contains(view, "Error") {
		t.Errorf("model built with an API key should authenticate:\n%s", view)
	}
	if got, _ := srv.headerFor("/v1/search"); got != testAPIKey {
		t.Errorf("search request carried key %q, want %q", got, testAPIKey)
	}
}

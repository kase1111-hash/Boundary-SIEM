package tui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"boundary-siem/internal/tui/api"
	"boundary-siem/internal/tui/scenes"
	"boundary-siem/internal/tui/styles"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// keyMsg builds a tea.KeyMsg for the given key string.
func keyMsg(s string) tea.KeyMsg {
	switch s {
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

// ---------------------------------------------------------------------------
// 1. Model Initialization
// ---------------------------------------------------------------------------

func TestNewModelReturnsNonNil(t *testing.T) {
	m := New("http://localhost:8080")
	if m == nil {
		t.Fatal("New() returned nil")
	}
}

func TestNewModelDefaultScene(t *testing.T) {
	m := New("http://localhost:8080")
	if m.scene != SceneDashboard {
		t.Errorf("expected initial scene SceneDashboard (%d), got %d", SceneDashboard, m.scene)
	}
}

func TestNewModelSubScenesNonNil(t *testing.T) {
	m := New("http://localhost:8080")
	if m.dashboard == nil {
		t.Error("dashboard scene is nil")
	}
	if m.events == nil {
		t.Error("events scene is nil")
	}
	if m.system == nil {
		t.Error("system scene is nil")
	}
}

func TestNewModelClientNonNil(t *testing.T) {
	m := New("http://localhost:8080")
	if m.client == nil {
		t.Error("client is nil")
	}
}

func TestNewModelNotQuitting(t *testing.T) {
	m := New("http://localhost:8080")
	if m.quitting {
		t.Error("model should not be quitting on init")
	}
}

func TestNewModelZeroDimensions(t *testing.T) {
	m := New("http://localhost:8080")
	if m.width != 0 || m.height != 0 {
		t.Errorf("expected zero dimensions, got %dx%d", m.width, m.height)
	}
}

func TestSceneConstants(t *testing.T) {
	if SceneDashboard != 0 {
		t.Errorf("expected SceneDashboard=0, got %d", SceneDashboard)
	}
	if SceneEvents != 1 {
		t.Errorf("expected SceneEvents=1, got %d", SceneEvents)
	}
	if SceneSystem != 2 {
		t.Errorf("expected SceneSystem=2, got %d", SceneSystem)
	}
}

func TestModelInitReturnsCommand(t *testing.T) {
	m := New("http://localhost:8080")
	cmd := m.Init()
	if cmd == nil {
		t.Error("Model.Init() returned nil, expected a batch command")
	}
}

// ---------------------------------------------------------------------------
// 2. API Client Construction and URL Building
// ---------------------------------------------------------------------------

func TestAPIClientConstructionNonNil(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}
}

func TestAPIClientVariousBaseURLs(t *testing.T) {
	urls := []string{
		"http://localhost:8080",
		"https://siem.example.com",
		"http://10.0.0.1:9090",
	}
	for _, u := range urls {
		client := api.NewClient(u)
		if client == nil {
			t.Errorf("NewClient(%q) returned nil", u)
		}
	}
}

func TestAPIClientGetHealthHitsCorrectPath(t *testing.T) {
	var requestedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		json.NewEncoder(w).Encode(api.HealthResponse{
			Status:        "healthy",
			QueueDepth:    0,
			QueueCapacity: 1000,
			UptimeSeconds: 120,
		})
	}))
	defer ts.Close()

	client := api.NewClient(ts.URL)
	_, err := client.GetHealth()
	if err != nil {
		t.Fatalf("GetHealth() error: %v", err)
	}
	if requestedPath != "/health" {
		t.Errorf("expected path /health, got %s", requestedPath)
	}
}

func TestAPIClientGetDreamingHitsCorrectPath(t *testing.T) {
	var requestedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		json.NewEncoder(w).Encode(api.DreamingResponse{
			Status:   "active",
			Activity: "ingesting",
		})
	}))
	defer ts.Close()

	client := api.NewClient(ts.URL)
	_, err := client.GetDreaming()
	if err != nil {
		t.Fatalf("GetDreaming() error: %v", err)
	}
	if requestedPath != "/api/system/dreaming" {
		t.Errorf("expected path /api/system/dreaming, got %s", requestedPath)
	}
}

func TestAPIClientGetEventsHitsCorrectPathAndQuery(t *testing.T) {
	var requestedPath, requestedQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		requestedQuery = r.URL.RawQuery
		json.NewEncoder(w).Encode(api.SearchResponse{
			Results:    []api.SearchResult{},
			TotalCount: 0,
		})
	}))
	defer ts.Close()

	client := api.NewClient(ts.URL)
	_, err := client.GetEvents(100)
	if err != nil {
		t.Fatalf("GetEvents() error: %v", err)
	}
	if requestedPath != "/v1/search" {
		t.Errorf("expected path /v1/search, got %s", requestedPath)
	}
	if !strings.Contains(requestedQuery, "limit=100") {
		t.Errorf("expected query to contain limit=100, got %s", requestedQuery)
	}
	if !strings.Contains(requestedQuery, "order=desc") {
		t.Errorf("expected query to contain order=desc, got %s", requestedQuery)
	}
}

func TestAPIClientGetEventsDefaultLimit(t *testing.T) {
	var requestedQuery string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedQuery = r.URL.RawQuery
		json.NewEncoder(w).Encode(api.SearchResponse{})
	}))
	defer ts.Close()

	client := api.NewClient(ts.URL)
	// A limit of 0 should default to 50
	_, err := client.GetEvents(0)
	if err != nil {
		t.Fatalf("GetEvents(0) error: %v", err)
	}
	if !strings.Contains(requestedQuery, "limit=50") {
		t.Errorf("expected default limit=50, got query %s", requestedQuery)
	}
}

func TestAPIClientGetStatsHitsAllEndpoints(t *testing.T) {
	var mu sync.Mutex
	requestedPaths := make(map[string]bool)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestedPaths[r.URL.Path] = true
		mu.Unlock()

		switch r.URL.Path {
		case "/health":
			json.NewEncoder(w).Encode(api.HealthResponse{
				Status:        "healthy",
				QueueDepth:    5,
				QueueCapacity: 1000,
				UptimeSeconds: 300,
			})
		case "/api/system/dreaming":
			json.NewEncoder(w).Encode(api.DreamingResponse{
				Status:   "active",
				Activity: "ingesting",
			})
		case "/metrics":
			w.Write([]byte("# HELP siem_events_total\nsiem_events_total 42\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client := api.NewClient(ts.URL)
	stats, err := client.GetStats()
	if err != nil {
		t.Fatalf("GetStats() error: %v", err)
	}
	if stats == nil {
		t.Fatal("GetStats() returned nil stats")
	}

	for _, p := range []string{"/health", "/api/system/dreaming", "/metrics"} {
		if !requestedPaths[p] {
			t.Errorf("expected GetStats to request %s", p)
		}
	}
}

func TestAPIClientGetStatsHealthyResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			json.NewEncoder(w).Encode(api.HealthResponse{
				Status:        "healthy",
				QueueDepth:    10,
				QueueCapacity: 1000,
				UptimeSeconds: 600,
			})
		case "/api/system/dreaming":
			json.NewEncoder(w).Encode(api.DreamingResponse{
				Status:      "active",
				Activity:    "ingesting",
				Description: "Processing events",
				Metrics: api.DreamingMetrics{
					EventsTotal:   200,
					QueueDepth:    10,
					QueueCapacity: 1000,
					EventsPerSec:  5.5,
				},
			})
		case "/metrics":
			w.Write([]byte("siem_queue_pushed_total 50\nsiem_queue_popped_total 45\nsiem_queue_dropped_total 2\n"))
		}
	}))
	defer ts.Close()

	client := api.NewClient(ts.URL)
	stats, err := client.GetStats()
	if err != nil {
		t.Fatalf("GetStats() error: %v", err)
	}
	if !stats.Healthy {
		t.Error("expected stats.Healthy to be true")
	}
	if stats.HealthStatus != "healthy" {
		t.Errorf("expected HealthStatus=healthy, got %s", stats.HealthStatus)
	}
	if stats.QueueSize != 10 {
		t.Errorf("expected QueueSize=10, got %d", stats.QueueSize)
	}
	if stats.QueueCapacity != 1000 {
		t.Errorf("expected QueueCapacity=1000, got %d", stats.QueueCapacity)
	}
	if stats.QueuePushed != 50 {
		t.Errorf("expected QueuePushed=50, got %d", stats.QueuePushed)
	}
	if stats.QueuePopped != 45 {
		t.Errorf("expected QueuePopped=45, got %d", stats.QueuePopped)
	}
	if stats.QueueDropped != 2 {
		t.Errorf("expected QueueDropped=2, got %d", stats.QueueDropped)
	}
}

func TestAPIClientGetStatsConnectionFailure(t *testing.T) {
	// Use a closed test server so connection is guaranteed to fail
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close()

	client := api.NewClient(ts.URL)
	stats, err := client.GetStats()
	// GetStats gracefully handles connection errors by returning
	// stats with Healthy=false rather than returning an error
	if err != nil {
		t.Fatalf("GetStats() should not return error on connection failure, got: %v", err)
	}
	if stats == nil {
		t.Fatal("expected non-nil stats even on connection failure")
	}
	if stats.Healthy {
		t.Error("expected Healthy=false on connection failure")
	}
}

func TestAPIClientGetEventsConvertsSearchResults(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(api.SearchResponse{
			Results: []api.SearchResult{
				{
					EventID:       "evt-001",
					Timestamp:     time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
					Action:        "login",
					Outcome:       "success",
					Severity:      3,
					SourceProduct: "AuthService",
					SourceVendor:  "Acme",
					ActorName:     "admin",
					Target:        "webapp",
				},
				{
					EventID:      "evt-002",
					Timestamp:    time.Date(2025, 1, 15, 10, 31, 0, 0, time.UTC),
					Action:       "file_access",
					Severity:     7,
					SourceVendor: "SecurityCorp",
				},
			},
			TotalCount: 2,
		})
	}))
	defer ts.Close()

	client := api.NewClient(ts.URL)
	resp, err := client.GetEvents(50)
	if err != nil {
		t.Fatalf("GetEvents() error: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("GetEvents() returned api error: %s", resp.Error)
	}
	if len(resp.Events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(resp.Events))
	}

	// First event: SourceProduct should be used as Source
	ev0 := resp.Events[0]
	if ev0.ID != "evt-001" {
		t.Errorf("expected event ID 'evt-001', got %s", ev0.ID)
	}
	if ev0.Source != "AuthService" {
		t.Errorf("expected source 'AuthService', got %s", ev0.Source)
	}
	if ev0.Actor != "admin" {
		t.Errorf("expected actor 'admin', got %s", ev0.Actor)
	}
	if ev0.Message != "login (success)" {
		t.Errorf("expected message 'login (success)', got %q", ev0.Message)
	}

	// Second event: SourceVendor fallback when SourceProduct is empty
	ev1 := resp.Events[1]
	if ev1.Source != "SecurityCorp" {
		t.Errorf("expected source fallback to vendor 'SecurityCorp', got %s", ev1.Source)
	}
	// No outcome, so message should just be the action
	if ev1.Message != "file_access" {
		t.Errorf("expected message 'file_access', got %q", ev1.Message)
	}
}

func TestAPIClientGetEventsNon200StatusCode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := api.NewClient(ts.URL)
	resp, err := client.GetEvents(10)
	if err != nil {
		t.Fatalf("GetEvents() should not return Go error for HTTP 500, got: %v", err)
	}
	if resp.Error == "" {
		t.Error("expected resp.Error to be non-empty for HTTP 500")
	}
}

// ---------------------------------------------------------------------------
// 3. Style Definitions Exist and Are Non-Empty
// ---------------------------------------------------------------------------

func TestStyleColorsNonEmpty(t *testing.T) {
	colors := []struct {
		name  string
		color lipgloss.Color
	}{
		{"Primary", styles.Primary},
		{"Secondary", styles.Secondary},
		{"Warning", styles.Warning},
		{"Error", styles.Error},
		{"MutedColor", styles.MutedColor},
		{"White", styles.White},
		{"Dark", styles.Dark},
	}
	for _, c := range colors {
		if string(c.color) == "" {
			t.Errorf("color %s is empty", c.name)
		}
	}
}

func TestStyleDefinitionsRenderContent(t *testing.T) {
	namedStyles := []struct {
		name  string
		style lipgloss.Style
	}{
		{"Title", styles.Title},
		{"Subtitle", styles.Subtitle},
		{"Box", styles.Box},
		{"StatusOK", styles.StatusOK},
		{"StatusWarning", styles.StatusWarning},
		{"StatusError", styles.StatusError},
		{"TabActive", styles.TabActive},
		{"TabInactive", styles.TabInactive},
		{"Help", styles.Help},
		{"TableHeader", styles.TableHeader},
		{"TableRow", styles.TableRow},
		{"TableRowSelected", styles.TableRowSelected},
		{"MetricCard", styles.MetricCard},
		{"MetricValue", styles.MetricValue},
		{"MetricLabel", styles.MetricLabel},
		{"Muted", styles.Muted},
	}

	for _, s := range namedStyles {
		rendered := s.style.Render("test")
		if !strings.Contains(rendered, "test") {
			t.Errorf("style %s: Render(\"test\") does not contain 'test', got %q", s.name, rendered)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. Scene Model Initialization
// ---------------------------------------------------------------------------

func TestNewDashboardSceneNonNil(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	d := scenes.NewDashboardScene(client)
	if d == nil {
		t.Fatal("NewDashboardScene() returned nil")
	}
}

func TestNewEventsSceneNonNil(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	e := scenes.NewEventsScene(client)
	if e == nil {
		t.Fatal("NewEventsScene() returned nil")
	}
}

func TestNewSystemSceneNonNil(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	s := scenes.NewSystemScene(client)
	if s == nil {
		t.Fatal("NewSystemScene() returned nil")
	}
}

func TestDashboardSceneInitReturnsCmd(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	d := scenes.NewDashboardScene(client)
	cmd := d.Init()
	if cmd == nil {
		t.Error("DashboardScene.Init() returned nil, expected a fetch command")
	}
}

func TestEventsSceneInitReturnsCmd(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	e := scenes.NewEventsScene(client)
	cmd := e.Init()
	if cmd == nil {
		t.Error("EventsScene.Init() returned nil, expected a fetch command")
	}
}

func TestSystemSceneInitReturnsCmd(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	s := scenes.NewSystemScene(client)
	cmd := s.Init()
	if cmd == nil {
		t.Error("SystemScene.Init() returned nil, expected a fetch command")
	}
}

func TestDashboardSceneTickCmdReturnsCmd(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	d := scenes.NewDashboardScene(client)
	cmd := d.TickCmd()
	if cmd == nil {
		t.Error("DashboardScene.TickCmd() returned nil")
	}
}

func TestEventsSceneTickCmdReturnsCmd(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	e := scenes.NewEventsScene(client)
	cmd := e.TickCmd()
	if cmd == nil {
		t.Error("EventsScene.TickCmd() returned nil")
	}
}

func TestSystemSceneTickCmdReturnsCmd(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	s := scenes.NewSystemScene(client)
	cmd := s.TickCmd()
	if cmd == nil {
		t.Error("SystemScene.TickCmd() returned nil")
	}
}

// ---------------------------------------------------------------------------
// 5. Message Handling
// ---------------------------------------------------------------------------

// --- Key Messages: Scene Switching ---

func TestUpdateSwitchToEventsScene(t *testing.T) {
	m := New("http://localhost:8080")
	m.Update(keyMsg("2"))
	if m.scene != SceneEvents {
		t.Errorf("expected SceneEvents after pressing '2', got %d", m.scene)
	}
}

func TestUpdateSwitchToSystemScene(t *testing.T) {
	m := New("http://localhost:8080")
	m.Update(keyMsg("3"))
	if m.scene != SceneSystem {
		t.Errorf("expected SceneSystem after pressing '3', got %d", m.scene)
	}
}

func TestUpdateSwitchBackToDashboard(t *testing.T) {
	m := New("http://localhost:8080")
	m.Update(keyMsg("2"))
	m.Update(keyMsg("1"))
	if m.scene != SceneDashboard {
		t.Errorf("expected SceneDashboard after pressing '1', got %d", m.scene)
	}
}

func TestUpdateTabCyclesThroughScenes(t *testing.T) {
	m := New("http://localhost:8080")

	// Dashboard -> Events
	m.Update(keyMsg("tab"))
	if m.scene != SceneEvents {
		t.Errorf("expected SceneEvents after first tab, got %d", m.scene)
	}

	// Events -> System
	m.Update(keyMsg("tab"))
	if m.scene != SceneSystem {
		t.Errorf("expected SceneSystem after second tab, got %d", m.scene)
	}

	// System -> Dashboard (wraps around)
	m.Update(keyMsg("tab"))
	if m.scene != SceneDashboard {
		t.Errorf("expected SceneDashboard after third tab (wrap), got %d", m.scene)
	}
}

func TestUpdateNoSceneChangeWhenAlreadyOnScene(t *testing.T) {
	m := New("http://localhost:8080")
	// Pressing '1' while already on dashboard should not change scene
	m.Update(keyMsg("1"))
	if m.scene != SceneDashboard {
		t.Errorf("scene should remain SceneDashboard, got %d", m.scene)
	}
}

// --- Key Messages: Quit ---

func TestUpdateQuitWithQ(t *testing.T) {
	m := New("http://localhost:8080")
	_, cmd := m.Update(keyMsg("q"))
	if !m.quitting {
		t.Error("expected quitting=true after pressing 'q'")
	}
	if cmd == nil {
		t.Error("expected non-nil command (tea.Quit) after pressing 'q'")
	}
}

func TestUpdateQuitWithCtrlC(t *testing.T) {
	m := New("http://localhost:8080")
	_, cmd := m.Update(keyMsg("ctrl+c"))
	if !m.quitting {
		t.Error("expected quitting=true after ctrl+c")
	}
	if cmd == nil {
		t.Error("expected non-nil command (tea.Quit) after ctrl+c")
	}
}

// --- WindowSizeMsg ---

func TestUpdateWindowSizeMsg(t *testing.T) {
	m := New("http://localhost:8080")
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	if m.width != 120 {
		t.Errorf("expected width=120, got %d", m.width)
	}
	if m.height != 40 {
		t.Errorf("expected height=40, got %d", m.height)
	}
}

func TestUpdateWindowSizeMsgReturnsNilCmd(t *testing.T) {
	m := New("http://localhost:8080")
	_, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	if cmd != nil {
		t.Error("expected nil command from WindowSizeMsg")
	}
}

// --- Scene-level WindowSizeMsg ---

func TestDashboardUpdateWindowSize(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	d := scenes.NewDashboardScene(client)
	updated, cmd := d.Update(tea.WindowSizeMsg{Width: 100, Height: 50})
	if updated == nil {
		t.Fatal("DashboardScene.Update returned nil")
	}
	if cmd != nil {
		t.Error("WindowSizeMsg should return nil command for dashboard")
	}
}

func TestEventsUpdateWindowSize(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	e := scenes.NewEventsScene(client)
	updated, cmd := e.Update(tea.WindowSizeMsg{Width: 100, Height: 50})
	if updated == nil {
		t.Fatal("EventsScene.Update returned nil")
	}
	if cmd != nil {
		t.Error("WindowSizeMsg should return nil command for events")
	}
}

func TestSystemUpdateWindowSize(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	s := scenes.NewSystemScene(client)
	updated, cmd := s.Update(tea.WindowSizeMsg{Width: 100, Height: 50})
	if updated == nil {
		t.Fatal("SystemScene.Update returned nil")
	}
	if cmd != nil {
		t.Error("WindowSizeMsg should return nil command for system")
	}
}

// --- TickMsg Handling ---

func TestDashboardTickMsgOwnScene(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	d := scenes.NewDashboardScene(client)
	tick := scenes.TickMsg{Scene: "dashboard", Time: time.Now()}
	_, cmd := d.Update(tick)
	if cmd == nil {
		t.Error("expected non-nil command when handling own TickMsg (should trigger fetch)")
	}
}

func TestDashboardTickMsgOtherScene(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	d := scenes.NewDashboardScene(client)
	tick := scenes.TickMsg{Scene: "events", Time: time.Now()}
	_, cmd := d.Update(tick)
	if cmd != nil {
		t.Error("dashboard should return nil command for events TickMsg")
	}
}

func TestEventsTickMsgOwnScene(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	e := scenes.NewEventsScene(client)
	tick := scenes.TickMsg{Scene: "events", Time: time.Now()}
	_, cmd := e.Update(tick)
	if cmd == nil {
		t.Error("expected non-nil command when events handles own TickMsg")
	}
}

func TestEventsTickMsgOtherScene(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	e := scenes.NewEventsScene(client)
	tick := scenes.TickMsg{Scene: "dashboard", Time: time.Now()}
	_, cmd := e.Update(tick)
	if cmd != nil {
		t.Error("events should return nil command for dashboard TickMsg")
	}
}

func TestSystemTickMsgOwnScene(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	s := scenes.NewSystemScene(client)
	tick := scenes.TickMsg{Scene: "system", Time: time.Now()}
	_, cmd := s.Update(tick)
	if cmd == nil {
		t.Error("expected non-nil command when system handles own TickMsg")
	}
}

func TestSystemTickMsgOtherScene(t *testing.T) {
	client := api.NewClient("http://localhost:8080")
	s := scenes.NewSystemScene(client)
	tick := scenes.TickMsg{Scene: "dashboard", Time: time.Now()}
	_, cmd := s.Update(tick)
	if cmd != nil {
		t.Error("system should return nil command for dashboard TickMsg")
	}
}

// --- View Output ---

func TestViewWhenQuittingIsEmpty(t *testing.T) {
	m := New("http://localhost:8080")
	m.quitting = true
	view := m.View()
	if view != "" {
		t.Errorf("expected empty view when quitting, got %q", view)
	}
}

func TestViewContainsTabLabels(t *testing.T) {
	m := New("http://localhost:8080")
	m.width = 80
	m.height = 24
	view := m.View()

	for _, label := range []string{"Dashboard", "Events", "System"} {
		if !strings.Contains(view, label) {
			t.Errorf("view should contain tab label %q", label)
		}
	}
}

func TestViewContainsFooterHelp(t *testing.T) {
	m := New("http://localhost:8080")
	m.width = 80
	m.height = 24
	view := m.View()
	if !strings.Contains(view, "Quit") {
		t.Error("view should contain 'Quit' in footer help")
	}
}

func TestViewDashboardSceneContent(t *testing.T) {
	m := New("http://localhost:8080")
	m.width = 100
	m.height = 40
	view := m.View()
	// Dashboard view should contain the dashboard title
	if !strings.Contains(view, "Boundary-SIEM Dashboard") {
		t.Error("dashboard view should contain 'Boundary-SIEM Dashboard'")
	}
}

func TestViewEventsSceneContent(t *testing.T) {
	m := New("http://localhost:8080")
	m.scene = SceneEvents
	m.width = 100
	m.height = 40
	view := m.View()
	if !strings.Contains(view, "Security Events") {
		t.Error("events view should contain 'Security Events'")
	}
}

func TestViewSystemSceneContent(t *testing.T) {
	m := New("http://localhost:8080")
	m.scene = SceneSystem
	m.width = 100
	m.height = 40
	view := m.View()
	if !strings.Contains(view, "System Information") {
		t.Error("system view should contain 'System Information'")
	}
}

// --- TickMsg Routing at Model Level ---

func TestModelRoutesTickToDashboardOnly(t *testing.T) {
	m := New("http://localhost:8080")
	m.scene = SceneDashboard
	tick := scenes.TickMsg{Scene: "dashboard", Time: time.Now()}
	_, cmd := m.Update(tick)
	// Should produce commands: the fetch cmd from dashboard + a new tick cmd
	if cmd == nil {
		t.Error("expected non-nil command when routing dashboard tick")
	}
}

func TestModelRoutesTickToEventsOnly(t *testing.T) {
	m := New("http://localhost:8080")
	m.scene = SceneEvents
	tick := scenes.TickMsg{Scene: "events", Time: time.Now()}
	_, cmd := m.Update(tick)
	if cmd == nil {
		t.Error("expected non-nil command when routing events tick")
	}
}

func TestModelRoutesTickToSystemOnly(t *testing.T) {
	m := New("http://localhost:8080")
	m.scene = SceneSystem
	tick := scenes.TickMsg{Scene: "system", Time: time.Now()}
	_, cmd := m.Update(tick)
	if cmd == nil {
		t.Error("expected non-nil command when routing system tick")
	}
}

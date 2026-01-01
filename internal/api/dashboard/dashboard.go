// Package dashboard provides the SOC dashboard API for the SIEM.
package dashboard

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// APIError represents a structured API error response.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// writeJSONError writes a structured JSON error response.
func writeJSONError(w http.ResponseWriter, status int, code, message, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(APIError{
		Code:    code,
		Message: message,
		Details: details,
	}); err != nil {
		slog.Error("failed to write error response", "error", err)
	}
}

// writeJSON writes a JSON response with proper error handling.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to write JSON response", "error", err)
	}
}

// DashboardAPI provides endpoints for the SOC dashboard.
type DashboardAPI struct {
	mu          sync.RWMutex
	widgets     map[string]*Widget
	layouts     map[string]*Layout
	preferences map[string]*UserPreferences
}

// Widget represents a dashboard widget.
type Widget struct {
	ID          string                 `json:"id"`
	Type        WidgetType             `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description,omitempty"`
	Config      map[string]interface{} `json:"config"`
	DataSource  string                 `json:"data_source"`
	RefreshRate time.Duration          `json:"refresh_rate"`
	Position    Position               `json:"position"`
	Size        Size                   `json:"size"`
}

// WidgetType defines widget types.
type WidgetType string

const (
	WidgetTypeChart      WidgetType = "chart"
	WidgetTypeTable      WidgetType = "table"
	WidgetTypeMetric     WidgetType = "metric"
	WidgetTypeMap        WidgetType = "map"
	WidgetTypeTimeline   WidgetType = "timeline"
	WidgetTypeAlertList  WidgetType = "alert_list"
	WidgetTypeTopN       WidgetType = "top_n"
	WidgetTypeHeatmap    WidgetType = "heatmap"
	WidgetTypeGauge      WidgetType = "gauge"
	WidgetTypeStatus     WidgetType = "status"
	WidgetTypeText       WidgetType = "text"
	WidgetTypeValidators WidgetType = "validators"
)

// Position defines widget position on the grid.
type Position struct {
	X int `json:"x"`
	Y int `json:"y"`
}

// Size defines widget size.
type Size struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}

// Layout represents a dashboard layout.
type Layout struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Widgets     []string  `json:"widgets"`
	IsDefault   bool      `json:"is_default"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserPreferences stores user dashboard preferences.
type UserPreferences struct {
	UserID        string            `json:"user_id"`
	DefaultLayout string            `json:"default_layout"`
	Theme         string            `json:"theme"`
	Timezone      string            `json:"timezone"`
	RefreshRate   time.Duration     `json:"refresh_rate"`
	Notifications NotificationPrefs `json:"notifications"`
}

// NotificationPrefs defines notification preferences.
type NotificationPrefs struct {
	Email     bool     `json:"email"`
	Slack     bool     `json:"slack"`
	Browser   bool     `json:"browser"`
	Sound     bool     `json:"sound"`
	Severities []string `json:"severities"`
}

// DashboardStats provides overall dashboard statistics.
type DashboardStats struct {
	TotalEvents        int64            `json:"total_events"`
	EventsPerSecond    float64          `json:"events_per_second"`
	ActiveAlerts       int              `json:"active_alerts"`
	CriticalAlerts     int              `json:"critical_alerts"`
	HighAlerts         int              `json:"high_alerts"`
	MediumAlerts       int              `json:"medium_alerts"`
	LowAlerts          int              `json:"low_alerts"`
	ValidatorsOnline   int              `json:"validators_online"`
	ValidatorsOffline  int              `json:"validators_offline"`
	NodesHealthy       int              `json:"nodes_healthy"`
	NodesUnhealthy     int              `json:"nodes_unhealthy"`
	ComplianceScore    float64          `json:"compliance_score"`
	ThreatLevel        string           `json:"threat_level"`
	TopSources         []SourceStats    `json:"top_sources"`
	TopAlertTypes      []AlertTypeStats `json:"top_alert_types"`
	RecentIncidents    []IncidentBrief  `json:"recent_incidents"`
	LastUpdated        time.Time        `json:"last_updated"`
}

// SourceStats provides statistics per source.
type SourceStats struct {
	Source string `json:"source"`
	Count  int64  `json:"count"`
}

// AlertTypeStats provides statistics per alert type.
type AlertTypeStats struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// IncidentBrief provides brief incident information.
type IncidentBrief struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// TimeSeriesData represents time series data for charts.
type TimeSeriesData struct {
	Labels   []string    `json:"labels"`
	Datasets []Dataset   `json:"datasets"`
	Interval string      `json:"interval"`
}

// Dataset represents a chart dataset.
type Dataset struct {
	Label string    `json:"label"`
	Data  []float64 `json:"data"`
	Color string    `json:"color,omitempty"`
}

// NewDashboardAPI creates a new dashboard API.
func NewDashboardAPI() *DashboardAPI {
	api := &DashboardAPI{
		widgets:     make(map[string]*Widget),
		layouts:     make(map[string]*Layout),
		preferences: make(map[string]*UserPreferences),
	}
	api.initDefaultWidgets()
	api.initDefaultLayouts()
	return api
}

// initDefaultWidgets creates default SOC widgets.
func (api *DashboardAPI) initDefaultWidgets() {
	widgets := []*Widget{
		{
			ID:          "events-timeline",
			Type:        WidgetTypeTimeline,
			Title:       "Event Timeline",
			Description: "Real-time event stream",
			DataSource:  "/api/events/stream",
			RefreshRate: 5 * time.Second,
			Position:    Position{X: 0, Y: 0},
			Size:        Size{Width: 12, Height: 4},
		},
		{
			ID:          "alert-summary",
			Type:        WidgetTypeMetric,
			Title:       "Active Alerts",
			Description: "Current alert counts by severity",
			DataSource:  "/api/alerts/summary",
			RefreshRate: 10 * time.Second,
			Position:    Position{X: 0, Y: 4},
			Size:        Size{Width: 3, Height: 2},
		},
		{
			ID:          "validator-status",
			Type:        WidgetTypeValidators,
			Title:       "Validator Health",
			Description: "Real-time validator status",
			DataSource:  "/api/validators/status",
			RefreshRate: 30 * time.Second,
			Position:    Position{X: 3, Y: 4},
			Size:        Size{Width: 3, Height: 2},
		},
		{
			ID:          "threat-gauge",
			Type:        WidgetTypeGauge,
			Title:       "Threat Level",
			Description: "Current threat assessment",
			DataSource:  "/api/threat/level",
			RefreshRate: 30 * time.Second,
			Position:    Position{X: 6, Y: 4},
			Size:        Size{Width: 2, Height: 2},
		},
		{
			ID:          "compliance-score",
			Type:        WidgetTypeGauge,
			Title:       "Compliance Score",
			Description: "Overall compliance status",
			DataSource:  "/api/compliance/score",
			RefreshRate: 60 * time.Second,
			Position:    Position{X: 8, Y: 4},
			Size:        Size{Width: 2, Height: 2},
		},
		{
			ID:          "eps-chart",
			Type:        WidgetTypeChart,
			Title:       "Events Per Second",
			Description: "Event ingestion rate over time",
			DataSource:  "/api/metrics/eps",
			RefreshRate: 10 * time.Second,
			Position:    Position{X: 10, Y: 4},
			Size:        Size{Width: 2, Height: 2},
			Config: map[string]interface{}{
				"chart_type": "line",
				"time_range": "1h",
			},
		},
		{
			ID:          "top-sources",
			Type:        WidgetTypeTopN,
			Title:       "Top Event Sources",
			Description: "Highest volume event sources",
			DataSource:  "/api/sources/top",
			RefreshRate: 30 * time.Second,
			Position:    Position{X: 0, Y: 6},
			Size:        Size{Width: 4, Height: 3},
			Config: map[string]interface{}{
				"limit": 10,
			},
		},
		{
			ID:          "alert-list",
			Type:        WidgetTypeAlertList,
			Title:       "Recent Alerts",
			Description: "Most recent security alerts",
			DataSource:  "/api/alerts/recent",
			RefreshRate: 10 * time.Second,
			Position:    Position{X: 4, Y: 6},
			Size:        Size{Width: 4, Height: 3},
			Config: map[string]interface{}{
				"limit": 20,
			},
		},
		{
			ID:          "geo-map",
			Type:        WidgetTypeMap,
			Title:       "Geographic Activity",
			Description: "Event locations worldwide",
			DataSource:  "/api/events/geo",
			RefreshRate: 60 * time.Second,
			Position:    Position{X: 8, Y: 6},
			Size:        Size{Width: 4, Height: 3},
		},
		{
			ID:          "mev-activity",
			Type:        WidgetTypeChart,
			Title:       "MEV Activity",
			Description: "Sandwich attacks and frontrunning",
			DataSource:  "/api/blockchain/mev",
			RefreshRate: 30 * time.Second,
			Position:    Position{X: 0, Y: 9},
			Size:        Size{Width: 4, Height: 2},
			Config: map[string]interface{}{
				"chart_type": "bar",
			},
		},
		{
			ID:          "sanctions-check",
			Type:        WidgetTypeTable,
			Title:       "OFAC Screening",
			Description: "Recent sanctions checks",
			DataSource:  "/api/compliance/screening",
			RefreshRate: 30 * time.Second,
			Position:    Position{X: 4, Y: 9},
			Size:        Size{Width: 4, Height: 2},
		},
		{
			ID:          "node-health",
			Type:        WidgetTypeHeatmap,
			Title:       "Node Health Matrix",
			Description: "Infrastructure health overview",
			DataSource:  "/api/nodes/health",
			RefreshRate: 30 * time.Second,
			Position:    Position{X: 8, Y: 9},
			Size:        Size{Width: 4, Height: 2},
		},
	}

	for _, w := range widgets {
		api.widgets[w.ID] = w
	}
}

// initDefaultLayouts creates default dashboard layouts.
func (api *DashboardAPI) initDefaultLayouts() {
	now := time.Now()
	layouts := []*Layout{
		{
			ID:          "soc-main",
			Name:        "SOC Main Dashboard",
			Description: "Primary SOC analyst view",
			Widgets: []string{
				"events-timeline", "alert-summary", "validator-status",
				"threat-gauge", "compliance-score", "eps-chart",
				"top-sources", "alert-list", "geo-map",
			},
			IsDefault: true,
			CreatedBy: "system",
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "blockchain-focus",
			Name:        "Blockchain Operations",
			Description: "Blockchain-specific monitoring",
			Widgets: []string{
				"validator-status", "mev-activity", "sanctions-check",
				"events-timeline", "alert-list",
			},
			IsDefault: false,
			CreatedBy: "system",
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "compliance-view",
			Name:        "Compliance Dashboard",
			Description: "Compliance and regulatory focus",
			Widgets: []string{
				"compliance-score", "sanctions-check", "alert-list",
				"events-timeline",
			},
			IsDefault: false,
			CreatedBy: "system",
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:          "infrastructure",
			Name:        "Infrastructure Health",
			Description: "Node and infrastructure monitoring",
			Widgets: []string{
				"node-health", "eps-chart", "top-sources",
				"events-timeline", "alert-summary",
			},
			IsDefault: false,
			CreatedBy: "system",
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	for _, l := range layouts {
		api.layouts[l.ID] = l
	}
}

// RegisterRoutes registers dashboard API routes.
func (api *DashboardAPI) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/dashboard/stats", api.handleStats)
	mux.HandleFunc("/api/dashboard/widgets", api.handleWidgets)
	mux.HandleFunc("/api/dashboard/layouts", api.handleLayouts)
	mux.HandleFunc("/api/dashboard/preferences", api.handlePreferences)
	mux.HandleFunc("/api/dashboard/timeseries", api.handleTimeSeries)
}

// handleStats returns dashboard statistics.
func (api *DashboardAPI) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed", "only GET is supported")
		return
	}

	stats := api.getStats()
	writeJSON(w, http.StatusOK, stats)
}

// getStats generates current dashboard statistics.
func (api *DashboardAPI) getStats() *DashboardStats {
	return &DashboardStats{
		TotalEvents:       1250000,
		EventsPerSecond:   1250.5,
		ActiveAlerts:      45,
		CriticalAlerts:    3,
		HighAlerts:        12,
		MediumAlerts:      18,
		LowAlerts:         12,
		ValidatorsOnline:  98,
		ValidatorsOffline: 2,
		NodesHealthy:      15,
		NodesUnhealthy:    1,
		ComplianceScore:   94.5,
		ThreatLevel:       "medium",
		TopSources: []SourceStats{
			{Source: "beacon-node-1", Count: 125000},
			{Source: "validator-client", Count: 98000},
			{Source: "execution-client", Count: 87500},
			{Source: "mev-relay", Count: 45000},
			{Source: "rpc-gateway", Count: 32000},
		},
		TopAlertTypes: []AlertTypeStats{
			{Type: "validator_missed_attestation", Count: 15},
			{Type: "rate_limit_exceeded", Count: 12},
			{Type: "mev_sandwich_detected", Count: 8},
			{Type: "high_gas_transaction", Count: 6},
			{Type: "sanctioned_address", Count: 4},
		},
		RecentIncidents: []IncidentBrief{
			{ID: "INC-001", Title: "Validator Slashing Event", Severity: "critical", Status: "investigating", CreatedAt: time.Now().Add(-1 * time.Hour)},
			{ID: "INC-002", Title: "RPC Rate Limit Abuse", Severity: "high", Status: "mitigated", CreatedAt: time.Now().Add(-3 * time.Hour)},
			{ID: "INC-003", Title: "Sanctioned Address Interaction", Severity: "critical", Status: "resolved", CreatedAt: time.Now().Add(-6 * time.Hour)},
		},
		LastUpdated: time.Now(),
	}
}

// handleWidgets returns available widgets.
func (api *DashboardAPI) handleWidgets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed", "only GET is supported")
		return
	}

	api.mu.RLock()
	defer api.mu.RUnlock()

	widgets := make([]*Widget, 0, len(api.widgets))
	for _, widget := range api.widgets {
		widgets = append(widgets, widget)
	}

	writeJSON(w, http.StatusOK, widgets)
}

// handleLayouts manages dashboard layouts.
func (api *DashboardAPI) handleLayouts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed", "only GET is supported")
		return
	}

	api.mu.RLock()
	defer api.mu.RUnlock()

	layouts := make([]*Layout, 0, len(api.layouts))
	for _, layout := range api.layouts {
		layouts = append(layouts, layout)
	}

	writeJSON(w, http.StatusOK, layouts)
}

// handlePreferences manages user preferences.
func (api *DashboardAPI) handlePreferences(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		userID := r.URL.Query().Get("user_id")
		if userID == "" {
			userID = "default"
		}
		api.mu.RLock()
		prefs, exists := api.preferences[userID]
		api.mu.RUnlock()

		if !exists {
			prefs = &UserPreferences{
				UserID:        userID,
				DefaultLayout: "soc-main",
				Theme:         "dark",
				Timezone:      "UTC",
				RefreshRate:   30 * time.Second,
				Notifications: NotificationPrefs{
					Email:      true,
					Browser:    true,
					Severities: []string{"critical", "high"},
				},
			}
		}
		writeJSON(w, http.StatusOK, prefs)

	case http.MethodPut:
		var prefs UserPreferences
		if err := json.NewDecoder(r.Body).Decode(&prefs); err != nil {
			writeJSONError(w, http.StatusBadRequest, "INVALID_REQUEST", "failed to parse request body", "")
			return
		}
		if prefs.UserID == "" {
			writeJSONError(w, http.StatusBadRequest, "MISSING_USER_ID", "user_id is required", "")
			return
		}
		api.mu.Lock()
		api.preferences[prefs.UserID] = &prefs
		api.mu.Unlock()

		writeJSON(w, http.StatusOK, prefs)

	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed", "only GET and PUT are supported")
	}
}

// handleTimeSeries returns time series data for charts.
func (api *DashboardAPI) handleTimeSeries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed", "only GET is supported")
		return
	}

	metric := r.URL.Query().Get("metric")
	timeRange := r.URL.Query().Get("range")
	if timeRange == "" {
		timeRange = "1h"
	}

	data := api.generateTimeSeries(metric, timeRange)
	writeJSON(w, http.StatusOK, data)
}

// generateTimeSeries generates sample time series data.
func (api *DashboardAPI) generateTimeSeries(metric, timeRange string) *TimeSeriesData {
	now := time.Now()
	labels := make([]string, 12)
	for i := 11; i >= 0; i-- {
		labels[11-i] = now.Add(-time.Duration(i*5) * time.Minute).Format("15:04")
	}

	return &TimeSeriesData{
		Labels:   labels,
		Interval: "5m",
		Datasets: []Dataset{
			{
				Label: "Events",
				Data:  []float64{1200, 1350, 1180, 1420, 1550, 1380, 1290, 1450, 1520, 1380, 1290, 1250},
				Color: "#3b82f6",
			},
			{
				Label: "Alerts",
				Data:  []float64{5, 8, 3, 12, 7, 4, 6, 9, 11, 5, 4, 6},
				Color: "#ef4444",
			},
		},
	}
}

// GetWidget returns a widget by ID.
func (api *DashboardAPI) GetWidget(id string) (*Widget, bool) {
	api.mu.RLock()
	defer api.mu.RUnlock()
	w, ok := api.widgets[id]
	return w, ok
}

// GetLayout returns a layout by ID.
func (api *DashboardAPI) GetLayout(id string) (*Layout, bool) {
	api.mu.RLock()
	defer api.mu.RUnlock()
	l, ok := api.layouts[id]
	return l, ok
}

// GetDefaultLayout returns the default layout.
func (api *DashboardAPI) GetDefaultLayout() *Layout {
	api.mu.RLock()
	defer api.mu.RUnlock()
	for _, l := range api.layouts {
		if l.IsDefault {
			return l
		}
	}
	return nil
}

// GetAllWidgets returns all widgets.
func (api *DashboardAPI) GetAllWidgets() []*Widget {
	api.mu.RLock()
	defer api.mu.RUnlock()
	widgets := make([]*Widget, 0, len(api.widgets))
	for _, w := range api.widgets {
		widgets = append(widgets, w)
	}
	return widgets
}

// GetAllLayouts returns all layouts.
func (api *DashboardAPI) GetAllLayouts() []*Layout {
	api.mu.RLock()
	defer api.mu.RUnlock()
	layouts := make([]*Layout, 0, len(api.layouts))
	for _, l := range api.layouts {
		layouts = append(layouts, l)
	}
	return layouts
}

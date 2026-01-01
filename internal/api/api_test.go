package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"boundary-siem/internal/api/auth"
	"boundary-siem/internal/api/dashboard"
	"boundary-siem/internal/api/reports"
)

// Dashboard API Tests

func TestDashboardAPI(t *testing.T) {
	api := dashboard.NewDashboardAPI()

	t.Run("GetAllWidgets", func(t *testing.T) {
		widgets := api.GetAllWidgets()
		if len(widgets) < 10 {
			t.Errorf("expected at least 10 widgets, got %d", len(widgets))
		}
	})

	t.Run("GetAllLayouts", func(t *testing.T) {
		layouts := api.GetAllLayouts()
		if len(layouts) < 4 {
			t.Errorf("expected at least 4 layouts, got %d", len(layouts))
		}
	})

	t.Run("GetDefaultLayout", func(t *testing.T) {
		layout := api.GetDefaultLayout()
		if layout == nil {
			t.Error("expected default layout, got nil")
		}
		if layout != nil && layout.ID != "soc-main" {
			t.Errorf("expected default layout ID 'soc-main', got '%s'", layout.ID)
		}
	})

	t.Run("GetWidget", func(t *testing.T) {
		widget, exists := api.GetWidget("events-timeline")
		if !exists {
			t.Error("expected events-timeline widget to exist")
		}
		if widget != nil && widget.Type != dashboard.WidgetTypeTimeline {
			t.Errorf("expected widget type 'timeline', got '%s'", widget.Type)
		}
	})

	t.Run("GetLayout", func(t *testing.T) {
		layout, exists := api.GetLayout("blockchain-focus")
		if !exists {
			t.Error("expected blockchain-focus layout to exist")
		}
		if layout != nil && len(layout.Widgets) == 0 {
			t.Error("expected layout to have widgets")
		}
	})
}

func TestDashboardHTTPEndpoints(t *testing.T) {
	api := dashboard.NewDashboardAPI()
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	t.Run("GET /api/dashboard/stats", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/dashboard/stats", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		var stats dashboard.DashboardStats
		if err := json.NewDecoder(rec.Body).Decode(&stats); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if stats.TotalEvents == 0 {
			t.Error("expected non-zero total events")
		}
		if stats.EventsPerSecond == 0 {
			t.Error("expected non-zero events per second")
		}
	})

	t.Run("GET /api/dashboard/widgets", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/dashboard/widgets", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		var widgets []*dashboard.Widget
		if err := json.NewDecoder(rec.Body).Decode(&widgets); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(widgets) < 10 {
			t.Errorf("expected at least 10 widgets, got %d", len(widgets))
		}
	})

	t.Run("GET /api/dashboard/layouts", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/dashboard/layouts", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		var layouts []*dashboard.Layout
		if err := json.NewDecoder(rec.Body).Decode(&layouts); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(layouts) < 4 {
			t.Errorf("expected at least 4 layouts, got %d", len(layouts))
		}
	})

	t.Run("GET /api/dashboard/preferences", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/dashboard/preferences?user_id=test", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		var prefs dashboard.UserPreferences
		if err := json.NewDecoder(rec.Body).Decode(&prefs); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if prefs.Theme != "dark" {
			t.Errorf("expected default theme 'dark', got '%s'", prefs.Theme)
		}
	})

	t.Run("GET /api/dashboard/timeseries", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/dashboard/timeseries?metric=events&range=1h", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		var data dashboard.TimeSeriesData
		if err := json.NewDecoder(rec.Body).Decode(&data); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(data.Labels) == 0 {
			t.Error("expected non-empty labels")
		}
		if len(data.Datasets) == 0 {
			t.Error("expected non-empty datasets")
		}
	})
}

func TestDashboardWidgetTypes(t *testing.T) {
	api := dashboard.NewDashboardAPI()
	widgets := api.GetAllWidgets()

	expectedTypes := map[dashboard.WidgetType]bool{
		dashboard.WidgetTypeTimeline:   false,
		dashboard.WidgetTypeMetric:     false,
		dashboard.WidgetTypeValidators: false,
		dashboard.WidgetTypeGauge:      false,
		dashboard.WidgetTypeChart:      false,
		dashboard.WidgetTypeTopN:       false,
		dashboard.WidgetTypeAlertList:  false,
		dashboard.WidgetTypeMap:        false,
		dashboard.WidgetTypeTable:      false,
		dashboard.WidgetTypeHeatmap:    false,
	}

	for _, widget := range widgets {
		if _, ok := expectedTypes[widget.Type]; ok {
			expectedTypes[widget.Type] = true
		}
	}

	for widgetType, found := range expectedTypes {
		if !found {
			t.Errorf("expected widget type %s to be present", widgetType)
		}
	}
}

// Auth API Tests

func TestAuthService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := auth.NewAuthService(logger)

	t.Run("GetDefaultUser", func(t *testing.T) {
		user, exists := svc.GetUser("admin")
		if !exists {
			t.Error("expected admin user to exist")
		}
		if user != nil && user.Username != "admin" {
			t.Errorf("expected username 'admin', got '%s'", user.Username)
		}
	})

	t.Run("GetDefaultTenant", func(t *testing.T) {
		tenant, exists := svc.GetTenant("default")
		if !exists {
			t.Error("expected default tenant to exist")
		}
		if tenant != nil && tenant.Name != "Default Organization" {
			t.Errorf("expected tenant name 'Default Organization', got '%s'", tenant.Name)
		}
	})

	t.Run("Authenticate", func(t *testing.T) {
		user, err := svc.Authenticate("admin", "password", "default")
		if err != nil {
			t.Fatalf("authentication failed: %v", err)
		}
		if user == nil {
			t.Error("expected user after authentication")
		}
	})

	t.Run("CreateSession", func(t *testing.T) {
		user, _ := svc.GetUser("admin")
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", "test-client")
		req.RemoteAddr = "127.0.0.1:12345"

		session, err := svc.CreateSession(user, req)
		if err != nil {
			t.Fatalf("failed to create session: %v", err)
		}
		if session.Token == "" {
			t.Error("expected non-empty session token")
		}
		if session.RefreshToken == "" {
			t.Error("expected non-empty refresh token")
		}
	})

	t.Run("ValidateSession", func(t *testing.T) {
		user, _ := svc.GetUser("admin")
		req := httptest.NewRequest("GET", "/", nil)
		session, _ := svc.CreateSession(user, req)

		validated, err := svc.ValidateSession(session.Token)
		if err != nil {
			t.Fatalf("session validation failed: %v", err)
		}
		if validated.ID != session.ID {
			t.Error("validated session ID doesn't match")
		}
	})

	t.Run("HasPermission", func(t *testing.T) {
		if !svc.HasPermission("admin", auth.PermissionAdmin) {
			t.Error("expected admin to have admin permission")
		}
		if !svc.HasPermission("admin", auth.PermissionViewAlerts) {
			t.Error("expected admin to have view_alerts permission")
		}
	})

	t.Run("CreateUser", func(t *testing.T) {
		newUser := &auth.User{
			ID:       "test-user",
			Username: "testuser",
			Email:    "test@example.com",
			Roles:    []auth.Role{auth.RoleAnalyst},
			TenantID: "default",
			Provider: auth.AuthProviderLocal,
		}
		err := svc.CreateUser(newUser)
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		user, exists := svc.GetUser("test-user")
		if !exists {
			t.Error("expected created user to exist")
		}
		if user != nil && len(user.Permissions) == 0 {
			t.Error("expected user to have permissions from role")
		}
	})

	t.Run("CreateTenant", func(t *testing.T) {
		newTenant := &auth.Tenant{
			ID:          "test-tenant",
			Name:        "Test Organization",
			Description: "Test tenant",
			Settings: &auth.TenantSettings{
				MaxUsers:     10,
				RequireMFA:   true,
				Features:     map[string]bool{"blockchain_monitoring": true},
			},
		}
		err := svc.CreateTenant(newTenant)
		if err != nil {
			t.Fatalf("failed to create tenant: %v", err)
		}

		tenant, exists := svc.GetTenant("test-tenant")
		if !exists {
			t.Error("expected created tenant to exist")
		}
		if tenant != nil && !tenant.Settings.RequireMFA {
			t.Error("expected MFA to be required")
		}
	})

	t.Run("GetAuditLog", func(t *testing.T) {
		// Trigger audit events via HTTP (audit logs are created by HTTP handlers)
		mux := http.NewServeMux()
		svc.RegisterRoutes(mux)

		body := `{"username": "admin", "password": "test", "tenant_id": "default"}`
		req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		entries := svc.GetAuditLog(10)
		if len(entries) == 0 {
			t.Error("expected audit log entries")
		}
	})
}

func TestAuthHTTPEndpoints(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := auth.NewAuthService(logger)
	mux := http.NewServeMux()
	svc.RegisterRoutes(mux)

	t.Run("POST /api/auth/login", func(t *testing.T) {
		body := `{"username": "admin", "password": "test", "tenant_id": "default"}`
		req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if result["token"] == nil {
			t.Error("expected token in response")
		}
	})

	t.Run("GET /api/users", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/users", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		var users []*auth.User
		if err := json.NewDecoder(rec.Body).Decode(&users); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(users) == 0 {
			t.Error("expected at least one user")
		}
	})

	t.Run("GET /api/tenants", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/tenants", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		var tenants []*auth.Tenant
		if err := json.NewDecoder(rec.Body).Decode(&tenants); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(tenants) == 0 {
			t.Error("expected at least one tenant")
		}
	})

	t.Run("GET /api/audit", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/audit", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})
}

func TestAuthRoles(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := auth.NewAuthService(logger)

	roles := []auth.Role{
		auth.RoleAdmin,
		auth.RoleAnalyst,
		auth.RoleViewer,
		auth.RoleCompliance,
		auth.RoleOperator,
		auth.RoleAuditor,
		auth.RoleAPIClient,
	}

	for _, role := range roles {
		t.Run(string(role), func(t *testing.T) {
			user := &auth.User{
				ID:       "test-" + string(role),
				Username: "test-" + string(role),
				Roles:    []auth.Role{role},
				TenantID: "default",
			}
			svc.CreateUser(user)

			created, exists := svc.GetUser(user.ID)
			if !exists {
				t.Error("expected user to exist")
			}
			if created != nil && len(created.Permissions) == 0 {
				t.Errorf("expected role %s to have permissions", role)
			}
		})
	}
}

// Reports API Tests

func TestReportService(t *testing.T) {
	svc := reports.NewReportService()

	t.Run("GetAllTemplates", func(t *testing.T) {
		templates := svc.GetAllTemplates()
		if len(templates) < 7 {
			t.Errorf("expected at least 7 templates, got %d", len(templates))
		}
	})

	t.Run("GetTemplate", func(t *testing.T) {
		template, exists := svc.GetTemplate("soc2-type2")
		if !exists {
			t.Error("expected SOC 2 template to exist")
		}
		if template != nil && template.Type != reports.ReportTypeSOC2 {
			t.Errorf("expected template type 'soc2', got '%s'", template.Type)
		}
		if template != nil && len(template.Sections) == 0 {
			t.Error("expected template to have sections")
		}
	})

	t.Run("GetISO27001Template", func(t *testing.T) {
		template, exists := svc.GetTemplate("iso27001-audit")
		if !exists {
			t.Error("expected ISO 27001 template to exist")
		}
		if template != nil && template.Type != reports.ReportTypeISO27001 {
			t.Errorf("expected template type 'iso27001', got '%s'", template.Type)
		}
	})

	t.Run("GetControls", func(t *testing.T) {
		soc2Controls := svc.GetControls("soc2")
		if len(soc2Controls) < 10 {
			t.Errorf("expected at least 10 SOC 2 controls, got %d", len(soc2Controls))
		}

		iso27001Controls := svc.GetControls("iso27001")
		if len(iso27001Controls) < 10 {
			t.Errorf("expected at least 10 ISO 27001 controls, got %d", len(iso27001Controls))
		}

		nistControls := svc.GetControls("nist")
		if len(nistControls) < 10 {
			t.Errorf("expected at least 10 NIST controls, got %d", len(nistControls))
		}
	})

	t.Run("CalculateComplianceScore", func(t *testing.T) {
		score := svc.CalculateComplianceScore()
		if score.Overall < 0 || score.Overall > 100 {
			t.Errorf("expected score between 0-100, got %f", score.Overall)
		}
		if score.ControlsTotal == 0 {
			t.Error("expected non-zero total controls")
		}
	})

	t.Run("GenerateReport", func(t *testing.T) {
		template, _ := svc.GetTemplate("executive-summary")
		report := svc.GenerateReport(
			template,
			reports.FormatPDF,
			time.Now().AddDate(0, -1, 0),
			time.Now(),
			nil,
			"default",
		)

		if report == nil {
			t.Fatal("expected report to be generated")
		}
		if report.Status != reports.StatusCompleted {
			t.Errorf("expected status 'completed', got '%s'", report.Status)
		}
		if len(report.Sections) == 0 {
			t.Error("expected report to have sections")
		}
	})
}

func TestReportHTTPEndpoints(t *testing.T) {
	svc := reports.NewReportService()
	mux := http.NewServeMux()
	svc.RegisterRoutes(mux)

	t.Run("GET /api/reports/templates", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/reports/templates", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		var templates []*reports.ReportTemplate
		if err := json.NewDecoder(rec.Body).Decode(&templates); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(templates) < 7 {
			t.Errorf("expected at least 7 templates, got %d", len(templates))
		}
	})

	t.Run("GET /api/compliance/controls", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/compliance/controls?framework=soc2", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		var controls []*reports.ComplianceControl
		if err := json.NewDecoder(rec.Body).Decode(&controls); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(controls) == 0 {
			t.Error("expected controls in response")
		}
	})

	t.Run("GET /api/compliance/score", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/compliance/score", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		var result map[string]interface{}
		if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if result["overall_score"] == nil {
			t.Error("expected overall_score in response")
		}
	})

	t.Run("POST /api/reports/generate", func(t *testing.T) {
		body := `{
			"template_id": "executive-summary",
			"format": "pdf",
			"start_date": "2024-01-01T00:00:00Z",
			"end_date": "2024-01-31T23:59:59Z",
			"tenant_id": "default"
		}`
		req := httptest.NewRequest("POST", "/api/reports/generate", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusCreated {
			t.Errorf("expected status 201, got %d", rec.Code)
		}

		var report reports.Report
		if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if report.ID == "" {
			t.Error("expected report ID")
		}
		if report.Status != reports.StatusCompleted {
			t.Errorf("expected status 'completed', got '%s'", report.Status)
		}
	})
}

func TestReportTemplateTypes(t *testing.T) {
	svc := reports.NewReportService()
	templates := svc.GetAllTemplates()

	expectedTypes := map[reports.ReportType]bool{
		reports.ReportTypeSOC2:        false,
		reports.ReportTypeISO27001:    false,
		reports.ReportTypePCIDSS:      false,
		reports.ReportTypeNIST:        false,
		reports.ReportTypeExecutive:   false,
		reports.ReportTypeIncident:    false,
		reports.ReportTypeThreat:      false,
		reports.ReportTypeOperational: false,
	}

	for _, template := range templates {
		if _, ok := expectedTypes[template.Type]; ok {
			expectedTypes[template.Type] = true
		}
	}

	for reportType, found := range expectedTypes {
		if !found {
			t.Errorf("expected report template type %s to be present", reportType)
		}
	}
}

func TestComplianceFrameworks(t *testing.T) {
	svc := reports.NewReportService()

	frameworks := []string{"soc2", "iso27001", "nist"}

	for _, framework := range frameworks {
		t.Run(framework, func(t *testing.T) {
			controls := svc.GetControls(framework)
			if len(controls) == 0 {
				t.Errorf("expected controls for framework %s", framework)
			}

			// Check control structure
			for _, control := range controls {
				if control.ID == "" {
					t.Error("expected control to have ID")
				}
				if control.ControlID == "" {
					t.Error("expected control to have ControlID")
				}
				if control.Name == "" {
					t.Error("expected control to have Name")
				}
				if control.Framework == "" {
					t.Error("expected control to have Framework")
				}
			}
		})
	}
}

// Integration Test
func TestFullAPIIntegration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	dashboardAPI := dashboard.NewDashboardAPI()
	authSvc := auth.NewAuthService(logger)
	reportSvc := reports.NewReportService()

	mux := http.NewServeMux()
	dashboardAPI.RegisterRoutes(mux)
	authSvc.RegisterRoutes(mux)
	reportSvc.RegisterRoutes(mux)

	// Test login and get session
	t.Run("LoginAndGetSession", func(t *testing.T) {
		// Login
		loginBody := `{"username": "admin", "password": "test", "tenant_id": "default"}`
		loginReq := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(loginBody))
		loginReq.Header.Set("Content-Type", "application/json")
		loginRec := httptest.NewRecorder()
		mux.ServeHTTP(loginRec, loginReq)

		if loginRec.Code != http.StatusOK {
			t.Fatalf("login failed with status %d", loginRec.Code)
		}

		var loginResult map[string]interface{}
		json.NewDecoder(loginRec.Body).Decode(&loginResult)
		token := loginResult["token"].(string)

		// Get session
		sessionReq := httptest.NewRequest("GET", "/api/auth/session", nil)
		sessionReq.Header.Set("Authorization", "Bearer "+token)
		sessionRec := httptest.NewRecorder()
		mux.ServeHTTP(sessionRec, sessionReq)

		if sessionRec.Code != http.StatusOK {
			t.Errorf("get session failed with status %d", sessionRec.Code)
		}
	})

	// Test full dashboard flow
	t.Run("DashboardFlow", func(t *testing.T) {
		// Get stats
		statsReq := httptest.NewRequest("GET", "/api/dashboard/stats", nil)
		statsRec := httptest.NewRecorder()
		mux.ServeHTTP(statsRec, statsReq)

		if statsRec.Code != http.StatusOK {
			t.Errorf("get stats failed with status %d", statsRec.Code)
		}

		// Get layouts
		layoutsReq := httptest.NewRequest("GET", "/api/dashboard/layouts", nil)
		layoutsRec := httptest.NewRecorder()
		mux.ServeHTTP(layoutsRec, layoutsReq)

		if layoutsRec.Code != http.StatusOK {
			t.Errorf("get layouts failed with status %d", layoutsRec.Code)
		}
	})

	// Test full reporting flow
	t.Run("ReportingFlow", func(t *testing.T) {
		// Get templates
		templatesReq := httptest.NewRequest("GET", "/api/reports/templates", nil)
		templatesRec := httptest.NewRecorder()
		mux.ServeHTTP(templatesRec, templatesReq)

		if templatesRec.Code != http.StatusOK {
			t.Errorf("get templates failed with status %d", templatesRec.Code)
		}

		// Get compliance score
		scoreReq := httptest.NewRequest("GET", "/api/compliance/score", nil)
		scoreRec := httptest.NewRecorder()
		mux.ServeHTTP(scoreRec, scoreReq)

		if scoreRec.Code != http.StatusOK {
			t.Errorf("get compliance score failed with status %d", scoreRec.Code)
		}

		// Generate report
		generateBody := `{
			"template_id": "soc2-type2",
			"format": "pdf",
			"start_date": "2024-01-01T00:00:00Z",
			"end_date": "2024-01-31T23:59:59Z",
			"tenant_id": "default"
		}`
		generateReq := httptest.NewRequest("POST", "/api/reports/generate", strings.NewReader(generateBody))
		generateReq.Header.Set("Content-Type", "application/json")
		generateRec := httptest.NewRecorder()
		mux.ServeHTTP(generateRec, generateReq)

		if generateRec.Code != http.StatusCreated {
			t.Errorf("generate report failed with status %d", generateRec.Code)
		}
	})
}

package boundarydaemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	cfg := ClientConfig{
		BaseURL:      "http://localhost:9000",
		APIKey:       "test-key",
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: time.Second,
	}

	client := NewClient(cfg)

	if client == nil {
		t.Fatal("NewClient returned nil")
	}
	if client.baseURL != "http://localhost:9000" {
		t.Errorf("expected baseURL 'http://localhost:9000', got %s", client.baseURL)
	}
	if client.apiKey != "test-key" {
		t.Errorf("expected apiKey 'test-key', got %s", client.apiKey)
	}
	if client.httpClient == nil {
		t.Error("expected non-nil httpClient")
	}
	if client.httpClient.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", client.httpClient.Timeout)
	}
}

func TestDefaultClientConfig(t *testing.T) {
	cfg := DefaultClientConfig()

	if cfg.BaseURL != "http://localhost:9000" {
		t.Errorf("expected BaseURL 'http://localhost:9000', got %s", cfg.BaseURL)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected Timeout 30s, got %v", cfg.Timeout)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("expected MaxRetries 3, got %d", cfg.MaxRetries)
	}
	if cfg.RetryBackoff != time.Second {
		t.Errorf("expected RetryBackoff 1s, got %v", cfg.RetryBackoff)
	}
}

func TestGetHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("expected path '/health', got %s", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("expected method 'GET', got %s", r.Method)
		}

		response := DaemonStatus{
			Status:         "healthy",
			Ready:          true,
			Live:           true,
			Version:        "1.0.0",
			Mode:           "normal",
			Uptime:         3600,
			ActiveSessions: 42,
			ThreatLevel:    "low",
			LastEvent:      time.Now().UTC(),
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	status, err := client.GetHealth(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.Status != "healthy" {
		t.Errorf("expected status 'healthy', got %s", status.Status)
	}
	if !status.Ready {
		t.Error("expected Ready to be true")
	}
	if status.ActiveSessions != 42 {
		t.Errorf("expected ActiveSessions 42, got %d", status.ActiveSessions)
	}
}

func TestGetStats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/stats" {
			t.Errorf("expected path '/api/v1/stats', got %s", r.URL.Path)
		}

		response := DaemonStats{
			TotalSessions:      1000,
			ActiveSessions:     50,
			TotalAuthAttempts:  5000,
			FailedAuthAttempts: 100,
			TotalAccessChecks:  10000,
			DeniedAccesses:     200,
			ThreatsDetected:    25,
			ThreatsBlocked:     20,
			PoliciesActive:     15,
			LastUpdated:        time.Now().UTC(),
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	stats, err := client.GetStats(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stats.TotalSessions != 1000 {
		t.Errorf("expected TotalSessions 1000, got %d", stats.TotalSessions)
	}
	if stats.ThreatsBlocked != 20 {
		t.Errorf("expected ThreatsBlocked 20, got %d", stats.ThreatsBlocked)
	}
}

func TestGetSessionEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/events/sessions" {
			t.Errorf("expected path '/api/v1/events/sessions', got %s", r.URL.Path)
		}

		// Verify query parameters
		since := r.URL.Query().Get("since")
		limit := r.URL.Query().Get("limit")
		if since == "" {
			t.Error("expected 'since' query parameter")
		}
		if limit != "100" {
			t.Errorf("expected limit '100', got %s", limit)
		}

		response := struct {
			Events []SessionEvent `json:"events"`
		}{
			Events: []SessionEvent{
				{
					ID:        "evt-001",
					Timestamp: time.Now().UTC(),
					EventType: "session.created",
					SessionID: "sess-001",
					UserID:    "user-001",
					Username:  "testuser",
					SourceIP:  "192.168.1.100",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	events, err := client.GetSessionEvents(ctx, time.Now().Add(-1*time.Hour), 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].SessionID != "sess-001" {
		t.Errorf("expected SessionID 'sess-001', got %s", events[0].SessionID)
	}
}

func TestGetAuthEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/events/auth" {
			t.Errorf("expected path '/api/v1/events/auth', got %s", r.URL.Path)
		}

		response := struct {
			Events []AuthEvent `json:"events"`
		}{
			Events: []AuthEvent{
				{
					ID:         "auth-001",
					Timestamp:  time.Now().UTC(),
					EventType:  "auth.login",
					UserID:     "user-001",
					Username:   "admin",
					SourceIP:   "10.0.0.1",
					AuthMethod: "password",
					Success:    true,
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	events, err := client.GetAuthEvents(ctx, time.Now().Add(-1*time.Hour), 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !events[0].Success {
		t.Error("expected Success to be true")
	}
}

func TestGetThreatEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/events/threats" {
			t.Errorf("expected path '/api/v1/events/threats', got %s", r.URL.Path)
		}

		response := struct {
			Events []ThreatEvent `json:"events"`
		}{
			Events: []ThreatEvent{
				{
					ID:          "threat-001",
					Timestamp:   time.Now().UTC(),
					EventType:   "threat.blocked",
					ThreatType:  "malware",
					Severity:    "critical",
					Description: "Malware detected",
					Blocked:     true,
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	events, err := client.GetThreatEvents(ctx, time.Now().Add(-1*time.Hour), 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Severity != "critical" {
		t.Errorf("expected Severity 'critical', got %s", events[0].Severity)
	}
}

func TestGetAuditLogs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/logs" {
			t.Errorf("expected path '/api/v1/audit/logs', got %s", r.URL.Path)
		}

		response := struct {
			Logs []AuditLogEntry `json:"logs"`
		}{
			Logs: []AuditLogEntry{
				{
					ID:            "audit-001",
					Timestamp:     time.Now().UTC(),
					EventType:     "config.changed",
					Actor:         "admin",
					Action:        "update",
					Target:        "/etc/config.yaml",
					Outcome:       "success",
					ContentHash:   "sha256:abc",
					Signature:     "sig:xyz",
					SignatureAlgo: "ed25519",
					Verified:      true,
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	logs, err := client.GetAuditLogs(ctx, time.Now().Add(-1*time.Hour), 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if !logs[0].Verified {
		t.Error("expected Verified to be true")
	}
}

func TestVerifyAuditLog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/verify/audit-001" {
			t.Errorf("expected path '/api/v1/audit/verify/audit-001', got %s", r.URL.Path)
		}

		response := AuditLogEntry{
			ID:            "audit-001",
			Timestamp:     time.Now().UTC(),
			EventType:     "test.event",
			Actor:         "admin",
			Action:        "test",
			Target:        "target",
			Outcome:       "success",
			Signature:     "verified-sig",
			SignatureAlgo: "ed25519",
			Verified:      true,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	entry, err := client.VerifyAuditLog(ctx, "audit-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !entry.Verified {
		t.Error("expected Verified to be true")
	}
}

func TestDoRequest_WithAPIKey(t *testing.T) {
	var receivedAPIKey string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAPIKey = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		BaseURL: server.URL,
		APIKey:  "secret-api-key",
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	_, err := client.GetHealth(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedAPIKey != "secret-api-key" {
		t.Errorf("expected API key 'secret-api-key', got %s", receivedAPIKey)
	}
}

func TestDoRequest_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	_, err := client.GetHealth(ctx)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestDoRequest_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // Slow response
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client := NewClient(ClientConfig{
		BaseURL: server.URL,
		Timeout: 10 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.GetHealth(ctx)
	if err == nil {
		t.Fatal("expected error for context cancellation")
	}
}

package alerting

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// E2E round 2: GET /v1/alerts ignored invalid filters. since=2026-10-02 (a
// date, accepted by /v1/search) and since=now-1m listed every alert,
// status=bogus and severity=CRITICAL listed none with 200, limit=abc was
// replaced by the default, and an empty list was null.

func listAlertsRequest(t *testing.T, h *Handler, query string) (int, map[string]json.RawMessage) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.HandleListAlerts(rec, httptest.NewRequest(http.MethodGet, "/v1/alerts?"+query, nil))
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET /v1/alerts?%s: invalid JSON %q", query, rec.Body.String())
	}
	return rec.Code, body
}

func TestListAlertsRejectsInvalidFilters(t *testing.T) {
	mgr := NewManager(ManagerConfig{DeduplicationWindow: time.Hour, RetentionPeriod: time.Hour, MaxAlerts: 100}, nil)
	h := NewHandler(mgr)

	for _, query := range []string{
		"since=yesterday",
		"until=2026-13-01",
		"since=now-1x",
		"since=now&until=now-1h",
		"status=bogus",
		"severity=urgent",
		"limit=abc",
		"limit=0",
		"limit=-1",
		"limit=100000",
		"offset=-1",
		"offset=x",
	} {
		code, body := listAlertsRequest(t, h, query)
		if code != http.StatusBadRequest {
			t.Errorf("GET /v1/alerts?%s = %d, want 400", query, code)
			continue
		}
		if len(body["details"]) < 3 {
			t.Errorf("GET /v1/alerts?%s: no details in %v", query, body)
		}
	}
}

func TestListAlertsFilterFormats(t *testing.T) {
	mgr := NewManager(ManagerConfig{DeduplicationWindow: time.Hour, RetentionPeriod: time.Hour, MaxAlerts: 100}, nil)
	ctx := context.Background()
	for i, sev := range []int{10, 10, 3} {
		a := makeCorrelationAlert("r", string(rune('a'+i)), "x", sev)
		if err := mgr.HandleCorrelationAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	h := NewHandler(mgr)
	tomorrow := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02")

	for _, tt := range []struct {
		query string
		want  int
	}{
		{"", 3},
		{"since=" + tomorrow, 0}, // a date, like /v1/search
		{"since=now-1h", 3},
		{"since=now%2B1h", 0}, // now+1h is in the future
		{"until=now-1h", 0},
		{"severity=CRITICAL", 2}, // case-insensitive
		{"severity=medium", 1},
		{"status=NEW", 3},
		{"status=resolved", 0},
		{"limit=2", 2},
		{"limit=2&offset=2", 1},
	} {
		code, body := listAlertsRequest(t, h, tt.query)
		if code != http.StatusOK {
			t.Errorf("GET /v1/alerts?%s = %d %v, want 200", tt.query, code, body)
			continue
		}
		var alerts []*Alert
		if err := json.Unmarshal(body["alerts"], &alerts); err != nil {
			t.Fatal(err)
		}
		if len(alerts) != tt.want {
			t.Errorf("GET /v1/alerts?%s listed %d alerts, want %d", tt.query, len(alerts), tt.want)
		}
		if tt.want == 0 && strings.TrimSpace(string(body["alerts"])) != "[]" {
			t.Errorf("GET /v1/alerts?%s alerts = %s, want []", tt.query, body["alerts"])
		}
	}
}

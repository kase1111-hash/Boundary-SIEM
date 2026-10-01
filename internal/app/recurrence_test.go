package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// E2E round 2 (t_recur): with the shipped configuration (correlation and
// alerting dedup_window 15m) a key export after its alert was resolved
// raised no alert, and a repeated blocked RPC call was not merged into its
// open alert: the engine dropped both firings before the alert manager saw
// them.

type fullAlertJSON struct {
	ID         string         `json:"id"`
	RuleID     string         `json:"rule_id"`
	Status     string         `json:"status"`
	EventCount int            `json:"event_count"`
	EventIDs   []string       `json:"event_ids"`
	Metadata   map[string]any `json:"metadata"`
}

func listAlerts(t *testing.T, a *App, ruleID string) []fullAlertJSON {
	t.Helper()
	code, body := apiRequest(t, a, http.MethodGet, "/v1/alerts?limit=500&rule_id="+ruleID, nil)
	if code != http.StatusOK {
		t.Fatalf("GET /v1/alerts = %d %s", code, body)
	}
	var resp struct {
		Alerts []fullAlertJSON `json:"alerts"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode alerts: %v: %s", err, body)
	}
	return resp.Alerts
}

func recurTriggers(target, ip string) map[string]any {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return map[string]any{"events": []map[string]any{
		{
			"timestamp": now,
			"source":    map[string]any{"product": "recur-test", "host": "signer-01"},
			"action":    "key.export",
			"target":    target,
			"outcome":   "success",
			"severity":  8,
			"actor":     map[string]any{"type": "user", "id": "ops", "ip_address": "10.78.0.9"},
		},
		{
			"timestamp": now,
			"source":    map[string]any{"product": "recur-test", "host": "node-01"},
			"action":    "rpc.admin",
			"target":    "admin_addPeer",
			"outcome":   "failure",
			"severity":  8,
			"actor":     map[string]any{"type": "user", "id": "anon", "ip_address": ip},
		},
	}}
}

func TestRecurrenceWithShippedDedupWindow(t *testing.T) {
	cfg := testConfig(t)
	if cfg.Correlation.DedupWindow != 15*time.Minute || cfg.Alerting.DedupWindow != 15*time.Minute {
		t.Fatalf("default dedup windows = %v/%v, want the shipped 15m", cfg.Correlation.DedupWindow, cfg.Alerting.DedupWindow)
	}
	cfg.Correlation.RecurrenceInterval = 100 * time.Millisecond // 10s by default
	a := startApp(t, cfg, newMemStore())

	const target, ip = "rk-recur-1", "10.78.0.3"
	if code, body := apiRequest(t, a, http.MethodPost, "/v1/events", recurTriggers(target, ip)); code != http.StatusOK {
		t.Fatalf("POST /v1/events = %d %s", code, body)
	}
	export := waitForAlert(t, a, "sec-005")
	waitForAlert(t, a, "sec-001")

	if code, body := apiRequest(t, a, http.MethodPost, "/v1/alerts/"+export.ID+"/resolve", map[string]string{"user": "analyst"}); code != http.StatusOK {
		t.Fatalf("resolve = %d %s", code, body)
	}
	time.Sleep(150 * time.Millisecond) // past recurrence_interval, well inside dedup_window

	if code, body := apiRequest(t, a, http.MethodPost, "/v1/events", recurTriggers(target, ip)); code != http.StatusOK {
		t.Fatalf("POST /v1/events = %d %s", code, body)
	}

	// The resumed key export raises a new alert listing only the new event.
	waitFor(t, "a new sec-005 alert after resolve", func() bool { return len(listAlerts(t, a, "sec-005")) == 2 })
	for _, al := range listAlerts(t, a, "sec-005") {
		switch {
		case al.ID == export.ID:
			if al.Status != "resolved" || al.EventCount != 1 {
				t.Errorf("resolved alert = %+v, want resolved with 1 event", al)
			}
		case al.Status != "new" || al.EventCount != 1 || len(al.EventIDs) != 1:
			t.Errorf("new alert = %+v, want new with only the resumed export", al)
		}
	}

	// The repeated RPC call is merged into the open alert, counted once.
	waitFor(t, "sec-001 recurrence merged", func() bool {
		alerts := listAlerts(t, a, "sec-001")
		return len(alerts) == 1 && alerts[0].EventCount >= 2
	})
	rpc := listAlerts(t, a, "sec-001")
	if len(rpc) != 1 {
		t.Fatalf("sec-001 alerts = %d, want 1", len(rpc))
	}
	distinct := map[string]bool{}
	for _, id := range rpc[0].EventIDs {
		distinct[id] = true
	}
	if rpc[0].EventCount != 2 || len(rpc[0].EventIDs) != 2 || len(distinct) != 2 {
		t.Errorf("sec-001 event_count=%d event_ids=%v, want 2 distinct events", rpc[0].EventCount, rpc[0].EventIDs)
	}
	if fmt.Sprint(rpc[0].Metadata["occurrences"]) != "2" {
		t.Errorf("sec-001 metadata = %v, want occurrences 2", rpc[0].Metadata)
	}
}

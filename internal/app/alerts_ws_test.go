package app

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"boundary-siem/internal/ws"
)

// E2E round 3 (t_ws_merge): a recurrence merged into an open alert changed
// its event_count, but nothing was pushed on /ws/events, so live views kept
// the stale count until their next poll.
func TestWebSocket_RecurrenceMergePushed(t *testing.T) {
	cfg := testConfig(t)
	cfg.Correlation.RecurrenceInterval = 100 * time.Millisecond // 10s by default
	a := startApp(t, cfg, newMemStore())

	conn := dialWS(t, a)
	if err := conn.WriteJSON(map[string]string{"type": "auth", "api_key": testAPIKey}); err != nil {
		t.Fatal(err)
	}
	if m := readWS(t, conn); msgType(m) != ws.TypeAuthOK {
		t.Fatalf("first message = %v, want auth_ok", m)
	}
	waitFor(t, "ws client registered", func() bool { return a.hub.Clients() == 1 })

	// nextAlert returns the next alert frame of rule sec-005.
	nextAlert := func() fullAlertJSON {
		t.Helper()
		for {
			m := readWS(t, conn)
			if msgType(m) != ws.TypeAlert {
				continue
			}
			var al fullAlertJSON
			if err := json.Unmarshal(m["data"], &al); err != nil {
				t.Fatal(err)
			}
			if al.RuleID == "sec-005" {
				return al
			}
		}
	}

	const target, ip = "wsm-m1", "10.78.0.21"
	if code, body := apiRequest(t, a, http.MethodPost, "/v1/events", recurTriggers(target, ip)); code != http.StatusOK {
		t.Fatalf("POST /v1/events = %d %s", code, body)
	}
	first := nextAlert()
	if first.Status != "new" || first.EventCount != 1 {
		t.Fatalf("first alert frame = %+v, want a new alert with 1 event", first)
	}

	time.Sleep(150 * time.Millisecond) // past recurrence_interval, inside dedup_window
	if code, body := apiRequest(t, a, http.MethodPost, "/v1/events", recurTriggers(target, ip)); code != http.StatusOK {
		t.Fatalf("POST /v1/events = %d %s", code, body)
	}
	merged := nextAlert()
	if merged.ID != first.ID || merged.EventCount != 2 {
		t.Errorf("frame after the recurrence = %+v, want alert %s with event_count 2", merged, first.ID)
	}
	if occ, _ := merged.Metadata["occurrences"].(float64); occ != 2 {
		t.Errorf("frame metadata = %v, want occurrences 2", merged.Metadata)
	}
}

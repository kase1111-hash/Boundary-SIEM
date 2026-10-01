package app

import (
	"encoding/json"
	"net/http"
	"testing"
)

// E2E round 2: every dashboard alert action was recorded as the hard-coded
// user "operator". The API key that made the request is recorded with the
// user the request names, or alone when it names none.
func TestAlertActionsRecordTheAPIKey(t *testing.T) {
	cfg := testConfig(t)
	cfg.Auth.APIKeys = []string{"another-key-0123456789", testAPIKey} // testAPIKey is api-key-2
	a := startApp(t, cfg, newMemStore())

	if code, body := apiRequest(t, a, http.MethodPost, "/v1/events", recurTriggers("rk-attr-1", "10.78.0.4")); code != http.StatusOK {
		t.Fatalf("POST /v1/events = %d %s", code, body)
	}
	alert := waitForAlert(t, a, "sec-005")
	path := "/v1/alerts/" + alert.ID

	if code, body := apiRequest(t, a, http.MethodPost, path+"/acknowledge", map[string]string{"user": "alice"}); code != http.StatusOK {
		t.Fatalf("acknowledge = %d %s", code, body)
	}
	if code, body := apiRequest(t, a, http.MethodPost, path+"/notes", map[string]string{"content": "checked"}); code != http.StatusOK {
		t.Fatalf("note without author = %d %s", code, body)
	}
	if code, body := apiRequest(t, a, http.MethodPost, path+"/resolve", nil); code != http.StatusOK {
		t.Fatalf("resolve without a body = %d %s", code, body)
	}

	code, body := apiRequest(t, a, http.MethodGet, path, nil)
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d %s", path, code, body)
	}
	var got struct {
		AckedBy    string `json:"acked_by"`
		ResolvedBy string `json:"resolved_by"`
		Notes      []struct {
			Author string `json:"author"`
		} `json:"notes"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.AckedBy != "alice (api-key-2)" {
		t.Errorf("acked_by = %q, want %q", got.AckedBy, "alice (api-key-2)")
	}
	if got.ResolvedBy != "api-key-2" {
		t.Errorf("resolved_by = %q, want %q", got.ResolvedBy, "api-key-2")
	}
	if len(got.Notes) != 1 || got.Notes[0].Author != "api-key-2" {
		t.Errorf("notes = %+v, want one by api-key-2", got.Notes)
	}
}

// The dashboard reads auth_required from the public /health before it
// requests any data, so it no longer starts with three 401s.
func TestHealthReportsAuthRequired(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		cfg := testConfig(t)
		cfg.Auth.Enabled = enabled
		a := startApp(t, cfg, newMemStore())
		resp, err := http.Get("http://" + a.Addr() + "/health")
		if err != nil {
			t.Fatal(err)
		}
		var health struct {
			AuthRequired *bool `json:"auth_required"`
		}
		err = json.NewDecoder(resp.Body).Decode(&health)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if health.AuthRequired == nil || *health.AuthRequired != enabled {
			t.Errorf("auth.enabled=%v: /health auth_required = %v, want %v", enabled, health.AuthRequired, enabled)
		}
	}
}

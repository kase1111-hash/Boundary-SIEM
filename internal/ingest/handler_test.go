package ingest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
)

func newTestHandler() *Handler {
	validator := schema.NewValidator()
	q := queue.NewRingBuffer(1000)
	return NewHandler(validator, q)
}

func TestHandler_HandleEvents(t *testing.T) {
	handler := newTestHandler()

	t.Run("single valid event", func(t *testing.T) {
		body := `{
			"events": [{
				"timestamp": "` + time.Now().UTC().Format(time.RFC3339) + `",
				"source": {"product": "test-product"},
				"action": "test.action",
				"outcome": "success",
				"severity": 5
			}]
		}`

		req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.HandleEvents(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}

		var resp IngestResponse
		json.NewDecoder(rec.Body).Decode(&resp)

		if !resp.Success {
			t.Errorf("Success = false, want true")
		}
		if resp.Accepted != 1 {
			t.Errorf("Accepted = %d, want 1", resp.Accepted)
		}
		if resp.Rejected != 0 {
			t.Errorf("Rejected = %d, want 0", resp.Rejected)
		}
	})

	t.Run("batch events", func(t *testing.T) {
		now := time.Now().UTC().Format(time.RFC3339)
		body := `{
			"events": [
				{"timestamp": "` + now + `", "source": {"product": "test"}, "action": "test.one", "outcome": "success", "severity": 1},
				{"timestamp": "` + now + `", "source": {"product": "test"}, "action": "test.two", "outcome": "failure", "severity": 5},
				{"timestamp": "` + now + `", "source": {"product": "test"}, "action": "test.three", "outcome": "unknown", "severity": 10}
			]
		}`

		req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.HandleEvents(rec, req)

		var resp IngestResponse
		json.NewDecoder(rec.Body).Decode(&resp)

		if resp.Accepted != 3 {
			t.Errorf("Accepted = %d, want 3", resp.Accepted)
		}
	})

	t.Run("empty events array", func(t *testing.T) {
		body := `{"events": []}`

		req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.HandleEvents(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		body := `{"events": [invalid json`

		req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.HandleEvents(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})

	t.Run("invalid event rejected", func(t *testing.T) {
		body := `{
			"events": [{
				"timestamp": "` + time.Now().UTC().Format(time.RFC3339) + `",
				"source": {"product": "test"},
				"action": "INVALID ACTION FORMAT",
				"outcome": "success",
				"severity": 5
			}]
		}`

		req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.HandleEvents(rec, req)

		var resp IngestResponse
		json.NewDecoder(rec.Body).Decode(&resp)

		if resp.Success {
			t.Error("Success = true, want false")
		}
		if resp.Rejected != 1 {
			t.Errorf("Rejected = %d, want 1", resp.Rejected)
		}
		if len(resp.Errors) == 0 {
			t.Error("Errors should not be empty")
		}
	})

	t.Run("partial success", func(t *testing.T) {
		now := time.Now().UTC().Format(time.RFC3339)
		body := `{
			"events": [
				{"timestamp": "` + now + `", "source": {"product": "test"}, "action": "valid.action", "outcome": "success", "severity": 5},
				{"timestamp": "` + now + `", "source": {"product": "test"}, "action": "INVALID", "outcome": "success", "severity": 5}
			]
		}`

		req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.HandleEvents(rec, req)

		if rec.Code != http.StatusMultiStatus {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusMultiStatus)
		}

		var resp IngestResponse
		json.NewDecoder(rec.Body).Decode(&resp)

		if resp.Accepted != 1 {
			t.Errorf("Accepted = %d, want 1", resp.Accepted)
		}
		if resp.Rejected != 1 {
			t.Errorf("Rejected = %d, want 1", resp.Rejected)
		}
	})

	t.Run("severity out of range", func(t *testing.T) {
		body := `{
			"events": [{
				"timestamp": "` + time.Now().UTC().Format(time.RFC3339) + `",
				"source": {"product": "test"},
				"action": "test.action",
				"outcome": "success",
				"severity": 15
			}]
		}`

		req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.HandleEvents(rec, req)

		var resp IngestResponse
		json.NewDecoder(rec.Body).Decode(&resp)

		if resp.Rejected != 1 {
			t.Errorf("Rejected = %d, want 1", resp.Rejected)
		}
	})

	t.Run("event with actor", func(t *testing.T) {
		body := `{
			"events": [{
				"timestamp": "` + time.Now().UTC().Format(time.RFC3339) + `",
				"source": {"product": "test", "host": "test-host"},
				"action": "auth.login",
				"actor": {
					"type": "user",
					"id": "user123",
					"name": "John Doe",
					"ip_address": "192.168.1.100"
				},
				"target": "resource:database",
				"outcome": "success",
				"severity": 3,
				"metadata": {"session_id": "sess123"}
			}]
		}`

		req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.HandleEvents(rec, req)

		var resp IngestResponse
		json.NewDecoder(rec.Body).Decode(&resp)

		if resp.Accepted != 1 {
			t.Errorf("Accepted = %d, want 1", resp.Accepted)
		}
	})

	t.Run("batch size exceeded", func(t *testing.T) {
		h := newTestHandler().WithMaxBatch(5)

		events := make([]map[string]any, 10)
		for i := range events {
			events[i] = map[string]any{
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"source":    map[string]string{"product": "test"},
				"action":    "test.action",
				"outcome":   "success",
				"severity":  5,
			}
		}
		body, _ := json.Marshal(map[string]any{"events": events})

		req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		h.HandleEvents(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})
}

func TestHandler_HealthCheck(t *testing.T) {
	handler := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.HealthCheck(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]any
	json.NewDecoder(rec.Body).Decode(&resp)

	if resp["status"] != "healthy" {
		t.Errorf("status = %v, want healthy", resp["status"])
	}

	if _, ok := resp["queue_depth"]; !ok {
		t.Error("queue_depth should be present")
	}

	if _, ok := resp["uptime_seconds"]; !ok {
		t.Error("uptime_seconds should be present")
	}
}

func TestHandler_Metrics(t *testing.T) {
	handler := newTestHandler()

	// Send some events first
	body := `{
		"events": [{
			"timestamp": "` + time.Now().UTC().Format(time.RFC3339) + `",
			"source": {"product": "test"},
			"action": "test.action",
			"outcome": "success",
			"severity": 5
		}]
	}`

	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.HandleEvents(rec, req)

	// Now check metrics
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec = httptest.NewRecorder()

	handler.Metrics(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body = rec.Body.String()

	if !strings.Contains(body, "siem_events_total") {
		t.Error("metrics should contain siem_events_total")
	}

	if !strings.Contains(body, "siem_queue_depth") {
		t.Error("metrics should contain siem_queue_depth")
	}

	if !strings.Contains(body, "siem_uptime_seconds") {
		t.Error("metrics should contain siem_uptime_seconds")
	}
}

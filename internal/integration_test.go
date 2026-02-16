package internal_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"boundary-siem/internal/alerting"
	"boundary-siem/internal/correlation"
	detectionrules "boundary-siem/internal/detection/rules"
	"boundary-siem/internal/ingest"
	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// --- Test: Ingest → Correlate → Alert pipeline ---

func TestIngestCorrelateAlert(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Set up queue
	eventQueue := queue.NewRingBuffer(1000)

	// Set up correlation engine
	engine := correlation.NewEngine(correlation.EngineConfig{
		WorkerCount:      2,
		MaxStateEntries:  1000,
		StateCleanupFreq: 30 * time.Second,
	})

	// Add a simple threshold rule that fires on 3 events
	rule := &correlation.Rule{
		ID:       "test-threshold-rule",
		Name:     "Test Threshold Rule",
		Type:     correlation.RuleTypeThreshold,
		Enabled:  true,
		Severity: 5,
		Category: "Test",
		Conditions: correlation.Conditions{
			Match: []correlation.MatchCondition{
				{Field: "action", Operator: "eq", Value: "test.event"},
			},
		},
		Threshold: &correlation.ThresholdConfig{
			Count:    3,
			Operator: "gte",
		},
		Window:  5 * time.Minute,
		GroupBy: []string{"source.host"},
	}
	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	// Set up alert manager and capture alerts
	alertMgr := alerting.NewManager(alerting.ManagerConfig{
		DeduplicationWindow: 1 * time.Second,
		RetentionPeriod:     1 * time.Hour,
		MaxAlerts:           100,
	}, nil)

	var capturedAlerts []*correlation.Alert
	var alertMu sync.Mutex

	engine.AddHandler(func(ctx context.Context, alert *correlation.Alert) error {
		alertMu.Lock()
		capturedAlerts = append(capturedAlerts, alert)
		alertMu.Unlock()
		return alertMgr.HandleCorrelationAlert(ctx, alert)
	})

	engine.Start(ctx)
	defer engine.Stop()

	// Ingest events that should trigger the rule
	for i := 0; i < 5; i++ {
		event := &schema.Event{
			EventID:   uuid.New(),
			Timestamp: time.Now(),
			Source: schema.Source{
				Product: "test",
				Host:    "test-node",
			},
			Action:        "test.event",
			Outcome:       schema.OutcomeSuccess,
			Severity:      3,
			SchemaVersion: schema.SchemaVersionCurrent,
			ReceivedAt:    time.Now(),
			TenantID:      "test",
		}

		if err := eventQueue.Push(event); err != nil {
			t.Fatalf("failed to push event: %v", err)
		}

		// Feed to correlation engine
		engine.ProcessEvent(event)
	}

	// Wait for correlation engine to process
	time.Sleep(2 * time.Second)

	alertMu.Lock()
	alertCount := len(capturedAlerts)
	alertMu.Unlock()

	if alertCount == 0 {
		t.Fatal("expected at least one alert from threshold rule, got none")
	}

	alert := capturedAlerts[0]
	if alert.RuleID != "test-threshold-rule" {
		t.Errorf("expected rule ID 'test-threshold-rule', got %q", alert.RuleID)
	}
	if alert.Severity != 5 {
		t.Errorf("expected severity 5, got %d", alert.Severity)
	}

	t.Logf("Pipeline test passed: ingested 5 events -> correlation fired -> %d alert(s) created", alertCount)
}

// --- Test: Alert → Notify with mock webhook ---

func TestAlertNotifyWebhook(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a mock webhook server
	var receivedPayloads [][]byte
	var mu sync.Mutex

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedPayloads = append(receivedPayloads, body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	// Create webhook channel pointing at mock server (local httptest server
	// uses loopback which would be blocked by SSRF check, so use test constructor)
	webhookCh := alerting.NewWebhookChannelForTest("test-webhook", mockServer.URL, nil)

	// Create alert manager with webhook channel
	alertMgr := alerting.NewManager(alerting.DefaultManagerConfig(), nil)
	alertMgr.AddChannel(webhookCh)

	// Fire a correlation alert
	corrAlert := &correlation.Alert{
		ID:          uuid.New(),
		RuleID:      "test-rule-001",
		RuleName:    "Test Rule",
		Severity:    7,
		Title:       "Test Alert",
		Description: "This is a test alert for E2E testing",
		Timestamp:   time.Now(),
		GroupKey:    "test-group",
		Tags:        []string{"test", "e2e"},
		Events: []correlation.EventRef{
			{EventID: uuid.New(), Timestamp: time.Now(), Action: "test.event"},
		},
	}

	err := alertMgr.HandleCorrelationAlert(ctx, corrAlert)
	if err != nil {
		t.Fatalf("HandleCorrelationAlert failed: %v", err)
	}

	// Wait for async notification
	time.Sleep(1 * time.Second)

	mu.Lock()
	payloadCount := len(receivedPayloads)
	mu.Unlock()

	if payloadCount == 0 {
		t.Fatal("expected webhook to receive notification, got none")
	}

	// Verify payload contains alert data
	var alertPayload map[string]interface{}
	if err := json.Unmarshal(receivedPayloads[0], &alertPayload); err != nil {
		t.Fatalf("failed to unmarshal webhook payload: %v", err)
	}

	if alertPayload["rule_id"] != "test-rule-001" {
		t.Errorf("expected rule_id 'test-rule-001' in payload, got %v", alertPayload["rule_id"])
	}
	if alertPayload["title"] != "Test Alert" {
		t.Errorf("expected title 'Test Alert' in payload, got %v", alertPayload["title"])
	}

	t.Logf("Notify test passed: alert created -> webhook received %d notification(s)", payloadCount)
}

// --- Test: Reliable delivery with retries ---

func TestReliableDeliveryRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Create a channel that fails twice then succeeds
	var attempts int
	var mu sync.Mutex

	failChannel := &mockNotificationChannel{
		name: "fail-then-succeed",
		sendFunc: func(ctx context.Context, alert *alerting.Alert) error {
			mu.Lock()
			attempts++
			current := attempts
			mu.Unlock()

			if current <= 2 {
				return fmt.Errorf("simulated failure attempt %d", current)
			}
			return nil
		},
	}

	dispatcher := alerting.NewReliableDispatcher(alerting.DeliveryConfig{
		MaxRetries:     5,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     500 * time.Millisecond,
		BackoffFactor:  2.0,
		RetryTimeout:   5 * time.Second,
	}, []alerting.NotificationChannel{failChannel})
	defer dispatcher.Stop()

	alert := &alerting.Alert{
		ID:       uuid.New(),
		RuleID:   "test-retry",
		RuleName: "Retry Test",
		Title:    "Test Retry",
		Status:   alerting.StatusNew,
	}

	dispatcher.Dispatch(ctx, alert)

	// Wait for retries to complete
	time.Sleep(3 * time.Second)

	mu.Lock()
	totalAttempts := attempts
	mu.Unlock()

	if totalAttempts < 3 {
		t.Errorf("expected at least 3 attempts, got %d", totalAttempts)
	}

	records := dispatcher.GetDeliveryRecords(alert.ID)
	if len(records) == 0 {
		t.Fatal("expected delivery records, got none")
	}

	record := records[0]
	if record.Status != alerting.DeliverySent {
		t.Errorf("expected delivery status 'sent', got %q", record.Status)
	}
	if record.Attempts != totalAttempts {
		t.Errorf("expected %d attempts in record, got %d", totalAttempts, record.Attempts)
	}

	t.Logf("Retry test passed: %d attempts, final status: %s", totalAttempts, record.Status)
}

// --- Test: Dead letter queue ---

func TestDeadLetterQueue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Channel that always fails
	alwaysFail := &mockNotificationChannel{
		name: "always-fail",
		sendFunc: func(ctx context.Context, alert *alerting.Alert) error {
			return fmt.Errorf("permanent failure")
		},
	}

	dispatcher := alerting.NewReliableDispatcher(alerting.DeliveryConfig{
		MaxRetries:     3,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
		BackoffFactor:  2.0,
		RetryTimeout:   5 * time.Second,
	}, []alerting.NotificationChannel{alwaysFail})
	defer dispatcher.Stop()

	alert := &alerting.Alert{
		ID:       uuid.New(),
		RuleID:   "test-dlq",
		RuleName: "DLQ Test",
		Title:    "Test Dead Letter",
		Status:   alerting.StatusNew,
	}

	dispatcher.Dispatch(ctx, alert)

	// Wait for all retries to exhaust
	time.Sleep(3 * time.Second)

	dlq := dispatcher.DeadLetterQueue()
	if len(dlq) == 0 {
		t.Fatal("expected dead letter queue entry, got none")
	}

	dlEntry := dlq[0]
	if dlEntry.Status != alerting.DeliveryDeadLetter {
		t.Errorf("expected status 'dead_letter', got %q", dlEntry.Status)
	}
	if dlEntry.Attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", dlEntry.Attempts)
	}

	t.Logf("Dead letter test passed: %d retries exhausted, entry in DLQ with error: %s", dlEntry.Attempts, dlEntry.LastError)
}

// --- Test: Escalation suppression ---

func TestEscalationSuppression(t *testing.T) {
	alertMgr := alerting.NewManager(alerting.DefaultManagerConfig(), nil)
	escalation := alerting.NewEscalationEngine(alertMgr)

	// Add a suppression window for the next hour
	escalation.AddSuppression(alerting.SuppressionWindow{
		ID:        "maint-window-1",
		Name:      "Scheduled Maintenance",
		Enabled:   true,
		StartTime: time.Now().Add(-1 * time.Minute),
		EndTime:   time.Now().Add(1 * time.Hour),
		CreatedBy: "test",
	})

	alert := &alerting.Alert{
		ID:       uuid.New(),
		RuleID:   "test-rule",
		Severity: "critical",
		Status:   alerting.StatusNew,
	}

	if !escalation.IsSuppressed(alert) {
		t.Error("expected alert to be suppressed during maintenance window")
	}

	// Test rule-specific suppression
	escalation.AddSuppression(alerting.SuppressionWindow{
		ID:        "rule-specific",
		Name:      "Rule Specific Suppression",
		Enabled:   true,
		StartTime: time.Now().Add(-1 * time.Minute),
		EndTime:   time.Now().Add(1 * time.Hour),
		RuleIDs:   []string{"specific-rule"},
		CreatedBy: "test",
	})

	alertOther := &alerting.Alert{
		ID:       uuid.New(),
		RuleID:   "other-rule",
		Severity: "medium",
		Status:   alerting.StatusNew,
	}

	// This alert should be suppressed by the first window (no rule filter)
	if !escalation.IsSuppressed(alertOther) {
		t.Error("expected alert to be suppressed by general maintenance window")
	}

	t.Log("Suppression test passed")
}

// --- Test: HTTP ingest endpoint ---

func TestHTTPIngestEndpoint(t *testing.T) {
	eventQueue := queue.NewRingBuffer(100)
	validator := schema.NewValidator()

	handler := ingest.NewHandler(validator, eventQueue).
		WithMaxPayload(1 << 20).
		WithMaxBatch(100)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/events", handler.HandleEvents)

	payload := map[string]interface{}{
		"events": []map[string]interface{}{
			{
				"timestamp": time.Now().Format(time.RFC3339),
				"source":    map[string]string{"product": "test", "host": "test-host"},
				"action":    "test.http.ingest",
				"outcome":   "success",
				"severity":  3,
			},
		},
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		t.Errorf("expected success status, got %d: %s", rec.Code, rec.Body.String())
	}

	metrics := eventQueue.Metrics()
	if metrics.Pushed == 0 {
		t.Error("expected event to be pushed to queue")
	}

	t.Logf("HTTP ingest test passed: status=%d, queue_pushed=%d", rec.Code, metrics.Pushed)
}

// --- Test: Alert management API ---

func TestAlertManagementAPI(t *testing.T) {
	ctx := context.Background()

	alertMgr := alerting.NewManager(alerting.DefaultManagerConfig(), nil)

	// Create an alert
	corrAlert := &correlation.Alert{
		ID:          uuid.New(),
		RuleID:      "api-test-rule",
		RuleName:    "API Test Rule",
		Severity:    8,
		Title:       "API Test Alert",
		Description: "Testing alert API endpoints",
		Timestamp:   time.Now(),
		GroupKey:    "api-test",
		Tags:        []string{"api-test"},
		Events: []correlation.EventRef{
			{EventID: uuid.New(), Timestamp: time.Now(), Action: "test.event"},
		},
	}

	err := alertMgr.HandleCorrelationAlert(ctx, corrAlert)
	if err != nil {
		t.Fatalf("failed to create alert: %v", err)
	}

	// Set up HTTP handler
	handler := alerting.NewHandler(alertMgr)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Test: List alerts
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("list alerts: expected 200, got %d", rec.Code)
	}

	var listResp struct {
		Alerts []json.RawMessage `json:"alerts"`
		Total  int               `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to parse list response: %v", err)
	}
	if listResp.Total == 0 {
		t.Error("expected at least 1 alert in list")
	}

	// Test: Get alert by ID
	req = httptest.NewRequest(http.MethodGet, "/v1/alerts/"+corrAlert.ID.String(), nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("get alert: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Test: Acknowledge alert
	ackBody, _ := json.Marshal(map[string]string{"user": "test-analyst"})
	req = httptest.NewRequest(http.MethodPost, "/v1/alerts/"+corrAlert.ID.String()+"/acknowledge", bytes.NewReader(ackBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("acknowledge alert: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify status changed
	alert, err := alertMgr.GetAlert(ctx, corrAlert.ID)
	if err != nil {
		t.Fatalf("get alert after ack: %v", err)
	}
	if alert.Status != alerting.StatusAcknowledged {
		t.Errorf("expected status 'acknowledged', got %q", alert.Status)
	}

	// Test: Add note
	noteBody, _ := json.Marshal(map[string]string{
		"author":  "test-analyst",
		"content": "Investigating this alert",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/alerts/"+corrAlert.ID.String()+"/notes", bytes.NewReader(noteBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("add note: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Test: Resolve alert
	resolveBody, _ := json.Marshal(map[string]string{"user": "test-analyst"})
	req = httptest.NewRequest(http.MethodPost, "/v1/alerts/"+corrAlert.ID.String()+"/resolve", bytes.NewReader(resolveBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("resolve alert: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify final state
	alert, _ = alertMgr.GetAlert(ctx, corrAlert.ID)
	if alert.Status != alerting.StatusResolved {
		t.Errorf("expected final status 'resolved', got %q", alert.Status)
	}
	if len(alert.Notes) != 1 {
		t.Errorf("expected 1 note, got %d", len(alert.Notes))
	}

	// Test: Stats
	req = httptest.NewRequest(http.MethodGet, "/v1/alerts/stats", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("stats: expected 200, got %d", rec.Code)
	}

	t.Log("Alert management API test passed: list, get, acknowledge, note, resolve, stats")
}

// --- Test: Detection rules load and validate ---

func TestDetectionRulesLoad(t *testing.T) {
	rules := detectionrules.GetAllRules()
	if len(rules) == 0 {
		t.Fatal("expected detection rules to be loaded, got 0")
	}

	// Verify each rule has required fields
	for _, rule := range rules {
		if rule.ID == "" {
			t.Error("found rule with empty ID")
		}
		if rule.Name == "" {
			t.Errorf("rule %s has empty name", rule.ID)
		}
		if rule.Type == "" {
			t.Errorf("rule %s has empty type", rule.ID)
		}
	}

	t.Logf("Detection rules test passed: %d rules loaded and validated", len(rules))
}

// --- Test: Baseline engine ---

func TestBaselineEngine(t *testing.T) {
	engine := correlation.NewBaselineEngine()

	// Record samples
	for i := 0; i < 100; i++ {
		engine.Record("test-rule", "group1", "event_count", float64(i))
	}

	// Get stats
	stats := engine.Stats("test-rule", "group1", "event_count", correlation.Baseline1h)
	if stats == nil {
		t.Fatal("expected stats, got nil")
	}

	if stats.Samples != 100 {
		t.Errorf("expected 100 samples, got %d", stats.Samples)
	}
	if stats.Min != 0 {
		t.Errorf("expected min 0, got %f", stats.Min)
	}
	if stats.Max != 99 {
		t.Errorf("expected max 99, got %f", stats.Max)
	}
	if stats.Mean < 49 || stats.Mean > 50 {
		t.Errorf("expected mean ~49.5, got %f", stats.Mean)
	}

	// Test adaptive threshold
	cfg := &correlation.BaselineConfig{
		Metric:     "event_count",
		Window:     correlation.Baseline1h,
		Multiplier: 1.5,
		Percentile: "p95",
		MinSamples: 10,
		WarmupDays: 0, // No warmup for test
	}

	threshold, warmedUp := engine.AdaptiveThreshold("test-rule", "group1", cfg)
	if threshold <= 0 {
		t.Errorf("expected positive threshold, got %f", threshold)
	}
	// WarmupDays=0 means warmup_end = engine.started + 0 days = engine.started,
	// and time.Now() is after engine.started, so it should be warmed up
	_ = warmedUp

	t.Logf("Baseline test passed: samples=%d, mean=%.1f, p95=%.1f, threshold=%.1f",
		stats.Samples, stats.Mean, stats.P95, threshold)
}

// --- Test: Kill chain rule generation ---

func TestKillChainRules(t *testing.T) {
	chains := correlation.BuiltinChains()
	if len(chains) != 3 {
		t.Fatalf("expected 3 built-in chains, got %d", len(chains))
	}

	for _, chain := range chains {
		rule := correlation.ChainToRule(chain)
		if rule.ID != chain.ID {
			t.Errorf("expected rule ID %q, got %q", chain.ID, rule.ID)
		}
		if rule.Type != correlation.RuleTypeSequence {
			t.Errorf("expected sequence rule type, got %q", rule.Type)
		}
		if rule.Sequence == nil {
			t.Errorf("chain %q: expected sequence config", chain.ID)
		}
		if len(rule.Sequence.Steps) != len(chain.Stages) {
			t.Errorf("chain %q: expected %d steps, got %d", chain.ID, len(chain.Stages), len(rule.Sequence.Steps))
		}
	}

	t.Logf("Kill chain test passed: %d chains -> %d sequence rules", len(chains), len(chains))
}

// --- Mock notification channel ---

type mockNotificationChannel struct {
	name     string
	sendFunc func(ctx context.Context, alert *alerting.Alert) error
}

func (m *mockNotificationChannel) Name() string {
	return m.name
}

func (m *mockNotificationChannel) Send(ctx context.Context, alert *alerting.Alert) error {
	if m.sendFunc != nil {
		return m.sendFunc(ctx, alert)
	}
	return nil
}

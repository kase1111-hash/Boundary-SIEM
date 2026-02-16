package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"boundary-siem/internal/correlation"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mockChannel is a test double that records every alert it receives.
type mockChannel struct {
	name       string
	sendFunc   func(ctx context.Context, alert *Alert) error
	sentAlerts []*Alert
	mu         sync.Mutex
}

func newMockChannel(name string) *mockChannel {
	return &mockChannel{name: name}
}

func (m *mockChannel) Name() string {
	return m.name
}

func (m *mockChannel) Send(ctx context.Context, alert *Alert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentAlerts = append(m.sentAlerts, alert)
	if m.sendFunc != nil {
		return m.sendFunc(ctx, alert)
	}
	return nil
}

func (m *mockChannel) getSentAlerts() []*Alert {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Alert, len(m.sentAlerts))
	copy(out, m.sentAlerts)
	return out
}

// makeCorrelationAlert builds a minimal correlation.Alert for testing.
func makeCorrelationAlert(ruleID, groupKey, title string, severity int) *correlation.Alert {
	return &correlation.Alert{
		ID:          uuid.New(),
		RuleID:      ruleID,
		RuleName:    "Test Rule: " + ruleID,
		Severity:    severity,
		Title:       title,
		Description: "Test description for " + title,
		Timestamp:   time.Now(),
		GroupKey:    groupKey,
		Events: []correlation.EventRef{
			{EventID: uuid.New(), Timestamp: time.Now(), Action: "test-action"},
		},
		Tags: []string{"test"},
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}

// ---------------------------------------------------------------------------
// 1. Alert creation and validation
// ---------------------------------------------------------------------------

func TestAlertCreation(t *testing.T) {
	id := uuid.New()
	now := time.Now()

	alert := &Alert{
		ID:          id,
		RuleID:      "rule-001",
		RuleName:    "Brute Force Detection",
		Severity:    correlation.SeverityHigh,
		Status:      StatusNew,
		Title:       "Multiple Failed Logins",
		Description: "Detected 50 failed login attempts",
		CreatedAt:   now,
		UpdatedAt:   now,
		GroupKey:    "src_ip:10.0.0.1",
		EventCount:  50,
		Tags:        []string{"brute-force", "authentication"},
		MITRE: &correlation.MITREMapping{
			TacticID:    "TA0006",
			TacticName:  "Credential Access",
			TechniqueID: "T1110",
		},
		Metadata: map[string]interface{}{
			"source_ip": "10.0.0.1",
		},
	}

	if alert.ID != id {
		t.Errorf("expected ID %s, got %s", id, alert.ID)
	}
	if alert.RuleID != "rule-001" {
		t.Errorf("expected RuleID 'rule-001', got %s", alert.RuleID)
	}
	if alert.Severity != correlation.SeverityHigh {
		t.Errorf("expected Severity high, got %s", alert.Severity)
	}
	if alert.Status != StatusNew {
		t.Errorf("expected Status 'new', got %s", alert.Status)
	}
	if alert.EventCount != 50 {
		t.Errorf("expected EventCount 50, got %d", alert.EventCount)
	}
	if len(alert.Tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(alert.Tags))
	}
	if alert.MITRE == nil {
		t.Fatal("expected MITRE mapping to be set")
	}
	if alert.MITRE.TechniqueID != "T1110" {
		t.Errorf("expected MITRE technique T1110, got %s", alert.MITRE.TechniqueID)
	}
	if alert.Metadata["source_ip"] != "10.0.0.1" {
		t.Errorf("expected metadata source_ip '10.0.0.1', got %v", alert.Metadata["source_ip"])
	}
}

func TestAlertJSONRoundTrip(t *testing.T) {
	id := uuid.New()
	now := time.Now().Truncate(time.Second) // truncate for JSON round-trip

	alert := &Alert{
		ID:          id,
		RuleID:      "rule-002",
		RuleName:    "SQL Injection",
		Severity:    correlation.SeverityCritical,
		Status:      StatusNew,
		Title:       "SQL Injection Detected",
		Description: "SQL injection attempt on /api/users",
		CreatedAt:   now,
		UpdatedAt:   now,
		EventCount:  1,
		Tags:        []string{"sqli", "web"},
	}

	data, err := json.Marshal(alert)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded Alert
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.ID != id {
		t.Errorf("ID mismatch: got %s, want %s", decoded.ID, id)
	}
	if decoded.RuleID != "rule-002" {
		t.Errorf("RuleID mismatch: got %s, want rule-002", decoded.RuleID)
	}
	if decoded.Severity != correlation.SeverityCritical {
		t.Errorf("Severity mismatch: got %s, want critical", decoded.Severity)
	}
	if decoded.Status != StatusNew {
		t.Errorf("Status mismatch: got %s, want new", decoded.Status)
	}
	if decoded.Title != "SQL Injection Detected" {
		t.Errorf("Title mismatch: got %s", decoded.Title)
	}
	if len(decoded.Tags) != 2 {
		t.Errorf("Tags count mismatch: got %d, want 2", len(decoded.Tags))
	}
}

func TestAlertStatusConstants(t *testing.T) {
	expected := map[AlertStatus]string{
		StatusNew:          "new",
		StatusAcknowledged: "acknowledged",
		StatusInProgress:   "in_progress",
		StatusResolved:     "resolved",
		StatusSuppressed:   "suppressed",
	}

	for status, want := range expected {
		if string(status) != want {
			t.Errorf("status constant %q should be %q", status, want)
		}
	}
}

func TestAlertOptionalFieldsOmitEmpty(t *testing.T) {
	alert := &Alert{
		ID:        uuid.New(),
		RuleID:    "rule-003",
		Severity:  correlation.SeverityLow,
		Status:    StatusNew,
		Title:     "Minimal Alert",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	data, err := json.Marshal(alert)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	raw := string(data)
	// Fields tagged omitempty should not appear when zero-valued.
	if strings.Contains(raw, "acked_at") {
		t.Error("acked_at should be omitted when nil")
	}
	if strings.Contains(raw, "resolved_at") {
		t.Error("resolved_at should be omitted when nil")
	}
	if strings.Contains(raw, `"mitre"`) {
		t.Error("mitre should be omitted when nil")
	}
}

// ---------------------------------------------------------------------------
// 2. Alert manager -- adding / removing channels
// ---------------------------------------------------------------------------

func TestNewManager(t *testing.T) {
	config := DefaultManagerConfig()
	mgr := NewManager(config, nil)

	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	stats := mgr.Stats()
	if stats["total"].(int) != 0 {
		t.Errorf("expected 0 alerts, got %d", stats["total"])
	}
	if stats["channels"].(int) != 0 {
		t.Errorf("expected 0 channels, got %d", stats["channels"])
	}
}

func TestManagerAddChannel(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)

	ch1 := newMockChannel("channel-1")
	ch2 := newMockChannel("channel-2")

	mgr.AddChannel(ch1)
	if n := mgr.Stats()["channels"].(int); n != 1 {
		t.Errorf("expected 1 channel after first add, got %d", n)
	}

	mgr.AddChannel(ch2)
	if n := mgr.Stats()["channels"].(int); n != 2 {
		t.Errorf("expected 2 channels after second add, got %d", n)
	}
}

func TestManagerAddMultipleChannelTypes(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)

	mgr.AddChannel(newMockChannel("webhook"))
	mgr.AddChannel(newMockChannel("slack"))
	mgr.AddChannel(newMockChannel("pagerduty"))

	if n := mgr.Stats()["channels"].(int); n != 3 {
		t.Errorf("expected 3 channels, got %d", n)
	}
}

func TestManagerSendNotificationsToMultipleChannels(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)

	ch1 := newMockChannel("channel-1")
	ch2 := newMockChannel("channel-2")
	ch3 := newMockChannel("channel-3")

	mgr.AddChannel(ch1)
	mgr.AddChannel(ch2)
	mgr.AddChannel(ch3)

	ctx := context.Background()
	corrAlert := makeCorrelationAlert("multi-ch-rule", "multi-ch-group", "Multi Channel Test", 3)
	_ = mgr.HandleCorrelationAlert(ctx, corrAlert)

	// sendNotifications dispatches in goroutines; wait briefly.
	time.Sleep(100 * time.Millisecond)

	for _, ch := range []*mockChannel{ch1, ch2, ch3} {
		if n := len(ch.getSentAlerts()); n != 1 {
			t.Errorf("%s: expected 1 alert, got %d", ch.Name(), n)
		}
	}
}

func TestManagerNotificationChannelErrorDoesNotBlock(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)

	failCh := &mockChannel{
		name: "fail-channel",
		sendFunc: func(_ context.Context, _ *Alert) error {
			return fmt.Errorf("send failed")
		},
	}
	successCh := newMockChannel("success-channel")

	mgr.AddChannel(failCh)
	mgr.AddChannel(successCh)

	ctx := context.Background()
	corrAlert := makeCorrelationAlert("err-rule", "err-group", "Error Test", 2)
	err := mgr.HandleCorrelationAlert(ctx, corrAlert)

	// HandleCorrelationAlert should not surface notification errors.
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if n := len(successCh.getSentAlerts()); n != 1 {
		t.Errorf("success channel expected 1 alert, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// 3. Alert deduplication logic
// ---------------------------------------------------------------------------

func TestDeduplicationSuppressesDuplicate(t *testing.T) {
	config := ManagerConfig{
		DeduplicationWindow: 1 * time.Minute,
		RetentionPeriod:     24 * time.Hour,
		MaxAlerts:           1000,
	}
	mgr := NewManager(config, nil)
	ch := newMockChannel("test")
	mgr.AddChannel(ch)

	ctx := context.Background()

	// First alert should be delivered.
	alert1 := makeCorrelationAlert("rule-1", "group-a", "First Alert", 3)
	if err := mgr.HandleCorrelationAlert(ctx, alert1); err != nil {
		t.Fatalf("first alert failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Second alert with same rule+group within window should be suppressed.
	alert2 := makeCorrelationAlert("rule-1", "group-a", "Duplicate Alert", 3)
	if err := mgr.HandleCorrelationAlert(ctx, alert2); err != nil {
		t.Fatalf("second alert failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	if n := len(ch.getSentAlerts()); n != 1 {
		t.Errorf("expected 1 notification (duplicate suppressed), got %d", n)
	}
}

func TestDeduplicationDifferentRulesNotSuppressed(t *testing.T) {
	config := ManagerConfig{
		DeduplicationWindow: 1 * time.Minute,
		RetentionPeriod:     24 * time.Hour,
		MaxAlerts:           1000,
	}
	mgr := NewManager(config, nil)
	ch := newMockChannel("test")
	mgr.AddChannel(ch)

	ctx := context.Background()

	a1 := makeCorrelationAlert("rule-1", "group-a", "Alert from rule 1", 3)
	a2 := makeCorrelationAlert("rule-2", "group-a", "Alert from rule 2", 3)

	_ = mgr.HandleCorrelationAlert(ctx, a1)
	_ = mgr.HandleCorrelationAlert(ctx, a2)

	time.Sleep(50 * time.Millisecond)

	if n := len(ch.getSentAlerts()); n != 2 {
		t.Errorf("expected 2 notifications (different rules), got %d", n)
	}
}

func TestDeduplicationDifferentGroupsNotSuppressed(t *testing.T) {
	config := ManagerConfig{
		DeduplicationWindow: 1 * time.Minute,
		RetentionPeriod:     24 * time.Hour,
		MaxAlerts:           1000,
	}
	mgr := NewManager(config, nil)
	ch := newMockChannel("test")
	mgr.AddChannel(ch)

	ctx := context.Background()

	a1 := makeCorrelationAlert("rule-1", "group-a", "Alert group A", 3)
	a2 := makeCorrelationAlert("rule-1", "group-b", "Alert group B", 3)

	_ = mgr.HandleCorrelationAlert(ctx, a1)
	_ = mgr.HandleCorrelationAlert(ctx, a2)

	time.Sleep(50 * time.Millisecond)

	if n := len(ch.getSentAlerts()); n != 2 {
		t.Errorf("expected 2 notifications (different groups), got %d", n)
	}
}

func TestDeduplicationWindowExpiry(t *testing.T) {
	config := ManagerConfig{
		DeduplicationWindow: 50 * time.Millisecond,
		RetentionPeriod:     24 * time.Hour,
		MaxAlerts:           1000,
	}
	mgr := NewManager(config, nil)
	ch := newMockChannel("test")
	mgr.AddChannel(ch)

	ctx := context.Background()

	a1 := makeCorrelationAlert("rule-1", "group-a", "First", 3)
	_ = mgr.HandleCorrelationAlert(ctx, a1)

	// Wait for the dedup window to expire.
	time.Sleep(100 * time.Millisecond)

	a2 := makeCorrelationAlert("rule-1", "group-a", "After Window", 3)
	_ = mgr.HandleCorrelationAlert(ctx, a2)

	time.Sleep(50 * time.Millisecond)

	if n := len(ch.getSentAlerts()); n != 2 {
		t.Errorf("expected 2 notifications (window expired), got %d", n)
	}
}

func TestDeduplicationKeyFormat(t *testing.T) {
	// Verify that dedup key is "ruleID:groupKey" by sending alerts with
	// deliberately overlapping substrings that should NOT collide.
	config := ManagerConfig{
		DeduplicationWindow: 1 * time.Minute,
		RetentionPeriod:     24 * time.Hour,
		MaxAlerts:           1000,
	}
	mgr := NewManager(config, nil)
	ch := newMockChannel("test")
	mgr.AddChannel(ch)

	ctx := context.Background()

	// rule "a:b" + group "c"  =>  key "a:b:c"
	// rule "a"   + group "b:c" => key "a:b:c"
	// These generate the same dedup key, so the second should be suppressed.
	a1 := makeCorrelationAlert("a:b", "c", "Alert 1", 2)
	a2 := makeCorrelationAlert("a", "b:c", "Alert 2", 2)

	_ = mgr.HandleCorrelationAlert(ctx, a1)
	_ = mgr.HandleCorrelationAlert(ctx, a2)

	time.Sleep(50 * time.Millisecond)

	// Both produce dedup key "a:b:c" and "a:b:c" -- second is suppressed.
	sent := ch.getSentAlerts()
	if len(sent) != 1 {
		t.Errorf("expected 1 notification (same dedup key), got %d", len(sent))
	}
}

// ---------------------------------------------------------------------------
// 4. Rate limiting of alerts
// ---------------------------------------------------------------------------
// The deduplication window acts as the rate-limiting mechanism.

func TestRateLimitingBurstWithinWindow(t *testing.T) {
	config := ManagerConfig{
		DeduplicationWindow: 200 * time.Millisecond,
		RetentionPeriod:     24 * time.Hour,
		MaxAlerts:           1000,
	}
	mgr := NewManager(config, nil)
	ch := newMockChannel("test")
	mgr.AddChannel(ch)

	ctx := context.Background()

	// Fire 5 identical alerts in rapid succession.
	for i := 0; i < 5; i++ {
		a := makeCorrelationAlert("rule-flood", "group-x", fmt.Sprintf("Flood %d", i), 2)
		_ = mgr.HandleCorrelationAlert(ctx, a)
	}

	time.Sleep(50 * time.Millisecond)

	if n := len(ch.getSentAlerts()); n != 1 {
		t.Errorf("expected 1 notification (rate limited), got %d", n)
	}
}

func TestRateLimitingMultipleBursts(t *testing.T) {
	config := ManagerConfig{
		DeduplicationWindow: 50 * time.Millisecond,
		RetentionPeriod:     24 * time.Hour,
		MaxAlerts:           1000,
	}
	mgr := NewManager(config, nil)
	ch := newMockChannel("test")
	mgr.AddChannel(ch)

	ctx := context.Background()

	// First burst.
	for i := 0; i < 3; i++ {
		a := makeCorrelationAlert("rule-burst", "group-y", fmt.Sprintf("Burst1-%d", i), 2)
		_ = mgr.HandleCorrelationAlert(ctx, a)
	}

	// Wait for window to expire.
	time.Sleep(100 * time.Millisecond)

	// Second burst.
	for i := 0; i < 3; i++ {
		a := makeCorrelationAlert("rule-burst", "group-y", fmt.Sprintf("Burst2-%d", i), 2)
		_ = mgr.HandleCorrelationAlert(ctx, a)
	}

	time.Sleep(50 * time.Millisecond)

	if n := len(ch.getSentAlerts()); n != 2 {
		t.Errorf("expected 2 notifications (one per burst), got %d", n)
	}
}

func TestRateLimitingConcurrentSenders(t *testing.T) {
	config := ManagerConfig{
		DeduplicationWindow: 1 * time.Second,
		RetentionPeriod:     24 * time.Hour,
		MaxAlerts:           1000,
	}
	mgr := NewManager(config, nil)

	var sendCount atomic.Int32
	ch := &mockChannel{
		name: "concurrent-test",
		sendFunc: func(_ context.Context, _ *Alert) error {
			sendCount.Add(1)
			return nil
		},
	}
	mgr.AddChannel(ch)

	ctx := context.Background()

	// 10 goroutines all fire the same rule+group simultaneously.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := makeCorrelationAlert("rule-concurrent", "group-z", fmt.Sprintf("Concurrent %d", i), 3)
			_ = mgr.HandleCorrelationAlert(ctx, a)
		}(i)
	}
	wg.Wait()

	time.Sleep(100 * time.Millisecond)

	if c := sendCount.Load(); c != 1 {
		t.Errorf("expected exactly 1 notification from concurrent sends, got %d", c)
	}
}

// ---------------------------------------------------------------------------
// 5. Channel configuration validation
// ---------------------------------------------------------------------------

func TestDefaultManagerConfig(t *testing.T) {
	config := DefaultManagerConfig()

	if config.DeduplicationWindow != 15*time.Minute {
		t.Errorf("expected 15m dedup window, got %v", config.DeduplicationWindow)
	}
	if config.RetentionPeriod != 30*24*time.Hour {
		t.Errorf("expected 30-day retention, got %v", config.RetentionPeriod)
	}
	if config.MaxAlerts != 100000 {
		t.Errorf("expected 100000 max alerts, got %d", config.MaxAlerts)
	}
}

func TestEmailConfigPortDefaults(t *testing.T) {
	// TLS => port 465.
	ch := NewEmailChannel(&EmailConfig{UseTLS: true})
	if ch.config.SMTPPort != 465 {
		t.Errorf("expected port 465 with TLS, got %d", ch.config.SMTPPort)
	}

	// Non-TLS => port 587.
	ch2 := NewEmailChannel(&EmailConfig{UseTLS: false})
	if ch2.config.SMTPPort != 587 {
		t.Errorf("expected port 587 without TLS, got %d", ch2.config.SMTPPort)
	}

	// Custom port should be preserved.
	ch3 := NewEmailChannel(&EmailConfig{SMTPPort: 2525})
	if ch3.config.SMTPPort != 2525 {
		t.Errorf("expected port 2525, got %d", ch3.config.SMTPPort)
	}
}

func TestSlackChannelConfig(t *testing.T) {
	ch := NewSlackChannel("https://hooks.slack.com/test", "#alerts", "SIEMBot")
	if ch.Name() != "slack" {
		t.Errorf("expected name 'slack', got %s", ch.Name())
	}
	if ch.channel != "#alerts" {
		t.Errorf("expected channel '#alerts', got %s", ch.channel)
	}
	if ch.username != "SIEMBot" {
		t.Errorf("expected username 'SIEMBot', got %s", ch.username)
	}
	if ch.client == nil {
		t.Error("expected non-nil http client")
	}
}

func TestDiscordChannelConfig(t *testing.T) {
	ch := NewDiscordChannel("https://discord.com/api/webhooks/test", "SIEMBot")
	if ch.Name() != "discord" {
		t.Errorf("expected name 'discord', got %s", ch.Name())
	}
	if ch.username != "SIEMBot" {
		t.Errorf("expected username 'SIEMBot', got %s", ch.username)
	}
	if ch.client == nil {
		t.Error("expected non-nil http client")
	}
}

func TestPagerDutyChannelConfig(t *testing.T) {
	ch := NewPagerDutyChannel("test-routing-key")
	if ch.Name() != "pagerduty" {
		t.Errorf("expected name 'pagerduty', got %s", ch.Name())
	}
	if ch.routingKey != "test-routing-key" {
		t.Errorf("expected routing key 'test-routing-key', got %s", ch.routingKey)
	}
	if ch.client == nil {
		t.Error("expected non-nil http client")
	}
}

func TestTelegramChannelConfig(t *testing.T) {
	ch := NewTelegramChannel("bot-token-123", "chat-456")
	if ch.Name() != "telegram" {
		t.Errorf("expected name 'telegram', got %s", ch.Name())
	}
	if ch.botToken != "bot-token-123" {
		t.Errorf("expected botToken 'bot-token-123', got %s", ch.botToken)
	}
	if ch.chatID != "chat-456" {
		t.Errorf("expected chatID 'chat-456', got %s", ch.chatID)
	}
	if ch.client == nil {
		t.Error("expected non-nil http client")
	}
}

func TestWebhookChannelConfig(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer test-token",
		"X-Source":       "boundary-siem",
	}
	ch, err := NewWebhookChannel("my-webhook", "https://example.com/hook", headers)
	if err != nil {
		t.Fatalf("NewWebhookChannel failed: %v", err)
	}
	if ch.Name() != "my-webhook" {
		t.Errorf("expected name 'my-webhook', got %s", ch.Name())
	}
	if ch.url != "https://example.com/hook" {
		t.Errorf("expected url, got %s", ch.url)
	}
	if len(ch.headers) != 2 {
		t.Errorf("expected 2 headers, got %d", len(ch.headers))
	}
	if ch.client == nil {
		t.Error("expected non-nil http client")
	}
}

func TestLogChannelConfig(t *testing.T) {
	var called bool
	logger := func(format string, args ...interface{}) {
		called = true
	}
	ch := NewLogChannel(logger)
	if ch.Name() != "log" {
		t.Errorf("expected name 'log', got %s", ch.Name())
	}

	alert := &Alert{
		ID:          uuid.New(),
		RuleID:      "test-rule",
		Title:       "Test",
		Description: "Test",
		Severity:    correlation.SeverityLow,
		EventCount:  1,
		Tags:        []string{"test"},
		CreatedAt:   time.Now(),
	}
	_ = ch.Send(context.Background(), alert)
	if !called {
		t.Error("expected logger to be called")
	}
}

// ---------------------------------------------------------------------------
// Webhook channel -- httptest-based integration
// ---------------------------------------------------------------------------

func TestWebhookChannelSendSuccess(t *testing.T) {
	var receivedBody []byte
	var receivedHeaders http.Header

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		receivedBody = buf
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ch := NewWebhookChannelForTest("test-hook", server.URL, map[string]string{
		"X-Custom-Header": "custom-value",
		"Authorization":   "Bearer test-token",
	})

	alert := &Alert{
		ID:          uuid.New(),
		RuleID:      "webhook-test-rule",
		Title:       "Webhook Test Alert",
		Description: "Testing webhook delivery",
		Severity:    correlation.SeverityHigh,
		Status:      StatusNew,
		EventCount:  3,
		Tags:        []string{"test"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := ch.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	if receivedHeaders.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", receivedHeaders.Get("Content-Type"))
	}
	if receivedHeaders.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("expected X-Custom-Header 'custom-value', got %s", receivedHeaders.Get("X-Custom-Header"))
	}
	if receivedHeaders.Get("Authorization") != "Bearer test-token" {
		t.Errorf("expected Authorization header, got %s", receivedHeaders.Get("Authorization"))
	}

	var decoded Alert
	if err := json.Unmarshal(receivedBody, &decoded); err != nil {
		t.Fatalf("received body is not valid JSON: %v", err)
	}
	if decoded.Title != "Webhook Test Alert" {
		t.Errorf("expected title 'Webhook Test Alert', got %s", decoded.Title)
	}
}

func TestWebhookChannelNon2xxResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer server.Close()

	ch := NewWebhookChannelForTest("fail-hook", server.URL, nil)
	alert := &Alert{
		ID:        uuid.New(),
		RuleID:    "test",
		Title:     "Test",
		Severity:  correlation.SeverityLow,
		CreatedAt: time.Now(),
	}

	err := ch.Send(context.Background(), alert)
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code 500: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Slack channel -- httptest-based integration
// ---------------------------------------------------------------------------

func TestSlackChannelSendSuccess(t *testing.T) {
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ch := NewSlackChannel(server.URL, "#security-alerts", "BoundarySIEM")
	alert := &Alert{
		ID:          uuid.New(),
		RuleID:      "slack-test-rule",
		Title:       "Slack Test Alert",
		Description: "Testing Slack delivery",
		Severity:    correlation.SeverityCritical,
		Status:      StatusNew,
		EventCount:  7,
		Tags:        []string{"critical", "exfiltration"},
		GroupKey:    "src:10.0.0.5",
		CreatedAt:   time.Now(),
		MITRE: &correlation.MITREMapping{
			TacticID:    "TA0010",
			TacticName:  "Exfiltration",
			TechniqueID: "T1048",
		},
	}

	if err := ch.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	if receivedPayload["channel"] != "#security-alerts" {
		t.Errorf("expected channel '#security-alerts', got %v", receivedPayload["channel"])
	}
	if receivedPayload["username"] != "BoundarySIEM" {
		t.Errorf("expected username 'BoundarySIEM', got %v", receivedPayload["username"])
	}

	attachments, ok := receivedPayload["attachments"].([]interface{})
	if !ok || len(attachments) == 0 {
		t.Fatal("expected at least one attachment")
	}
	att := attachments[0].(map[string]interface{})
	if att["color"] != "#FF0000" {
		t.Errorf("expected critical color #FF0000, got %v", att["color"])
	}
}

func TestSlackChannelNon200Response(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("invalid_token"))
	}))
	defer server.Close()

	ch := NewSlackChannel(server.URL, "#test", "bot")
	alert := &Alert{
		ID:        uuid.New(),
		RuleID:    "test",
		Title:     "Test",
		Severity:  correlation.SeverityLow,
		CreatedAt: time.Now(),
	}

	err := ch.Send(context.Background(), alert)
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status code 403: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Discord channel -- httptest-based integration
// ---------------------------------------------------------------------------

func TestDiscordChannelSendSuccess(t *testing.T) {
	var receivedPayload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ch := NewDiscordChannel(server.URL, "BoundarySIEM")
	alert := &Alert{
		ID:          uuid.New(),
		RuleID:      "discord-test-rule",
		Title:       "Discord Test Alert",
		Description: "Testing Discord delivery",
		Severity:    correlation.SeverityMedium,
		Status:      StatusNew,
		EventCount:  2,
		Tags:        []string{"medium", "recon"},
		CreatedAt:   time.Now(),
	}

	if err := ch.Send(context.Background(), alert); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	if receivedPayload["username"] != "BoundarySIEM" {
		t.Errorf("expected username 'BoundarySIEM', got %v", receivedPayload["username"])
	}

	embeds, ok := receivedPayload["embeds"].([]interface{})
	if !ok || len(embeds) == 0 {
		t.Fatal("expected at least one embed")
	}
	embed := embeds[0].(map[string]interface{})
	if _, ok := embed["color"]; !ok {
		t.Error("expected color in embed")
	}
}

func TestDiscordChannelNon2xxResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer server.Close()

	ch := NewDiscordChannel(server.URL, "bot")
	alert := &Alert{
		ID:        uuid.New(),
		RuleID:    "test",
		Title:     "Test",
		Severity:  correlation.SeverityLow,
		CreatedAt: time.Now(),
	}

	err := ch.Send(context.Background(), alert)
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should mention status code 400: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Severity mappings for each channel type
// ---------------------------------------------------------------------------

func TestSlackSeverityColors(t *testing.T) {
	ch := NewSlackChannel("http://fake", "#test", "bot")
	tests := []struct {
		severity correlation.Severity
		want     string
	}{
		{correlation.SeverityCritical, "#FF0000"},
		{correlation.SeverityHigh, "#FFA500"},
		{correlation.SeverityMedium, "#FFFF00"},
		{correlation.SeverityLow, "#00FF00"},
		{correlation.Severity("unknown"), "#808080"},
	}
	for _, tt := range tests {
		if got := ch.severityColor(tt.severity); got != tt.want {
			t.Errorf("Slack severityColor(%s) = %s, want %s", tt.severity, got, tt.want)
		}
	}
}

func TestDiscordSeverityColors(t *testing.T) {
	ch := NewDiscordChannel("http://fake", "bot")
	tests := []struct {
		severity correlation.Severity
		want     int
	}{
		{correlation.SeverityCritical, 0xFF0000},
		{correlation.SeverityHigh, 0xFFA500},
		{correlation.SeverityMedium, 0xFFFF00},
		{correlation.SeverityLow, 0x00FF00},
		{correlation.Severity("unknown"), 0x808080},
	}
	for _, tt := range tests {
		if got := ch.severityColor(tt.severity); got != tt.want {
			t.Errorf("Discord severityColor(%s) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

func TestPagerDutySeverityMapping(t *testing.T) {
	ch := NewPagerDutyChannel("test-key")
	tests := []struct {
		severity correlation.Severity
		want     string
	}{
		{correlation.SeverityCritical, "critical"},
		{correlation.SeverityHigh, "error"},
		{correlation.SeverityMedium, "warning"},
		{correlation.SeverityLow, "info"},
		{correlation.Severity("unknown"), "info"},
	}
	for _, tt := range tests {
		if got := ch.mapSeverity(tt.severity); got != tt.want {
			t.Errorf("PagerDuty mapSeverity(%s) = %s, want %s", tt.severity, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Slack / Discord buildFields
// ---------------------------------------------------------------------------

func TestSlackBuildFields(t *testing.T) {
	ch := NewSlackChannel("http://fake", "#test", "bot")
	alert := &Alert{
		Severity:   correlation.SeverityHigh,
		EventCount: 42,
		GroupKey:   "src:10.0.0.1",
		Tags:       []string{"lateral-movement", "internal"},
		MITRE: &correlation.MITREMapping{
			TacticID:    "TA0008",
			TacticName:  "Lateral Movement",
			TechniqueID: "T1021",
		},
	}
	fields := ch.buildFields(alert)
	// Expected: Severity, Events, Group, Tags, MITRE = 5
	if len(fields) != 5 {
		t.Errorf("expected 5 fields, got %d", len(fields))
	}
	if fields[0]["title"] != "Severity" {
		t.Errorf("first field should be Severity, got %v", fields[0]["title"])
	}
	if fields[1]["value"] != "42" {
		t.Errorf("events field value should be '42', got %v", fields[1]["value"])
	}
}

func TestSlackBuildFieldsMinimal(t *testing.T) {
	ch := NewSlackChannel("http://fake", "#test", "bot")
	alert := &Alert{
		Severity:   correlation.SeverityLow,
		EventCount: 1,
		// No GroupKey, Tags, or MITRE
	}
	fields := ch.buildFields(alert)
	// Expected: Severity, Events = 2
	if len(fields) != 2 {
		t.Errorf("expected 2 fields for minimal alert, got %d", len(fields))
	}
}

func TestDiscordBuildFields(t *testing.T) {
	ch := NewDiscordChannel("http://fake", "bot")
	alert := &Alert{
		Severity:   correlation.SeverityMedium,
		EventCount: 10,
		Tags:       []string{"recon", "scanning"},
	}
	fields := ch.buildFields(alert)
	// Expected: Severity, Events, Tags = 3
	if len(fields) != 3 {
		t.Errorf("expected 3 fields, got %d", len(fields))
	}
	if fields[0]["name"] != "Severity" {
		t.Errorf("first field name should be 'Severity', got %v", fields[0]["name"])
	}
}

func TestDiscordBuildFieldsMinimal(t *testing.T) {
	ch := NewDiscordChannel("http://fake", "bot")
	alert := &Alert{
		Severity:   correlation.SeverityLow,
		EventCount: 1,
	}
	fields := ch.buildFields(alert)
	// Expected: Severity, Events = 2 (no tags)
	if len(fields) != 2 {
		t.Errorf("expected 2 fields for minimal alert, got %d", len(fields))
	}
}

// ---------------------------------------------------------------------------
// escapeMarkdown
// ---------------------------------------------------------------------------

func TestEscapeMarkdown(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello_world", "hello\\_world"},
		{"*bold*", "\\*bold\\*"},
		{"no special chars", "no special chars"},
		{"combo_*test[1]", "combo\\_\\*test\\[1\\]"},
		{"a.b!", "a\\.b\\!"},
	}

	for _, tt := range tests {
		got := escapeMarkdown(tt.input)
		if got != tt.want {
			t.Errorf("escapeMarkdown(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Manager lifecycle -- store, get, ack, resolve, assign, note, list, cleanup
// ---------------------------------------------------------------------------

func TestManagerStoresAndRetrievesAlert(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	ctx := context.Background()

	corrAlert := makeCorrelationAlert("store-rule", "store-group", "Stored Alert", 3)
	if err := mgr.HandleCorrelationAlert(ctx, corrAlert); err != nil {
		t.Fatalf("HandleCorrelationAlert failed: %v", err)
	}

	alert, err := mgr.GetAlert(ctx, corrAlert.ID)
	if err != nil {
		t.Fatalf("GetAlert failed: %v", err)
	}
	if alert.Title != "Stored Alert" {
		t.Errorf("expected title 'Stored Alert', got %s", alert.Title)
	}
	if alert.Status != StatusNew {
		t.Errorf("expected status 'new', got %s", alert.Status)
	}
}

func TestManagerGetAlertNotFound(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	_, err := mgr.GetAlert(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error for non-existent alert")
	}
}

func TestManagerAcknowledgeAlert(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	ctx := context.Background()

	corrAlert := makeCorrelationAlert("ack-rule", "ack-group", "Ack Test", 2)
	_ = mgr.HandleCorrelationAlert(ctx, corrAlert)

	if err := mgr.AcknowledgeAlert(ctx, corrAlert.ID, "admin"); err != nil {
		t.Fatalf("AcknowledgeAlert failed: %v", err)
	}

	alert, _ := mgr.GetAlert(ctx, corrAlert.ID)
	if alert.Status != StatusAcknowledged {
		t.Errorf("expected status 'acknowledged', got %s", alert.Status)
	}
	if alert.AckedBy != "admin" {
		t.Errorf("expected acked_by 'admin', got %s", alert.AckedBy)
	}
	if alert.AckedAt == nil {
		t.Error("expected AckedAt to be set")
	}
}

func TestManagerAcknowledgeAlertNotFound(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	if err := mgr.AcknowledgeAlert(context.Background(), uuid.New(), "admin"); err == nil {
		t.Error("expected error for non-existent alert")
	}
}

func TestManagerResolveAlert(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	ctx := context.Background()

	corrAlert := makeCorrelationAlert("resolve-rule", "resolve-group", "Resolve Test", 1)
	_ = mgr.HandleCorrelationAlert(ctx, corrAlert)

	if err := mgr.ResolveAlert(ctx, corrAlert.ID, "analyst"); err != nil {
		t.Fatalf("ResolveAlert failed: %v", err)
	}

	alert, _ := mgr.GetAlert(ctx, corrAlert.ID)
	if alert.Status != StatusResolved {
		t.Errorf("expected status 'resolved', got %s", alert.Status)
	}
	if alert.ResolvedBy != "analyst" {
		t.Errorf("expected resolved_by 'analyst', got %s", alert.ResolvedBy)
	}
	if alert.ResolvedAt == nil {
		t.Error("expected ResolvedAt to be set")
	}
}

func TestManagerResolveAlertNotFound(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	if err := mgr.ResolveAlert(context.Background(), uuid.New(), "analyst"); err == nil {
		t.Error("expected error for non-existent alert")
	}
}

func TestManagerAddNote(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	ctx := context.Background()

	corrAlert := makeCorrelationAlert("note-rule", "note-group", "Note Test", 2)
	_ = mgr.HandleCorrelationAlert(ctx, corrAlert)

	if err := mgr.AddNote(ctx, corrAlert.ID, "analyst", "This is a false positive"); err != nil {
		t.Fatalf("AddNote failed: %v", err)
	}

	alert, _ := mgr.GetAlert(ctx, corrAlert.ID)
	if len(alert.Notes) != 1 {
		t.Fatalf("expected 1 note, got %d", len(alert.Notes))
	}
	if alert.Notes[0].Author != "analyst" {
		t.Errorf("expected note author 'analyst', got %s", alert.Notes[0].Author)
	}
	if alert.Notes[0].Content != "This is a false positive" {
		t.Errorf("unexpected note content: %s", alert.Notes[0].Content)
	}
}

func TestManagerAddNoteNotFound(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	if err := mgr.AddNote(context.Background(), uuid.New(), "analyst", "note"); err == nil {
		t.Error("expected error for non-existent alert")
	}
}

func TestManagerAssignAlert(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	ctx := context.Background()

	corrAlert := makeCorrelationAlert("assign-rule", "assign-group", "Assign Test", 3)
	_ = mgr.HandleCorrelationAlert(ctx, corrAlert)

	if err := mgr.AssignAlert(ctx, corrAlert.ID, "security-analyst"); err != nil {
		t.Fatalf("AssignAlert failed: %v", err)
	}

	alert, _ := mgr.GetAlert(ctx, corrAlert.ID)
	if alert.AssignedTo != "security-analyst" {
		t.Errorf("expected assigned_to 'security-analyst', got %s", alert.AssignedTo)
	}
	if alert.Status != StatusInProgress {
		t.Errorf("expected status 'in_progress', got %s", alert.Status)
	}
}

func TestManagerAssignAlertNotFound(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	if err := mgr.AssignAlert(context.Background(), uuid.New(), "analyst"); err == nil {
		t.Error("expected error for non-existent alert")
	}
}

func TestManagerListAlerts(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		a := makeCorrelationAlert(
			fmt.Sprintf("list-rule-%d", i),
			fmt.Sprintf("list-group-%d", i),
			fmt.Sprintf("List Alert %d", i),
			(i%4)+1,
		)
		_ = mgr.HandleCorrelationAlert(ctx, a)
	}

	// All alerts.
	all, err := mgr.ListAlerts(ctx, AlertFilter{})
	if err != nil {
		t.Fatalf("ListAlerts failed: %v", err)
	}
	if len(all) != 5 {
		t.Errorf("expected 5 alerts, got %d", len(all))
	}

	// Filter by status.
	statusNew := StatusNew
	newAlerts, _ := mgr.ListAlerts(ctx, AlertFilter{Status: &statusNew})
	if len(newAlerts) != 5 {
		t.Errorf("expected 5 new alerts, got %d", len(newAlerts))
	}

	// Filter by RuleID.
	ruleAlerts, _ := mgr.ListAlerts(ctx, AlertFilter{RuleID: "list-rule-0"})
	if len(ruleAlerts) != 1 {
		t.Errorf("expected 1 alert for list-rule-0, got %d", len(ruleAlerts))
	}

	// Pagination.
	paginated, _ := mgr.ListAlerts(ctx, AlertFilter{Limit: 2})
	if len(paginated) != 2 {
		t.Errorf("expected 2 alerts with limit, got %d", len(paginated))
	}

	// Offset beyond total.
	empty, _ := mgr.ListAlerts(ctx, AlertFilter{Offset: 100})
	if len(empty) != 0 {
		t.Errorf("expected 0 alerts with large offset, got %d", len(empty))
	}
}

func TestManagerListAlertsBySeverity(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	ctx := context.Background()

	// IntToSeverity mapping: <=2 Low, <=5 Medium, <=8 High, >8 Critical
	_ = mgr.HandleCorrelationAlert(ctx, makeCorrelationAlert("sev-1", "sev-1", "Critical", 10))
	_ = mgr.HandleCorrelationAlert(ctx, makeCorrelationAlert("sev-2", "sev-2", "High", 7))
	_ = mgr.HandleCorrelationAlert(ctx, makeCorrelationAlert("sev-3", "sev-3", "Low", 1))

	crit := correlation.SeverityCritical
	critAlerts, _ := mgr.ListAlerts(ctx, AlertFilter{Severity: &crit})
	if len(critAlerts) != 1 {
		t.Errorf("expected 1 critical alert, got %d", len(critAlerts))
	}
}

func TestManagerStats(t *testing.T) {
	mgr := NewManager(DefaultManagerConfig(), nil)
	ctx := context.Background()

	a1 := makeCorrelationAlert("stats-1", "stats-1", "Stats 1", 4)
	a2 := makeCorrelationAlert("stats-2", "stats-2", "Stats 2", 3)
	_ = mgr.HandleCorrelationAlert(ctx, a1)
	_ = mgr.HandleCorrelationAlert(ctx, a2)

	_ = mgr.ResolveAlert(ctx, a1.ID, "admin")

	stats := mgr.Stats()
	if stats["total"].(int) != 2 {
		t.Errorf("expected total 2, got %v", stats["total"])
	}
	statusCounts := stats["by_status"].(map[string]int)
	if statusCounts["new"] != 1 {
		t.Errorf("expected 1 new, got %d", statusCounts["new"])
	}
	if statusCounts["resolved"] != 1 {
		t.Errorf("expected 1 resolved, got %d", statusCounts["resolved"])
	}
}

func TestManagerCleanupRemovesOldResolvedAlerts(t *testing.T) {
	config := ManagerConfig{
		DeduplicationWindow: 50 * time.Millisecond,
		RetentionPeriod:     100 * time.Millisecond,
		MaxAlerts:           1000,
	}
	mgr := NewManager(config, nil)
	ctx := context.Background()

	corrAlert := makeCorrelationAlert("cleanup-rule", "cleanup-group", "Cleanup Test", 1)
	_ = mgr.HandleCorrelationAlert(ctx, corrAlert)
	_ = mgr.ResolveAlert(ctx, corrAlert.ID, "admin")

	// Backdate the creation time so it falls outside the retention window.
	mgr.mu.Lock()
	mgr.alerts[corrAlert.ID].CreatedAt = time.Now().Add(-1 * time.Hour)
	mgr.mu.Unlock()

	removed := mgr.Cleanup(ctx)
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if n := mgr.Stats()["total"].(int); n != 0 {
		t.Errorf("expected 0 alerts after cleanup, got %d", n)
	}
}

func TestManagerCleanupKeepsUnresolvedAlerts(t *testing.T) {
	config := ManagerConfig{
		DeduplicationWindow: 50 * time.Millisecond,
		RetentionPeriod:     100 * time.Millisecond,
		MaxAlerts:           1000,
	}
	mgr := NewManager(config, nil)
	ctx := context.Background()

	corrAlert := makeCorrelationAlert("cleanup-keep", "cleanup-keep", "Keep Test", 3)
	_ = mgr.HandleCorrelationAlert(ctx, corrAlert)

	// Backdate but leave as "new" (not resolved).
	mgr.mu.Lock()
	mgr.alerts[corrAlert.ID].CreatedAt = time.Now().Add(-1 * time.Hour)
	mgr.mu.Unlock()

	removed := mgr.Cleanup(ctx)
	if removed != 0 {
		t.Errorf("expected 0 removed (alert not resolved), got %d", removed)
	}
}

func TestManagerCleanupPrunesDedupMap(t *testing.T) {
	config := ManagerConfig{
		DeduplicationWindow: 50 * time.Millisecond,
		RetentionPeriod:     24 * time.Hour,
		MaxAlerts:           1000,
	}
	mgr := NewManager(config, nil)
	ctx := context.Background()

	corrAlert := makeCorrelationAlert("dedup-cleanup", "dedup-cleanup", "Dedup Cleanup", 1)
	_ = mgr.HandleCorrelationAlert(ctx, corrAlert)

	mgr.mu.RLock()
	initialLen := len(mgr.dedup)
	mgr.mu.RUnlock()
	if initialLen != 1 {
		t.Fatalf("expected 1 dedup entry, got %d", initialLen)
	}

	// Wait longer than 2x the dedup window so entries expire.
	time.Sleep(150 * time.Millisecond)

	mgr.Cleanup(ctx)

	mgr.mu.RLock()
	finalLen := len(mgr.dedup)
	mgr.mu.RUnlock()
	if finalLen != 0 {
		t.Errorf("expected 0 dedup entries after cleanup, got %d", finalLen)
	}
}

// ---------------------------------------------------------------------------
// AlertFilter.matches
// ---------------------------------------------------------------------------

func TestAlertFilterMatches(t *testing.T) {
	now := time.Now()
	statusNew := StatusNew
	sevHigh := correlation.SeverityHigh

	alert := &Alert{
		Status:    StatusNew,
		Severity:  correlation.SeverityHigh,
		RuleID:    "test-rule",
		CreatedAt: now,
	}

	tests := []struct {
		name   string
		filter AlertFilter
		want   bool
	}{
		{"empty filter matches all", AlertFilter{}, true},
		{"matching status", AlertFilter{Status: &statusNew}, true},
		{"matching severity", AlertFilter{Severity: &sevHigh}, true},
		{"matching rule ID", AlertFilter{RuleID: "test-rule"}, true},
		{"non-matching rule ID", AlertFilter{RuleID: "other-rule"}, false},
		{"since before creation", AlertFilter{Since: timePtr(now.Add(-1 * time.Hour))}, true},
		{"since after creation", AlertFilter{Since: timePtr(now.Add(1 * time.Hour))}, false},
		{"until after creation", AlertFilter{Until: timePtr(now.Add(1 * time.Hour))}, true},
		{"until before creation", AlertFilter{Until: timePtr(now.Add(-1 * time.Hour))}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.matches(alert); got != tt.want {
				t.Errorf("filter.matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

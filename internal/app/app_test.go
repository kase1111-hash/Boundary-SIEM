package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"boundary-siem/internal/config"
	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"
	"boundary-siem/internal/storage"
	"boundary-siem/internal/ws"
)

const testAPIKey = "test-key-0123456789"

// memStore is an in-memory EventStore standing in for ClickHouse.
type memStore struct {
	mu     sync.Mutex
	events map[uuid.UUID]*schema.Event
	dups   int
	closed bool
	delay  time.Duration
	block  chan struct{} // when non-nil, Write blocks until it is closed
}

func newMemStore() *memStore {
	return &memStore{events: make(map[uuid.UUID]*schema.Event)}
}

func (m *memStore) Write(e *schema.Event) error {
	if m.block != nil {
		<-m.block
	}
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return storage.ErrWriterClosed
	}
	if _, ok := m.events[e.EventID]; ok {
		m.dups++
	}
	m.events[e.EventID] = e
	return nil
}

func (m *memStore) Flush() error { return nil }

func (m *memStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *memStore) Metrics() storage.BatchWriterMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	return storage.BatchWriterMetrics{Written: uint64(len(m.events))}
}

func (m *memStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func (m *memStore) find(fn func(*schema.Event) bool) *schema.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.events {
		if fn(e) {
			return e
		}
	}
	return nil
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.APIKeys = []string{testAPIKey}
	cfg.Storage.Enabled = false
	cfg.Ingest.CEF.UDP.Enabled = false
	cfg.Ingest.CEF.TCP.Enabled = false
	cfg.Ingest.CEF.DTLS.Enabled = false
	cfg.Correlation.RulesDir = filepath.Join(t.TempDir(), "rules")
	cfg.Correlation.SeedRulesDir = filepath.Join("..", "..", "rules") // the shipped rules
	cfg.WebSocket.StatsInterval = 0
	cfg.Server.ShutdownTimeout = 8 * time.Second
	return cfg
}

func startApp(t *testing.T, cfg *config.Config, store EventStore) *App {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, Options{Store: store, Listener: ln})
	if err != nil {
		_ = ln.Close()
		t.Fatalf("New: %v", err)
	}
	if err := a.Start(); err != nil {
		a.Shutdown(5 * time.Second)
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { a.Shutdown(5 * time.Second) })
	return a
}

func apiRequest(t *testing.T, a *App, method, path string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, "http://"+a.Addr()+path, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", testAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// failedLogins builds n failed logins from one IP: the shipped
// community-brute-force-login rule fires at 20 within 5 minutes.
func failedLogins(n int, ip string) map[string]any {
	events := make([]map[string]any, n)
	for i := range events {
		events[i] = map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
			"source":    map[string]any{"product": "wiring-test", "host": "web-01"},
			"action":    "auth.login",
			"outcome":   "failure",
			"severity":  5,
			"actor":     map[string]any{"type": "user", "id": fmt.Sprintf("user-%d", i), "ip_address": ip},
		}
	}
	return map[string]any{"events": events}
}

type alertJSON struct {
	ID         string `json:"id"`
	RuleID     string `json:"rule_id"`
	Status     string `json:"status"`
	EventCount int    `json:"event_count"`
}

func waitForAlert(t *testing.T, a *App, ruleID string) alertJSON {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		code, body := apiRequest(t, a, http.MethodGet, "/v1/alerts?limit=500", nil)
		if code != http.StatusOK {
			t.Fatalf("GET /v1/alerts = %d %s", code, body)
		}
		var resp struct {
			Alerts []alertJSON `json:"alerts"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decode alerts: %v: %s", err, body)
		}
		for _, al := range resp.Alerts {
			if al.RuleID == ruleID {
				return al
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no alert for rule %s", ruleID)
	return alertJSON{}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestPipeline_IngestedEventsReachStorageAndCorrelation is the regression
// test for ingested events never reaching the correlation engine: events
// posted to /v1/events must be stored and must raise the shipped rule's
// alert.
func TestPipeline_IngestedEventsReachStorageAndCorrelation(t *testing.T) {
	store := newMemStore()
	a := startApp(t, testConfig(t), store)

	// The shipped rules were seeded into the rules directory and loaded.
	if code, body := apiRequest(t, a, http.MethodGet, "/v1/rules/community-brute-force-login", nil); code != http.StatusOK {
		t.Fatalf("shipped rule not loaded: %d %s", code, body)
	}

	code, body := apiRequest(t, a, http.MethodPost, "/v1/events", failedLogins(25, "203.0.113.7"))
	if code != http.StatusOK {
		t.Fatalf("POST /v1/events = %d %s", code, body)
	}

	alert := waitForAlert(t, a, "community-brute-force-login")
	if alert.EventCount < 20 {
		t.Errorf("alert event_count = %d, want >= 20", alert.EventCount)
	}
	waitFor(t, "25 events in storage", func() bool { return store.count() == 25 })
	if e := store.find(func(*schema.Event) bool { return true }); e.TenantID != "default" {
		t.Errorf("stored tenant = %q, want the configured default tenant", e.TenantID)
	}

	// Metrics show the events went through the correlation engine.
	resp, err := http.Get("http://" + a.Addr() + "/metrics") // unauthenticated
	if err != nil {
		t.Fatal(err)
	}
	metrics, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{"siem_events_total 25\n", "siem_correlation_events_total 25\n", "siem_correlation_events_dropped_total 0\n"} {
		if !strings.Contains(string(metrics), want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
}

// TestPipeline_StorageDisabledStillCorrelates covers development mode
// without storage: events are still correlated.
func TestPipeline_StorageDisabledStillCorrelates(t *testing.T) {
	cfg := testConfig(t)
	a := startApp(t, cfg, nil)
	if code, body := apiRequest(t, a, http.MethodPost, "/v1/events", failedLogins(21, "203.0.113.9")); code != http.StatusOK {
		t.Fatalf("POST = %d %s", code, body)
	}
	waitForAlert(t, a, "community-brute-force-login")
}

func TestPipeline_HealthReadyAndAuth(t *testing.T) {
	a := startApp(t, testConfig(t), newMemStore())
	base := "http://" + a.Addr()

	for _, path := range []string{"/health", "/ready", "/metrics"} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s without a key = %d, want 200", path, resp.StatusCode)
		}
	}
	for _, path := range []string{"/v1/alerts", "/v1/rules", "/api/system/dreaming"} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a key = %d, want 401", path, resp.StatusCode)
		}
	}

	resp, err := http.Get(base + "/health")
	if err != nil {
		t.Fatal(err)
	}
	var health struct {
		Status     string                    `json:"status"`
		Components map[string]map[string]any `json:"components"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if health.Status != "healthy" {
		t.Errorf("health status = %q", health.Status)
	}
	for _, name := range []string{"storage", "cef_udp", "cef_tcp", "cef_dtls", "correlation", "websocket"} {
		if _, ok := health.Components[name]; !ok {
			t.Errorf("health components miss %s: %v", name, health.Components)
		}
	}
	if health.Components["cef_tcp"]["status"] != "disabled" || health.Components["websocket"]["status"] != "up" {
		t.Errorf("components = %v", health.Components)
	}
}

func dialWS(t *testing.T, a *App) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial("ws://"+a.Addr()+"/ws/events", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func readWS(t *testing.T, conn *websocket.Conn) map[string]json.RawMessage {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	return m
}

func msgType(m map[string]json.RawMessage) string {
	var s string
	_ = json.Unmarshal(m["type"], &s)
	return s
}

// TestWebSocket_AuthAndAlertStream checks /ws/events end to end: in-band
// auth through the full middleware stack, then new alerts and alert
// lifecycle changes pushed as {"type":"alert"} messages.
func TestWebSocket_AuthAndAlertStream(t *testing.T) {
	a := startApp(t, testConfig(t), newMemStore())

	// A wrong key is refused with 4401.
	bad := dialWS(t, a)
	if err := bad.WriteJSON(map[string]string{"type": "auth", "api_key": "wrong"}); err != nil {
		t.Fatal(err)
	}
	_ = bad.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _, err := bad.ReadMessage()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != ws.CloseAuthFailed || ce.Text != ws.ReasonInvalidKey {
		t.Fatalf("wrong key: %v, want close 4401 invalid API key", err)
	}

	conn := dialWS(t, a)
	if err := conn.WriteJSON(map[string]string{"type": "auth", "api_key": testAPIKey}); err != nil {
		t.Fatal(err)
	}
	if m := readWS(t, conn); msgType(m) != ws.TypeAuthOK {
		t.Fatalf("first message = %v, want auth_ok", m)
	}
	if err := conn.WriteJSON(map[string]string{"type": "ping"}); err != nil {
		t.Fatal(err)
	}
	if m := readWS(t, conn); msgType(m) != ws.TypePong {
		t.Fatalf("ping answered with %v", m)
	}
	waitFor(t, "ws client registered", func() bool { return a.hub.Clients() == 1 })

	if code, body := apiRequest(t, a, http.MethodPost, "/v1/events", failedLogins(20, "198.51.100.20")); code != http.StatusOK {
		t.Fatalf("POST = %d %s", code, body)
	}

	var alert alertJSON
	for alert.RuleID != "community-brute-force-login" {
		m := readWS(t, conn)
		if msgType(m) != ws.TypeAlert {
			continue
		}
		if err := json.Unmarshal(m["data"], &alert); err != nil {
			t.Fatal(err)
		}
	}
	if alert.Status != "new" || alert.ID == "" {
		t.Fatalf("alert = %+v", alert)
	}

	if code, body := apiRequest(t, a, http.MethodPost, "/v1/alerts/"+alert.ID+"/acknowledge", map[string]string{"user": "analyst"}); code != http.StatusOK {
		t.Fatalf("acknowledge = %d %s", code, body)
	}
	for {
		m := readWS(t, conn)
		if msgType(m) != ws.TypeAlert {
			continue
		}
		var update alertJSON
		if err := json.Unmarshal(m["data"], &update); err != nil {
			t.Fatal(err)
		}
		if update.ID == alert.ID && update.Status == "acknowledged" {
			break
		}
	}
}

// TestShutdown_NoLossOfAcceptedEvents is the regression test for shutdown
// discarding events still in the ring buffer: every event acknowledged with
// HTTP 200/207 must be in storage after Shutdown, which must stay bounded.
func TestShutdown_NoLossOfAcceptedEvents(t *testing.T) {
	store := newMemStore()
	store.delay = 20 * time.Microsecond // a storage backend that is not instant
	cfg := testConfig(t)
	cfg.RateLimit.Enabled = false
	a := startApp(t, cfg, store)

	const clients, perRequest, requests = 8, 500, 10
	var acknowledged atomic.Int64
	var wg sync.WaitGroup
	started := make(chan struct{})
	var once sync.Once
	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			client := &http.Client{Timeout: 10 * time.Second}
			for r := 0; r < requests; r++ {
				payload, _ := json.Marshal(failedLogins(perRequest, fmt.Sprintf("192.0.2.%d", c+1)))
				req, _ := http.NewRequest(http.MethodPost, "http://"+a.Addr()+"/v1/events", bytes.NewReader(payload))
				req.Header.Set("X-API-Key", testAPIKey)
				resp, err := client.Do(req)
				if err != nil {
					return // server shut down
				}
				var body struct {
					Accepted int `json:"accepted"`
				}
				_ = json.NewDecoder(resp.Body).Decode(&body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusMultiStatus {
					acknowledged.Add(int64(body.Accepted))
				}
				once.Do(func() { close(started) })
			}
		}(c)
	}

	<-started
	time.Sleep(20 * time.Millisecond) // let the queue fill up
	report := a.Shutdown(cfg.Server.ShutdownTimeout)
	wg.Wait()

	if report.Duration > cfg.Server.ShutdownTimeout {
		t.Errorf("shutdown took %v, budget %v", report.Duration, cfg.Server.ShutdownTimeout)
	}
	ack := acknowledged.Load()
	if ack == 0 {
		t.Fatal("no request was acknowledged before shutdown")
	}
	stored := store.count()
	if int64(stored) < ack {
		t.Errorf("stored %d events but %d were acknowledged: accepted events lost at shutdown", stored, ack)
	}
	if uint64(stored) != report.Accepted {
		t.Errorf("stored %d, queue accepted %d", stored, report.Accepted)
	}
	if report.Lost != 0 || report.Undrained != 0 {
		t.Errorf("report = %+v, want no loss", report)
	}
	if store.dups != 0 {
		t.Errorf("%d events stored twice", store.dups)
	}
	t.Logf("acknowledged=%d stored=%d shutdown=%v", ack, stored, report.Duration)
}

// TestShutdown_BoundedWhenStorageHangs checks a frozen storage backend
// cannot stretch shutdown past its budget, and that the loss is reported
// instead of silently ignored.
func TestShutdown_BoundedWhenStorageHangs(t *testing.T) {
	store := newMemStore()
	store.block = make(chan struct{})
	defer close(store.block)
	cfg := testConfig(t)
	cfg.Server.ShutdownTimeout = 2 * time.Second
	a := startApp(t, cfg, store)

	if code, body := apiRequest(t, a, http.MethodPost, "/v1/events", failedLogins(100, "192.0.2.50")); code != http.StatusOK {
		t.Fatalf("POST = %d %s", code, body)
	}

	start := time.Now()
	report := a.Shutdown(cfg.Server.ShutdownTimeout)
	if elapsed := time.Since(start); elapsed > cfg.Server.ShutdownTimeout+time.Second {
		t.Errorf("shutdown took %v with a hung store, budget %v", elapsed, cfg.Server.ShutdownTimeout)
	}
	if report.Lost == 0 {
		t.Errorf("report = %+v, want the undelivered events counted as lost", report)
	}
	// Every event is lost, including the ones the consumer workers popped
	// and are stuck writing (neither queued nor counted as consumed).
	if report.Accepted != 100 || report.Lost != report.Accepted {
		t.Errorf("report = %+v, want all 100 accepted events counted as lost", report)
	}
}

// TestShutdown_BoundedWhenAlertHandlingHangs is the regression test for
// shutdown waiting on alert handling: the alert manager persists every alert
// to ClickHouse with the run context, which a frozen server holds until the
// driver's 5 minute read timeout, and the correlation engine's Stop waited
// for it before the run context was cancelled.
func TestShutdown_BoundedWhenAlertHandlingHangs(t *testing.T) {
	cfg := testConfig(t)
	cfg.Server.ShutdownTimeout = 2 * time.Second
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, Options{Store: newMemStore(), Listener: ln})
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	entered := make(chan struct{})
	var once sync.Once
	// Like persistAlert against a frozen ClickHouse: returns only when its
	// context is cancelled.
	a.engine.AddHandler(func(ctx context.Context, _ *correlation.Alert) error {
		once.Do(func() { close(entered) })
		<-ctx.Done()
		return ctx.Err()
	})
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}

	if code, body := apiRequest(t, a, http.MethodPost, "/v1/events", failedLogins(25, "192.0.2.77")); code != http.StatusOK {
		t.Fatalf("POST = %d %s", code, body)
	}
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		a.cancelRun()
		a.Shutdown(cfg.Server.ShutdownTimeout)
		t.Fatal("no alert reached the handler")
	}

	done := make(chan ShutdownReport, 1)
	start := time.Now()
	go func() { done <- a.Shutdown(cfg.Server.ShutdownTimeout) }()
	select {
	case <-done:
	case <-time.After(cfg.Server.ShutdownTimeout + 3*time.Second):
		a.cancelRun() // unblock the handler so the test can finish
		<-done
		t.Fatalf("shutdown blocked on a hung alert handler for %v (budget %v)", time.Since(start), cfg.Server.ShutdownTimeout)
	}
	if elapsed := time.Since(start); elapsed > cfg.Server.ShutdownTimeout+time.Second {
		t.Errorf("shutdown took %v with a hung alert handler, budget %v", elapsed, cfg.Server.ShutdownTimeout)
	}
}

// TestPipeline_CEFTCPReachesStorageAndCorrelation checks CEF events take
// the same path as JSON events and count in siem_events_total.
func TestPipeline_CEFTCPReachesStorageAndCorrelation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	store := newMemStore()
	cfg := testConfig(t)
	cfg.Ingest.CEF.TCP.Enabled = true
	cfg.Ingest.CEF.TCP.Address = addr
	a := startApp(t, cfg, store)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	line := "CEF:0|Acme|Firewall|1.0|100|Login failed|5|src=203.0.113.44 suser=bob outcome=failure\n"
	for i := 0; i < 3; i++ {
		if _, err := conn.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	_ = conn.Close()

	waitFor(t, "CEF events in storage", func() bool { return store.count() == 3 })
	waitFor(t, "CEF events correlated", func() bool { return a.corrSink.Metrics().Forwarded == 3 })

	resp, err := http.Get("http://" + a.Addr() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	metrics, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	for _, want := range []string{"siem_events_total 3\n", `siem_events_ingested_total{transport="tcp"} 3`} {
		if !strings.Contains(string(metrics), want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
}

// memQuarantine is an in-memory events_quarantine.
type memQuarantine struct {
	mu      sync.Mutex
	entries []*storage.QuarantineEntry
}

func (m *memQuarantine) WriteBatch(_ context.Context, entries []*storage.QuarantineEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, entries...)
	return nil
}

func (m *memQuarantine) codes() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.entries))
	for _, e := range m.entries {
		out[e.SourceFormat+"/"+e.ErrorCode] = e.RawEvent
	}
	return out
}

// TestPipeline_RejectedEventsQuarantined checks rejected events from every
// transport reach events_quarantine: malformed and invalid JSON over HTTP,
// and unparsable and invalid CEF over TCP.
func TestPipeline_RejectedEventsQuarantined(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cefAddr := ln.Addr().String()
	_ = ln.Close()

	cfg := testConfig(t)
	cfg.Ingest.CEF.TCP.Enabled = true
	cfg.Ingest.CEF.TCP.Address = cefAddr
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	quarantine := &memQuarantine{}
	a, err := New(cfg, Options{Store: newMemStore(), Listener: httpLn, Quarantine: quarantine})
	if err != nil {
		_ = httpLn.Close()
		t.Fatal(err)
	}
	if err := a.Start(); err != nil {
		a.Shutdown(5 * time.Second)
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Shutdown(5 * time.Second) })

	req, _ := http.NewRequest(http.MethodPost, "http://"+a.Addr()+"/v1/events", strings.NewReader(`{"events":[{`))
	req.Header.Set("X-API-Key", testAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed JSON = %d, want 400", resp.StatusCode)
	}
	if code, body := apiRequest(t, a, http.MethodPost, "/v1/events", map[string]any{"action": "x.y"}); code != http.StatusBadRequest {
		t.Fatalf("invalid event = %d %s, want 400", code, body)
	}

	conn, err := net.Dial("tcp", cefAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("NOT_A_CEF_MESSAGE\nCEF:0|Acme|Fw|1.0|100|Old|5|rt=1000000000000 src=203.0.113.9\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	want := []string{"json/parse_failed", "json/validation_failed", "cef/parse_failed", "cef/validation_failed"}
	waitFor(t, "rejected events quarantined", func() bool {
		got := quarantine.codes()
		for _, w := range want {
			if _, ok := got[w]; !ok {
				return false
			}
		}
		return true
	})
	if raw := quarantine.codes()["cef/parse_failed"]; raw != "NOT_A_CEF_MESSAGE" {
		t.Errorf("quarantined CEF raw = %q", raw)
	}
}

func TestSeedRules(t *testing.T) {
	seed := t.TempDir()
	for name, content := range map[string]string{
		"a.yaml":      "id: a\n",
		"b.json":      "{}",
		"README.md":   "not a rule",
		".hidden.yml": "id: hidden\n",
	} {
		if err := os.WriteFile(filepath.Join(seed, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(t.TempDir(), "rules")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("id: customised\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := seedRules(dir, seed)
	if err != nil || n != 1 {
		t.Fatalf("seedRules = %d, %v; want 1 file copied", n, err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "a.yaml")); string(data) != "id: customised\n" {
		t.Errorf("existing rule overwritten: %q", data)
	}
	for _, name := range []string{"b.json", seededMarker} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing: %v", name, err)
		}
	}
	for _, name := range []string{"README.md", ".hidden.yml"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s copied", name)
		}
	}

	// A rule deleted through the API is not restored on the next start.
	if err := os.Remove(filepath.Join(dir, "b.json")); err != nil {
		t.Fatal(err)
	}
	if n, err := seedRules(dir, seed); err != nil || n != 0 {
		t.Errorf("second seedRules = %d, %v; want nothing copied", n, err)
	}

	// Seeding a directory into itself, or from a missing directory, is a no-op.
	if n, err := seedRules(seed, seed); err != nil || n != 0 {
		t.Errorf("self seed = %d, %v", n, err)
	}
	if n, err := seedRules(filepath.Join(t.TempDir(), "x"), filepath.Join(t.TempDir(), "missing")); err != nil || n != 0 {
		t.Errorf("missing seed dir = %d, %v", n, err)
	}
}

// TestDTLSWiring checks the DTLS server is built from the configuration:
// without certificates startup fails, and the plain-UDP fallback (only with
// allow_insecure) is reported as degraded.
func TestDTLSWiring(t *testing.T) {
	cfg := testConfig(t)
	cfg.Ingest.CEF.DTLS.Enabled = true
	cfg.Ingest.CEF.DTLS.Address = "127.0.0.1:0"
	cfg.Ingest.CEF.DTLS.CertFile = ""
	cfg.Ingest.CEF.DTLS.KeyFile = ""
	if _, err := New(cfg, Options{Store: newMemStore()}); err == nil {
		t.Fatal("New accepted DTLS without certificates")
	}

	cfg = testConfig(t)
	cfg.Ingest.CEF.DTLS.Enabled = true
	cfg.Ingest.CEF.DTLS.Address = "127.0.0.1:0"
	cfg.Ingest.CEF.DTLS.AllowInsecure = true
	cfg.Ingest.CEF.DTLS.CertFile = ""
	cfg.Ingest.CEF.DTLS.KeyFile = ""
	a := startApp(t, cfg, newMemStore())
	dtls := a.components()["cef_dtls"]
	if !dtls.Enabled || dtls.Status != "degraded" {
		t.Errorf("cef_dtls = %+v, want enabled and degraded (plain UDP fallback)", dtls)
	}
}

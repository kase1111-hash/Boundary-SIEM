package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"boundary-siem/internal/config"
	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
	"boundary-siem/internal/storage"
)

// memQuarantine is an in-memory QuarantineStore.
type memQuarantine struct {
	mu      sync.Mutex
	entries []*storage.QuarantineEntry
	err     error
}

func (m *memQuarantine) WriteBatch(_ context.Context, entries []*storage.QuarantineEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.entries = append(m.entries, entries...)
	return nil
}

func (m *memQuarantine) all() []*storage.QuarantineEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*storage.QuarantineEntry(nil), m.entries...)
}

func postEvents(t *testing.T, h *Handler, body string) (*httptest.ResponseRecorder, IngestResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
	req.RemoteAddr = "198.51.100.7:4242"
	rec := httptest.NewRecorder()
	h.HandleEvents(rec, req)
	var resp IngestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, resp
}

func validEventJSON(action string) string {
	return `{"timestamp":"` + time.Now().UTC().Format(time.RFC3339) +
		`","source":{"product":"p"},"action":"` + action + `","outcome":"success","severity":3}`
}

func TestHandleEvents_AcceptsBareObjectAndArray(t *testing.T) {
	q := queue.NewRingBuffer(10)
	h := NewHandler(schema.NewValidator(), q).WithDefaultTenant("acme")

	rec, resp := postEvents(t, h, validEventJSON("auth.login"))
	if rec.Code != http.StatusOK || resp.Accepted != 1 {
		t.Fatalf("bare object: status %d resp %+v body %s", rec.Code, resp, rec.Body)
	}

	rec, resp = postEvents(t, h, "["+validEventJSON("a.one")+","+validEventJSON("a.two")+"]")
	if rec.Code != http.StatusOK || resp.Accepted != 2 {
		t.Fatalf("array: status %d resp %+v", rec.Code, resp)
	}

	rec, _ = postEvents(t, h, `{}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no events provided") {
		t.Errorf("empty object: status %d body %s, want 400 no events provided", rec.Code, rec.Body)
	}

	for i := 0; i < 3; i++ {
		ev, err := q.Pop()
		if err != nil {
			t.Fatal(err)
		}
		if ev.TenantID != "acme" {
			t.Errorf("TenantID = %q, want the default tenant acme", ev.TenantID)
		}
	}
}

func TestHandleEvents_QuarantinesRejectedEvents(t *testing.T) {
	store := &memQuarantine{}
	qr := NewQuarantiner(store, 100)
	h := NewHandler(schema.NewValidator(), queue.NewRingBuffer(10)).WithQuarantine(qr)

	// One valid, one invalid (severity out of range).
	bad := `{"timestamp":"` + time.Now().UTC().Format(time.RFC3339) + `","source":{"product":"p"},"action":"x.y","outcome":"success","severity":99}`
	rec, resp := postEvents(t, h, `{"events":[`+validEventJSON("x.ok")+`,`+bad+`]}`)
	if rec.Code != http.StatusMultiStatus || resp.Accepted != 1 || resp.Rejected != 1 {
		t.Fatalf("status %d resp %+v", rec.Code, resp)
	}
	rec, _ = postEvents(t, h, `{"events":[{`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON status = %d", rec.Code)
	}

	if err := qr.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries := store.all()
	if len(entries) != 2 {
		t.Fatalf("quarantined %d entries, want 2", len(entries))
	}
	codes := map[string]bool{}
	for _, e := range entries {
		codes[e.ErrorCode] = true
		if e.SourceIP != "198.51.100.7" || e.SourceFormat != storage.QuarantineFormatJSON {
			t.Errorf("entry %+v: want source ip 198.51.100.7 and json format", e)
		}
	}
	if !codes[storage.QuarantineCodeValidationFailed] || !codes[storage.QuarantineCodeParseFailed] {
		t.Errorf("codes = %v, want validation_failed and parse_failed", codes)
	}
	if m := qr.Metrics(); m.Written != 2 || m.Dropped != 0 {
		t.Errorf("quarantine metrics = %+v", m)
	}
}

// gatedQuarantine blocks every write until gate is closed, then fails it.
type gatedQuarantine struct {
	gate chan struct{}
}

func (g *gatedQuarantine) WriteBatch(ctx context.Context, _ []*storage.QuarantineEntry) error {
	select {
	case <-g.gate:
	case <-ctx.Done():
	}
	return errors.New("clickhouse down")
}

func TestQuarantiner_BoundedAndTruncated(t *testing.T) {
	store := &gatedQuarantine{gate: make(chan struct{})}
	qr := NewQuarantiner(store, 2)
	big := strings.Repeat("x", maxQuarantineRaw+100)
	start := time.Now()
	// The writer holds at most one batch in memory plus the 2-entry buffer.
	const n = 3 * quarantineBatchSize
	for i := 0; i < n; i++ {
		qr.Submit(storage.NewQuarantineEntry(big, "", storage.QuarantineFormatJSON, storage.QuarantineCodeParseFailed))
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Submit blocked for %v on a stalled store", elapsed)
	}
	close(store.gate)
	if err := qr.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := qr.Metrics()
	if m.Submitted+m.Dropped != n || m.Dropped == 0 {
		t.Errorf("metrics = %+v, want drops with a 2-entry buffer", m)
	}
	if m.Failed != m.Submitted {
		t.Errorf("failed = %d, want every submitted entry to fail (store down)", m.Failed)
	}

	ok := &memQuarantine{}
	qr = NewQuarantiner(ok, 10)
	qr.Submit(storage.NewQuarantineEntry(big, "", storage.QuarantineFormatJSON, storage.QuarantineCodeParseFailed))
	_ = qr.Close(context.Background())
	if got := len(ok.all()[0].RawEvent); got != maxQuarantineRaw {
		t.Errorf("raw length = %d, want truncated to %d", got, maxQuarantineRaw)
	}
}

// TestQuarantiner_TruncationReleasesPayload is the regression test for
// truncated quarantine entries pinning the whole rejected payload: the
// truncated raw event was a substring of the original, so every buffered
// entry kept up to max_payload_size (10 MB) alive while storage was slow.
func TestQuarantiner_TruncationReleasesPayload(t *testing.T) {
	store := &gatedQuarantine{gate: make(chan struct{})}
	const n = 64
	qr := NewQuarantiner(store, n)
	defer func() {
		close(store.gate)
		_ = qr.Close(context.Background())
	}()

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < n; i++ {
		raw := strings.Repeat(string(rune('a'+i%26)), 1<<20) // a fresh 1 MiB payload
		qr.Submit(storage.NewQuarantineEntry(raw, "", storage.QuarantineFormatJSON, storage.QuarantineCodeParseFailed))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)

	if m := qr.Metrics(); m.Submitted != n {
		t.Fatalf("metrics = %+v, want all %d entries buffered", m, n)
	}
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	// n truncated copies take n x 64 KiB = 4 MiB; pinning the payloads
	// would take n x 1 MiB = 64 MiB.
	if limit := int64(4 * n * maxQuarantineRaw); retained > limit {
		t.Errorf("%d buffered entries retain %d MiB, want at most %d MiB: truncation keeps the full payloads alive",
			n, retained>>20, limit>>20)
	}
}

func TestHandleEvents_QueueUnavailableIs503(t *testing.T) {
	q := queue.NewRingBuffer(1)
	h := NewHandler(schema.NewValidator(), q)
	if rec, _ := postEvents(t, h, validEventJSON("a.b")); rec.Code != http.StatusOK {
		t.Fatalf("first event status %d", rec.Code)
	}
	rec, resp := postEvents(t, h, validEventJSON("a.b"))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("queue full: status %d (Retry-After %q), want 503", rec.Code, rec.Header().Get("Retry-After"))
	}
	if resp.Rejected != 1 {
		t.Errorf("resp = %+v", resp)
	}

	q.Close()
	if rec, _ := postEvents(t, h, validEventJSON("a.b")); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("closed queue: status %d, want 503", rec.Code)
	}
}

func TestHealthAndReady(t *testing.T) {
	q := queue.NewRingBuffer(10)
	storageStatus := ComponentStatus{Status: StatusUp, Enabled: true}
	var mu sync.Mutex
	h := NewHandler(schema.NewValidator(), q).WithComponents(func() map[string]ComponentStatus {
		mu.Lock()
		defer mu.Unlock()
		return map[string]ComponentStatus{
			"storage": storageStatus,
			"cef_udp": {Status: StatusDisabled},
			"cef_tcp": {Status: StatusUp, Enabled: true, Address: ":5515"},
		}
	})

	get := func(handler http.HandlerFunc, path string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return rec.Code, body
	}

	code, body := get(h.HealthCheck, "/health")
	if code != http.StatusOK || body["status"] != "healthy" {
		t.Fatalf("health = %d %v", code, body)
	}
	comps, _ := body["components"].(map[string]any)
	if tcp, _ := comps["cef_tcp"].(map[string]any); tcp["address"] != ":5515" {
		t.Errorf("components = %v", comps)
	}
	if code, body = get(h.Ready, "/ready"); code != http.StatusOK || body["status"] != "ready" {
		t.Errorf("ready = %d %v", code, body)
	}

	// Storage unreachable: /health stays 200 but degraded, /ready is 503.
	mu.Lock()
	storageStatus = ComponentStatus{Status: StatusDown, Enabled: true, Message: "ping failed"}
	mu.Unlock()
	code, body = get(h.HealthCheck, "/health")
	if code != http.StatusOK || body["status"] != "degraded" {
		t.Errorf("health with storage down = %d %v, want 200 degraded", code, body)
	}
	code, body = get(h.Ready, "/ready")
	if code != http.StatusServiceUnavailable || !strings.Contains(strings.Join(toStrings(body["reasons"]), ";"), "storage down: ping failed") {
		t.Errorf("ready with storage down = %d %v", code, body)
	}

	mu.Lock()
	storageStatus = ComponentStatus{Status: StatusUp, Enabled: true}
	mu.Unlock()
	h.SetShuttingDown()
	if code, body = get(h.Ready, "/ready"); code != http.StatusServiceUnavailable {
		t.Errorf("ready while shutting down = %d %v", code, body)
	}
}

func toStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// TestMetrics_CountsCEFEvents checks that siem_events_total includes events
// accepted over CEF, not only HTTP.
func TestMetrics_CountsCEFEvents(t *testing.T) {
	q := queue.NewRingBuffer(10)
	h := NewHandler(schema.NewValidator(), q).
		WithSources(func() []SourceMetrics {
			return []SourceMetrics{
				{Transport: "udp", Received: 5, Queued: 2, Errors: 3, ParseErrors: 2, ValidationErrors: 1},
				{Transport: "tcp", Received: 4, Queued: 4, OversizedLines: 1},
			}
		}).
		WithMetrics(func() []Metric {
			return []Metric{
				{Name: "siem_correlation_events_dropped_total", Help: "x", Type: "counter", Value: 7},
				{Name: "siem_component_up", Help: "y", Labels: map[string]string{"component": "storage"}, Value: 1},
				{Name: "siem_component_up", Help: "y", Labels: map[string]string{"component": "cef_tcp"}, Value: 0},
			}
		})
	if rec, _ := postEvents(t, h, validEventJSON("a.b")); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}

	rec := httptest.NewRecorder()
	h.Metrics(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		"siem_events_total 7\n",
		`siem_events_ingested_total{transport="http"} 1`,
		`siem_events_ingested_total{transport="udp"} 2`,
		`siem_cef_parse_errors_total{transport="udp"} 2`,
		`siem_cef_oversized_lines_total{transport="tcp"} 1`,
		"siem_correlation_events_dropped_total 7\n",
		`siem_component_up{component="storage"} 1`,
		`siem_component_up{component="cef_tcp"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q:\n%s", want, body)
		}
	}
	if strings.Count(body, "# TYPE siem_component_up") != 1 {
		t.Errorf("TYPE line repeated for one metric:\n%s", body)
	}
	if strings.Contains(body, `siem_cef_oversized_lines_total{transport="udp"}`) {
		t.Error("oversized lines exported for udp")
	}
}

func testMiddlewareConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.APIKeys = []string{"good-key"}
	cfg.RateLimit.Enabled = false
	cfg.CORS.Enabled = false
	return cfg
}

func TestAuthMiddleware_PublicAndProtectedPaths(t *testing.T) {
	cfg := testMiddlewareConfig()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h, stop := WithMiddleware(ok, cfg)
	defer stop()

	tests := []struct {
		method, path, key string
		want              int
	}{
		{http.MethodGet, "/health", "", http.StatusTeapot},
		{http.MethodGet, "/ready", "", http.StatusTeapot},
		{http.MethodGet, "/metrics", "", http.StatusTeapot},
		{http.MethodGet, "/ws/events", "", http.StatusTeapot}, // in-band auth
		{http.MethodGet, "/ws", "", http.StatusTeapot},
		{http.MethodGet, "/api/system/dreaming", "", http.StatusUnauthorized},
		{http.MethodGet, "/v1/alerts", "", http.StatusUnauthorized},
		{http.MethodGet, "/v1/alerts", "bad-key", http.StatusUnauthorized},
		{http.MethodGet, "/v1/alerts", "good-key", http.StatusTeapot},
		{http.MethodGet, "/", "", http.StatusUnauthorized}, // no web UI configured
	}
	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, tt.path, nil)
		if tt.key != "" {
			req.Header.Set("X-API-Key", tt.key)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Errorf("%s %s key=%q: status %d, want %d", tt.method, tt.path, tt.key, rec.Code, tt.want)
		}
		if rec.Code == http.StatusUnauthorized && rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("401 content type = %q", rec.Header().Get("Content-Type"))
		}
	}

	// With the dashboard served, static GETs are public but the API is not.
	cfg.Server.WebDir = "web/dist"
	h, stop2 := WithMiddleware(ok, cfg)
	defer stop2()
	for _, tt := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/", http.StatusTeapot},
		{http.MethodGet, "/assets/index.js", http.StatusTeapot},
		{http.MethodGet, "/alerts/123", http.StatusTeapot},
		{http.MethodPost, "/alerts", http.StatusUnauthorized},
		{http.MethodGet, "/v1/stats", http.StatusUnauthorized},
		{http.MethodGet, "/api/system/dreaming", http.StatusUnauthorized},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
		if rec.Code != tt.want {
			t.Errorf("web UI: %s %s = %d, want %d", tt.method, tt.path, rec.Code, tt.want)
		}
	}
}

// E2E round 1: the configured security headers (CSP, X-Frame-Options, HSTS,
// ...) were never applied by siem-ingest although startup diagnostics
// listed them as enabled, so the dashboard could be framed.
func TestWithMiddleware_AppliesSecurityHeaders(t *testing.T) {
	cfg := testMiddlewareConfig()
	cfg.Server.WebDir = "web/dist"
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h, stop := WithMiddleware(ok, cfg)
	defer stop()

	for _, tt := range []struct{ path, key string }{
		{"/", ""},                  // dashboard
		{"/v1/alerts", "good-key"}, // API
		{"/v1/alerts", ""},         // auth error
		{"/health", ""},
	} {
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		if tt.key != "" {
			req.Header.Set("X-API-Key", tt.key)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		hdr := rec.Header()
		if csp := hdr.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: Content-Security-Policy = %q", tt.path, csp)
		}
		if got := hdr.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("%s: X-Frame-Options = %q, want DENY", tt.path, got)
		}
		if got := hdr.Get("Strict-Transport-Security"); !strings.HasPrefix(got, "max-age=") {
			t.Errorf("%s: Strict-Transport-Security = %q", tt.path, got)
		}
		if got := hdr.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q", tt.path, got)
		}
	}

	// security_headers.enabled: false turns them off.
	cfg.SecurityHeaders.Enabled = false
	h2, stop2 := WithMiddleware(ok, cfg)
	defer stop2()
	rec := httptest.NewRecorder()
	h2.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get("Content-Security-Policy") != "" || rec.Header().Get("X-Frame-Options") != "" {
		t.Errorf("security headers sent although disabled: %v", rec.Header())
	}
}

func TestValidAPIKey(t *testing.T) {
	keys := []string{"alpha", "beta"}
	for key, want := range map[string]bool{"alpha": true, "beta": true, "gamma": false, "": false, "alph": false} {
		if got := ValidAPIKey(key, keys); got != want {
			t.Errorf("ValidAPIKey(%q) = %v, want %v", key, got, want)
		}
	}
	if ValidAPIKey("", []string{""}) {
		t.Error("an empty key must never be valid")
	}
}

// TestLoggingMiddleware_Hijack checks that WebSocket upgrades can hijack the
// connection through the logging wrapper.
func TestLoggingMiddleware_Hijack(t *testing.T) {
	hijacked := make(chan error, 1)
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			hijacked <- errors.New("writer is not a Hijacker")
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			hijacked <- err
			return
		}
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n\r\nhello")
		_ = brw.Flush()
		_ = conn.Close()
		hijacked <- nil
	})
	srv := httptest.NewServer(loggingMiddleware(inner))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	status, _ := bufio.NewReader(conn).ReadString('\n')
	if err := <-hijacked; err != nil {
		t.Fatalf("hijack through logging middleware: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Errorf("status line = %q", status)
	}
}

// TestWithMiddleware_StopsRateLimiter checks the rate limiter's cleanup
// goroutine ends when the returned stop function is called.
func TestWithMiddleware_StopsRateLimiter(t *testing.T) {
	cfg := testMiddlewareConfig()
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.CleanupPeriod = time.Hour

	before := runtime.NumGoroutine()
	_, stop := WithMiddleware(http.NotFoundHandler(), cfg)
	if runtime.NumGoroutine() <= before {
		t.Skip("could not observe the cleanup goroutine starting")
	}
	stop()
	stop() // idempotent
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Errorf("goroutines = %d after stop, want <= %d", n, before)
	}
}

func TestRateLimit_AppliesAndExemptsProbes(t *testing.T) {
	cfg := testMiddlewareConfig()
	cfg.Auth.Enabled = false
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.RequestsPerIP = 2
	cfg.RateLimit.BurstSize = 0
	h, stop := WithMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}), cfg)
	defer stop()

	codes := []int{}
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/alerts", nil))
		codes = append(codes, rec.Code)
	}
	if codes[2] != http.StatusTooManyRequests {
		t.Errorf("codes = %v, want the third request limited", codes)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code == http.StatusTooManyRequests {
		t.Error("/ready was rate limited")
	}
}

func TestStaticHandler(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html>app</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("console.log(1)"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := NewStaticHandler(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		path     string
		want     int
		contains string
	}{
		{"/", http.StatusOK, "app"},
		{"/alerts/42", http.StatusOK, "app"},
		{"/assets/app.js", http.StatusOK, "console.log"},
		{"/assets/missing.js", http.StatusNotFound, ""},
		{"/v1/nothing", http.StatusNotFound, `"error"`},
		{"/../../etc/passwd", http.StatusBadRequest, ""}, // dot-dot paths are refused
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
		if rec.Code != tt.want || !strings.Contains(rec.Body.String(), tt.contains) {
			t.Errorf("GET %s = %d %q, want %d containing %q", tt.path, rec.Code, rec.Body.String(), tt.want, tt.contains)
		}
	}

	if _, err := NewStaticHandler(t.TempDir()); err == nil {
		t.Error("NewStaticHandler accepted a directory without index.html")
	}
}

package ingest

import (
	"context"
	"net"
	"testing"
	"time"

	"boundary-siem/internal/ingest/cef"
	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
)

// validCEFLine returns a newline-terminated CEF message that will pass
// parsing, normalization, and validation.
// SignatureID "100" maps to "session.created" in DefaultActionMappings.
func validCEFLine() string {
	return "CEF:0|Security|TestProduct|1.0|100|Session Created|5|src=192.168.1.1 outcome=success\n"
}

// newTestTCPServer creates a TCPServer backed by real parser, normalizer,
// validator and queue, configured to listen on a random localhost port.
// Optional config override functions can be passed to tweak the defaults.
func newTestTCPServer(t *testing.T, overrides ...func(*TCPServerConfig)) (*TCPServer, *queue.RingBuffer) {
	t.Helper()

	parser := cef.NewParser(cef.DefaultParserConfig())
	normalizer := cef.NewNormalizer(cef.DefaultNormalizerConfig())
	validator := schema.NewValidator()
	q := queue.NewRingBuffer(1000)

	cfg := DefaultTCPServerConfig()
	cfg.Address = "127.0.0.1:0" // kernel-assigned port
	for _, fn := range overrides {
		fn(&cfg)
	}

	srv := NewTCPServer(cfg, parser, normalizer, validator, q)
	return srv, q
}

// waitForCondition polls until fn returns true or the timeout elapses.
func waitForCondition(timeout time.Duration, fn func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// --- 1. Test TCPServerConfig defaults ---

func TestDefaultTCPServerConfig(t *testing.T) {
	cfg := DefaultTCPServerConfig()

	if cfg.Address != ":5515" {
		t.Errorf("Address = %q, want %q", cfg.Address, ":5515")
	}
	if cfg.TLSEnabled {
		t.Error("TLSEnabled should be false by default")
	}
	if cfg.TLSCertFile != "" {
		t.Errorf("TLSCertFile = %q, want empty", cfg.TLSCertFile)
	}
	if cfg.TLSKeyFile != "" {
		t.Errorf("TLSKeyFile = %q, want empty", cfg.TLSKeyFile)
	}
	if cfg.MaxConnections != 1000 {
		t.Errorf("MaxConnections = %d, want 1000", cfg.MaxConnections)
	}
	if cfg.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout = %v, want 5m", cfg.IdleTimeout)
	}
	if cfg.MaxLineLength != 65535 {
		t.Errorf("MaxLineLength = %d, want 65535", cfg.MaxLineLength)
	}
}

func TestDefaultTCPServerConfig_PositiveValues(t *testing.T) {
	cfg := DefaultTCPServerConfig()

	if cfg.MaxConnections <= 0 {
		t.Error("MaxConnections should be positive")
	}
	if cfg.IdleTimeout <= 0 {
		t.Error("IdleTimeout should be positive")
	}
	if cfg.MaxLineLength <= 0 {
		t.Error("MaxLineLength should be positive")
	}
}

// --- 2. Test TCP server start/stop lifecycle ---

func TestTCPServer_StartStop(t *testing.T) {
	srv, _ := newTestTCPServer(t)

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Listener should be non-nil and have a real address.
	if srv.listener == nil {
		t.Fatal("listener should not be nil after Start()")
	}
	addr := srv.listener.Addr().String()
	if addr == "" {
		t.Fatal("listener address should not be empty")
	}

	// Verify we can connect while the server is running.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial() should succeed while server is running: %v", err)
	}
	conn.Close()

	// Stop the server gracefully.
	srv.Stop()

	// After Stop returns the listener is closed; new connections must fail.
	_, err = net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err == nil {
		t.Error("Dial() should fail after Stop()")
	}
}

func TestTCPServer_StopIsIdempotentAfterClose(t *testing.T) {
	srv, _ := newTestTCPServer(t)

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Stopping should work without panic even if there are no active
	// connections and the server was only briefly alive.
	srv.Stop()
}

func TestTCPServer_ContextCancellation(t *testing.T) {
	srv, _ := newTestTCPServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	addr := srv.listener.Addr().String()

	// Cancel the context -- the accept loop should exit.
	cancel()

	// Give the accept loop time to notice the cancellation.
	time.Sleep(300 * time.Millisecond)

	// Stop cleans up the rest.
	srv.Stop()

	_, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err == nil {
		t.Error("Dial() should fail after context cancellation and Stop()")
	}
}

// --- 3. Test accepting connections and processing CEF messages ---

func TestTCPServer_AcceptAndProcessSingleCEF(t *testing.T) {
	srv, q := newTestTCPServer(t)

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	addr := srv.listener.Addr().String()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}

	if _, err := conn.Write([]byte(validCEFLine())); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	conn.Close()

	// Poll the queue until the event arrives.
	var event *schema.Event
	ok := waitForCondition(2*time.Second, func() bool {
		event, _ = q.Pop()
		return event != nil
	})
	if !ok {
		t.Fatal("expected an event in the queue, got none within timeout")
	}

	// Verify fields produced by the parser -> normalizer pipeline.
	if event.Source.Product != "TestProduct" {
		t.Errorf("Source.Product = %q, want %q", event.Source.Product, "TestProduct")
	}
	if event.Action != "session.created" {
		t.Errorf("Action = %q, want %q", event.Action, "session.created")
	}
	if event.Severity != 5 {
		t.Errorf("Severity = %d, want 5", event.Severity)
	}
	if event.Outcome != schema.OutcomeSuccess {
		t.Errorf("Outcome = %q, want %q", event.Outcome, schema.OutcomeSuccess)
	}
}

func TestTCPServer_MultipleMessagesOnOneConnection(t *testing.T) {
	srv, q := newTestTCPServer(t)

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	addr := srv.listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}

	const msgCount = 5
	for i := 0; i < msgCount; i++ {
		if _, err := conn.Write([]byte(validCEFLine())); err != nil {
			t.Fatalf("Write() error on message %d: %v", i, err)
		}
	}
	conn.Close()

	received := 0
	waitForCondition(2*time.Second, func() bool {
		if _, err := q.Pop(); err == nil {
			received++
		}
		return received >= msgCount
	})

	if received != msgCount {
		t.Errorf("received %d events, want %d", received, msgCount)
	}
}

func TestTCPServer_MultipleConnections(t *testing.T) {
	srv, q := newTestTCPServer(t)

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	addr := srv.listener.Addr().String()

	const connCount = 3
	for i := 0; i < connCount; i++ {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("Dial() error for conn %d: %v", i, err)
		}
		if _, err := conn.Write([]byte(validCEFLine())); err != nil {
			t.Fatalf("Write() error for conn %d: %v", i, err)
		}
		conn.Close()
	}

	received := 0
	waitForCondition(2*time.Second, func() bool {
		if _, err := q.Pop(); err == nil {
			received++
		}
		return received >= connCount
	})

	if received != connCount {
		t.Errorf("received %d events, want %d", received, connCount)
	}
}

func TestTCPServer_InvalidCEFMessage(t *testing.T) {
	srv, q := newTestTCPServer(t)

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	addr := srv.listener.Addr().String()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}

	// Send a line that is not valid CEF.
	if _, err := conn.Write([]byte("NOT_A_CEF_MESSAGE\n")); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	conn.Close()

	// Wait a reasonable amount and verify nothing was queued.
	time.Sleep(500 * time.Millisecond)

	if _, err := q.Pop(); err == nil {
		t.Error("invalid CEF should not produce a queued event")
	}
}

// --- 4. Test connection limit enforcement (max connections) ---

func TestTCPServer_MaxConnections(t *testing.T) {
	const maxConns = 2

	srv, _ := newTestTCPServer(t, func(cfg *TCPServerConfig) {
		cfg.MaxConnections = maxConns
	})

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	addr := srv.listener.Addr().String()

	// Open maxConns connections and keep them alive.
	conns := make([]net.Conn, 0, maxConns)
	for i := 0; i < maxConns; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("Dial() error for connection %d: %v", i, err)
		}
		// Write a message so the server fully handles the connection.
		if _, err := c.Write([]byte(validCEFLine())); err != nil {
			t.Fatalf("Write() error for connection %d: %v", i, err)
		}
		conns = append(conns, c)
	}

	// Wait until all connections are registered by the server.
	ok := waitForCondition(2*time.Second, func() bool {
		return srv.ActiveConnections() >= maxConns
	})
	if !ok {
		t.Fatalf("ActiveConnections() = %d, want %d", srv.ActiveConnections(), maxConns)
	}

	// Open one more connection; the server should accept then immediately close it.
	extra, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial() error for extra connection: %v", err)
	}
	defer extra.Close()

	// Reading from the rejected connection should yield an error (EOF or reset).
	extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, readErr := extra.Read(buf)
	if readErr == nil {
		t.Error("expected error when reading from rejected connection, got nil")
	}

	// The active count should not have grown past maxConns.
	if srv.ActiveConnections() > maxConns {
		t.Errorf("ActiveConnections() = %d, should not exceed %d", srv.ActiveConnections(), maxConns)
	}

	// Clean up held connections.
	for _, c := range conns {
		c.Close()
	}

	// After closing all clients, active connections should drop to 0.
	ok = waitForCondition(2*time.Second, func() bool {
		return srv.ActiveConnections() == 0
	})
	if !ok {
		t.Errorf("ActiveConnections() = %d after all clients closed, want 0", srv.ActiveConnections())
	}
}

// --- 5. Test metrics collection ---

func TestTCPServer_Metrics_InitiallyZero(t *testing.T) {
	srv, _ := newTestTCPServer(t)

	m := srv.Metrics()

	if m.Connections != 0 {
		t.Errorf("Connections = %d, want 0", m.Connections)
	}
	if m.Received != 0 {
		t.Errorf("Received = %d, want 0", m.Received)
	}
	if m.Parsed != 0 {
		t.Errorf("Parsed = %d, want 0", m.Parsed)
	}
	if m.Queued != 0 {
		t.Errorf("Queued = %d, want 0", m.Queued)
	}
	if m.Errors != 0 {
		t.Errorf("Errors = %d, want 0", m.Errors)
	}
}

func TestTCPServer_Metrics_AfterValidMessages(t *testing.T) {
	srv, _ := newTestTCPServer(t)

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	addr := srv.listener.Addr().String()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}

	const validCount = 3
	for i := 0; i < validCount; i++ {
		if _, err := conn.Write([]byte(validCEFLine())); err != nil {
			t.Fatalf("Write() error: %v", err)
		}
	}
	conn.Close()

	// Wait for all messages to be received.
	ok := waitForCondition(2*time.Second, func() bool {
		return srv.Metrics().Received >= validCount
	})
	if !ok {
		t.Fatalf("timed out waiting for Received >= %d, got %d", validCount, srv.Metrics().Received)
	}

	m := srv.Metrics()

	if m.Connections < 1 {
		t.Errorf("Connections = %d, want >= 1", m.Connections)
	}
	if m.Received != validCount {
		t.Errorf("Received = %d, want %d", m.Received, validCount)
	}
	if m.Parsed != validCount {
		t.Errorf("Parsed = %d, want %d", m.Parsed, validCount)
	}
	if m.Queued != validCount {
		t.Errorf("Queued = %d, want %d", m.Queued, validCount)
	}
	if m.Errors != 0 {
		t.Errorf("Errors = %d, want 0", m.Errors)
	}
}

func TestTCPServer_Metrics_CountsErrors(t *testing.T) {
	srv, _ := newTestTCPServer(t)

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	addr := srv.listener.Addr().String()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}

	// Send a mix of valid and invalid messages.
	const validCount = 2
	const invalidCount = 3

	for i := 0; i < validCount; i++ {
		if _, err := conn.Write([]byte(validCEFLine())); err != nil {
			t.Fatalf("Write() error: %v", err)
		}
	}
	for i := 0; i < invalidCount; i++ {
		if _, err := conn.Write([]byte("GARBAGE_LINE\n")); err != nil {
			t.Fatalf("Write() error: %v", err)
		}
	}
	conn.Close()

	// Wait until all messages have been received.
	totalSent := uint64(validCount + invalidCount)
	ok := waitForCondition(2*time.Second, func() bool {
		return srv.Metrics().Received >= totalSent
	})
	if !ok {
		t.Fatalf("timed out waiting for Received >= %d, got %d", totalSent, srv.Metrics().Received)
	}

	m := srv.Metrics()

	if m.Received != totalSent {
		t.Errorf("Received = %d, want %d", m.Received, totalSent)
	}
	if m.Parsed != validCount {
		t.Errorf("Parsed = %d, want %d", m.Parsed, validCount)
	}
	if m.Queued != validCount {
		t.Errorf("Queued = %d, want %d", m.Queued, validCount)
	}
	if m.Errors != invalidCount {
		t.Errorf("Errors = %d, want %d", m.Errors, invalidCount)
	}
}

func TestTCPServer_ActiveConnections(t *testing.T) {
	srv, _ := newTestTCPServer(t)

	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	addr := srv.listener.Addr().String()

	if srv.ActiveConnections() != 0 {
		t.Fatalf("ActiveConnections() = %d before any dial, want 0", srv.ActiveConnections())
	}

	// Open two connections and keep them alive.
	c1, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial() c1 error: %v", err)
	}
	if _, err := c1.Write([]byte(validCEFLine())); err != nil {
		t.Fatalf("Write() c1 error: %v", err)
	}

	c2, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial() c2 error: %v", err)
	}
	if _, err := c2.Write([]byte(validCEFLine())); err != nil {
		t.Fatalf("Write() c2 error: %v", err)
	}

	ok := waitForCondition(2*time.Second, func() bool {
		return srv.ActiveConnections() >= 2
	})
	if !ok {
		t.Fatalf("ActiveConnections() = %d, want >= 2", srv.ActiveConnections())
	}

	// Close one connection -- count should decrease.
	c1.Close()
	ok = waitForCondition(2*time.Second, func() bool {
		return srv.ActiveConnections() <= 1
	})
	if !ok {
		t.Errorf("ActiveConnections() = %d after closing c1, want <= 1", srv.ActiveConnections())
	}

	// Close the other.
	c2.Close()
	ok = waitForCondition(2*time.Second, func() bool {
		return srv.ActiveConnections() == 0
	})
	if !ok {
		t.Errorf("ActiveConnections() = %d after closing c2, want 0", srv.ActiveConnections())
	}
}

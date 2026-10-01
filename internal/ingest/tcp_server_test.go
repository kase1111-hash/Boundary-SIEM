package ingest

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"strings"
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
	if err := extra.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error: %v", err)
	}
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

// --- 6. Regression tests for framing, shutdown and limits ---

// sendAndClose dials addr, writes payload and closes the connection.
func sendAndClose(t *testing.T, addr, payload string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
}

// sendAndCloseTLS is sendAndClose over TLS; Close sends close_notify.
func sendAndCloseTLS(t *testing.T, addr, payload string) {
	t.Helper()
	// The server uses a throwaway self-signed certificate.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("Dial() error: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
}

// TestTCPServer_FinalLineWithoutNewline is a regression test for the last
// message being dropped when the sender closes without a trailing newline.
func TestTCPServer_FinalLineWithoutNewline(t *testing.T) {
	line := strings.TrimSuffix(validCEFLine(), "\n")
	certFile, keyFile := writeSelfSignedCert(t)

	tests := []struct {
		name       string
		tls        bool
		payload    string
		wantQueued uint64
	}{
		{"two lines, last unterminated", false, line + "\n" + line, 2},
		{"single unterminated line", false, line, 1},
		{"CRLF terminated lines", false, line + "\r\n" + line + "\r\n", 2},
		{"blank keepalive lines are ignored", false, "\n\r\n" + line + "\n\n", 1},
		{"tls: two lines, last unterminated", true, line + "\n" + line, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, q := newTestTCPServer(t, func(cfg *TCPServerConfig) {
				cfg.TLSEnabled = tt.tls
				cfg.TLSCertFile = certFile
				cfg.TLSKeyFile = keyFile
			})
			if err := srv.Start(context.Background()); err != nil {
				t.Fatalf("Start() error: %v", err)
			}
			defer srv.Stop()

			if tt.tls {
				sendAndCloseTLS(t, srv.listener.Addr().String(), tt.payload)
			} else {
				sendAndClose(t, srv.listener.Addr().String(), tt.payload)
			}

			waitForCondition(2*time.Second, func() bool {
				return srv.Metrics().Queued >= tt.wantQueued
			})
			// Give a wrongly counted extra line a chance to show up.
			time.Sleep(50 * time.Millisecond)

			m := srv.Metrics()
			if m.Queued != tt.wantQueued || q.Len() != int(tt.wantQueued) {
				t.Errorf("queued = %d (queue len %d), want %d", m.Queued, q.Len(), tt.wantQueued)
			}
			if m.Received != tt.wantQueued {
				t.Errorf("Received = %d, want %d", m.Received, tt.wantQueued)
			}
			if m.Errors != 0 {
				t.Errorf("Errors = %d, want 0", m.Errors)
			}
		})
	}
}

// E2E round 1: a final line without a newline was dropped silently (no
// metric, no quarantine) when the connection ended with an error instead of
// a clean EOF: a reset (a TLS client closing without reading the session
// tickets), the idle timeout, or Stop.
func TestTCPServer_FinalLineAfterReadError(t *testing.T) {
	line := strings.TrimSuffix(validCEFLine(), "\n")
	certFile, keyFile := writeSelfSignedCert(t)

	tests := []struct {
		name string
		tls  bool
		// end ends the connection after the payload was written.
		end func(t *testing.T, conn net.Conn, srv *TCPServer)
	}{
		{"reset", false, func(t *testing.T, conn net.Conn, _ *TCPServer) { resetConn(t, conn) }},
		{"tls: reset without close_notify", true, func(t *testing.T, conn net.Conn, _ *TCPServer) { resetConn(t, conn) }},
		{"idle timeout", false, func(*testing.T, net.Conn, *TCPServer) {}},
		{"stop", false, func(t *testing.T, _ net.Conn, srv *TCPServer) {
			time.Sleep(100 * time.Millisecond) // the server has read the partial line
			srv.Stop()
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, q := newTestTCPServer(t, func(cfg *TCPServerConfig) {
				cfg.TLSEnabled = tt.tls
				cfg.TLSCertFile = certFile
				cfg.TLSKeyFile = keyFile
				cfg.IdleTimeout = 300 * time.Millisecond
			})
			if err := srv.Start(context.Background()); err != nil {
				t.Fatalf("Start() error: %v", err)
			}
			defer srv.Stop()

			addr := srv.listener.Addr().String()
			raw, err := net.DialTimeout("tcp", addr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			conn := raw
			if tt.tls {
				tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
				if err := tc.Handshake(); err != nil {
					t.Fatal(err)
				}
				conn = tc
			}
			defer raw.Close()
			if _, err := conn.Write([]byte(line + "\n" + line)); err != nil {
				t.Fatal(err)
			}
			tt.end(t, raw, srv)

			if !waitForCondition(3*time.Second, func() bool { return srv.Metrics().Queued >= 2 }) {
				m := srv.Metrics()
				t.Fatalf("queued = %d, received = %d, errors = %d: the unterminated final line was dropped",
					m.Queued, m.Received, m.Errors)
			}
			if q.Len() != 2 {
				t.Errorf("queue len = %d, want 2", q.Len())
			}
		})
	}
}

// resetConn closes conn with SO_LINGER 0, so the peer sees a reset instead
// of a clean FIN.
func resetConn(t *testing.T, conn net.Conn) {
	t.Helper()
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("not a TCP connection: %T", conn)
	}
	if err := tcp.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // let the payload reach the server first
	_ = tcp.Close()
}

// TestTCPServer_StopClosesIdleConnections is a regression test for Stop()
// blocking until every idle client hit IdleTimeout (5 minutes by default).
func TestTCPServer_StopClosesIdleConnections(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)

	tests := []struct {
		name string
		tls  bool
	}{
		{"plain", false},
		{"tls", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, q := newTestTCPServer(t, func(cfg *TCPServerConfig) {
				cfg.IdleTimeout = time.Minute
				cfg.TLSEnabled = tt.tls
				cfg.TLSCertFile = certFile
				cfg.TLSKeyFile = keyFile
			})
			if err := srv.Start(context.Background()); err != nil {
				t.Fatalf("Start() error: %v", err)
			}
			addr := srv.listener.Addr().String()

			const clients = 3
			conns := make([]net.Conn, 0, clients)
			for i := 0; i < clients; i++ {
				var c net.Conn
				var err error
				if tt.tls {
					// The server uses a throwaway self-signed certificate.
					c, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr,
						&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
				} else {
					c, err = net.DialTimeout("tcp", addr, time.Second)
				}
				if err != nil {
					t.Fatalf("Dial() error: %v", err)
				}
				defer c.Close()
				if _, err := c.Write([]byte(validCEFLine())); err != nil {
					t.Fatalf("Write() error: %v", err)
				}
				conns = append(conns, c)
			}
			if !waitForCondition(2*time.Second, func() bool {
				return srv.ActiveConnections() == clients && q.Len() == clients
			}) {
				t.Fatalf("ActiveConnections() = %d, queued = %d, want %d", srv.ActiveConnections(), q.Len(), clients)
			}

			// All clients are now idle; Stop must not wait for IdleTimeout.
			start := time.Now()
			stopWithin(t, srv.Stop, 2*time.Second)
			t.Logf("Stop() took %v with %d idle clients", time.Since(start), clients)

			if n := srv.ActiveConnections(); n != 0 {
				t.Errorf("ActiveConnections() = %d after Stop, want 0", n)
			}
			// The server side is closed, so clients see EOF rather than a timeout.
			for i, c := range conns {
				if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatalf("SetReadDeadline: %v", err)
				}
				if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
					t.Errorf("client %d read after Stop: err = %v, want connection closed", i, err)
				}
			}
		})
	}
}

// TestTCPServer_StopIsIdempotent checks that a second Stop does not panic.
func TestTCPServer_StopIsIdempotent(t *testing.T) {
	srv, _ := newTestTCPServer(t)
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	srv.Stop()
	stopWithin(t, srv.Stop, time.Second)
}

// TestTCPServer_MaxLineLength is a regression test for MaxLineLength not being
// enforced: lines of any length were buffered and parsed.
func TestTCPServer_MaxLineLength(t *testing.T) {
	const maxLen = 1024
	base := strings.TrimSuffix(validCEFLine(), "\n") + " msg="
	// cefLine returns a valid CEF line of exactly n bytes (without newline).
	cefLine := func(n int) string {
		return base + strings.Repeat("x", n-len(base))
	}

	tests := []struct {
		name          string
		first         string
		wantQueued    uint64
		wantOversized uint64
	}{
		{"line at the limit is accepted", cefLine(maxLen), 2, 0},
		{"line one byte over the limit is dropped", cefLine(maxLen + 1), 1, 1},
		{"8 KiB line is dropped", cefLine(8 << 10), 1, 1},
		{"1 MiB line is dropped", cefLine(1 << 20), 1, 1},
		{"CRLF line at the limit is accepted", cefLine(maxLen-1) + "\r", 2, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, q := newTestTCPServer(t, func(cfg *TCPServerConfig) {
				cfg.MaxLineLength = maxLen
			})
			if err := srv.Start(context.Background()); err != nil {
				t.Fatalf("Start() error: %v", err)
			}
			defer srv.Stop()

			// The oversized line is followed by a normal one, which must
			// still be processed: the stream stays in sync.
			sendAndClose(t, srv.listener.Addr().String(), tt.first+"\n"+validCEFLine())

			if !waitForCondition(5*time.Second, func() bool {
				return srv.Metrics().Received >= 2
			}) {
				t.Fatalf("timed out waiting for 2 received lines; metrics=%+v", srv.Metrics())
			}
			waitForCondition(time.Second, func() bool { return srv.Metrics().Queued >= tt.wantQueued })

			m := srv.Metrics()
			if m.Queued != tt.wantQueued || q.Len() != int(tt.wantQueued) {
				t.Errorf("queued = %d (queue len %d), want %d", m.Queued, q.Len(), tt.wantQueued)
			}
			if m.OversizedLines != tt.wantOversized {
				t.Errorf("OversizedLines = %d, want %d", m.OversizedLines, tt.wantOversized)
			}
			if m.Errors != tt.wantOversized {
				t.Errorf("Errors = %d, want %d", m.Errors, tt.wantOversized)
			}
		})
	}
}

// TestTCPServer_SyslogFramedCEF is a regression test for syslog-framed CEF
// ("<PRI>timestamp host CEF:...") being rejected by the TCP listener, and
// checks that parse failures are counted separately.
func TestTCPServer_SyslogFramedCEF(t *testing.T) {
	srv, q := newTestTCPServer(t)
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer srv.Stop()

	header := "<134>" + time.Now().UTC().Format("Jan _2 15:04:05") + " host1 "
	payload := header + validCEFLine() + "garbage line\n"
	sendAndClose(t, srv.listener.Addr().String(), payload)

	if !waitForCondition(2*time.Second, func() bool { return srv.Metrics().Received >= 2 }) {
		t.Fatalf("timed out; metrics=%+v", srv.Metrics())
	}
	var event *schema.Event
	if !waitForCondition(2*time.Second, func() bool {
		event, _ = q.Pop()
		return event != nil
	}) {
		t.Fatalf("syslog-framed CEF was not queued; metrics=%+v", srv.Metrics())
	}
	if event.Source.Host != "host1" {
		t.Errorf("Source.Host = %q, want host1 (from the syslog header)", event.Source.Host)
	}
	m := srv.Metrics()
	if m.Queued != 1 || m.ParseErrors != 1 || m.Errors != 1 {
		t.Errorf("metrics = %+v, want Queued=1 ParseErrors=1 Errors=1", m)
	}
}

// TestTCPServer_ContextCancelClosesConnections checks that cancelling the
// context passed to Start closes idle client connections, with and without
// TLS, instead of leaving them open until IdleTimeout. With TLS the accept
// loop used to block in Accept and never saw the cancellation.
func TestTCPServer_ContextCancelClosesConnections(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)

	for _, useTLS := range []bool{false, true} {
		name := "plain"
		if useTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) {
			srv, q := newTestTCPServer(t, func(cfg *TCPServerConfig) {
				cfg.IdleTimeout = time.Minute
				cfg.TLSEnabled = useTLS
				cfg.TLSCertFile = certFile
				cfg.TLSKeyFile = keyFile
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := srv.Start(ctx); err != nil {
				t.Fatalf("Start() error: %v", err)
			}
			defer stopWithin(t, srv.Stop, 2*time.Second)
			addr := srv.listener.Addr().String()

			var c net.Conn
			var err error
			if useTLS {
				// The server uses a throwaway self-signed certificate.
				c, err = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr,
					&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
			} else {
				c, err = net.DialTimeout("tcp", addr, time.Second)
			}
			if err != nil {
				t.Fatalf("Dial() error: %v", err)
			}
			defer c.Close()
			if _, err := c.Write([]byte(validCEFLine())); err != nil {
				t.Fatalf("Write() error: %v", err)
			}
			if !waitForCondition(2*time.Second, func() bool { return q.Len() == 1 }) {
				t.Fatalf("event not queued; metrics=%+v", srv.Metrics())
			}

			cancel()
			if !waitForCondition(2*time.Second, func() bool { return srv.ActiveConnections() == 0 }) {
				t.Fatalf("ActiveConnections() = %d two seconds after cancel, want 0", srv.ActiveConnections())
			}
		})
	}
}

package ws

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func keyChecker(keys ...string) func(string) bool {
	return func(k string) bool {
		for _, want := range keys {
			if k == want {
				return true
			}
		}
		return false
	}
}

func newTestHub(t *testing.T, cfg Config) (*Hub, *httptest.Server, string) {
	t.Helper()
	hub := NewHub(cfg, nil)
	mux := http.NewServeMux()
	mux.Handle("GET /ws/events", hub)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		hub.Close()
		srv.Close()
	})
	return hub, srv, "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/events"
}

func dial(t *testing.T, url string, header http.Header) *websocket.Conn {
	t.Helper()
	conn, resp, err := websocket.DefaultDialer.Dial(url, header)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("dial %s: %v (status %d)", url, err, status)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func sendJSON(t *testing.T, conn *websocket.Conn, v any) {
	t.Helper()
	if err := conn.WriteJSON(v); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readMsg(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("decode %q: %v", data, err)
	}
	return m
}

// expectClose reads until the server closes and returns the close code and
// reason.
func expectClose(t *testing.T, conn *websocket.Conn) (int, string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, _, err := conn.ReadMessage()
		if err == nil {
			continue
		}
		var ce *websocket.CloseError
		if errors.As(err, &ce) {
			return ce.Code, ce.Text
		}
		t.Fatalf("expected a close frame, got %v", err)
	}
}

func authed(t *testing.T, url, key string) *websocket.Conn {
	t.Helper()
	conn := dial(t, url, nil)
	sendJSON(t, conn, map[string]string{"type": "auth", "api_key": key})
	if m := readMsg(t, conn); m["type"] != TypeAuthOK {
		t.Fatalf("first message = %v, want auth_ok", m)
	}
	return conn
}

func waitClients(t *testing.T, hub *Hub, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for hub.Clients() != n {
		if time.Now().After(deadline) {
			t.Fatalf("clients = %d, want %d", hub.Clients(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHub_AuthPingAndBroadcast(t *testing.T) {
	hub, _, url := newTestHub(t, Config{AuthEnabled: true, APIKeyValid: keyChecker("k1")})
	conn := authed(t, url, "k1")

	sendJSON(t, conn, map[string]string{"type": "ping"})
	if m := readMsg(t, conn); m["type"] != TypePong {
		t.Fatalf("ping answered with %v, want pong", m)
	}

	waitClients(t, hub, 1)
	alert := map[string]any{"id": "a-1", "rule_id": "r", "severity": "high", "status": "new"}
	if err := hub.Broadcast(TypeAlert, alert); err != nil {
		t.Fatal(err)
	}
	m := readMsg(t, conn)
	data, _ := m["data"].(map[string]any)
	if m["type"] != TypeAlert || data["id"] != "a-1" {
		t.Fatalf("broadcast = %v", m)
	}

	// Unknown and non-JSON frames are ignored, the connection stays up.
	sendJSON(t, conn, map[string]string{"type": "subscribe"})
	if err := conn.WriteMessage(websocket.TextMessage, []byte("not json")); err != nil {
		t.Fatal(err)
	}
	sendJSON(t, conn, map[string]string{"type": "ping"})
	if m := readMsg(t, conn); m["type"] != TypePong {
		t.Fatalf("after ignored frames got %v, want pong", m)
	}

	if mt := hub.Metrics(); mt.Clients != 1 || mt.MessagesSent < 3 {
		t.Errorf("metrics = %+v", mt)
	}
}

func TestHub_AuthFailures(t *testing.T) {
	hub, _, url := newTestHub(t, Config{
		AuthEnabled: true,
		APIKeyValid: keyChecker("k1"),
		AuthTimeout: 300 * time.Millisecond,
	})

	tests := []struct {
		name   string
		send   func(*websocket.Conn)
		reason string
	}{
		{"invalid key", func(c *websocket.Conn) { sendJSON(t, c, map[string]string{"type": "auth", "api_key": "nope"}) }, ReasonInvalidKey},
		{"empty key", func(c *websocket.Conn) { sendJSON(t, c, map[string]string{"type": "auth", "api_key": ""}) }, ReasonMissingKey},
		{"no key field", func(c *websocket.Conn) { sendJSON(t, c, map[string]string{"type": "auth"}) }, ReasonMissingKey},
		{"not an auth message", func(c *websocket.Conn) { sendJSON(t, c, map[string]string{"type": "ping"}) }, ReasonAuthRequired},
		{"binary frame", func(c *websocket.Conn) { _ = c.WriteMessage(websocket.BinaryMessage, []byte("{}")) }, ReasonAuthRequired},
		{"silence", func(*websocket.Conn) {}, ReasonAuthRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := dial(t, url, nil)
			tt.send(conn)
			code, reason := expectClose(t, conn)
			if code != CloseAuthFailed || reason != tt.reason {
				t.Errorf("close = %d %q, want %d %q", code, reason, CloseAuthFailed, tt.reason)
			}
		})
	}
	if hub.Clients() != 0 {
		t.Errorf("clients = %d after failed auth", hub.Clients())
	}
	if got := hub.Metrics().AuthFailures; got != uint64(len(tests)) {
		t.Errorf("auth failures = %d, want %d", got, len(tests))
	}
}

func TestHub_AuthDisabledAcceptsAnyKey(t *testing.T) {
	_, _, url := newTestHub(t, Config{AuthEnabled: false})
	authed(t, url, "")
}

func TestHub_OriginPolicy(t *testing.T) {
	_, srv, url := newTestHub(t, Config{CORSEnabled: true, AllowedOrigins: []string{"https://soc.example.com"}})

	for _, tt := range []struct {
		origin string
		ok     bool
	}{
		{"", true},
		{srv.URL, true}, // same origin
		{"https://soc.example.com", true},
		{"https://evil.example.com", false},
		{"null", false},
	} {
		h := http.Header{}
		if tt.origin != "" {
			h.Set("Origin", tt.origin)
		}
		conn, resp, err := websocket.DefaultDialer.Dial(url, h)
		if conn != nil {
			_ = conn.Close()
		}
		if tt.ok && err != nil {
			t.Errorf("origin %q refused: %v", tt.origin, err)
		}
		if !tt.ok && (err == nil || resp == nil || resp.StatusCode != http.StatusForbidden) {
			t.Errorf("origin %q accepted (err %v)", tt.origin, err)
		}
	}

	// CORS disabled: only same-origin browsers.
	_, srv2, url2 := newTestHub(t, Config{CORSEnabled: false, AllowedOrigins: []string{"*"}})
	if _, _, err := websocket.DefaultDialer.Dial(url2, http.Header{"Origin": {"https://other.example.com"}}); err == nil {
		t.Error("cross-origin accepted with CORS disabled")
	}
	if c, _, err := websocket.DefaultDialer.Dial(url2, http.Header{"Origin": {srv2.URL}}); err != nil {
		t.Errorf("same origin refused with CORS disabled: %v", err)
	} else {
		_ = c.Close()
	}

	// Wildcard.
	_, _, url3 := newTestHub(t, Config{CORSEnabled: true, AllowedOrigins: []string{"*"}})
	if c, _, err := websocket.DefaultDialer.Dial(url3, http.Header{"Origin": {"https://any.example.com"}}); err != nil {
		t.Errorf("wildcard origin refused: %v", err)
	} else {
		_ = c.Close()
	}
}

func TestHub_MaxClients(t *testing.T) {
	_, _, url := newTestHub(t, Config{MaxClients: 1})
	authed(t, url, "")
	_, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second client: err %v, want 503", err)
	}
}

// TestHub_SlowClientDropped checks a client that does not read is
// disconnected and never blocks Broadcast.
func TestHub_SlowClientDropped(t *testing.T) {
	hub, _, url := newTestHub(t, Config{SendQueueSize: 4, WriteTimeout: 200 * time.Millisecond})
	slow := authed(t, url, "")
	fast := authed(t, url, "")
	waitClients(t, hub, 2)

	big := strings.Repeat("x", 256*1024)
	start := time.Now()
	for i := 0; i < 200 && hub.Metrics().SlowClientsDropped == 0; i++ {
		if err := hub.Broadcast(TypeStats, map[string]string{"blob": big}); err != nil {
			t.Fatal(err)
		}
		// Keep the fast client drained.
		_ = fast.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, _, err := fast.ReadMessage(); err != nil {
			t.Fatalf("fast client: %v", err)
		}
	}
	if hub.Metrics().SlowClientsDropped == 0 {
		t.Fatal("slow client was never dropped")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("broadcasting took %v", elapsed)
	}
	waitClients(t, hub, 1)
	_ = slow.Close()

	// The fast client still works.
	sendJSON(t, fast, map[string]string{"type": "ping"})
	for {
		if m := readMsg(t, fast); m["type"] == TypePong {
			break
		}
	}
}

func TestHub_CloseDisconnectsClients(t *testing.T) {
	hub, _, url := newTestHub(t, Config{})
	conn := authed(t, url, "")
	pending := dial(t, url, nil) // connected, not yet authenticated
	waitClients(t, hub, 1)

	done := make(chan struct{})
	go func() {
		hub.Close()
		close(done)
	}()
	if code, _ := expectClose(t, conn); code != websocket.CloseGoingAway {
		t.Errorf("close code = %d, want 1001", code)
	}
	if code, _ := expectClose(t, pending); code != websocket.CloseGoingAway {
		t.Errorf("pending close code = %d, want 1001", code)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
	hub.Close() // idempotent

	_, resp, err := websocket.DefaultDialer.Dial(url, nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("dial after Close: err %v, want 503", err)
	}
	if err := hub.Broadcast(TypeAlert, map[string]string{}); err != nil {
		t.Errorf("Broadcast after Close: %v", err)
	}
}

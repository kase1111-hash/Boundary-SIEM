package tui

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"boundary-siem/internal/tui/api"
	"boundary-siem/internal/tui/scenes"
)

// ---------------------------------------------------------------------------
// Review follow-ups for R19: the API key must not follow redirects to another
// origin, server-supplied text must not reach the terminal raw, and a server
// that answers /health with an HTTP error is not "unreachable".
// ---------------------------------------------------------------------------

// Go's http.Client copies custom headers such as X-API-Key on every redirect
// (it only strips Authorization/Cookie across domains), so a redirect to
// another host or a downgrade to http would hand the key to a third party.
func TestAPIKeyNotForwardedOnCrossOriginRedirect(t *testing.T) {
	var mu sync.Mutex
	var leaked []string

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		leaked = append(leaked, r.Header.Get(api.DefaultAuthHeader))
		mu.Unlock()
		encodeJSON(t, w, map[string]any{"status": "healthy", "queue_capacity": 1})
	}))
	defer other.Close()
	_, otherPort, err := net.SplitHostPort(other.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// "localhost" is a different host than the 127.0.0.1 origin.
		http.Redirect(w, r, "http://localhost:"+otherPort+r.URL.Path, http.StatusFound)
	}))
	defer origin.Close()

	client := api.NewClient(origin.URL, api.WithAPIKey(testAPIKey))
	if _, err := client.GetHealth(); err != nil {
		t.Fatalf("GetHealth: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(leaked) == 0 {
		t.Fatal("redirect target was not requested")
	}
	for _, v := range leaked {
		if v != "" {
			t.Errorf("API key %q was sent to the redirect target on another origin", v)
		}
	}
}

func TestAPIKeyKeptOnSameOriginRedirect(t *testing.T) {
	var got string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old/health" {
			http.Redirect(w, r, "/health", http.StatusMovedPermanently)
			return
		}
		got = r.Header.Get(api.DefaultAuthHeader)
		encodeJSON(t, w, map[string]any{"status": "healthy", "queue_capacity": 1})
	}))
	defer ts.Close()

	if _, err := api.NewClient(ts.URL+"/old", api.WithAPIKey(testAPIKey)).GetHealth(); err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	if got != testAPIKey {
		t.Errorf("same-origin redirect lost the API key: got %q", got)
	}
}

// A reverse proxy answers errors with multi-line HTML; a hostile server can
// embed terminal escape sequences. Neither may reach the TUI verbatim.
func TestServerErrorTextIsSanitized(t *testing.T) {
	const nginx502 = "<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n" +
		"<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n</body>\r\n</html>\r\n"
	const escape = "denied\x1b]52;c;cHduZWQ=\x07\x1b[2J\nsecond line"

	tests := []struct {
		name    string
		status  int
		body    string
		want    string
		notWant []string
	}{
		{
			name:    "html error page",
			status:  http.StatusBadGateway,
			body:    nginx502,
			want:    "502",
			notWant: []string{"<html>", "\n", "\r"},
		},
		{
			name:    "escape sequences",
			status:  http.StatusUnauthorized,
			body:    escape,
			want:    "denied",
			notWant: []string{"\x1b", "\x07", "\n"},
		},
		{
			name:    "json escape sequences",
			status:  http.StatusUnauthorized,
			body:    `{"error":"bad\u001b[31m key\nnext"}`,
			want:    "bad",
			notWant: []string{"\x1b", "\n"},
		},
		{
			name:   "rate limiter message field",
			status: http.StatusTooManyRequests,
			body:   `{"code":"RATE_LIMITED","message":"too many requests","retry_after":3}`,
			want:   "too many requests",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				writeBody(t, w, tt.body)
			}))
			defer ts.Close()

			resp, err := api.NewClient(ts.URL).GetEvents(10)
			if err != nil {
				t.Fatalf("GetEvents: %v", err)
			}
			if !strings.Contains(resp.Error, tt.want) {
				t.Errorf("Error = %q, want it to contain %q", resp.Error, tt.want)
			}
			for _, s := range tt.notWant {
				if strings.Contains(resp.Error, s) {
					t.Errorf("Error = %q must not contain %q", resp.Error, s)
				}
			}

			e := scenes.NewEventsScene(api.NewClient(ts.URL))
			e, _ = e.Update(runCmd(t, e.Init()))
			if view := e.View(); strings.Contains(view, "\x1b]") || strings.Contains(view, "\x07") {
				t.Errorf("events view contains raw escape sequences: %q", view)
			}
		})
	}
}

func TestHealthComponentsAreSanitized(t *testing.T) {
	srv := newAuthServer(t, api.DefaultAuthHeader, testAPIKey)
	srv.setHealth(map[string]any{
		"status": "healthy", "queue_depth": 0, "queue_capacity": 10, "uptime_seconds": 1,
		"components": map[string]any{
			"cef_udp":          map[string]any{"status": "up\x1b[2J", "message": "line1\nline2\x1b]0;title\x07"},
			"evil\x1b]0;x\x07": "up",
		},
	})
	stats, err := api.NewClient(srv.URL, api.WithAPIKey(testAPIKey)).GetStats()
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	d := scenes.NewDashboardScene(api.NewClient(srv.URL, api.WithAPIKey(testAPIKey)))
	d, _ = d.Update(runCmd(t, d.Init()))
	view := d.View()
	for _, s := range []string{"\x1b[2J", "\x1b]0;", "\x07", "line1\nline2"} {
		if strings.Contains(view, s) {
			t.Errorf("dashboard view contains server-supplied control text %q", s)
		}
	}
	if got := stats.Components["cef_udp"].Status; got != "up" {
		t.Errorf("cef_udp status = %q, want %q", got, "up")
	}
}

// /health answering with an HTTP error means the server is reachable but
// unhealthy (wrong -server port, proxy error, ...), not "unreachable".
func TestHealthHTTPErrorIsNotUnreachable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	stats, err := api.NewClient(ts.URL).GetStats()
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.Connected {
		t.Error("Connected must stay false when /health fails")
	}
	if !stats.Reachable {
		t.Error("Reachable must be true when the server answered")
	}

	d := scenes.NewDashboardScene(api.NewClient(ts.URL))
	d, _ = d.Update(runCmd(t, d.Init()))
	view := d.View()
	if strings.Contains(strings.ToLower(view), "unreachable") {
		t.Errorf("server that answered HTTP 404 shown as unreachable:\n%s", view)
	}
	if !strings.Contains(view, "404") {
		t.Errorf("dashboard should show the HTTP status:\n%s", view)
	}

	s := scenes.NewSystemScene(api.NewClient(ts.URL))
	s, _ = s.Update(runCmd(t, s.Init()))
	if view := s.View(); strings.Contains(view, "Not connected") {
		t.Errorf("system view shows a responding server as not connected:\n%s", view)
	}
}

package tui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"boundary-siem/internal/tui/api"

	tea "github.com/charmbracelet/bubbletea"
)

// E2E round 1: in a 140x45 terminal the System tab was taller than the
// window, so the tab bar ("1 Dashboard 2 Events 3 System") scrolled off the
// top. The header and footer must stay on screen and the scene scroll.
func TestSystemTabKeepsTabBarVisible(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			encodeJSON(t, w, api.HealthResponse{Status: "healthy", QueueDepth: 1, QueueCapacity: 100, UptimeSeconds: 60})
		case "/api/system/dreaming":
			encodeJSON(t, w, api.DreamingResponse{Status: "active", Activity: "ingesting", Description: "Processing events"})
		case "/metrics":
			writeBody(t, w, "siem_queue_pushed_total 5\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	m := New(ts.URL)
	m.Update(tea.WindowSizeMsg{Width: 140, Height: 30})
	m.Update(keyMsg("3"))
	m.Update(m.system.Init()()) // the scene's first fetch

	full := m.system.View()
	if n := strings.Count(full, "\n") + 1; n <= 30 {
		t.Fatalf("system scene is only %d lines; the test needs one taller than the window", n)
	}

	check := func(when string) string {
		t.Helper()
		view := m.View()
		lines := strings.Split(view, "\n")
		if len(lines) > 30 {
			t.Errorf("%s: view has %d lines, more than the 30-row window", when, len(lines))
		}
		if !strings.Contains(lines[0], "1 Dashboard") || !strings.Contains(lines[0], "3 System") {
			t.Errorf("%s: first line %q is not the tab bar", when, lines[0])
		}
		if !strings.Contains(lines[len(lines)-1], "[q] Quit") {
			t.Errorf("%s: last line %q is not the footer", when, lines[len(lines)-1])
		}
		return view
	}

	top := check("top")
	if !strings.Contains(top, "more line(s) (↓/j to scroll)") {
		t.Error("clipped view does not say that more lines follow")
	}
	for i := 0; i < 100; i++ {
		m.Update(keyMsg("j"))
	}
	bottom := check("scrolled to the end")
	if bottom == top || !strings.Contains(bottom, "Last updated") {
		t.Error("scrolling down did not reveal the end of the scene")
	}
	m.Update(tea.KeyMsg{Type: tea.KeyHome})
	if again := check("home"); again != top {
		t.Error("home did not return to the top")
	}
}

func TestClipLines(t *testing.T) {
	content := "a\nb\nc\nd\ne"
	if got, off := clipLines(content, 10, 3); got != content || off != 0 {
		t.Errorf("content that fits = %q, %d", got, off)
	}
	got, off := clipLines(content, 3, 99)
	if off != 2 || !strings.HasSuffix(got, "\ne") || strings.Count(got, "\n") != 2 {
		t.Errorf("clamped clip = %q, %d, want the last 3 lines with offset 2", got, off)
	}
}

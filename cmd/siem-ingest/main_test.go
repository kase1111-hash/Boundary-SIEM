package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// E2E round 2: the deploy artifacts passed "--config <file>" and used a
// "health" command for the container HEALTHCHECK, which no binary
// understood (siem-ingest ignored its arguments; the TUI started instead).

func TestParseArgs(t *testing.T) {
	for _, tt := range []struct {
		args       []string
		wantConfig string
		wantHealth bool
		wantErr    bool
	}{
		{args: nil},
		{args: []string{"-config", "/etc/boundary-siem/config.yaml"}, wantConfig: "/etc/boundary-siem/config.yaml"},
		{args: []string{"--config=/etc/x.yaml"}, wantConfig: "/etc/x.yaml"},
		{args: []string{"health"}, wantHealth: true},
		{args: []string{"-config", "/etc/x.yaml", "health"}, wantConfig: "/etc/x.yaml", wantHealth: true},
		{args: []string{"health", "-config", "/etc/y.yaml"}, wantConfig: "/etc/y.yaml", wantHealth: true},
		{args: []string{"serve"}, wantErr: true},
		{args: []string{"health", "now"}, wantErr: true},
		{args: []string{"health", "-url", "http://example.com/"}, wantErr: true},
		{args: []string{"-bogus"}, wantErr: true},
	} {
		c, err := parseArgs(tt.args, &bytes.Buffer{})
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseArgs(%q) succeeded, want an error", tt.args)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseArgs(%q) error = %v", tt.args, err)
			continue
		}
		if c.configPath != tt.wantConfig || c.health != tt.wantHealth {
			t.Errorf("parseArgs(%q) = %+v", tt.args, c)
		}
	}
}

func TestDispatchUnknownCommandExits2(t *testing.T) {
	var stderr bytes.Buffer
	if code := dispatch([]string{"serve", "--config", "x"}, &bytes.Buffer{}, &stderr); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "serve"`) {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// configFor writes a configuration file whose server.http_port is the port
// of srv.
func configFor(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  http_port: "+port+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHealthCommand(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"status":"degraded"}`))
	}))
	defer healthy.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer failing.Close()

	var stdout, stderr bytes.Buffer
	if code := dispatch([]string{"-config", configFor(t, healthy), "health"}, &stdout, &stderr); code != 0 {
		t.Errorf("health of a serving instance = %d (%s), want 0", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "degraded" {
		t.Errorf("stdout = %q, want the reported status", stdout.String())
	}
	if code := dispatch([]string{"health", "-config", configFor(t, failing)}, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 {
		t.Errorf("health answering 503 = %d, want 1", code)
	}

	// Nothing listening.
	stopped := httptest.NewServer(http.NotFoundHandler())
	cfg := configFor(t, stopped)
	stopped.Close()
	if code := dispatch([]string{"-config", cfg, "health"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 {
		t.Errorf("health with nothing listening = %d, want 1", code)
	}

	// A -config file that does not exist is an error, not the defaults.
	if code := dispatch([]string{"-config", filepath.Join(t.TempDir(), "missing.yaml"), "health"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 {
		t.Errorf("health with a missing -config file = %d, want 1", code)
	}
}

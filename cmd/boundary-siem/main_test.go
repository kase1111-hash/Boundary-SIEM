package main

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"

	"boundary-siem/internal/tui/api"
)

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		wantServer string
		wantKey    string
		wantHeader string
		wantErr    bool
	}{
		{
			name:       "defaults",
			wantServer: "http://localhost:8080",
			wantHeader: api.DefaultAuthHeader,
		},
		{
			name:       "api key flag",
			args:       []string{"-api-key", "flag-key"},
			wantServer: "http://localhost:8080",
			wantKey:    "flag-key",
			wantHeader: api.DefaultAuthHeader,
		},
		{
			name:       "api key from environment",
			env:        map[string]string{"SIEM_API_KEY": "env-key"},
			wantServer: "http://localhost:8080",
			wantKey:    "env-key",
			wantHeader: api.DefaultAuthHeader,
		},
		{
			name:       "flag overrides environment",
			args:       []string{"-api-key=flag-key"},
			env:        map[string]string{"SIEM_API_KEY": "env-key"},
			wantServer: "http://localhost:8080",
			wantKey:    "flag-key",
			wantHeader: api.DefaultAuthHeader,
		},
		{
			name:       "custom header from flag",
			args:       []string{"-api-key-header", "X-Custom", "-s", "https://siem.example.com"},
			wantServer: "https://siem.example.com",
			wantHeader: "X-Custom",
		},
		{
			name:       "custom header from environment",
			env:        map[string]string{"SIEM_API_KEY_HEADER": "X-Env-Header"},
			wantServer: "http://localhost:8080",
			wantHeader: "X-Env-Header",
		},
		{
			name:    "server URL without scheme is rejected",
			args:    []string{"-server", "localhost:8080"},
			wantErr: true,
		},
		{
			name:    "unsupported scheme is rejected",
			args:    []string{"-server", "ftp://localhost"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			opts, err := parseFlags(tt.args, envFrom(tt.env), &stderr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got options %+v", opts)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFlags: %v", err)
			}
			if opts.serverURL != tt.wantServer {
				t.Errorf("serverURL = %q, want %q", opts.serverURL, tt.wantServer)
			}
			if opts.apiKey != tt.wantKey {
				t.Errorf("apiKey = %q, want %q", opts.apiKey, tt.wantKey)
			}
			if opts.apiKeyHeader != tt.wantHeader {
				t.Errorf("apiKeyHeader = %q, want %q", opts.apiKeyHeader, tt.wantHeader)
			}
		})
	}
}

// The usage text must not print the API key taken from the environment.
func TestParseFlagsHelpDoesNotLeakKey(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseFlags([]string{"-h"}, envFrom(map[string]string{"SIEM_API_KEY": "sk_secret_value"}), &stderr)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("expected flag.ErrHelp, got %v", err)
	}
	out := stderr.String()
	if strings.Contains(out, "sk_secret_value") {
		t.Errorf("usage output leaks the API key:\n%s", out)
	}
	for _, want := range []string{"-api-key", "SIEM_API_KEY"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage output should mention %q:\n%s", want, out)
		}
	}
}

func TestInsecureKeyWarning(t *testing.T) {
	tests := []struct {
		server string
		key    string
		warn   bool
	}{
		{"http://siem.example.com:8080", "k", true},
		{"https://siem.example.com", "k", false},
		{"http://localhost:8080", "k", false},
		{"http://127.0.0.1:8080", "k", false},
		{"http://[::1]:8080", "k", false},
		{"http://siem.example.com:8080", "", false},
	}
	for _, tt := range tests {
		got := insecureKeyWarning(&options{serverURL: tt.server, apiKey: tt.key}) != ""
		if got != tt.warn {
			t.Errorf("insecureKeyWarning(%q, key=%q) = %v, want %v", tt.server, tt.key, got, tt.warn)
		}
	}
}

func TestClientOptions(t *testing.T) {
	if got := clientOptions(&options{}); len(got) != 0 {
		t.Errorf("expected no client options without a key, got %d", len(got))
	}
	if got := clientOptions(&options{apiKey: "k", apiKeyHeader: "X-API-Key"}); len(got) != 2 {
		t.Errorf("expected key and header options, got %d", len(got))
	}
}

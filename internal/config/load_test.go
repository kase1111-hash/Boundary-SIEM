package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoad_EnvOverridesWithoutConfigFile is the regression test for env
// overrides being ignored when no config file exists: env-only deployments
// (containers) could not set the port or enable authentication.
func TestLoad_EnvOverridesWithoutConfigFile(t *testing.T) {
	t.Setenv("SIEM_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("SIEM_HTTP_PORT", "8099")
	t.Setenv("SIEM_API_KEY", "envkey123")
	t.Setenv("CLICKHOUSE_PASSWORD", "s3cret")
	t.Setenv("SIEM_STORAGE_ENABLED", "true")
	t.Setenv("SIEM_RULES_DIR", "/var/lib/siem/rules")
	t.Setenv("SIEM_SEED_RULES_DIR", "/usr/share/boundary-siem/rules")
	t.Setenv("SIEM_SHUTDOWN_TIMEOUT", "5s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.HTTPPort != 8099 {
		t.Errorf("HTTPPort = %d, want 8099", cfg.Server.HTTPPort)
	}
	if !cfg.Auth.Enabled {
		t.Error("Auth.Enabled = false, want true when SIEM_API_KEY is set")
	}
	if len(cfg.Auth.APIKeys) != 1 || cfg.Auth.APIKeys[0] != "envkey123" {
		t.Errorf("APIKeys = %v, want [envkey123]", cfg.Auth.APIKeys)
	}
	if cfg.Storage.ClickHouse.Password != "s3cret" {
		t.Errorf("ClickHouse password = %q, want s3cret", cfg.Storage.ClickHouse.Password)
	}
	if !cfg.Storage.Enabled {
		t.Error("Storage.Enabled = false, want true")
	}
	if cfg.Correlation.RulesDir != "/var/lib/siem/rules" {
		t.Errorf("RulesDir = %q, want /var/lib/siem/rules", cfg.Correlation.RulesDir)
	}
	if cfg.Correlation.SeedRulesDir != "/usr/share/boundary-siem/rules" {
		t.Errorf("SeedRulesDir = %q, want /usr/share/boundary-siem/rules", cfg.Correlation.SeedRulesDir)
	}
	if cfg.Server.ShutdownTimeout != 5*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 5s", cfg.Server.ShutdownTimeout)
	}
}

// E2E round 1: an environment-only deployment could not move or disable the
// CEF listeners, so a second instance failed with "Port 5515 is not
// available".
func TestLoad_CEFListenerEnvOverrides(t *testing.T) {
	t.Setenv("SIEM_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("SIEM_CEF_TCP_ADDRESS", ":5525")
	t.Setenv("SIEM_CEF_UDP_ENABLED", "false")
	t.Setenv("SIEM_CEF_UDP_ADDRESS", ":5524")
	t.Setenv("SIEM_CEF_DTLS_ENABLED", "true")
	t.Setenv("SIEM_CEF_DTLS_ADDRESS", " 127.0.0.1:5526 ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cef := cfg.Ingest.CEF
	if !cef.TCP.Enabled || cef.TCP.Address != ":5525" {
		t.Errorf("TCP = enabled %v at %q, want enabled at :5525", cef.TCP.Enabled, cef.TCP.Address)
	}
	if cef.UDP.Enabled || cef.UDP.Address != ":5524" {
		t.Errorf("UDP = enabled %v at %q, want disabled, :5524", cef.UDP.Enabled, cef.UDP.Address)
	}
	if !cef.DTLS.Enabled || cef.DTLS.Address != "127.0.0.1:5526" {
		t.Errorf("DTLS = enabled %v at %q, want enabled at 127.0.0.1:5526", cef.DTLS.Enabled, cef.DTLS.Address)
	}

	t.Setenv("SIEM_CEF_TCP_ENABLED", "0")
	t.Setenv("SIEM_CEF_UDP_ENABLED", "maybe") // invalid: ignored
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Ingest.CEF.TCP.Enabled {
		t.Error("SIEM_CEF_TCP_ENABLED=0 left the TCP listener enabled")
	}
	if cfg.Ingest.CEF.UDP.Enabled != DefaultConfig().Ingest.CEF.UDP.Enabled {
		t.Error("an invalid SIEM_CEF_UDP_ENABLED changed the setting")
	}
}

func TestLoad_FileThenEnvOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `
server:
  http_port: 9090
  shutdown_timeout: 6s
auth:
  enabled: true
  api_keys: [file-key]
alerting:
  dedup_window: 1m
  notifications:
    channels:
      - name: default
        type: webhook
        url: "https://hooks.example.com/${TEST_HOOK_TOKEN}"
        headers:
          Authorization: "Bearer ${TEST_HOOK_SECRET}"
      - name: pager
        type: pagerduty
        routing_key: "${TEST_ROUTING_KEY}"
        escalation_only: true
websocket:
  enabled: false
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIEM_CONFIG_PATH", path)
	t.Setenv("SIEM_API_KEY", "env-key")
	t.Setenv("TEST_HOOK_TOKEN", "tok$en")
	t.Setenv("TEST_HOOK_SECRET", "hook-secret")
	t.Setenv("TEST_ROUTING_KEY", "rk-123")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Server.HTTPPort != 9090 {
		t.Errorf("HTTPPort = %d, want 9090 from file", cfg.Server.HTTPPort)
	}
	if cfg.Server.ShutdownTimeout != 6*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 6s", cfg.Server.ShutdownTimeout)
	}
	if got := cfg.Auth.APIKeys; len(got) != 2 || got[0] != "file-key" || got[1] != "env-key" {
		t.Errorf("APIKeys = %v, want [file-key env-key]", got)
	}
	if cfg.Alerting.DedupWindow != time.Minute {
		t.Errorf("Alerting.DedupWindow = %v, want 1m", cfg.Alerting.DedupWindow)
	}
	if cfg.WebSocket.Enabled {
		t.Error("WebSocket.Enabled = true, want false from file")
	}
	// Defaults survive for keys the file does not set.
	if cfg.WebSocket.MaxClients != 100 {
		t.Errorf("WebSocket.MaxClients = %d, want default 100", cfg.WebSocket.MaxClients)
	}

	chans := cfg.Alerting.Notifications.Channels
	if len(chans) != 2 {
		t.Fatalf("channels = %d, want 2", len(chans))
	}
	if chans[0].URL != "https://hooks.example.com/tok$en" {
		t.Errorf("webhook url = %q, want the expanded token", chans[0].URL)
	}
	if chans[0].Headers["Authorization"] != "Bearer hook-secret" {
		t.Errorf("webhook header = %q, want expanded secret", chans[0].Headers["Authorization"])
	}
	if chans[1].RoutingKey != "rk-123" || !chans[1].EscalationOnly {
		t.Errorf("pagerduty channel = %+v, want routing key rk-123 and escalation_only", chans[1])
	}
}

func TestLoad_InvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("server: [not a map"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIEM_CONFIG_PATH", path)
	if _, err := Load(); err == nil {
		t.Fatal("Load() succeeded on malformed YAML, want error")
	}
}

func TestExpandEnvRefs(t *testing.T) {
	t.Setenv("EXPAND_A", "alpha")
	tests := []struct{ in, want string }{
		{"", ""},
		{"plain", "plain"},
		{"${EXPAND_A}", "alpha"},
		{"x-${EXPAND_A}-y", "x-alpha-y"},
		{"$EXPAND_A", "$EXPAND_A"},       // only ${NAME} is expanded
		{"pa$$word", "pa$$word"},         // literal dollars survive
		{"${EXPAND_UNSET_VAR}", ""},      // unset variables expand to ""
		{"${not valid}", "${not valid}"}, // not a variable reference
	}
	for _, tt := range tests {
		if got := expandEnvRefs(tt.in); got != tt.want {
			t.Errorf("expandEnvRefs(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEnvDurationOverride(t *testing.T) {
	cfg := DefaultConfig()
	want := cfg.Server.ShutdownTimeout

	t.Setenv("SIEM_SHUTDOWN_TIMEOUT", "soon")
	cfg.applyEnvOverrides()
	if cfg.Server.ShutdownTimeout != want {
		t.Errorf("invalid duration changed ShutdownTimeout to %v", cfg.Server.ShutdownTimeout)
	}

	t.Setenv("SIEM_SHUTDOWN_TIMEOUT", "-3s")
	cfg.applyEnvOverrides()
	if cfg.Server.ShutdownTimeout != want {
		t.Errorf("negative duration changed ShutdownTimeout to %v", cfg.Server.ShutdownTimeout)
	}

	t.Setenv("SIEM_SHUTDOWN_TIMEOUT", " 4s ")
	cfg.applyEnvOverrides()
	if cfg.Server.ShutdownTimeout != 4*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 4s", cfg.Server.ShutdownTimeout)
	}
}

func TestValidate_ShutdownTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.ShutdownTimeout = 0
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() accepted a zero shutdown_timeout")
	}
}

func TestDefaultConfig_WiringDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.ShutdownTimeout <= 0 || cfg.Server.ShutdownTimeout >= 10*time.Second {
		t.Errorf("ShutdownTimeout = %v, want positive and below Docker's 10s grace period", cfg.Server.ShutdownTimeout)
	}
	if cfg.Correlation.RulesDir == "" {
		t.Error("Correlation.RulesDir is empty")
	}
	if !cfg.WebSocket.Enabled || cfg.WebSocket.MaxClients <= 0 || cfg.WebSocket.SendQueueSize <= 0 || cfg.WebSocket.WriteTimeout <= 0 {
		t.Errorf("WebSocket defaults = %+v", cfg.WebSocket)
	}
	if cfg.Alerting.DedupWindow <= 0 || cfg.Alerting.EscalationInterval <= 0 {
		t.Errorf("Alerting defaults = %+v", cfg.Alerting)
	}
	if cfg.Ingest.CEF.DTLS.MaxConnections <= 0 {
		t.Errorf("DTLS.MaxConnections = %d, want positive", cfg.Ingest.CEF.DTLS.MaxConnections)
	}
	exempt := map[string]bool{}
	for _, p := range cfg.RateLimit.ExemptPaths {
		exempt[p] = true
	}
	for _, p := range []string{"/health", "/ready", "/metrics"} {
		if !exempt[p] {
			t.Errorf("rate limit exempt paths %v miss %s", cfg.RateLimit.ExemptPaths, p)
		}
	}
}

// TestNewSecretsManager_FileDir checks that secrets.file_secrets_dir (and
// SIEM_SECRETS_DIR) reach the file provider; it used to read /etc/secrets
// whatever was configured.
func TestNewSecretsManager_FileDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wiring_test_secret") /* the file provider lowercases keys */, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIEM_SECRETS_DIR", dir)
	t.Setenv("SIEM_SECRETS_FILE_ENABLED", "true")

	cfg := DefaultConfig()
	cfg.Secrets.EnableEnv = false
	cfg.applyEnvOverrides()
	if cfg.Secrets.FileSecretsDir != dir {
		t.Fatalf("FileSecretsDir = %q, want %q", cfg.Secrets.FileSecretsDir, dir)
	}

	mgr, err := cfg.NewSecretsManager()
	if err != nil {
		t.Fatalf("NewSecretsManager() error = %v", err)
	}
	defer mgr.Close()

	got, err := mgr.Get(context.Background(), "WIRING_TEST_SECRET")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != "from-file" {
		t.Errorf("secret = %q, want from-file", got)
	}
}

// TestLoad_ShippedConfig keeps configs/config.yaml loadable and valid.
func TestLoad_ShippedConfig(t *testing.T) {
	t.Setenv("SIEM_CONFIG_PATH", filepath.Join("..", "..", "configs", "config.yaml"))
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load(shipped config) error = %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("shipped config invalid: %v", err)
	}
	if cfg.Server.ShutdownTimeout != 8*time.Second {
		t.Errorf("shutdown_timeout = %v, want 8s", cfg.Server.ShutdownTimeout)
	}
	if !cfg.WebSocket.Enabled || cfg.WebSocket.StatsInterval != 30*time.Second {
		t.Errorf("websocket = %+v", cfg.WebSocket)
	}
	if cfg.Correlation.RulesDir != "data/rules" || cfg.Correlation.SeedRulesDir != "rules" {
		t.Errorf("rules dirs = %q, %q", cfg.Correlation.RulesDir, cfg.Correlation.SeedRulesDir)
	}
	if cfg.Ingest.CEF.DTLS.MaxConnections != 1000 {
		t.Errorf("dtls max_connections = %d", cfg.Ingest.CEF.DTLS.MaxConnections)
	}
	if len(cfg.Alerting.Notifications.Channels) != 0 {
		t.Errorf("shipped notification channels = %+v, want none", cfg.Alerting.Notifications.Channels)
	}
}

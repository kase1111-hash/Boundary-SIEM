package config

import (
	"os"
	"path/filepath"
	"testing"
)

// E2E round 2: SIEM_STORAGE_ENABLED=false was ignored (only "true" was
// honoured), and so were the "other" value of the other SIEM_*_ENABLED
// overrides; DTLS could not be enabled without a config file because no
// variable set its certificate and key.

func TestLoad_BoolOverridesWorkBothWays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
storage:
  enabled: true
cors:
  enabled: false
rate_limit:
  enabled: true
security_headers:
  enabled: true
  hsts_enabled: true
  csp_enabled: false
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIEM_CONFIG_PATH", path)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Storage.Enabled || cfg.CORS.Enabled || !cfg.RateLimit.Enabled || cfg.SecurityHeaders.CSPEnabled {
		t.Fatalf("file settings not loaded: storage %v cors %v ratelimit %v csp %v",
			cfg.Storage.Enabled, cfg.CORS.Enabled, cfg.RateLimit.Enabled, cfg.SecurityHeaders.CSPEnabled)
	}

	t.Setenv("SIEM_STORAGE_ENABLED", "false")
	t.Setenv("SIEM_CORS_ENABLED", "true")
	t.Setenv("SIEM_RATELIMIT_ENABLED", "0")
	t.Setenv("SIEM_HSTS_ENABLED", "FALSE")
	t.Setenv("SIEM_CSP_ENABLED", "1")
	t.Setenv("SIEM_SECRETS_FILE_ENABLED", "true")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Storage.Enabled {
		t.Error("SIEM_STORAGE_ENABLED=false left storage enabled")
	}
	if !cfg.CORS.Enabled {
		t.Error("SIEM_CORS_ENABLED=true left CORS disabled")
	}
	if cfg.RateLimit.Enabled {
		t.Error("SIEM_RATELIMIT_ENABLED=0 left rate limiting enabled")
	}
	if cfg.SecurityHeaders.HSTSEnabled || !cfg.SecurityHeaders.CSPEnabled {
		t.Errorf("HSTS %v CSP %v, want false and true", cfg.SecurityHeaders.HSTSEnabled, cfg.SecurityHeaders.CSPEnabled)
	}
	if !cfg.Secrets.EnableFile {
		t.Error("SIEM_SECRETS_FILE_ENABLED=true ignored")
	}

	// An invalid value leaves the setting alone.
	t.Setenv("SIEM_STORAGE_ENABLED", "nope")
	if cfg, err = Load(); err != nil || !cfg.Storage.Enabled {
		t.Errorf("SIEM_STORAGE_ENABLED=nope: storage %v err %v, want the file's true", cfg.Storage.Enabled, err)
	}
}

func TestLoad_CEFCertificateEnvOverrides(t *testing.T) {
	t.Setenv("SIEM_CONFIG_PATH", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("SIEM_CEF_DTLS_ENABLED", "true")
	t.Setenv("SIEM_CEF_DTLS_CERT_FILE", "/etc/siem/dtls.crt")
	t.Setenv("SIEM_CEF_DTLS_KEY_FILE", "/etc/siem/dtls.key")
	t.Setenv("SIEM_CEF_DTLS_CA_FILE", "/etc/siem/ca.crt")
	t.Setenv("SIEM_CEF_DTLS_REQUIRE_CLIENT_CERT", "true")
	t.Setenv("SIEM_CEF_TCP_TLS_ENABLED", "true")
	t.Setenv("SIEM_CEF_TCP_TLS_CERT_FILE", "/etc/siem/tcp.crt")
	t.Setenv("SIEM_CEF_TCP_TLS_KEY_FILE", "/etc/siem/tcp.key")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	dtls, tcp := cfg.Ingest.CEF.DTLS, cfg.Ingest.CEF.TCP
	if !dtls.Enabled || dtls.CertFile != "/etc/siem/dtls.crt" || dtls.KeyFile != "/etc/siem/dtls.key" ||
		dtls.CAFile != "/etc/siem/ca.crt" || !dtls.RequireClientCert {
		t.Errorf("DTLS = %+v", dtls)
	}
	if !tcp.TLSEnabled || tcp.TLSCertFile != "/etc/siem/tcp.crt" || tcp.TLSKeyFile != "/etc/siem/tcp.key" {
		t.Errorf("TCP TLS = enabled %v cert %q key %q", tcp.TLSEnabled, tcp.TLSCertFile, tcp.TLSKeyFile)
	}
}

package ingest

import (
	"testing"
	"time"
)

func TestDefaultDTLSServerConfig(t *testing.T) {
	cfg := DefaultDTLSServerConfig()

	if cfg.Address == "" {
		t.Error("Address should have default value")
	}
	if cfg.Workers <= 0 {
		t.Error("Workers should be positive")
	}
	if cfg.MaxMessageSize <= 0 {
		t.Error("MaxMessageSize should be positive")
	}
	if cfg.ConnectionTimeout <= 0 {
		t.Error("ConnectionTimeout should be positive")
	}
	if cfg.IdleTimeout <= 0 {
		t.Error("IdleTimeout should be positive")
	}
	if cfg.AllowInsecure {
		t.Error("AllowInsecure should be false by default")
	}
}

func TestNewDTLSServer_RequiresCertificate(t *testing.T) {
	cfg := DefaultDTLSServerConfig()
	// No cert file configured, AllowInsecure is false

	_, err := NewDTLSServer(cfg, nil, nil, nil, nil, nil)
	if err != ErrDTLSCertRequired {
		t.Errorf("Expected ErrDTLSCertRequired, got %v", err)
	}
}

func TestNewDTLSServer_AllowInsecure(t *testing.T) {
	cfg := DefaultDTLSServerConfig()
	cfg.AllowInsecure = true

	server, err := NewDTLSServer(cfg, nil, nil, nil, nil, nil)
	if err != nil {
		t.Errorf("AllowInsecure should allow creation without certs: %v", err)
	}
	if server == nil {
		t.Error("Server should not be nil")
	}
}

func TestNewDTLSServer_MutualTLSRequiresCA(t *testing.T) {
	cfg := DefaultDTLSServerConfig()
	cfg.AllowInsecure = true
	cfg.RequireClientCert = true
	// No CA file configured

	_, err := NewDTLSServer(cfg, nil, nil, nil, nil, nil)
	if err != ErrDTLSClientCertRequired {
		t.Errorf("Expected ErrDTLSClientCertRequired, got %v", err)
	}
}

func TestDTLSServerMetrics(t *testing.T) {
	cfg := DefaultDTLSServerConfig()
	cfg.AllowInsecure = true

	server, _ := NewDTLSServer(cfg, nil, nil, nil, nil, nil)

	metrics := server.Metrics()

	// Initial metrics should be zero
	if metrics.Connections != 0 {
		t.Errorf("Connections = %d, want 0", metrics.Connections)
	}
	if metrics.Received != 0 {
		t.Errorf("Received = %d, want 0", metrics.Received)
	}
	if metrics.Errors != 0 {
		t.Errorf("Errors = %d, want 0", metrics.Errors)
	}
	if metrics.InsecureWarned {
		t.Error("InsecureWarned should be false until started")
	}
}

func TestDTLSServer_IsSecure(t *testing.T) {
	cfg := DefaultDTLSServerConfig()
	cfg.AllowInsecure = true

	server, _ := NewDTLSServer(cfg, nil, nil, nil, nil, nil)

	// Before starting, should not be secure
	if server.IsSecure() {
		t.Error("Should not be secure before starting")
	}
}

func TestDTLSServerConfig_Defaults(t *testing.T) {
	cfg := DefaultDTLSServerConfig()

	// Check specific values
	if cfg.Address != ":5516" {
		t.Errorf("Address = %s, want :5516", cfg.Address)
	}
	if cfg.Workers != 8 {
		t.Errorf("Workers = %d, want 8", cfg.Workers)
	}
	if cfg.MaxMessageSize != 65535 {
		t.Errorf("MaxMessageSize = %d, want 65535", cfg.MaxMessageSize)
	}
	if cfg.ConnectionTimeout != 30*time.Second {
		t.Errorf("ConnectionTimeout = %v, want 30s", cfg.ConnectionTimeout)
	}
	if cfg.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout = %v, want 5m", cfg.IdleTimeout)
	}
}

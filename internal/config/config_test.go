package config

import (
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	// Test server defaults
	if cfg.Server.HTTPPort != 8080 {
		t.Errorf("expected HTTPPort 8080, got %d", cfg.Server.HTTPPort)
	}
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("expected ReadTimeout 30s, got %v", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout != 30*time.Second {
		t.Errorf("expected WriteTimeout 30s, got %v", cfg.Server.WriteTimeout)
	}

	// Test queue defaults
	if cfg.Queue.Size != 100000 {
		t.Errorf("expected Queue.Size 100000, got %d", cfg.Queue.Size)
	}
	if cfg.Queue.OverflowPolicy != "reject" {
		t.Errorf("expected Queue.OverflowPolicy 'reject', got %s", cfg.Queue.OverflowPolicy)
	}

	// Test ingest defaults
	if cfg.Ingest.MaxBatchSize != 1000 {
		t.Errorf("expected MaxBatchSize 1000, got %d", cfg.Ingest.MaxBatchSize)
	}
	if cfg.Ingest.MaxPayloadSize != 10*1024*1024 {
		t.Errorf("expected MaxPayloadSize 10MB, got %d", cfg.Ingest.MaxPayloadSize)
	}

	// Test CORS defaults
	if !cfg.CORS.Enabled {
		t.Error("expected CORS.Enabled to be true")
	}
	if len(cfg.CORS.AllowedOrigins) == 0 || cfg.CORS.AllowedOrigins[0] != "*" {
		t.Errorf("expected AllowedOrigins ['*'], got %v", cfg.CORS.AllowedOrigins)
	}

	// Test rate limit defaults
	if !cfg.RateLimit.Enabled {
		t.Error("expected RateLimit.Enabled to be true")
	}
	if cfg.RateLimit.RequestsPerIP != 1000 {
		t.Errorf("expected RequestsPerIP 1000, got %d", cfg.RateLimit.RequestsPerIP)
	}

	// Test security headers defaults
	if !cfg.SecurityHeaders.Enabled {
		t.Error("expected SecurityHeaders.Enabled to be true")
	}
	if !cfg.SecurityHeaders.HSTSEnabled {
		t.Error("expected HSTSEnabled to be true")
	}
	if cfg.SecurityHeaders.FrameOptionsValue != "DENY" {
		t.Errorf("expected FrameOptionsValue 'DENY', got %s", cfg.SecurityHeaders.FrameOptionsValue)
	}

	// Test boundary daemon defaults
	if cfg.BoundaryDaemon.Enabled {
		t.Error("expected BoundaryDaemon.Enabled to be false by default")
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := DefaultConfig()
	err := cfg.Validate()
	if err != nil {
		t.Errorf("DefaultConfig should be valid, got error: %v", err)
	}
}

func TestValidate_InvalidHTTPPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"zero port", 0},
		{"negative port", -1},
		{"too high port", 65536},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Server.HTTPPort = tt.port
			err := cfg.Validate()
			if err == nil {
				t.Error("expected validation error for invalid port")
			}
		})
	}
}

func TestValidate_InvalidQueueSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Queue.Size = 0
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for zero queue size")
	}

	cfg.Queue.Size = -1
	err = cfg.Validate()
	if err == nil {
		t.Error("expected validation error for negative queue size")
	}
}

func TestValidate_InvalidMaxBatchSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Ingest.MaxBatchSize = 0
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for zero max batch size")
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "StrongPass123!@#",
			wantErr:  false,
		},
		{
			name:     "too short",
			password: "Short1!",
			wantErr:  true,
		},
		{
			name:     "no uppercase",
			password: "lowercase123!@#",
			wantErr:  true,
		},
		{
			name:     "no lowercase",
			password: "UPPERCASE123!@#",
			wantErr:  true,
		},
		{
			name:     "no digit",
			password: "NoDigitsHere!!!",
			wantErr:  true,
		},
		{
			name:     "no special char",
			password: "NoSpecialChar123",
			wantErr:  true,
		},
		{
			name:     "minimum valid",
			password: "Abcdefghij1!",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordStrength(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sep      string
		expected []string
	}{
		{
			name:     "simple split",
			input:    "a,b,c",
			sep:      ",",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "with spaces",
			input:    "a , b , c",
			sep:      ",",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "empty parts filtered",
			input:    "a,,b",
			sep:      ",",
			expected: []string{"a", "b"},
		},
		{
			name:     "single value",
			input:    "single",
			sep:      ",",
			expected: []string{"single"},
		},
		{
			name:     "empty string",
			input:    "",
			sep:      ",",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input, tt.sep)
			if len(result) != len(tt.expected) {
				t.Errorf("splitAndTrim(%q, %q) = %v, expected %v", tt.input, tt.sep, result, tt.expected)
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("splitAndTrim(%q, %q)[%d] = %q, expected %q", tt.input, tt.sep, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  hello  ", "hello"},
		{"\thello\t", "hello"},
		{"\nhello\n", "hello"},
		{"\r\nhello\r\n", "hello"},
		{"hello", "hello"},
		{"", ""},
		{"   ", ""},
	}

	for _, tt := range tests {
		result := trimSpace(tt.input)
		if result != tt.expected {
			t.Errorf("trimSpace(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	// Save and restore env vars
	originalPort := os.Getenv("SIEM_HTTP_PORT")
	originalLogLevel := os.Getenv("SIEM_LOG_LEVEL")
	originalAPIKey := os.Getenv("SIEM_API_KEY")
	originalCORSEnabled := os.Getenv("SIEM_CORS_ENABLED")
	originalRateLimitEnabled := os.Getenv("SIEM_RATELIMIT_ENABLED")
	defer func() {
		os.Setenv("SIEM_HTTP_PORT", originalPort)
		os.Setenv("SIEM_LOG_LEVEL", originalLogLevel)
		os.Setenv("SIEM_API_KEY", originalAPIKey)
		os.Setenv("SIEM_CORS_ENABLED", originalCORSEnabled)
		os.Setenv("SIEM_RATELIMIT_ENABLED", originalRateLimitEnabled)
	}()

	t.Run("HTTP port override", func(t *testing.T) {
		os.Setenv("SIEM_HTTP_PORT", "9000")
		cfg := DefaultConfig()
		cfg.applyEnvOverrides()
		if cfg.Server.HTTPPort != 9000 {
			t.Errorf("expected HTTPPort 9000, got %d", cfg.Server.HTTPPort)
		}
	})

	t.Run("log level override", func(t *testing.T) {
		os.Setenv("SIEM_LOG_LEVEL", "debug")
		cfg := DefaultConfig()
		cfg.applyEnvOverrides()
		if cfg.Logging.Level != "debug" {
			t.Errorf("expected log level 'debug', got %s", cfg.Logging.Level)
		}
	})

	t.Run("API key override", func(t *testing.T) {
		os.Setenv("SIEM_API_KEY", "test-key-123")
		cfg := DefaultConfig()
		cfg.applyEnvOverrides()
		if !cfg.Auth.Enabled {
			t.Error("expected Auth.Enabled to be true when API key is set")
		}
		found := false
		for _, key := range cfg.Auth.APIKeys {
			if key == "test-key-123" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected API key to be added to APIKeys")
		}
	})

	t.Run("CORS disabled override", func(t *testing.T) {
		os.Setenv("SIEM_CORS_ENABLED", "false")
		cfg := DefaultConfig()
		cfg.applyEnvOverrides()
		if cfg.CORS.Enabled {
			t.Error("expected CORS.Enabled to be false")
		}
	})

	t.Run("rate limit disabled override", func(t *testing.T) {
		os.Setenv("SIEM_RATELIMIT_ENABLED", "false")
		cfg := DefaultConfig()
		cfg.applyEnvOverrides()
		if cfg.RateLimit.Enabled {
			t.Error("expected RateLimit.Enabled to be false")
		}
	})
}

func TestLoadAuthFromEnv(t *testing.T) {
	// Save and restore env vars
	original := map[string]string{
		"BOUNDARY_ADMIN_USERNAME":        os.Getenv("BOUNDARY_ADMIN_USERNAME"),
		"BOUNDARY_ADMIN_PASSWORD":        os.Getenv("BOUNDARY_ADMIN_PASSWORD"),
		"BOUNDARY_ADMIN_EMAIL":           os.Getenv("BOUNDARY_ADMIN_EMAIL"),
		"BOUNDARY_REQUIRE_PASSWORD_CHANGE": os.Getenv("BOUNDARY_REQUIRE_PASSWORD_CHANGE"),
	}
	defer func() {
		for k, v := range original {
			os.Setenv(k, v)
		}
	}()

	t.Run("load admin credentials from env", func(t *testing.T) {
		os.Setenv("BOUNDARY_ADMIN_USERNAME", "testadmin")
		os.Setenv("BOUNDARY_ADMIN_PASSWORD", "TestPass123!@#")
		os.Setenv("BOUNDARY_ADMIN_EMAIL", "admin@test.com")
		os.Setenv("BOUNDARY_REQUIRE_PASSWORD_CHANGE", "true")

		cfg := DefaultConfig()
		cfg.LoadAuthFromEnv()

		if cfg.Auth.DefaultAdminUsername != "testadmin" {
			t.Errorf("expected username 'testadmin', got %s", cfg.Auth.DefaultAdminUsername)
		}
		if cfg.Auth.DefaultAdminPassword != "TestPass123!@#" {
			t.Errorf("expected password 'TestPass123!@#', got %s", cfg.Auth.DefaultAdminPassword)
		}
		if cfg.Auth.DefaultAdminEmail != "admin@test.com" {
			t.Errorf("expected email 'admin@test.com', got %s", cfg.Auth.DefaultAdminEmail)
		}
		if !cfg.Auth.RequirePasswordChange {
			t.Error("expected RequirePasswordChange to be true")
		}
	})
}

func TestValidate_WithPassword(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Auth.DefaultAdminPassword = "weak"
	err := cfg.Validate()
	if err == nil {
		t.Error("expected validation error for weak password")
	}

	cfg.Auth.DefaultAdminPassword = "StrongPassword123!"
	err = cfg.Validate()
	if err != nil {
		t.Errorf("expected no error for strong password, got: %v", err)
	}
}

func TestDefaultBoundaryDaemonConfig(t *testing.T) {
	cfg := DefaultBoundaryDaemonConfig()

	if cfg.Enabled {
		t.Error("expected Enabled to be false by default")
	}
	if cfg.Client.BaseURL != "http://localhost:9000" {
		t.Errorf("expected BaseURL 'http://localhost:9000', got %s", cfg.Client.BaseURL)
	}
	if cfg.Client.Timeout != 30*time.Second {
		t.Errorf("expected Timeout 30s, got %v", cfg.Client.Timeout)
	}
	if cfg.Ingester.PollInterval != 30*time.Second {
		t.Errorf("expected PollInterval 30s, got %v", cfg.Ingester.PollInterval)
	}
	if cfg.Ingester.SessionBatchSize != 500 {
		t.Errorf("expected SessionBatchSize 500, got %d", cfg.Ingester.SessionBatchSize)
	}
	if !cfg.Ingester.IngestSessions {
		t.Error("expected IngestSessions to be true")
	}
	if !cfg.Ingester.IngestAuth {
		t.Error("expected IngestAuth to be true")
	}
	if !cfg.Ingester.IngestThreats {
		t.Error("expected IngestThreats to be true")
	}
	if cfg.Normalizer.DefaultTenantID != "default" {
		t.Errorf("expected DefaultTenantID 'default', got %s", cfg.Normalizer.DefaultTenantID)
	}
}

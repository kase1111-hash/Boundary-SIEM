package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestSecurityHeadersMiddleware tests the security headers middleware.
func TestSecurityHeadersMiddleware(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := DefaultSecurityHeadersConfig()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := SecurityHeadersMiddleware(cfg, logger)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)

	// Check HSTS header
	hsts := rec.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("expected HSTS header to be set")
	}
	if !strings.Contains(hsts, "max-age=31536000") {
		t.Errorf("expected HSTS max-age=31536000, got %s", hsts)
	}
	if !strings.Contains(hsts, "includeSubDomains") {
		t.Error("expected HSTS to include subdomains")
	}

	// Check CSP header
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("expected CSP header to be set")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("expected CSP default-src 'self', got %s", csp)
	}

	// Check X-Frame-Options
	frameOptions := rec.Header().Get("X-Frame-Options")
	if frameOptions != "DENY" {
		t.Errorf("expected X-Frame-Options DENY, got %s", frameOptions)
	}

	// Check X-Content-Type-Options
	contentType := rec.Header().Get("X-Content-Type-Options")
	if contentType != "nosniff" {
		t.Errorf("expected X-Content-Type-Options nosniff, got %s", contentType)
	}

	// Check X-XSS-Protection
	xss := rec.Header().Get("X-XSS-Protection")
	if xss != "1; mode=block" {
		t.Errorf("expected X-XSS-Protection 1; mode=block, got %s", xss)
	}

	// Check Referrer-Policy
	referrer := rec.Header().Get("Referrer-Policy")
	if referrer != "strict-origin-when-cross-origin" {
		t.Errorf("expected Referrer-Policy strict-origin-when-cross-origin, got %s", referrer)
	}

	// Check Permissions-Policy
	permissions := rec.Header().Get("Permissions-Policy")
	if permissions == "" {
		t.Error("expected Permissions-Policy header to be set")
	}

	// Check Cross-Origin-Opener-Policy
	coop := rec.Header().Get("Cross-Origin-Opener-Policy")
	if coop != "same-origin" {
		t.Errorf("expected Cross-Origin-Opener-Policy same-origin, got %s", coop)
	}

	// Check Cross-Origin-Resource-Policy
	corp := rec.Header().Get("Cross-Origin-Resource-Policy")
	if corp != "same-origin" {
		t.Errorf("expected Cross-Origin-Resource-Policy same-origin, got %s", corp)
	}
}

// TestSecurityHeadersDisabled tests that middleware can be disabled.
func TestSecurityHeadersDisabled(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.Enabled = false

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := SecurityHeadersMiddleware(cfg, nil)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)

	// When disabled, no security headers should be set
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("expected no HSTS header when disabled")
	}
	if rec.Header().Get("Content-Security-Policy") != "" {
		t.Error("expected no CSP header when disabled")
	}
}

// TestHSTSConfiguration tests HSTS header configuration.
func TestHSTSConfiguration(t *testing.T) {
	tests := []struct {
		name              string
		enabled           bool
		maxAge            int
		includeSubdomains bool
		preload           bool
		want              string
	}{
		{
			name:              "full_hsts",
			enabled:           true,
			maxAge:            63072000, // 2 years
			includeSubdomains: true,
			preload:           true,
			want:              "max-age=63072000; includeSubDomains; preload",
		},
		{
			name:              "basic_hsts",
			enabled:           true,
			maxAge:            31536000,
			includeSubdomains: false,
			preload:           false,
			want:              "max-age=31536000",
		},
		{
			name:              "hsts_disabled",
			enabled:           false,
			maxAge:            31536000,
			includeSubdomains: true,
			preload:           true,
			want:              "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultSecurityHeadersConfig()
			cfg.HSTSEnabled = tt.enabled
			cfg.HSTSMaxAge = tt.maxAge
			cfg.HSTSIncludeSubdomains = tt.includeSubdomains
			cfg.HSTSPreload = tt.preload

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := SecurityHeadersMiddleware(cfg, nil)
			wrappedHandler := middleware(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rec, req)

			got := rec.Header().Get("Strict-Transport-Security")
			if got != tt.want {
				t.Errorf("HSTS header = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCSPConfiguration tests CSP header configuration.
func TestCSPConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		cfg        SecurityHeadersConfig
		wantHeader string
		wantValue  string
	}{
		{
			name: "basic_csp",
			cfg: SecurityHeadersConfig{
				Enabled:       true,
				CSPEnabled:    true,
				CSPDefaultSrc: []string{"'self'"},
				CSPScriptSrc:  []string{"'self'", "'unsafe-inline'"},
			},
			wantHeader: "Content-Security-Policy",
			wantValue:  "default-src 'self'; script-src 'self' 'unsafe-inline'",
		},
		{
			name: "report_only_csp",
			cfg: SecurityHeadersConfig{
				Enabled:       true,
				CSPEnabled:    true,
				CSPDefaultSrc: []string{"'self'"},
				CSPReportOnly: true,
			},
			wantHeader: "Content-Security-Policy-Report-Only",
			wantValue:  "default-src 'self'",
		},
		{
			name: "full_csp",
			cfg: SecurityHeadersConfig{
				Enabled:           true,
				CSPEnabled:        true,
				CSPDefaultSrc:     []string{"'self'"},
				CSPScriptSrc:      []string{"'self'"},
				CSPStyleSrc:       []string{"'self'", "'unsafe-inline'"},
				CSPImgSrc:         []string{"'self'", "data:"},
				CSPFontSrc:        []string{"'self'"},
				CSPConnectSrc:     []string{"'self'"},
				CSPFrameAncestors: []string{"'none'"},
			},
			wantHeader: "Content-Security-Policy",
			wantValue:  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := SecurityHeadersMiddleware(tt.cfg, nil)
			wrappedHandler := middleware(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rec, req)

			got := rec.Header().Get(tt.wantHeader)
			if got != tt.wantValue {
				t.Errorf("CSP header = %q, want %q", got, tt.wantValue)
			}
		})
	}
}

// TestFrameOptionsConfiguration tests X-Frame-Options configuration.
func TestFrameOptionsConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		value   string
		want    string
	}{
		{
			name:    "deny",
			enabled: true,
			value:   "DENY",
			want:    "DENY",
		},
		{
			name:    "sameorigin",
			enabled: true,
			value:   "SAMEORIGIN",
			want:    "SAMEORIGIN",
		},
		{
			name:    "disabled",
			enabled: false,
			value:   "DENY",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultSecurityHeadersConfig()
			cfg.FrameOptionsEnabled = tt.enabled
			cfg.FrameOptionsValue = tt.value

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := SecurityHeadersMiddleware(cfg, nil)
			wrappedHandler := middleware(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			rec := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(rec, req)

			got := rec.Header().Get("X-Frame-Options")
			if got != tt.want {
				t.Errorf("X-Frame-Options = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCustomHeaders tests custom headers configuration.
func TestCustomHeaders(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.CustomHeaders = map[string]string{
		"X-Custom-Header":  "custom-value",
		"X-Another-Header": "another-value",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := SecurityHeadersMiddleware(cfg, nil)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Custom-Header"); got != "custom-value" {
		t.Errorf("X-Custom-Header = %q, want %q", got, "custom-value")
	}

	if got := rec.Header().Get("X-Another-Header"); got != "another-value" {
		t.Errorf("X-Another-Header = %q, want %q", got, "another-value")
	}
}

// TestBuildCSP tests the CSP builder function.
func TestBuildCSP(t *testing.T) {
	tests := []struct {
		name string
		cfg  SecurityHeadersConfig
		want string
	}{
		{
			name: "empty",
			cfg:  SecurityHeadersConfig{},
			want: "",
		},
		{
			name: "default_src_only",
			cfg: SecurityHeadersConfig{
				CSPDefaultSrc: []string{"'self'"},
			},
			want: "default-src 'self'",
		},
		{
			name: "multiple_directives",
			cfg: SecurityHeadersConfig{
				CSPDefaultSrc: []string{"'self'"},
				CSPScriptSrc:  []string{"'self'", "https://cdn.example.com"},
				CSPStyleSrc:   []string{"'self'", "'unsafe-inline'"},
			},
			want: "default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCSP(tt.cfg)
			if got != tt.want {
				t.Errorf("buildCSP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCrossOriginPolicies tests cross-origin policy headers.
func TestCrossOriginPolicies(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()
	cfg.CrossOriginOpenerPolicyEnabled = true
	cfg.CrossOriginOpenerPolicyValue = "same-origin"
	cfg.CrossOriginEmbedderPolicyEnabled = true
	cfg.CrossOriginEmbedderPolicyValue = "require-corp"
	cfg.CrossOriginResourcePolicyEnabled = true
	cfg.CrossOriginResourcePolicyValue = "same-origin"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := SecurityHeadersMiddleware(cfg, nil)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Cross-Origin-Opener-Policy"); got != "same-origin" {
		t.Errorf("Cross-Origin-Opener-Policy = %q, want same-origin", got)
	}

	if got := rec.Header().Get("Cross-Origin-Embedder-Policy"); got != "require-corp" {
		t.Errorf("Cross-Origin-Embedder-Policy = %q, want require-corp", got)
	}

	if got := rec.Header().Get("Cross-Origin-Resource-Policy"); got != "same-origin" {
		t.Errorf("Cross-Origin-Resource-Policy = %q, want same-origin", got)
	}
}

// TestDefaultSecurityHeadersConfig tests the default configuration.
func TestDefaultSecurityHeadersConfig(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()

	if !cfg.Enabled {
		t.Error("expected default config to be enabled")
	}

	if !cfg.HSTSEnabled {
		t.Error("expected HSTS to be enabled by default")
	}

	if cfg.HSTSMaxAge != 31536000 {
		t.Errorf("expected HSTS max age 31536000, got %d", cfg.HSTSMaxAge)
	}

	if !cfg.CSPEnabled {
		t.Error("expected CSP to be enabled by default")
	}

	if cfg.FrameOptionsValue != "DENY" {
		t.Errorf("expected frame options DENY, got %s", cfg.FrameOptionsValue)
	}

	if !cfg.ContentTypeOptionsEnabled {
		t.Error("expected content type options to be enabled")
	}

	if !cfg.XSSProtectionEnabled {
		t.Error("expected XSS protection to be enabled")
	}

	if cfg.XSSProtectionValue != "1; mode=block" {
		t.Errorf("expected XSS protection '1; mode=block', got %s", cfg.XSSProtectionValue)
	}
}

// TestSecurityHeadersPreservesResponse tests that middleware doesn't affect response.
func TestSecurityHeadersPreservesResponse(t *testing.T) {
	cfg := DefaultSecurityHeadersConfig()

	expectedBody := "test response body"
	expectedStatus := http.StatusCreated

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(expectedStatus)
		w.Write([]byte(expectedBody))
	})

	middleware := SecurityHeadersMiddleware(cfg, nil)
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(rec, req)

	if rec.Code != expectedStatus {
		t.Errorf("status code = %d, want %d", rec.Code, expectedStatus)
	}

	if rec.Body.String() != expectedBody {
		t.Errorf("body = %q, want %q", rec.Body.String(), expectedBody)
	}

	// But security headers should still be set
	if rec.Header().Get("X-Frame-Options") == "" {
		t.Error("expected security headers to be set even with custom response")
	}
}

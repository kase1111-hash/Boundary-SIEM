// Package middleware provides HTTP middleware for the SIEM.
package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"boundary-siem/internal/config"
)

// SecurityHeadersConfig holds security headers configuration.
type SecurityHeadersConfig struct {
	// Enabled indicates if security headers are enabled.
	Enabled bool

	// HSTS (HTTP Strict Transport Security)
	HSTSEnabled           bool
	HSTSMaxAge            int  // Max age in seconds (default: 31536000 = 1 year)
	HSTSIncludeSubdomains bool // Include subdomains
	HSTSPreload           bool // Allow preload

	// CSP (Content Security Policy)
	CSPEnabled        bool
	CSPDefaultSrc     []string // default-src directive
	CSPScriptSrc      []string // script-src directive
	CSPStyleSrc       []string // style-src directive
	CSPImgSrc         []string // img-src directive
	CSPFontSrc        []string // font-src directive
	CSPConnectSrc     []string // connect-src directive
	CSPFrameAncestors []string // frame-ancestors directive
	CSPReportOnly     bool     // Report-only mode (doesn't enforce)

	// Frame Options
	FrameOptionsEnabled bool
	FrameOptionsValue   string // DENY, SAMEORIGIN, or ALLOW-FROM uri

	// Content Type Options
	ContentTypeOptionsEnabled bool

	// XSS Protection
	XSSProtectionEnabled bool
	XSSProtectionValue   string // 0, 1, or 1; mode=block

	// Referrer Policy
	ReferrerPolicyEnabled bool
	ReferrerPolicyValue   string // no-referrer, strict-origin-when-cross-origin, etc.

	// Permissions Policy
	PermissionsPolicyEnabled bool
	PermissionsPolicyValue   string // geolocation=(), microphone=(), etc.

	// Cross-Origin Policies
	CrossOriginOpenerPolicyEnabled   bool
	CrossOriginOpenerPolicyValue     string // same-origin, same-origin-allow-popups, unsafe-none
	CrossOriginEmbedderPolicyEnabled bool
	CrossOriginEmbedderPolicyValue   string // require-corp, credentialless
	CrossOriginResourcePolicyEnabled bool
	CrossOriginResourcePolicyValue   string // same-origin, same-site, cross-origin

	// Custom headers
	CustomHeaders map[string]string
}

// DefaultSecurityHeadersConfig returns production-ready security headers configuration.
func DefaultSecurityHeadersConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		Enabled: true,

		// HSTS - Force HTTPS for 1 year
		HSTSEnabled:           true,
		HSTSMaxAge:            31536000, // 1 year
		HSTSIncludeSubdomains: true,
		HSTSPreload:           false, // Requires manual submission to preload list

		// CSP - Strict content security policy
		CSPEnabled:        true,
		CSPDefaultSrc:     []string{"'self'"},
		CSPScriptSrc:      []string{"'self'"},
		CSPStyleSrc:       []string{"'self'"},
		CSPImgSrc:         []string{"'self'", "data:", "https:"},
		CSPFontSrc:        []string{"'self'"},
		CSPConnectSrc:     []string{"'self'"},
		CSPFrameAncestors: []string{"'none'"},
		CSPReportOnly:     false,

		// Frame Options - Prevent clickjacking
		FrameOptionsEnabled: true,
		FrameOptionsValue:   "DENY",

		// Content Type Options - Prevent MIME sniffing
		ContentTypeOptionsEnabled: true,

		// XSS Protection - Enable browser XSS filter
		XSSProtectionEnabled: true,
		XSSProtectionValue:   "1; mode=block",

		// Referrer Policy - Control referrer information
		ReferrerPolicyEnabled: true,
		ReferrerPolicyValue:   "strict-origin-when-cross-origin",

		// Permissions Policy - Restrict browser features
		PermissionsPolicyEnabled: true,
		PermissionsPolicyValue:   "geolocation=(), microphone=(), camera=(), payment=(), usb=()",

		// Cross-Origin Policies
		CrossOriginOpenerPolicyEnabled:   true,
		CrossOriginOpenerPolicyValue:     "same-origin",
		CrossOriginEmbedderPolicyEnabled: false, // Can break some integrations
		CrossOriginEmbedderPolicyValue:   "require-corp",
		CrossOriginResourcePolicyEnabled: true,
		CrossOriginResourcePolicyValue:   "same-origin",

		CustomHeaders: make(map[string]string),
	}
}

// SecurityHeadersMiddleware returns a middleware that sets security headers.
func SecurityHeadersMiddleware(cfg SecurityHeadersConfig, logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	if !cfg.Enabled {
		logger.Info("security headers middleware disabled")
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	logger.Info("security headers middleware initialized",
		"hsts_enabled", cfg.HSTSEnabled,
		"csp_enabled", cfg.CSPEnabled,
		"frame_options", cfg.FrameOptionsValue)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// HSTS - HTTP Strict Transport Security
			if cfg.HSTSEnabled {
				hsts := fmt.Sprintf("max-age=%d", cfg.HSTSMaxAge)
				if cfg.HSTSIncludeSubdomains {
					hsts += "; includeSubDomains"
				}
				if cfg.HSTSPreload {
					hsts += "; preload"
				}
				w.Header().Set("Strict-Transport-Security", hsts)
			}

			// CSP - Content Security Policy
			if cfg.CSPEnabled {
				csp := buildCSP(cfg)
				header := "Content-Security-Policy"
				if cfg.CSPReportOnly {
					header = "Content-Security-Policy-Report-Only"
				}
				w.Header().Set(header, csp)
			}

			// X-Frame-Options - Prevent clickjacking
			if cfg.FrameOptionsEnabled && cfg.FrameOptionsValue != "" {
				w.Header().Set("X-Frame-Options", cfg.FrameOptionsValue)
			}

			// X-Content-Type-Options - Prevent MIME sniffing
			if cfg.ContentTypeOptionsEnabled {
				w.Header().Set("X-Content-Type-Options", "nosniff")
			}

			// X-XSS-Protection - Browser XSS filter
			if cfg.XSSProtectionEnabled && cfg.XSSProtectionValue != "" {
				w.Header().Set("X-XSS-Protection", cfg.XSSProtectionValue)
			}

			// Referrer-Policy - Control referrer information
			if cfg.ReferrerPolicyEnabled && cfg.ReferrerPolicyValue != "" {
				w.Header().Set("Referrer-Policy", cfg.ReferrerPolicyValue)
			}

			// Permissions-Policy - Restrict browser features
			if cfg.PermissionsPolicyEnabled && cfg.PermissionsPolicyValue != "" {
				w.Header().Set("Permissions-Policy", cfg.PermissionsPolicyValue)
			}

			// Cross-Origin-Opener-Policy
			if cfg.CrossOriginOpenerPolicyEnabled && cfg.CrossOriginOpenerPolicyValue != "" {
				w.Header().Set("Cross-Origin-Opener-Policy", cfg.CrossOriginOpenerPolicyValue)
			}

			// Cross-Origin-Embedder-Policy
			if cfg.CrossOriginEmbedderPolicyEnabled && cfg.CrossOriginEmbedderPolicyValue != "" {
				w.Header().Set("Cross-Origin-Embedder-Policy", cfg.CrossOriginEmbedderPolicyValue)
			}

			// Cross-Origin-Resource-Policy
			if cfg.CrossOriginResourcePolicyEnabled && cfg.CrossOriginResourcePolicyValue != "" {
				w.Header().Set("Cross-Origin-Resource-Policy", cfg.CrossOriginResourcePolicyValue)
			}

			// Custom headers
			for key, value := range cfg.CustomHeaders {
				w.Header().Set(key, value)
			}

			next.ServeHTTP(w, r)
		})
	}
}

// buildCSP builds the Content-Security-Policy header value.
func buildCSP(cfg SecurityHeadersConfig) string {
	var directives []string

	if len(cfg.CSPDefaultSrc) > 0 {
		directives = append(directives, "default-src "+strings.Join(cfg.CSPDefaultSrc, " "))
	}

	if len(cfg.CSPScriptSrc) > 0 {
		directives = append(directives, "script-src "+strings.Join(cfg.CSPScriptSrc, " "))
	}

	if len(cfg.CSPStyleSrc) > 0 {
		directives = append(directives, "style-src "+strings.Join(cfg.CSPStyleSrc, " "))
	}

	if len(cfg.CSPImgSrc) > 0 {
		directives = append(directives, "img-src "+strings.Join(cfg.CSPImgSrc, " "))
	}

	if len(cfg.CSPFontSrc) > 0 {
		directives = append(directives, "font-src "+strings.Join(cfg.CSPFontSrc, " "))
	}

	if len(cfg.CSPConnectSrc) > 0 {
		directives = append(directives, "connect-src "+strings.Join(cfg.CSPConnectSrc, " "))
	}

	if len(cfg.CSPFrameAncestors) > 0 {
		directives = append(directives, "frame-ancestors "+strings.Join(cfg.CSPFrameAncestors, " "))
	}

	return strings.Join(directives, "; ")
}

// NewSecurityHeadersMiddleware creates security headers middleware from config.
func NewSecurityHeadersMiddleware(cfg *config.Config, logger *slog.Logger) func(http.Handler) http.Handler {
	if cfg == nil {
		return SecurityHeadersMiddleware(DefaultSecurityHeadersConfig(), logger)
	}

	// Convert config.SecurityHeadersConfig to middleware.SecurityHeadersConfig
	middlewareCfg := SecurityHeadersConfig{
		Enabled:                          cfg.SecurityHeaders.Enabled,
		HSTSEnabled:                      cfg.SecurityHeaders.HSTSEnabled,
		HSTSMaxAge:                       cfg.SecurityHeaders.HSTSMaxAge,
		HSTSIncludeSubdomains:            cfg.SecurityHeaders.HSTSIncludeSubdomains,
		HSTSPreload:                      cfg.SecurityHeaders.HSTSPreload,
		CSPEnabled:                       cfg.SecurityHeaders.CSPEnabled,
		CSPDefaultSrc:                    cfg.SecurityHeaders.CSPDefaultSrc,
		CSPScriptSrc:                     cfg.SecurityHeaders.CSPScriptSrc,
		CSPStyleSrc:                      cfg.SecurityHeaders.CSPStyleSrc,
		CSPImgSrc:                        cfg.SecurityHeaders.CSPImgSrc,
		CSPFontSrc:                       cfg.SecurityHeaders.CSPFontSrc,
		CSPConnectSrc:                    cfg.SecurityHeaders.CSPConnectSrc,
		CSPFrameAncestors:                cfg.SecurityHeaders.CSPFrameAncestors,
		CSPReportOnly:                    cfg.SecurityHeaders.CSPReportOnly,
		FrameOptionsEnabled:              cfg.SecurityHeaders.FrameOptionsEnabled,
		FrameOptionsValue:                cfg.SecurityHeaders.FrameOptionsValue,
		ContentTypeOptionsEnabled:        cfg.SecurityHeaders.ContentTypeOptionsEnabled,
		XSSProtectionEnabled:             cfg.SecurityHeaders.XSSProtectionEnabled,
		XSSProtectionValue:               cfg.SecurityHeaders.XSSProtectionValue,
		ReferrerPolicyEnabled:            cfg.SecurityHeaders.ReferrerPolicyEnabled,
		ReferrerPolicyValue:              cfg.SecurityHeaders.ReferrerPolicyValue,
		PermissionsPolicyEnabled:         cfg.SecurityHeaders.PermissionsPolicyEnabled,
		PermissionsPolicyValue:           cfg.SecurityHeaders.PermissionsPolicyValue,
		CrossOriginOpenerPolicyEnabled:   cfg.SecurityHeaders.CrossOriginOpenerPolicyEnabled,
		CrossOriginOpenerPolicyValue:     cfg.SecurityHeaders.CrossOriginOpenerPolicyValue,
		CrossOriginEmbedderPolicyEnabled: cfg.SecurityHeaders.CrossOriginEmbedderPolicyEnabled,
		CrossOriginEmbedderPolicyValue:   cfg.SecurityHeaders.CrossOriginEmbedderPolicyValue,
		CrossOriginResourcePolicyEnabled: cfg.SecurityHeaders.CrossOriginResourcePolicyEnabled,
		CrossOriginResourcePolicyValue:   cfg.SecurityHeaders.CrossOriginResourcePolicyValue,
		CustomHeaders:                    cfg.SecurityHeaders.CustomHeaders,
	}

	return SecurityHeadersMiddleware(middlewareCfg, logger)
}

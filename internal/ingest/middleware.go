package ingest

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"boundary-siem/internal/config"
)

// WithMiddleware wraps the handler with middleware.
func WithMiddleware(handler http.Handler, cfg *config.Config) http.Handler {
	// Apply middleware in reverse order (last applied runs first)
	h := handler

	// Recovery middleware
	h = recoveryMiddleware(h)

	// Logging middleware
	h = loggingMiddleware(h)

	// API key authentication (if enabled)
	if cfg.Auth.Enabled {
		h = authMiddleware(h, cfg.Auth)
	}

	// Rate limiting (if enabled) - after auth so authenticated requests are also limited
	if cfg.RateLimit.Enabled {
		h = rateLimitMiddleware(h, cfg.RateLimit)
	}

	// CORS middleware (if enabled) - must be outermost to handle preflight OPTIONS
	if cfg.CORS.Enabled {
		h = corsMiddleware(h, cfg.CORS)
	}

	return h
}

// loggingMiddleware logs HTTP requests.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration_ms", duration.Milliseconds(),
			"remote_addr", r.RemoteAddr,
		)
	})
}

// authMiddleware checks for valid API key.
func authMiddleware(next http.Handler, authCfg config.AuthConfig) http.Handler {
	// Build a set of valid API keys for O(1) lookup
	validKeys := make(map[string]bool)
	for _, key := range authCfg.APIKeys {
		validKeys[key] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health and metrics endpoints
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := r.Header.Get(authCfg.APIKeyHeader)
		if apiKey == "" {
			http.Error(w, `{"success":false,"error":"missing API key"}`, http.StatusUnauthorized)
			return
		}

		if !validKeys[apiKey] {
			http.Error(w, `{"success":false,"error":"invalid API key"}`, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// recoveryMiddleware recovers from panics.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("panic recovered", "error", err, "path", r.URL.Path)
				http.Error(w, `{"success":false,"error":"internal server error"}`, http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// corsMiddleware handles CORS preflight and adds CORS headers to responses.
func corsMiddleware(next http.Handler, corsCfg config.CORSConfig) http.Handler {
	// Build allowed origins map for O(1) lookup (unless wildcard)
	allowAll := false
	allowedOrigins := make(map[string]bool)
	for _, origin := range corsCfg.AllowedOrigins {
		if origin == "*" {
			allowAll = true
			break
		}
		allowedOrigins[origin] = true
	}

	// Pre-build header values
	allowMethods := joinStrings(corsCfg.AllowedMethods, ", ")
	allowHeaders := joinStrings(corsCfg.AllowedHeaders, ", ")
	exposeHeaders := joinStrings(corsCfg.ExposedHeaders, ", ")
	maxAge := fmt.Sprintf("%d", corsCfg.MaxAge)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// If no origin header, it's not a CORS request - proceed normally
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check if origin is allowed
		originAllowed := allowAll || allowedOrigins[origin]
		if !originAllowed {
			// Origin not allowed - don't add CORS headers, let request proceed
			// The browser will block the response
			slog.Warn("CORS origin not allowed", "origin", origin, "path", r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}

		// Set CORS headers
		if allowAll {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}

		if corsCfg.AllowCredentials && !allowAll {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if exposeHeaders != "" {
			w.Header().Set("Access-Control-Expose-Headers", exposeHeaders)
		}

		// Handle preflight OPTIONS request
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", allowMethods)
			w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
			w.Header().Set("Access-Control-Max-Age", maxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// joinStrings joins strings with a separator.
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

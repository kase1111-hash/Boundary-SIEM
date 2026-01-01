package ingest

import (
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

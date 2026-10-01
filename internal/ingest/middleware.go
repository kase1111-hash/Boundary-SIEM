package ingest

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"boundary-siem/internal/config"
	"boundary-siem/internal/middleware"
)

// Paths served without API-key authentication. /health, /ready and
// /metrics are probes; the WebSocket endpoints authenticate in-band (the
// first message carries the key) because browsers cannot set headers on a
// WebSocket handshake.
var publicPaths = map[string]bool{
	"/health":    true,
	"/ready":     true,
	"/metrics":   true,
	"/ws":        true,
	"/ws/events": true,
}

// isAPIPath reports whether path belongs to the data API, which always
// requires authentication when it is enabled.
func isAPIPath(path string) bool {
	return path == "/v1" || strings.HasPrefix(path, "/v1/") ||
		path == "/api" || strings.HasPrefix(path, "/api/")
}

// WithMiddleware wraps the handler with recovery, logging, authentication,
// rate limiting and CORS, as configured. It returns the wrapped handler and
// a function that releases the middleware's background resources (the rate
// limiter's cleanup goroutine); call it on shutdown. It is safe to call more
// than once.
func WithMiddleware(handler http.Handler, cfg *config.Config) (http.Handler, func()) {
	// Apply middleware in reverse order (last applied runs first)
	h := handler

	// Recovery middleware
	h = recoveryMiddleware(h)

	// Logging middleware
	h = loggingMiddleware(h)

	// API key authentication (if enabled)
	if cfg.Auth.Enabled {
		h = authMiddleware(h, cfg.Auth, cfg.Server.WebDir != "")
	}

	// Rate limiting (if enabled) - after auth so authenticated requests are also limited
	stop := func() {}
	if cfg.RateLimit.Enabled {
		limiter := middleware.NewRateLimiter(cfg.RateLimit, slog.Default())
		h = limiter.Middleware()(h)
		stop = limiter.Stop
	}

	// CORS middleware (if enabled) - must be outermost to handle preflight OPTIONS
	if cfg.CORS.Enabled {
		h = corsMiddleware(h, cfg.CORS)
	}

	return h, stop
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

// validAPIKey reports whether key is one of keys. Every key is compared in
// constant time so the comparison does not leak how much of a key matched.
func validAPIKey(key string, keys []string) bool {
	valid := 0
	for _, k := range keys {
		valid |= subtle.ConstantTimeCompare([]byte(key), []byte(k))
	}
	return valid == 1
}

// ValidAPIKey reports whether key is a configured API key, using the same
// constant-time comparison as the HTTP middleware. An empty key is never
// valid.
func ValidAPIKey(key string, keys []string) bool {
	return key != "" && validAPIKey(key, keys)
}

// authMiddleware checks for valid API key.
func authMiddleware(next http.Handler, authCfg config.AuthConfig, webUI bool) http.Handler {
	header := authCfg.APIKeyHeader
	if header == "" {
		header = "X-API-Key"
	}
	keys := append([]string(nil), authCfg.APIKeys...)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if publicPaths[path] ||
			// The dashboard's static files hold no data; the dashboard
			// asks for an API key and sends it with its API calls.
			(webUI && !isAPIPath(path) && (r.Method == http.MethodGet || r.Method == http.MethodHead)) {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := r.Header.Get(header)
		if apiKey == "" {
			writeAuthError(w, "missing API key")
			return
		}

		if !validAPIKey(apiKey, keys) {
			writeAuthError(w, "invalid API key")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeAuthError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, `{"success":false,"error":%q}`+"\n", message)
}

// recoveryMiddleware recovers from panics.
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				if err == http.ErrAbortHandler {
					panic(err)
				}
				slog.Error("panic recovered", "error", err, "path", r.URL.Path)
				http.Error(w, `{"success":false,"error":"internal server error"}`, http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code. It
// passes Hijack and Flush through, so WebSocket upgrades and streaming work
// behind the logging middleware.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// Hijack implements http.Hijacker for WebSocket upgrades.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer %T does not support hijacking", rw.ResponseWriter)
	}
	conn, brw, err := hj.Hijack()
	if err == nil {
		rw.statusCode = http.StatusSwitchingProtocols
	}
	return conn, brw, err
}

// Flush implements http.Flusher.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
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
	allowMethods := strings.Join(corsCfg.AllowedMethods, ", ")
	allowHeaders := strings.Join(corsCfg.AllowedHeaders, ", ")
	exposeHeaders := strings.Join(corsCfg.ExposedHeaders, ", ")
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

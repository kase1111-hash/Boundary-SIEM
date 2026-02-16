// Package middleware provides HTTP middleware for the SIEM platform.
package middleware

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/config"
)

// RateLimiter implements a sliding window rate limiter with per-IP tracking.
// It uses an efficient token bucket algorithm with automatic cleanup of expired entries.
type RateLimiter struct {
	cfg         config.RateLimitConfig
	clients     map[string]*clientState
	mu          sync.RWMutex
	exemptPaths map[string]bool
	stopCleanup chan struct{}
	logger      *slog.Logger
}

// clientState tracks request counts for a single client IP.
type clientState struct {
	count     int64     // Current request count in window
	windowEnd time.Time // When current window expires
	mu        sync.Mutex
}

// NewRateLimiter creates a new rate limiter with the given configuration.
// It starts a background goroutine for periodic cleanup of expired entries.
func NewRateLimiter(cfg config.RateLimitConfig, logger *slog.Logger) *RateLimiter {
	if logger == nil {
		logger = slog.Default()
	}

	exemptPaths := make(map[string]bool)
	for _, path := range cfg.ExemptPaths {
		exemptPaths[path] = true
	}

	rl := &RateLimiter{
		cfg:         cfg,
		clients:     make(map[string]*clientState),
		exemptPaths: exemptPaths,
		stopCleanup: make(chan struct{}),
		logger:      logger,
	}

	// Start background cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// Allow checks if a request from the given IP should be allowed.
// Returns (allowed, remaining requests, reset time).
func (rl *RateLimiter) Allow(ip string) (bool, int, time.Time) {
	now := time.Now()

	// Get or create client state
	rl.mu.Lock()
	client, exists := rl.clients[ip]
	if !exists {
		client = &clientState{
			count:     0,
			windowEnd: now.Add(rl.cfg.WindowSize),
		}
		rl.clients[ip] = client
	}
	rl.mu.Unlock()

	client.mu.Lock()
	defer client.mu.Unlock()

	// Check if window has expired - reset if so
	if now.After(client.windowEnd) {
		client.count = 0
		client.windowEnd = now.Add(rl.cfg.WindowSize)
	}

	// Calculate limit (base + burst allowance)
	limit := int64(rl.cfg.RequestsPerIP + rl.cfg.BurstSize)
	remaining := limit - client.count - 1

	// Check if limit exceeded
	if client.count >= limit {
		return false, 0, client.windowEnd
	}

	// Increment counter
	client.count++
	if remaining < 0 {
		remaining = 0
	}

	return true, int(remaining), client.windowEnd
}

// cleanupLoop periodically removes expired client entries to prevent memory leaks.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cfg.CleanupPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopCleanup:
			return
		}
	}
}

// cleanup removes expired entries from the clients map.
func (rl *RateLimiter) cleanup() {
	now := time.Now()
	// Keep entries for 2 windows to handle edge cases
	expiredThreshold := now.Add(-rl.cfg.WindowSize * 2)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	removed := 0
	for ip, client := range rl.clients {
		client.mu.Lock()
		if client.windowEnd.Before(expiredThreshold) {
			delete(rl.clients, ip)
			removed++
		}
		client.mu.Unlock()
	}

	if removed > 0 {
		rl.logger.Debug("rate limiter cleanup", "removed", removed, "remaining", len(rl.clients))
	}
}

// Stop gracefully stops the rate limiter cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCleanup)
}

// IsExempt checks if a path is exempt from rate limiting.
func (rl *RateLimiter) IsExempt(path string) bool {
	return rl.exemptPaths[path]
}

// Stats returns current rate limiter statistics for monitoring.
func (rl *RateLimiter) Stats() RateLimiterStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	var totalRequests int64
	for _, client := range rl.clients {
		client.mu.Lock()
		totalRequests += client.count
		client.mu.Unlock()
	}

	return RateLimiterStats{
		TrackedIPs:    len(rl.clients),
		TotalRequests: totalRequests,
	}
}

// RateLimiterStats holds rate limiter statistics.
type RateLimiterStats struct {
	TrackedIPs    int   `json:"tracked_ips"`
	TotalRequests int64 `json:"total_requests"`
}

// Global metrics for rate limiting
var (
	rateLimitedTotal uint64 // Total number of rate-limited requests
	rateLimitAllowed uint64 // Total number of allowed requests
)

// GetRateLimitMetrics returns global rate limit metrics.
func GetRateLimitMetrics() (limited, allowed uint64) {
	return atomic.LoadUint64(&rateLimitedTotal), atomic.LoadUint64(&rateLimitAllowed)
}

// RateLimitMiddleware creates HTTP middleware that applies rate limiting based on client IP.
// It sets standard rate limit headers and returns 429 Too Many Requests when limit is exceeded.
func RateLimitMiddleware(cfg config.RateLimitConfig, logger *slog.Logger) func(http.Handler) http.Handler {
	limiter := NewRateLimiter(cfg, logger)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if rate limiting is disabled
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Check exempt paths
			if limiter.IsExempt(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Extract client IP
			ip := getClientIP(r, cfg.TrustProxy)

			// Check rate limit
			allowed, remaining, resetTime := limiter.Allow(ip)

			// Set rate limit headers (RFC 6585 compliant)
			limit := cfg.RequestsPerIP + cfg.BurstSize
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))

			if !allowed {
				atomic.AddUint64(&rateLimitedTotal, 1)

				logger.Warn("rate limit exceeded",
					"ip", ip,
					"path", r.URL.Path,
					"method", r.Method,
				)

				// Set Retry-After header
				retryAfter := int(time.Until(resetTime).Seconds()) + 1
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)

				// Return JSON error response
				fmt.Fprintf(w, `{"code":"RATE_LIMITED","message":"Too many requests. Please try again later.","retry_after":%d}`, retryAfter)
				return
			}

			atomic.AddUint64(&rateLimitAllowed, 1)
			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP from the HTTP request.
// If trustProxy is true, it checks X-Forwarded-For and X-Real-IP headers first.
// Uses the rightmost IP in X-Forwarded-For to prevent client-controlled spoofing.
func getClientIP(r *http.Request, trustProxy bool) string {
	// If we trust the proxy, check X-Forwarded-For header
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For: client, proxy1, proxy2
			// Use the rightmost IP — it was set by the trusted proxy closest to us
			// and cannot be spoofed by the client.
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				ip := trimSpace(parts[i])
				if ip != "" {
					return ip
				}
			}
		}

		// Also check X-Real-IP header (common in nginx)
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, return the whole address
		return r.RemoteAddr
	}
	return ip
}

// trimSpace removes leading and trailing whitespace from a string.
func trimSpace(s string) string {
	start := 0
	end := len(s)

	// Trim leading whitespace
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}

	// Trim trailing whitespace
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}

	return s[start:end]
}

// LoginRateLimiter applies per-username rate limiting for login endpoints.
// This limits brute-force attacks against specific usernames.
type LoginRateLimiter struct {
	attempts    map[string]*loginAttempt
	mu          sync.Mutex
	maxAttempts int
	window      time.Duration
}

type loginAttempt struct {
	count     int
	windowEnd time.Time
}

// NewLoginRateLimiter creates a per-username login rate limiter.
func NewLoginRateLimiter(maxAttempts int, window time.Duration) *LoginRateLimiter {
	return &LoginRateLimiter{
		attempts:    make(map[string]*loginAttempt),
		maxAttempts: maxAttempts,
		window:      window,
	}
}

// AllowLogin checks if a login attempt for the given username should be allowed.
func (l *LoginRateLimiter) AllowLogin(username string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	attempt, exists := l.attempts[username]
	if !exists || now.After(attempt.windowEnd) {
		l.attempts[username] = &loginAttempt{
			count:     1,
			windowEnd: now.Add(l.window),
		}
		return true
	}

	if attempt.count >= l.maxAttempts {
		return false
	}

	attempt.count++
	return true
}

// CleanupLoginAttempts removes expired entries from the login rate limiter.
func (l *LoginRateLimiter) CleanupLoginAttempts() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for username, attempt := range l.attempts {
		if now.After(attempt.windowEnd) {
			delete(l.attempts, username)
		}
	}
}

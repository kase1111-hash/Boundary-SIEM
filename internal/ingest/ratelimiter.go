// Package ingest handles HTTP ingestion of events.
package ingest

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
type RateLimiter struct {
	cfg         config.RateLimitConfig
	clients     map[string]*clientState
	mu          sync.RWMutex
	exemptPaths map[string]bool
	stopCleanup chan struct{}
}

// clientState tracks request counts for a single client.
type clientState struct {
	count     int64     // Current request count in window
	windowEnd time.Time // When current window expires
	mu        sync.Mutex
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(cfg config.RateLimitConfig) *RateLimiter {
	exemptPaths := make(map[string]bool)
	for _, path := range cfg.ExemptPaths {
		exemptPaths[path] = true
	}

	rl := &RateLimiter{
		cfg:         cfg,
		clients:     make(map[string]*clientState),
		exemptPaths: exemptPaths,
		stopCleanup: make(chan struct{}),
	}

	// Start background cleanup
	go rl.cleanupLoop()

	return rl
}

// Allow checks if a request from the given IP should be allowed.
// Returns (allowed, remaining, resetTime).
func (rl *RateLimiter) Allow(ip string) (bool, int, time.Time) {
	now := time.Now()

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

	// Check if window has expired
	if now.After(client.windowEnd) {
		// Reset window
		client.count = 0
		client.windowEnd = now.Add(rl.cfg.WindowSize)
	}

	// Calculate limit (base + burst)
	limit := int64(rl.cfg.RequestsPerIP + rl.cfg.BurstSize)
	remaining := limit - client.count - 1

	if client.count >= limit {
		return false, 0, client.windowEnd
	}

	client.count++
	if remaining < 0 {
		remaining = 0
	}

	return true, int(remaining), client.windowEnd
}

// cleanupLoop periodically removes expired client entries.
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

// cleanup removes expired entries.
func (rl *RateLimiter) cleanup() {
	now := time.Now()
	expiredThreshold := now.Add(-rl.cfg.WindowSize * 2) // Keep entries for 2 windows

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
		slog.Debug("rate limiter cleanup", "removed", removed, "remaining", len(rl.clients))
	}
}

// Stop stops the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCleanup)
}

// IsExempt checks if a path is exempt from rate limiting.
func (rl *RateLimiter) IsExempt(path string) bool {
	return rl.exemptPaths[path]
}

// Stats returns current rate limiter statistics.
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
	rateLimitedTotal uint64
	rateLimitAllowed uint64
)

// rateLimitMiddleware applies rate limiting based on client IP.
func rateLimitMiddleware(next http.Handler, cfg config.RateLimitConfig) http.Handler {
	limiter := NewRateLimiter(cfg)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check exempt paths
		if limiter.IsExempt(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Get client IP
		ip := getClientIP(r, cfg.TrustProxy)

		// Check rate limit
		allowed, remaining, resetTime := limiter.Allow(ip)

		// Set rate limit headers
		limit := cfg.RequestsPerIP + cfg.BurstSize
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime.Unix()))

		if !allowed {
			atomic.AddUint64(&rateLimitedTotal, 1)

			slog.Warn("rate limit exceeded",
				"ip", ip,
				"path", r.URL.Path,
				"method", r.Method,
			)

			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(time.Until(resetTime).Seconds())+1))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprintf(w, `{"code":"RATE_LIMITED","message":"too many requests","retry_after":%d}`,
				int(time.Until(resetTime).Seconds())+1)
			return
		}

		atomic.AddUint64(&rateLimitAllowed, 1)
		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the client IP from the request.
func getClientIP(r *http.Request, trustProxy bool) string {
	// If we trust the proxy, check X-Forwarded-For
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// X-Forwarded-For may contain multiple IPs, take the first
			for i := 0; i < len(xff); i++ {
				if xff[i] == ',' {
					return strings.TrimSpace(xff[:i])
				}
			}
			return strings.TrimSpace(xff)
		}

		// Also check X-Real-IP
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}


// GetRateLimitStats returns rate limiting statistics.
func GetRateLimitStats() (allowed, limited uint64) {
	return atomic.LoadUint64(&rateLimitAllowed), atomic.LoadUint64(&rateLimitedTotal)
}

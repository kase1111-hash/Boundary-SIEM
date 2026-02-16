package middleware

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"boundary-siem/internal/config"
)

// TestRateLimiter_Allow tests the basic Allow functionality.
func TestRateLimiter_Allow(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:       true,
		RequestsPerIP: 10,
		WindowSize:    time.Minute,
		BurstSize:     2,
		CleanupPeriod: 5 * time.Minute,
	}

	limiter := NewRateLimiter(cfg, slog.Default())
	defer limiter.Stop()

	ip := "192.168.1.100"

	// First 12 requests should succeed (10 + 2 burst)
	for i := 0; i < 12; i++ {
		allowed, remaining, _ := limiter.Allow(ip)
		if !allowed {
			t.Errorf("request %d should be allowed, but was denied", i+1)
		}
		expectedRemaining := 12 - i - 1
		if remaining != expectedRemaining {
			t.Errorf("request %d: expected remaining=%d, got %d", i+1, expectedRemaining, remaining)
		}
	}

	// 13th request should be denied
	allowed, remaining, resetTime := limiter.Allow(ip)
	if allowed {
		t.Error("request 13 should be denied, but was allowed")
	}
	if remaining != 0 {
		t.Errorf("expected remaining=0, got %d", remaining)
	}
	if resetTime.Before(time.Now()) {
		t.Error("reset time should be in the future")
	}
}

// TestRateLimiter_WindowReset tests that the window resets properly.
func TestRateLimiter_WindowReset(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:       true,
		RequestsPerIP: 5,
		WindowSize:    100 * time.Millisecond, // Short window for testing
		BurstSize:     0,
		CleanupPeriod: time.Second,
	}

	limiter := NewRateLimiter(cfg, slog.Default())
	defer limiter.Stop()

	ip := "192.168.1.101"

	// Use up the limit
	for i := 0; i < 5; i++ {
		allowed, _, _ := limiter.Allow(ip)
		if !allowed {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}

	// Next request should be denied
	allowed, _, _ := limiter.Allow(ip)
	if allowed {
		t.Error("request should be denied before window reset")
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	allowed, remaining, _ := limiter.Allow(ip)
	if !allowed {
		t.Error("request should be allowed after window reset")
	}
	if remaining != 4 {
		t.Errorf("expected remaining=4 after reset, got %d", remaining)
	}
}

// TestRateLimiter_MultipleIPs tests rate limiting with multiple IP addresses.
func TestRateLimiter_MultipleIPs(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:       true,
		RequestsPerIP: 3,
		WindowSize:    time.Minute,
		BurstSize:     0,
		CleanupPeriod: time.Second,
	}

	limiter := NewRateLimiter(cfg, slog.Default())
	defer limiter.Stop()

	ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}

	// Each IP should have its own limit
	for _, ip := range ips {
		for i := 0; i < 3; i++ {
			allowed, _, _ := limiter.Allow(ip)
			if !allowed {
				t.Errorf("IP %s: request %d should be allowed", ip, i+1)
			}
		}

		// 4th request should be denied
		allowed, _, _ := limiter.Allow(ip)
		if allowed {
			t.Errorf("IP %s: request 4 should be denied", ip)
		}
	}
}

// TestRateLimiter_Cleanup tests the cleanup of expired entries.
func TestRateLimiter_Cleanup(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:       true,
		RequestsPerIP: 10,
		WindowSize:    50 * time.Millisecond,
		BurstSize:     0,
		CleanupPeriod: 100 * time.Millisecond,
	}

	limiter := NewRateLimiter(cfg, slog.Default())
	defer limiter.Stop()

	// Add some requests
	for i := 0; i < 5; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		limiter.Allow(ip)
	}

	// Check initial state
	stats := limiter.Stats()
	if stats.TrackedIPs != 5 {
		t.Errorf("expected 5 tracked IPs, got %d", stats.TrackedIPs)
	}

	// Wait for cleanup to run (windows expire + cleanup period)
	time.Sleep(300 * time.Millisecond)

	// Trigger stats which should show cleaned state
	stats = limiter.Stats()
	if stats.TrackedIPs != 0 {
		t.Errorf("expected 0 tracked IPs after cleanup, got %d", stats.TrackedIPs)
	}
}

// TestRateLimiter_Stats tests statistics collection.
func TestRateLimiter_Stats(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:       true,
		RequestsPerIP: 10,
		WindowSize:    time.Minute,
		BurstSize:     5,
		CleanupPeriod: time.Second,
	}

	limiter := NewRateLimiter(cfg, slog.Default())
	defer limiter.Stop()

	// Make requests from 3 different IPs
	for i := 1; i <= 3; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		for j := 0; j < i; j++ {
			limiter.Allow(ip)
		}
	}

	stats := limiter.Stats()
	if stats.TrackedIPs != 3 {
		t.Errorf("expected 3 tracked IPs, got %d", stats.TrackedIPs)
	}

	// Total requests: 1 + 2 + 3 = 6
	if stats.TotalRequests != 6 {
		t.Errorf("expected 6 total requests, got %d", stats.TotalRequests)
	}
}

// TestRateLimiter_IsExempt tests path exemption.
func TestRateLimiter_IsExempt(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:       true,
		RequestsPerIP: 10,
		WindowSize:    time.Minute,
		BurstSize:     0,
		CleanupPeriod: time.Second,
		ExemptPaths:   []string{"/health", "/metrics"},
	}

	limiter := NewRateLimiter(cfg, slog.Default())
	defer limiter.Stop()

	tests := []struct {
		path     string
		expected bool
	}{
		{"/health", true},
		{"/metrics", true},
		{"/api/users", false},
		{"/healthcheck", false},
		{"/health/status", false},
	}

	for _, tt := range tests {
		result := limiter.IsExempt(tt.path)
		if result != tt.expected {
			t.Errorf("IsExempt(%q) = %v, expected %v", tt.path, result, tt.expected)
		}
	}
}

// TestRateLimitMiddleware tests the HTTP middleware.
func TestRateLimitMiddleware(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:       true,
		RequestsPerIP: 5,
		WindowSize:    time.Minute,
		BurstSize:     0,
		CleanupPeriod: time.Second,
		ExemptPaths:   []string{"/health"},
		TrustProxy:    false,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	middleware := RateLimitMiddleware(cfg, slog.Default())
	wrappedHandler := middleware(handler)

	t.Run("allows requests within limit", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest("GET", "/api/test", nil)
			req.RemoteAddr = "192.168.1.100:12345"
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("request %d: expected status 200, got %d", i+1, w.Code)
			}

			// Check rate limit headers
			if w.Header().Get("X-RateLimit-Limit") == "" {
				t.Error("missing X-RateLimit-Limit header")
			}
			if w.Header().Get("X-RateLimit-Remaining") == "" {
				t.Error("missing X-RateLimit-Remaining header")
			}
			if w.Header().Get("X-RateLimit-Reset") == "" {
				t.Error("missing X-RateLimit-Reset header")
			}
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("expected status 429, got %d", w.Code)
		}

		// Check Retry-After header
		if w.Header().Get("Retry-After") == "" {
			t.Error("missing Retry-After header")
		}

		// Check JSON response
		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Errorf("failed to parse JSON response: %v", err)
		}

		if response["code"] != "RATE_LIMITED" {
			t.Errorf("expected code RATE_LIMITED, got %v", response["code"])
		}
	})

	t.Run("exempts configured paths", func(t *testing.T) {
		// Even though previous tests exhausted the limit for this IP,
		// exempt paths should still work
		req := httptest.NewRequest("GET", "/health", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected exempt path to return 200, got %d", w.Code)
		}
	})

	t.Run("separate limits for different IPs", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "192.168.1.200:12345"
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("new IP should be allowed, got status %d", w.Code)
		}
	})
}

// TestRateLimitMiddleware_Disabled tests that middleware passes through when disabled.
func TestRateLimitMiddleware_Disabled(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:       false, // Disabled
		RequestsPerIP: 1,
		WindowSize:    time.Minute,
		BurstSize:     0,
		CleanupPeriod: time.Second,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := RateLimitMiddleware(cfg, slog.Default())
	wrappedHandler := middleware(handler)

	// Make many requests - should all pass through
	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected status 200 (disabled rate limit), got %d", i+1, w.Code)
		}
	}
}

// TestRateLimitMiddleware_TrustProxy tests X-Forwarded-For handling.
func TestRateLimitMiddleware_TrustProxy(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:       true,
		RequestsPerIP: 2,
		WindowSize:    time.Minute,
		BurstSize:     0,
		CleanupPeriod: time.Second,
		TrustProxy:    true,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := RateLimitMiddleware(cfg, slog.Default())
	wrappedHandler := middleware(handler)

	t.Run("uses X-Forwarded-For when trust proxy enabled", func(t *testing.T) {
		// Make 2 requests from same X-Forwarded-For IP
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/api/test", nil)
			req.RemoteAddr = "127.0.0.1:12345"
			req.Header.Set("X-Forwarded-For", "203.0.113.100")
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("request %d: expected status 200, got %d", i+1, w.Code)
			}
		}

		// 3rd request should be rate limited
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.100")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("expected status 429, got %d", w.Code)
		}
	})

	t.Run("uses X-Real-IP when present", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Real-IP", "203.0.113.200")
		w := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}
	})
}

// TestRateLimitMiddleware_Concurrent tests concurrent requests.
func TestRateLimitMiddleware_Concurrent(t *testing.T) {
	cfg := config.RateLimitConfig{
		Enabled:       true,
		RequestsPerIP: 100,
		WindowSize:    time.Minute,
		BurstSize:     50,
		CleanupPeriod: time.Second,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := RateLimitMiddleware(cfg, slog.Default())
	wrappedHandler := middleware(handler)

	// Run 200 concurrent requests from same IP
	var wg sync.WaitGroup
	successCount := int32(0)
	rateLimitedCount := int32(0)

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req := httptest.NewRequest("GET", "/api/test", nil)
			req.RemoteAddr = "192.168.1.100:12345"
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				successCount++
			} else if w.Code == http.StatusTooManyRequests {
				rateLimitedCount++
			}
		}()
	}

	wg.Wait()

	// Should have exactly 150 successes (100 + 50 burst) and 50 rate limited
	if successCount != 150 {
		t.Errorf("expected 150 successful requests, got %d", successCount)
	}
	if rateLimitedCount != 50 {
		t.Errorf("expected 50 rate limited requests, got %d", rateLimitedCount)
	}
}

// TestGetClientIP tests IP extraction logic.
func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		trustProxy bool
		expected   string
	}{
		{
			name:       "basic RemoteAddr",
			remoteAddr: "192.168.1.100:12345",
			trustProxy: false,
			expected:   "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For when trust proxy",
			remoteAddr: "127.0.0.1:12345",
			xff:        "203.0.113.100",
			trustProxy: true,
			expected:   "203.0.113.100",
		},
		{
			name:       "X-Forwarded-For ignored when not trust proxy",
			remoteAddr: "192.168.1.100:12345",
			xff:        "203.0.113.100",
			trustProxy: false,
			expected:   "192.168.1.100",
		},
		{
			name:       "X-Forwarded-For with multiple IPs",
			remoteAddr: "127.0.0.1:12345",
			xff:        "203.0.113.100, 198.51.100.50",
			trustProxy: true,
			expected:   "198.51.100.50", // Rightmost IP (set by trusted proxy, not client-spoofable)
		},
		{
			name:       "X-Real-IP when trust proxy",
			remoteAddr: "127.0.0.1:12345",
			xri:        "203.0.113.200",
			trustProxy: true,
			expected:   "203.0.113.200",
		},
		{
			name:       "X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr: "127.0.0.1:12345",
			xff:        "203.0.113.100",
			xri:        "203.0.113.200",
			trustProxy: true,
			expected:   "203.0.113.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}

			result := getClientIP(req, tt.trustProxy)
			if result != tt.expected {
				t.Errorf("expected IP %q, got %q", tt.expected, result)
			}
		})
	}
}

// BenchmarkRateLimiter_Allow benchmarks the Allow method.
func BenchmarkRateLimiter_Allow(b *testing.B) {
	cfg := config.RateLimitConfig{
		Enabled:       true,
		RequestsPerIP: 1000,
		WindowSize:    time.Minute,
		BurstSize:     100,
		CleanupPeriod: time.Minute,
	}

	limiter := NewRateLimiter(cfg, slog.Default())
	defer limiter.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.Allow("192.168.1.100")
	}
}

// BenchmarkRateLimitMiddleware benchmarks the middleware.
func BenchmarkRateLimitMiddleware(b *testing.B) {
	cfg := config.RateLimitConfig{
		Enabled:       true,
		RequestsPerIP: 10000,
		WindowSize:    time.Minute,
		BurstSize:     1000,
		CleanupPeriod: time.Minute,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := RateLimitMiddleware(cfg, slog.Default())
	wrappedHandler := middleware(handler)

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)
	}
}

package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"boundary-siem/internal/config"
)

// goroutinesSettleTo waits until the number of goroutines is at most max
// and reports whether it got there.
func goroutinesSettleTo(max int) bool {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if runtime.NumGoroutine() <= max {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func lifecycleConfig(enabled bool) config.RateLimitConfig {
	return config.RateLimitConfig{
		Enabled:       enabled,
		RequestsPerIP: 2,
		WindowSize:    time.Minute,
		CleanupPeriod: time.Hour,
	}
}

// TestRateLimitMiddleware_DisabledStartsNoGoroutine checks that building the
// middleware with rate limiting disabled starts no cleanup goroutine.
func TestRateLimitMiddleware_DisabledStartsNoGoroutine(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := 0; i < 10; i++ {
		_ = RateLimitMiddleware(lifecycleConfig(false), slog.Default())
	}
	if !goroutinesSettleTo(before) {
		t.Errorf("goroutines = %d after building 10 disabled middlewares, want at most %d", runtime.NumGoroutine(), before)
	}
}

// TestRateLimiter_StopIsIdempotent checks that Stop may be called more than
// once (for example by a deferred stop and an explicit shutdown).
func TestRateLimiter_StopIsIdempotent(t *testing.T) {
	limiter := NewRateLimiter(lifecycleConfig(true), slog.Default())
	limiter.Stop()
	limiter.Stop()
}

// TestRateLimitMiddleware_NilLogger checks that a nil logger falls back to
// the default logger instead of panicking when a request is rejected.
func TestRateLimitMiddleware_NilLogger(t *testing.T) {
	mw := RateLimitMiddleware(lifecycleConfig(true), nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	codes := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.RemoteAddr = "192.0.2.10:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		codes = append(codes, w.Code)
	}
	if codes[2] != http.StatusTooManyRequests {
		t.Errorf("status codes = %v, want the third request rejected with 429", codes)
	}
}

// TestNewRateLimiter_NonPositiveCleanupPeriod checks that a zero cleanup
// period does not crash the process: time.NewTicker panics on a non-positive
// interval, and that panic would happen in the background goroutine.
func TestNewRateLimiter_NonPositiveCleanupPeriod(t *testing.T) {
	cfg := lifecycleConfig(true)
	cfg.CleanupPeriod = 0
	limiter := NewRateLimiter(cfg, slog.Default())
	defer limiter.Stop()

	if limiter.cfg.CleanupPeriod != defaultCleanupPeriod {
		t.Errorf("CleanupPeriod = %v, want default %v", limiter.cfg.CleanupPeriod, defaultCleanupPeriod)
	}
	if allowed, _, _ := limiter.Allow("192.0.2.20"); !allowed {
		t.Error("first request should be allowed")
	}
	// Give the cleanup goroutine time to start its ticker.
	time.Sleep(50 * time.Millisecond)
}

// TestNewRateLimitMiddleware_StopEndsCleanupGoroutine checks that the stop
// function returned with the middleware ends the limiter's cleanup goroutine,
// and may be called more than once.
func TestNewRateLimitMiddleware_StopEndsCleanupGoroutine(t *testing.T) {
	const n = 10
	stops := make([]func(), 0, n)
	for i := 0; i < n; i++ {
		mw, stop := NewRateLimitMiddleware(lifecycleConfig(true), slog.Default())
		stops = append(stops, stop)

		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.RemoteAddr = "192.0.2.30:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
	}
	running := runtime.NumGoroutine()

	for _, stop := range stops {
		stop()
		stop()
	}
	if !goroutinesSettleTo(running - n) {
		t.Errorf("goroutines = %d after stopping %d limiters, want at most %d (was %d)", runtime.NumGoroutine(), n, running-n, running)
	}
}

// TestNewRateLimitMiddleware_Limits checks the middleware returned by
// NewRateLimitMiddleware enforces the limit when enabled and passes requests
// through when disabled.
func TestNewRateLimitMiddleware_Limits(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		wantCodes   []int
		wantHeaders bool
	}{
		{
			name:        "enabled",
			enabled:     true,
			wantCodes:   []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests},
			wantHeaders: true,
		},
		{
			name:      "disabled",
			enabled:   false,
			wantCodes: []int{http.StatusOK, http.StatusOK, http.StatusOK},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw, stop := NewRateLimitMiddleware(lifecycleConfig(tt.enabled), nil)
			defer stop()
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

			for i, want := range tt.wantCodes {
				req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
				req.RemoteAddr = "192.0.2.40:1234"
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				if w.Code != want {
					t.Errorf("request %d: status = %d, want %d", i+1, w.Code, want)
				}
				if got := w.Header().Get("X-RateLimit-Limit") != ""; got != tt.wantHeaders {
					t.Errorf("request %d: X-RateLimit-Limit present = %v, want %v", i+1, got, tt.wantHeaders)
				}
			}
		})
	}
}

// TestRateLimiter_Middleware checks middleware built from a caller-owned
// limiter counts requests against that limiter.
func TestRateLimiter_Middleware(t *testing.T) {
	limiter := NewRateLimiter(lifecycleConfig(true), slog.Default())
	defer limiter.Stop()

	handler := limiter.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "192.0.2.50:1234"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	stats := limiter.Stats()
	if stats.TrackedIPs != 1 || stats.TotalRequests != 1 {
		t.Errorf("Stats() = %+v, want 1 tracked IP with 1 request", stats)
	}
}

package cef

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func newCapturedRejectLogger(interval time.Duration) (*RejectLogger, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return NewRejectLogger(logger, "tcp", interval), &buf
}

func warnLines(buf *bytes.Buffer) []string {
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.Contains(line, "level=WARN") {
			lines = append(lines, line)
		}
	}
	return lines
}

// TestRejectLogger_RateLimitsWarnings checks that rejected messages are
// reported at WARN (they used to be DEBUG only) without flooding the log.
func TestRejectLogger_RateLimitsWarnings(t *testing.T) {
	rl, buf := newCapturedRejectLogger(time.Hour)

	for i := 0; i < 50; i++ {
		rl.Reject("parse", ErrInvalidCEF, "10.0.0.1", "garbage line")
	}
	lines := warnLines(buf)
	if len(lines) != 1 {
		t.Fatalf("got %d WARN lines for 50 rejections within one interval, want 1:\n%s", len(lines), buf.String())
	}
	for _, want := range []string{"transport=tcp", "stage=parse", "source=10.0.0.1", `sample="garbage line"`, "suppressed_since_last_warning=0"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("WARN line %q does not contain %q", lines[0], want)
		}
	}

	// Once the interval has passed, the next rejection is logged together
	// with the number suppressed in between.
	rl.mu.Lock()
	rl.lastWarn = time.Now().Add(-2 * time.Hour)
	rl.mu.Unlock()
	rl.Reject("validate", ErrInvalidSeverity, "10.0.0.2", "x")

	lines = warnLines(buf)
	if len(lines) != 2 {
		t.Fatalf("got %d WARN lines, want 2:\n%s", len(lines), buf.String())
	}
	if !strings.Contains(lines[1], "suppressed_since_last_warning=49") {
		t.Errorf("second WARN line %q should report 49 suppressed rejections", lines[1])
	}
}

func TestRejectLogger_Concurrent(t *testing.T) {
	rl, buf := newCapturedRejectLogger(time.Hour)

	const goroutines, perGoroutine = 8, 100
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				rl.Reject("parse", ErrInvalidCEF, "10.0.0.1", "garbage")
			}
		}()
	}
	wg.Wait()

	if n := len(warnLines(buf)); n != 1 {
		t.Fatalf("got %d WARN lines, want 1", n)
	}
	rl.mu.Lock()
	suppressed := rl.suppressed
	rl.mu.Unlock()
	if suppressed != goroutines*perGoroutine-1 {
		t.Errorf("suppressed = %d, want %d", suppressed, goroutines*perGoroutine-1)
	}
}

func TestRejectLogger_SampleIsTruncated(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"short", "  abc \n", "abc"},
		{"long ascii", strings.Repeat("a", 500), strings.Repeat("a", rejectSampleLen) + "..."},
		{"multibyte at the cut", strings.Repeat("a", rejectSampleLen-1) + "ééé", strings.Repeat("a", rejectSampleLen-1) + "..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sample(tt.raw); got != tt.want {
				t.Errorf("sample() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRejectLogger_NilLoggerUsesDefault(t *testing.T) {
	rl := NewRejectLogger(nil, "udp", 0)
	if rl.interval != DefaultRejectLogInterval {
		t.Errorf("interval = %v, want %v", rl.interval, DefaultRejectLogInterval)
	}
	// Must not panic.
	rl.Reject("parse", ErrInvalidCEF, "", "")
}

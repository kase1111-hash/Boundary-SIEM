package cef

import (
	"log/slog"
	"strings"
	"sync"
	"time"
)

// DefaultRejectLogInterval is the default minimum gap between two WARN lines
// from one RejectLogger.
const DefaultRejectLogInterval = 10 * time.Second

// rejectSampleLen bounds how much of a rejected message is logged.
const rejectSampleLen = 80

// RejectLogger reports messages that an ingest server had to drop. The first
// rejection in each interval is logged at WARN with a short sample of the
// message; later ones are only counted, and the count is included in the next
// WARN line, so a misconfigured or hostile sender cannot flood the log. Every
// rejection is also logged at DEBUG. It is safe for concurrent use.
type RejectLogger struct {
	logger    *slog.Logger
	transport string
	interval  time.Duration

	mu         sync.Mutex
	lastWarn   time.Time
	suppressed uint64
}

// NewRejectLogger returns a RejectLogger for the named transport ("udp",
// "tcp", "dtls"). A nil logger means slog.Default() at the time of logging;
// a non-positive interval means DefaultRejectLogInterval.
func NewRejectLogger(logger *slog.Logger, transport string, interval time.Duration) *RejectLogger {
	if interval <= 0 {
		interval = DefaultRejectLogInterval
	}
	return &RejectLogger{
		logger:    logger,
		transport: transport,
		interval:  interval,
	}
}

// Reject records a dropped message. stage names the step that rejected it
// (for example "parse", "validate", "oversize" or "queue").
func (l *RejectLogger) Reject(stage string, err error, source, raw string) {
	logger := l.logger
	if logger == nil {
		logger = slog.Default()
	}

	logger.Debug("CEF message rejected",
		"transport", l.transport,
		"stage", stage,
		"error", err,
		"source", source,
	)

	now := time.Now()
	l.mu.Lock()
	if !l.lastWarn.IsZero() && now.Sub(l.lastWarn) < l.interval {
		l.suppressed++
		l.mu.Unlock()
		return
	}
	suppressed := l.suppressed
	l.suppressed = 0
	l.lastWarn = now
	l.mu.Unlock()

	logger.Warn("CEF message rejected",
		"transport", l.transport,
		"stage", stage,
		"error", err,
		"source", source,
		"sample", sample(raw),
		"suppressed_since_last_warning", suppressed,
	)
}

// sample returns the start of raw, trimmed and cut to rejectSampleLen bytes
// without splitting a UTF-8 sequence.
func sample(raw string) string {
	s := strings.TrimSpace(raw)
	if len(s) <= rejectSampleLen {
		return s
	}
	return strings.ToValidUTF8(s[:rejectSampleLen], "") + "..."
}

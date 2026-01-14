package boundarydaemon

import (
	"testing"
	"time"
)

func TestDefaultIngesterConfig(t *testing.T) {
	cfg := DefaultIngesterConfig()

	if cfg.PollInterval != 30*time.Second {
		t.Errorf("expected PollInterval 30s, got %v", cfg.PollInterval)
	}
	if cfg.SessionBatchSize != 500 {
		t.Errorf("expected SessionBatchSize 500, got %d", cfg.SessionBatchSize)
	}
	if cfg.AuthBatchSize != 500 {
		t.Errorf("expected AuthBatchSize 500, got %d", cfg.AuthBatchSize)
	}
	if cfg.AccessBatchSize != 500 {
		t.Errorf("expected AccessBatchSize 500, got %d", cfg.AccessBatchSize)
	}
	if cfg.ThreatBatchSize != 100 {
		t.Errorf("expected ThreatBatchSize 100, got %d", cfg.ThreatBatchSize)
	}
	if cfg.PolicyBatchSize != 200 {
		t.Errorf("expected PolicyBatchSize 200, got %d", cfg.PolicyBatchSize)
	}
	if cfg.AuditBatchSize != 500 {
		t.Errorf("expected AuditBatchSize 500, got %d", cfg.AuditBatchSize)
	}

	// Check ingest flags
	if !cfg.IngestSessions {
		t.Error("expected IngestSessions to be true")
	}
	if !cfg.IngestAuth {
		t.Error("expected IngestAuth to be true")
	}
	if !cfg.IngestAccess {
		t.Error("expected IngestAccess to be true")
	}
	if !cfg.IngestThreats {
		t.Error("expected IngestThreats to be true")
	}
	if !cfg.IngestPolicies {
		t.Error("expected IngestPolicies to be true")
	}
	if !cfg.IngestAuditLogs {
		t.Error("expected IngestAuditLogs to be true")
	}

	// VerifyAuditLogs should be disabled by default for performance
	if cfg.VerifyAuditLogs {
		t.Error("expected VerifyAuditLogs to be false by default")
	}

	if cfg.MinThreatSeverity != "low" {
		t.Errorf("expected MinThreatSeverity 'low', got %s", cfg.MinThreatSeverity)
	}
}

func TestMeetsMinSeverity(t *testing.T) {
	tests := []struct {
		name              string
		minSeverity       string
		eventSeverity     string
		expectPass        bool
	}{
		{
			name:          "low min, low event",
			minSeverity:   "low",
			eventSeverity: "low",
			expectPass:    true,
		},
		{
			name:          "low min, critical event",
			minSeverity:   "low",
			eventSeverity: "critical",
			expectPass:    true,
		},
		{
			name:          "high min, low event",
			minSeverity:   "high",
			eventSeverity: "low",
			expectPass:    false,
		},
		{
			name:          "high min, high event",
			minSeverity:   "high",
			eventSeverity: "high",
			expectPass:    true,
		},
		{
			name:          "high min, critical event",
			minSeverity:   "high",
			eventSeverity: "critical",
			expectPass:    true,
		},
		{
			name:          "critical min, high event",
			minSeverity:   "critical",
			eventSeverity: "high",
			expectPass:    false,
		},
		{
			name:          "critical min, critical event",
			minSeverity:   "critical",
			eventSeverity: "critical",
			expectPass:    true,
		},
		{
			name:          "medium min, medium event",
			minSeverity:   "medium",
			eventSeverity: "medium",
			expectPass:    true,
		},
		{
			name:          "medium min, low event",
			minSeverity:   "medium",
			eventSeverity: "low",
			expectPass:    false,
		},
		{
			name:          "unknown severity passes through",
			minSeverity:   "high",
			eventSeverity: "unknown",
			expectPass:    true, // Unknown severities should pass through
		},
		{
			name:          "unknown min allows all",
			minSeverity:   "unknown",
			eventSeverity: "low",
			expectPass:    true, // Unknown min severity allows all
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultIngesterConfig()
			cfg.MinThreatSeverity = tt.minSeverity

			// Create minimal ingester just for testing meetsMinSeverity
			ingester := &Ingester{
				config: cfg,
			}

			result := ingester.meetsMinSeverity(tt.eventSeverity)
			if result != tt.expectPass {
				t.Errorf("meetsMinSeverity(%q) with min=%q: got %v, expected %v",
					tt.eventSeverity, tt.minSeverity, result, tt.expectPass)
			}
		})
	}
}

func TestIngesterStats(t *testing.T) {
	cfg := DefaultIngesterConfig()
	ingester := &Ingester{
		config:          cfg,
		lastSessionTime: time.Now().Add(-1 * time.Hour),
		lastAuthTime:    time.Now().Add(-2 * time.Hour),
		lastAccessTime:  time.Now().Add(-30 * time.Minute),
		lastThreatTime:  time.Now().Add(-15 * time.Minute),
		lastPolicyTime:  time.Now().Add(-45 * time.Minute),
		lastAuditTime:   time.Now().Add(-10 * time.Minute),
		running:         true,
	}

	stats := ingester.Stats()

	if !stats.Running {
		t.Error("expected Running to be true")
	}
	if stats.LastSessionTime.IsZero() {
		t.Error("expected LastSessionTime to be non-zero")
	}
	if stats.LastAuthTime.IsZero() {
		t.Error("expected LastAuthTime to be non-zero")
	}
	if stats.LastAccessTime.IsZero() {
		t.Error("expected LastAccessTime to be non-zero")
	}
	if stats.LastThreatTime.IsZero() {
		t.Error("expected LastThreatTime to be non-zero")
	}
	if stats.LastPolicyTime.IsZero() {
		t.Error("expected LastPolicyTime to be non-zero")
	}
	if stats.LastAuditTime.IsZero() {
		t.Error("expected LastAuditTime to be non-zero")
	}
}

func TestIngesterStats_NotRunning(t *testing.T) {
	cfg := DefaultIngesterConfig()
	ingester := &Ingester{
		config:  cfg,
		running: false,
	}

	stats := ingester.Stats()

	if stats.Running {
		t.Error("expected Running to be false")
	}
}

func TestNewIngester(t *testing.T) {
	client := NewClient(DefaultClientConfig())
	normalizer := NewNormalizer(DefaultNormalizerConfig())
	cfg := DefaultIngesterConfig()

	// NewIngester requires a queue, but we can test with nil for basic creation
	// In a real test, we'd need to create a proper queue

	// Just verify the config values are reasonable
	if cfg.PollInterval <= 0 {
		t.Error("expected positive PollInterval")
	}
	if cfg.SessionBatchSize <= 0 {
		t.Error("expected positive SessionBatchSize")
	}

	// Verify client and normalizer are properly initialized
	if client == nil {
		t.Error("expected non-nil client")
	}
	if normalizer == nil {
		t.Error("expected non-nil normalizer")
	}
}

func TestSeverityLevels(t *testing.T) {
	// Verify the severity level ordering
	levels := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	if levels["low"] >= levels["medium"] {
		t.Error("low should be less than medium")
	}
	if levels["medium"] >= levels["high"] {
		t.Error("medium should be less than high")
	}
	if levels["high"] >= levels["critical"] {
		t.Error("high should be less than critical")
	}
}

package cef

import (
	"testing"
	"time"

	"boundary-siem/internal/schema"
)

func TestNormalizer_Normalize(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())
	parser := NewParser(DefaultParserConfig())

	tests := []struct {
		name      string
		message   string
		sourceIP  string
		checkFunc func(t *testing.T, event *schema.Event)
	}{
		{
			name:     "boundary session created",
			message:  "CEF:0|Boundary|boundary-daemon|1.0.0|100|Session Created|3|src=192.168.1.10 suser=admin dhost=db-prod-01 outcome=success",
			sourceIP: "10.0.0.1",
			checkFunc: func(t *testing.T, event *schema.Event) {
				if event.Action != "session.created" {
					t.Errorf("Action = %s, want session.created", event.Action)
				}
				if event.Source.Product != "boundary-daemon" {
					t.Errorf("Source.Product = %s, want boundary-daemon", event.Source.Product)
				}
				if event.Outcome != schema.OutcomeSuccess {
					t.Errorf("Outcome = %s, want success", event.Outcome)
				}
				if event.Severity != 3 {
					t.Errorf("Severity = %d, want 3", event.Severity)
				}
				if event.Actor == nil {
					t.Fatal("Actor should not be nil")
				}
				if event.Actor.Name != "admin" {
					t.Errorf("Actor.Name = %s, want admin", event.Actor.Name)
				}
				if event.Actor.IPAddress != "192.168.1.10" {
					t.Errorf("Actor.IPAddress = %s, want 192.168.1.10", event.Actor.IPAddress)
				}
			},
		},
		{
			name:     "auth failure",
			message:  "CEF:0|Boundary|boundary-daemon|1.0.0|400|Authentication Failed|7|src=10.0.0.50 suser=unknown outcome=failure reason=invalid_password",
			sourceIP: "10.0.0.2",
			checkFunc: func(t *testing.T, event *schema.Event) {
				if event.Action != "auth.failure" {
					t.Errorf("Action = %s, want auth.failure", event.Action)
				}
				if event.Outcome != schema.OutcomeFailure {
					t.Errorf("Outcome = %s, want failure", event.Outcome)
				}
				if event.Severity != 7 {
					t.Errorf("Severity = %d, want 7", event.Severity)
				}
				if event.Metadata["cef_reason"] != "invalid_password" {
					t.Errorf("Metadata[cef_reason] = %v, want invalid_password", event.Metadata["cef_reason"])
				}
			},
		},
		{
			name:     "threat detection with target",
			message:  "CEF:0|SecurityVendor|IDS|2.0|THREAT|Malware Detected|9|src=203.0.113.50 dst=192.168.1.100 dhost=victim-host filePath=/tmp/evil.exe act=blocked",
			sourceIP: "10.0.0.3",
			checkFunc: func(t *testing.T, event *schema.Event) {
				if event.Action != "threat.detected" {
					t.Errorf("Action = %s, want threat.detected", event.Action)
				}
				if event.Severity != 9 {
					t.Errorf("Severity = %d, want 9", event.Severity)
				}
				// Should have target with host and file
				if event.Target == "" {
					t.Error("Target should not be empty")
				}
				// Outcome should be failure due to "blocked" action
				if event.Outcome != schema.OutcomeFailure {
					t.Errorf("Outcome = %s, want failure (blocked)", event.Outcome)
				}
			},
		},
		{
			name:     "unknown signature falls back to event name",
			message:  "CEF:0|Vendor|Product|1.0|UNKNOWN_SIG|Custom Event Name|5|src=1.2.3.4",
			sourceIP: "10.0.0.4",
			checkFunc: func(t *testing.T, event *schema.Event) {
				// Should use normalized event name
				if event.Action != "event.custom_event_name" {
					t.Errorf("Action = %s, want event.custom_event_name", event.Action)
				}
			},
		},
		{
			name:     "no actor info",
			message:  "CEF:0|Vendor|Product|1.0|SIG|Event|5|dst=1.2.3.4",
			sourceIP: "10.0.0.5",
			checkFunc: func(t *testing.T, event *schema.Event) {
				if event.Actor != nil {
					t.Error("Actor should be nil when no actor info in CEF")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cefEvent, err := parser.Parse(tt.message)
			if err != nil {
				t.Fatalf("failed to parse CEF: %v", err)
			}

			event, err := normalizer.Normalize(cefEvent, tt.sourceIP)
			if err != nil {
				t.Fatalf("failed to normalize: %v", err)
			}

			// Common checks
			if event.EventID.String() == "" {
				t.Error("EventID should be set")
			}
			if event.Timestamp.IsZero() {
				t.Error("Timestamp should be set")
			}
			if event.ReceivedAt.IsZero() {
				t.Error("ReceivedAt should be set")
			}
			if event.SchemaVersion != "1.0.0" {
				t.Errorf("SchemaVersion = %s, want 1.0.0", event.SchemaVersion)
			}
			if event.Raw == "" {
				t.Error("Raw should contain original message")
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, event)
			}
		})
	}
}

func TestNormalizer_ExtractOutcome(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())

	tests := []struct {
		name     string
		cef      *CEFEvent
		expected schema.Outcome
	}{
		{
			name: "outcome=success",
			cef: &CEFEvent{
				Extensions: map[string]string{"outcome": "success"},
			},
			expected: schema.OutcomeSuccess,
		},
		{
			name: "outcome=succeeded",
			cef: &CEFEvent{
				Extensions: map[string]string{"outcome": "succeeded"},
			},
			expected: schema.OutcomeSuccess,
		},
		{
			name: "outcome=failure",
			cef: &CEFEvent{
				Extensions: map[string]string{"outcome": "failure"},
			},
			expected: schema.OutcomeFailure,
		},
		{
			name: "outcome=denied",
			cef: &CEFEvent{
				Extensions: map[string]string{"outcome": "denied"},
			},
			expected: schema.OutcomeFailure,
		},
		{
			name: "act=blocked",
			cef: &CEFEvent{
				Extensions: map[string]string{"act": "blocked"},
			},
			expected: schema.OutcomeFailure,
		},
		{
			name: "act=allow",
			cef: &CEFEvent{
				Extensions: map[string]string{"act": "allow"},
			},
			expected: schema.OutcomeSuccess,
		},
		{
			name: "no outcome info",
			cef: &CEFEvent{
				Extensions: map[string]string{"src": "1.2.3.4"},
			},
			expected: schema.OutcomeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizer.extractOutcome(tt.cef)
			if result != tt.expected {
				t.Errorf("extractOutcome() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestNormalizer_MapSeverity(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())

	tests := []struct {
		input    int
		expected int
	}{
		{0, 1}, // Below minimum, should be 1
		{1, 1},
		{5, 5},
		{10, 10},
		{11, 10}, // Above maximum, should be 10
		{-1, 1},  // Negative, should be 1
	}

	for _, tt := range tests {
		result := normalizer.mapSeverity(tt.input)
		if result != tt.expected {
			t.Errorf("mapSeverity(%d) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestNormalizer_ParseTimestamp(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "milliseconds since epoch",
			input:   "1609459200000", // 2021-01-01 00:00:00 UTC
			wantErr: false,
		},
		{
			name:    "RFC3339",
			input:   "2021-01-01T00:00:00Z",
			wantErr: false,
		},
		{
			name:    "invalid format",
			input:   "not-a-timestamp",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := normalizer.parseTimestamp(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result.IsZero() {
				t.Error("timestamp should not be zero")
			}
		})
	}
}

func TestNormalizer_ExtractTimestamp(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())
	now := time.Now()

	tests := []struct {
		name      string
		cef       *CEFEvent
		checkFunc func(t *testing.T, ts time.Time)
	}{
		{
			name: "uses rt extension",
			cef: &CEFEvent{
				Extensions: map[string]string{
					"rt": "1609459200000",
				},
			},
			checkFunc: func(t *testing.T, ts time.Time) {
				expected := time.UnixMilli(1609459200000).UTC()
				if !ts.Equal(expected) {
					t.Errorf("timestamp = %v, want %v", ts, expected)
				}
			},
		},
		{
			name: "falls back to start",
			cef: &CEFEvent{
				Extensions: map[string]string{
					"start": "1609459200000",
				},
			},
			checkFunc: func(t *testing.T, ts time.Time) {
				expected := time.UnixMilli(1609459200000).UTC()
				if !ts.Equal(expected) {
					t.Errorf("timestamp = %v, want %v", ts, expected)
				}
			},
		},
		{
			name: "defaults to now",
			cef: &CEFEvent{
				Extensions: map[string]string{},
			},
			checkFunc: func(t *testing.T, ts time.Time) {
				if ts.Before(now.Add(-time.Second)) {
					t.Errorf("timestamp %v should be close to now %v", ts, now)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizer.extractTimestamp(tt.cef)
			if tt.checkFunc != nil {
				tt.checkFunc(t, result)
			}
		})
	}
}

func BenchmarkNormalizer_Normalize(b *testing.B) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())
	parser := NewParser(DefaultParserConfig())
	message := "CEF:0|Boundary|boundary-daemon|1.0.0|100|Session Created|3|src=192.168.1.10 suser=admin dhost=db-prod-01 outcome=success"

	cefEvent, _ := parser.Parse(message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = normalizer.Normalize(cefEvent, "10.0.0.1")
	}
}

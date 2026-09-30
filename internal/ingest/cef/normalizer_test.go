package cef

import (
	"strconv"
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

// TestNormalizer_ActionAlwaysValid is a regression test for event names with
// ':', '(' or a leading digit producing actions that fail the schema's
// action_format validation, which made the servers drop the events.
func TestNormalizer_ActionAlwaysValid(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())

	tests := []struct {
		name  string
		cef   *CEFEvent
		want  string
		label string
	}{
		{label: "fortinet colon", cef: &CEFEvent{SignatureID: "0000000013", Name: "traffic:forward accept"}, want: "event.traffic_forward_accept"},
		{label: "parentheses", cef: &CEFEvent{SignatureID: "942100", Name: "SQL Injection (libinjection)"}, want: "event.sql_injection_libinjection"},
		{label: "leading digit", cef: &CEFEvent{SignatureID: "x", Name: "404 Not Found"}, want: "event.n404_not_found"},
		{label: "plain name unchanged", cef: &CEFEvent{SignatureID: "x", Name: "Custom Event Name"}, want: "event.custom_event_name"},
		{label: "dotted name keeps dots", cef: &CEFEvent{SignatureID: "x", Name: "Network.Connection-Allowed"}, want: "network.connection_allowed"},
		{label: "empty segments dropped", cef: &CEFEvent{SignatureID: "x", Name: "a..b."}, want: "a.b"},
		{label: "digit segment", cef: &CEFEvent{SignatureID: "x", Name: "net.1st hop"}, want: "net.n1st_hop"},
		{label: "only punctuation", cef: &CEFEvent{SignatureID: "x", Name: "!!!"}, want: "event.unknown"},
		{label: "empty name", cef: &CEFEvent{SignatureID: "x", Name: ""}, want: "event.unknown"},
		{label: "non-ascii", cef: &CEFEvent{SignatureID: "x", Name: "Übergabe fehlgeschlagen"}, want: "event.bergabe_fehlgeschlagen"},
		{label: "act extension sanitised", cef: &CEFEvent{SignatureID: "x", Name: "n", Extensions: map[string]string{"act": "Block/Drop"}}, want: "event.block_drop"},
		{label: "mapped signature untouched", cef: &CEFEvent{SignatureID: "100", Name: "404 whatever"}, want: "session.created"},
	}

	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			if tt.cef.Extensions == nil {
				tt.cef.Extensions = map[string]string{}
			}
			got := normalizer.mapAction(tt.cef)
			if got != tt.want {
				t.Errorf("mapAction(%q) = %q, want %q", tt.cef.Name, got, tt.want)
			}
			if !schema.ValidateAction(got) {
				t.Errorf("mapAction(%q) = %q does not satisfy the schema action format", tt.cef.Name, got)
			}
		})
	}
}

// TestNormalizer_TimestampFormats is a regression test for the CEF-spec
// "MMM dd HH:mm:ss" family of rt/start formats: the year-less forms parsed
// to year 0 (and the event was rejected as too old), and the millisecond and
// time-zone variants fell back to time.Now().
func TestNormalizer_TimestampFormats(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())
	validator := schema.NewValidator()

	ref := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	refMs := ref.Add(123 * time.Millisecond)
	plus2 := time.FixedZone("", 2*3600)

	tests := []struct {
		name string
		ts   string
		want time.Time
	}{
		{"MMM dd HH:mm:ss", ref.Format("Jan 02 15:04:05"), ref},
		{"MMM d HH:mm:ss (space padded)", ref.Format("Jan _2 15:04:05"), ref},
		{"MMM dd HH:mm:ss.SSS", refMs.Format("Jan 02 15:04:05.000"), refMs},
		{"MMM dd HH:mm:ss zzz", ref.Format("Jan 02 15:04:05 MST"), ref},
		{"MMM dd HH:mm:ss.SSS zzz", refMs.Format("Jan 02 15:04:05.000 MST"), refMs},
		{"MMM dd HH:mm:ss numeric zone", ref.In(plus2).Format("Jan 02 15:04:05 -0700"), ref},
		{"MMM dd yyyy HH:mm:ss", ref.Format("Jan 02 2006 15:04:05"), ref},
		{"MMM dd yyyy HH:mm:ss.SSS", refMs.Format("Jan 02 2006 15:04:05.000"), refMs},
		{"MMM dd yyyy HH:mm:ss zzz", ref.Format("Jan 02 2006 15:04:05 MST"), ref},
		{"MMM dd yyyy HH:mm:ss.SSS zzz", refMs.Format("Jan 02 2006 15:04:05.000 MST"), refMs},
		{"MMM dd yyyy HH:mm:ss numeric zone", ref.In(plus2).Format("Jan 02 2006 15:04:05 -07:00"), ref},
		{"epoch milliseconds", strconv.FormatInt(refMs.UnixMilli(), 10), refMs},
		{"RFC3339", ref.Format(time.RFC3339), ref},
		{"RFC3339 with offset and millis", refMs.In(plus2).Format(time.RFC3339Nano), refMs},
		{"ISO without zone", ref.Format("2006-01-02 15:04:05"), ref},
	}

	for _, key := range []string{"rt", "start"} {
		for _, tt := range tests {
			t.Run(key+"/"+tt.name, func(t *testing.T) {
				cef := &CEFEvent{
					DeviceProduct: "P",
					SignatureID:   "100",
					Name:          "n",
					Severity:      5,
					Extensions:    map[string]string{key: tt.ts},
				}
				event, err := normalizer.Normalize(cef, "10.0.0.1")
				if err != nil {
					t.Fatalf("Normalize() error: %v", err)
				}
				if !event.Timestamp.Equal(tt.want) {
					t.Errorf("%s=%q -> Timestamp = %v, want %v", key, tt.ts, event.Timestamp, tt.want)
				}
				if err := validator.Validate(event); err != nil {
					t.Errorf("Validate() error: %v", err)
				}
			})
		}
	}
}

// TestNormalizer_YearlessTimestampYear checks how the year of a year-less
// timestamp is inferred, including across New Year.
func TestNormalizer_YearlessTimestampYear(t *testing.T) {
	utc := func(y int, mo time.Month, d, h, mi, s int) time.Time {
		return time.Date(y, mo, d, h, mi, s, 0, time.UTC)
	}

	tests := []struct {
		name string
		now  time.Time
		in   string
		want time.Time
	}{
		{"same day", utc(2026, 9, 30, 12, 0, 0), "Sep 30 10:15:00", utc(2026, 9, 30, 10, 15, 0)},
		{"months ago", utc(2026, 9, 30, 12, 0, 0), "Mar 01 00:00:00", utc(2026, 3, 1, 0, 0, 0)},
		{"slightly in the future keeps the year", utc(2026, 9, 30, 12, 0, 0), "Sep 30 14:00:00", utc(2026, 9, 30, 14, 0, 0)},
		{"late December received in January", utc(2026, 1, 1, 0, 0, 30), "Dec 31 23:59:50", utc(2025, 12, 31, 23, 59, 50)},
		{"early January from a sender ahead of us", utc(2025, 12, 31, 23, 59, 50), "Jan 01 00:00:10", utc(2026, 1, 1, 0, 0, 10)},
		{"zone offset applied before choosing the year", utc(2026, 1, 1, 0, 30, 0), "Jan 01 01:00:00 +0100", utc(2026, 1, 1, 0, 0, 0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNormalizer(DefaultNormalizerConfig())
			n.now = func() time.Time { return tt.now }
			got, err := n.parseTimestamp(tt.in)
			if err != nil {
				t.Fatalf("parseTimestamp(%q) error: %v", tt.in, err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("parseTimestamp(%q) at %v = %v, want %v", tt.in, tt.now, got, tt.want)
			}
		})
	}
}

// TestNormalizer_TimestampZoneAbbreviations checks that zone abbreviations
// get their real offset independently of the host's local zone, and that
// unknown ones are not silently read as UTC.
func TestNormalizer_TimestampZoneAbbreviations(t *testing.T) {
	n := NewNormalizer(DefaultNormalizerConfig())

	tests := []struct {
		in      string
		want    time.Time
		wantErr bool
	}{
		{in: "Sep 30 2026 10:15:00 UTC", want: time.Date(2026, 9, 30, 10, 15, 0, 0, time.UTC)},
		{in: "Sep 30 2026 10:15:00 GMT", want: time.Date(2026, 9, 30, 10, 15, 0, 0, time.UTC)},
		{in: "Sep 30 2026 10:15:00 PDT", want: time.Date(2026, 9, 30, 17, 15, 0, 0, time.UTC)},
		{in: "Sep 30 2026 10:15:00.250 CEST", want: time.Date(2026, 9, 30, 8, 15, 0, 250e6, time.UTC)},
		{in: "Sep 30 2026 10:15:00 XYZT", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := n.parseTimestamp(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseTimestamp(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTimestamp(%q) error: %v", tt.in, err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("parseTimestamp(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizer_SyslogHeaderFallback checks that the host and timestamp of a
// syslog-framed CEF message are used when the CEF extensions carry neither.
func TestNormalizer_SyslogHeaderFallback(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())
	parser := NewParser(DefaultParserConfig())
	validator := schema.NewValidator()

	ref := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)

	tests := []struct {
		name     string
		message  string
		wantHost string
		wantTS   time.Time
	}{
		{
			name:     "RFC3164 header supplies host and time",
			message:  "<134>" + ref.Format("Jan _2 15:04:05") + " fw01 CEF:0|Acme|FW|1.0|100|Session Created|5|src=10.0.0.1",
			wantHost: "fw01",
			wantTS:   ref,
		},
		{
			name:     "RFC5424 header supplies host and time",
			message:  "<134>1 " + ref.Format(time.RFC3339) + " fw02 app - - - CEF:0|Acme|FW|1.0|100|Session Created|5|src=10.0.0.1",
			wantHost: "fw02",
			wantTS:   ref,
		},
		{
			name:     "CEF extensions take precedence",
			message:  "<134>Jan 01 00:00:00 fw01 CEF:0|Acme|FW|1.0|100|Session Created|5|dvchost=dev1 rt=" + strconv.FormatInt(ref.UnixMilli(), 10),
			wantHost: "dev1",
			wantTS:   ref,
		},
		{
			name:     "no header falls back to the peer address",
			message:  "CEF:0|Acme|FW|1.0|100|Session Created|5|rt=" + strconv.FormatInt(ref.UnixMilli(), 10),
			wantHost: "192.0.2.9",
			wantTS:   ref,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cef, err := parser.Parse(tt.message)
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}
			event, err := normalizer.Normalize(cef, "192.0.2.9")
			if err != nil {
				t.Fatalf("Normalize() error: %v", err)
			}
			if event.Source.Host != tt.wantHost {
				t.Errorf("Source.Host = %q, want %q", event.Source.Host, tt.wantHost)
			}
			if !event.Timestamp.Equal(tt.wantTS) {
				t.Errorf("Timestamp = %v, want %v", event.Timestamp, tt.wantTS)
			}
			if err := validator.Validate(event); err != nil {
				t.Errorf("Validate() error: %v", err)
			}
		})
	}
}

// TestNormalizer_FortinetStyleEventValidates runs a realistic vendor message
// through parse, normalize and validate, which used to fail on the action.
func TestNormalizer_FortinetStyleEventValidates(t *testing.T) {
	normalizer := NewNormalizer(DefaultNormalizerConfig())
	parser := NewParser(DefaultParserConfig())
	validator := schema.NewValidator()

	msg := `<189>` + time.Now().UTC().Format("Jan _2 15:04:05") + ` fgt01 CEF:0|Fortinet|Fortigate|v7.2.4|00013|traffic:forward accept|3|deviceExternalId=FGT1 src=10.1.1.10 dst=8.8.8.8 spt=53211 dpt=53 msg=allowed\=yes`
	cef, err := parser.Parse(msg)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	event, err := normalizer.Normalize(cef, "10.0.0.1")
	if err != nil {
		t.Fatalf("Normalize() error: %v", err)
	}
	if err := validator.Validate(event); err != nil {
		t.Fatalf("Validate() error: %v (action=%q)", err, event.Action)
	}
	if event.Metadata["cef_msg"] != "allowed=yes" {
		t.Errorf("Metadata[cef_msg] = %v, want allowed=yes", event.Metadata["cef_msg"])
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

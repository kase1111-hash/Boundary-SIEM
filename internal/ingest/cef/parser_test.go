package cef

import (
	"errors"
	"fmt"
	"testing"
)

func TestParser_Parse(t *testing.T) {
	parser := NewParser(DefaultParserConfig())

	tests := []struct {
		name      string
		message   string
		wantErr   bool
		errType   error
		checkFunc func(t *testing.T, event *CEFEvent)
	}{
		{
			name:    "valid CEF message",
			message: "CEF:0|Boundary|boundary-daemon|1.0.0|100|Session Created|3|src=192.168.1.10 suser=admin",
			wantErr: false,
			checkFunc: func(t *testing.T, event *CEFEvent) {
				if event.Version != 0 {
					t.Errorf("Version = %d, want 0", event.Version)
				}
				if event.DeviceVendor != "Boundary" {
					t.Errorf("DeviceVendor = %s, want Boundary", event.DeviceVendor)
				}
				if event.DeviceProduct != "boundary-daemon" {
					t.Errorf("DeviceProduct = %s, want boundary-daemon", event.DeviceProduct)
				}
				if event.DeviceVersion != "1.0.0" {
					t.Errorf("DeviceVersion = %s, want 1.0.0", event.DeviceVersion)
				}
				if event.SignatureID != "100" {
					t.Errorf("SignatureID = %s, want 100", event.SignatureID)
				}
				if event.Name != "Session Created" {
					t.Errorf("Name = %s, want Session Created", event.Name)
				}
				if event.Severity != 3 {
					t.Errorf("Severity = %d, want 3", event.Severity)
				}
				if event.Extensions["src"] != "192.168.1.10" {
					t.Errorf("Extensions[src] = %s, want 192.168.1.10", event.Extensions["src"])
				}
				if event.Extensions["suser"] != "admin" {
					t.Errorf("Extensions[suser] = %s, want admin", event.Extensions["suser"])
				}
			},
		},
		{
			name:    "CEF with many extensions",
			message: "CEF:0|SecurityVendor|IDS|2.0|THREAT|Malware Detected|9|src=203.0.113.50 dst=192.168.1.100 act=blocked filePath=/tmp/evil.exe outcome=failure",
			wantErr: false,
			checkFunc: func(t *testing.T, event *CEFEvent) {
				if event.Severity != 9 {
					t.Errorf("Severity = %d, want 9", event.Severity)
				}
				if event.Extensions["src"] != "203.0.113.50" {
					t.Errorf("Extensions[src] = %s, want 203.0.113.50", event.Extensions["src"])
				}
				if event.Extensions["dst"] != "192.168.1.100" {
					t.Errorf("Extensions[dst] = %s, want 192.168.1.100", event.Extensions["dst"])
				}
				if event.Extensions["act"] != "blocked" {
					t.Errorf("Extensions[act] = %s, want blocked", event.Extensions["act"])
				}
				if event.Extensions["filePath"] != "/tmp/evil.exe" {
					t.Errorf("Extensions[filePath] = %s, want /tmp/evil.exe", event.Extensions["filePath"])
				}
				if event.Extensions["outcome"] != "failure" {
					t.Errorf("Extensions[outcome] = %s, want failure", event.Extensions["outcome"])
				}
			},
		},
		{
			name:    "CEF with no extensions",
			message: "CEF:0|Vendor|Product|1.0|SIG|Event Name|5|",
			wantErr: false,
			checkFunc: func(t *testing.T, event *CEFEvent) {
				if len(event.Extensions) != 0 {
					t.Errorf("Extensions should be empty, got %d", len(event.Extensions))
				}
			},
		},
		{
			name:    "CEF with escaped pipe in name",
			message: `CEF:0|Vendor|Product|1.0|SIG|Event \| Name|5|src=1.2.3.4`,
			wantErr: false,
			checkFunc: func(t *testing.T, event *CEFEvent) {
				if event.Name != "Event | Name" {
					t.Errorf("Name = %s, want 'Event | Name'", event.Name)
				}
			},
		},
		{
			name:    "invalid - not CEF format",
			message: "This is not a CEF message",
			wantErr: true,
			errType: ErrInvalidCEF,
		},
		{
			name:    "invalid - missing fields",
			message: "CEF:0|Vendor|Product|",
			wantErr: true,
			errType: ErrInvalidCEF,
		},
		{
			name:    "invalid - bad version",
			message: "CEF:abc|Vendor|Product|1.0|SIG|Name|5|",
			wantErr: true,
			errType: ErrMissingVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := parser.Parse(tt.message)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Parse() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Parse() unexpected error: %v", err)
				return
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, event)
			}
		})
	}
}

func TestParser_StrictMode(t *testing.T) {
	strictParser := NewParser(ParserConfig{
		StrictMode:    true,
		MaxExtensions: 100,
	})

	// Invalid severity in strict mode should fail
	_, err := strictParser.Parse("CEF:0|Vendor|Product|1.0|SIG|Name|invalid|")
	if err == nil {
		t.Error("expected error for invalid severity in strict mode")
	}

	// Same message in non-strict mode should pass with default severity
	lenientParser := NewParser(ParserConfig{
		StrictMode:    false,
		MaxExtensions: 100,
	})

	event, err := lenientParser.Parse("CEF:0|Vendor|Product|1.0|SIG|Name|invalid|")
	if err != nil {
		t.Errorf("unexpected error in lenient mode: %v", err)
	}
	if event.Severity != 5 {
		t.Errorf("expected default severity 5, got %d", event.Severity)
	}
}

func TestParser_MaxExtensions(t *testing.T) {
	parser := NewParser(ParserConfig{
		StrictMode:    false,
		MaxExtensions: 2,
	})

	event, err := parser.Parse("CEF:0|V|P|1|S|N|5|a=1 b=2 c=3 d=4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(event.Extensions) > 2 {
		t.Errorf("expected max 2 extensions, got %d", len(event.Extensions))
	}
}

func TestParser_ParseExtensions(t *testing.T) {
	parser := NewParser(DefaultParserConfig())

	tests := []struct {
		name       string
		message    string
		extensions map[string]string
	}{
		{
			name:    "simple key=value pairs",
			message: "CEF:0|V|P|1|S|N|5|key1=value1 key2=value2",
			extensions: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
		{
			name:    "value with spaces",
			message: "CEF:0|V|P|1|S|N|5|msg=This is a message with spaces next=value",
			extensions: map[string]string{
				"msg":  "This is a message with spaces",
				"next": "value",
			},
		},
		{
			name:    "numeric values",
			message: `CEF:0|V|P|1|S|N|5|spt=443 dpt=8080 cn1=12345`,
			extensions: map[string]string{
				"spt": "443",
				"dpt": "8080",
				"cn1": "12345",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := parser.Parse(tt.message)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for key, expectedValue := range tt.extensions {
				if event.Extensions[key] != expectedValue {
					t.Errorf("Extensions[%s] = %s, want %s", key, event.Extensions[key], expectedValue)
				}
			}
		})
	}
}

// TestParser_EscapesAppliedOnce is a regression test for escapes being
// processed twice (once while splitting the header and again per field),
// which corrupted values and split extensions on escaped '='.
func TestParser_EscapesAppliedOnce(t *testing.T) {
	parser := NewParser(DefaultParserConfig())

	tests := []struct {
		name       string
		message    string
		vendor     string
		evName     string
		extensions map[string]string
		absentKeys []string
	}{
		{
			name:    "escaped backslash followed by escaped pipe in header",
			message: `CEF:0|a\\\|b|P|1|S|N|5|src=10.0.0.1`,
			vendor:  `a\|b`,
			evName:  "N",
		},
		{
			name:    "escaped pipe in header",
			message: `CEF:0|V|P|1|S|Event \| Name|5|`,
			vendor:  "V",
			evName:  "Event | Name",
		},
		{
			name:    "unknown escape in header is kept literally",
			message: `CEF:0|V\x|P|1|S|N|5|`,
			vendor:  `V\x`,
			evName:  "N",
		},
		{
			name:    "escaped equals in extension value",
			message: `CEF:0|V|P|1|S|N|5|msg=token\=abc src=10.0.0.1`,
			vendor:  "V",
			evName:  "N",
			extensions: map[string]string{
				"msg": "token=abc",
				"src": "10.0.0.1",
			},
			absentKeys: []string{"token"},
		},
		{
			name:    "escaped backslashes in windows path",
			message: `CEF:0|V|P|1|S|N|5|filePath=C:\\new\\temp fname=a.txt`,
			vendor:  "V",
			evName:  "N",
			extensions: map[string]string{
				"filePath": `C:\new\temp`,
				"fname":    "a.txt",
			},
		},
		{
			name:    "escaped newline in extension value",
			message: `CEF:0|V|P|1|S|N|5|msg=line1\nline2\rend`,
			vendor:  "V",
			evName:  "N",
			extensions: map[string]string{
				"msg": "line1\nline2\rend",
			},
		},
		{
			name:    "escaped backslash before n is not a newline",
			message: `CEF:0|V|P|1|S|N|5|msg=a\\nb`,
			vendor:  "V",
			evName:  "N",
			extensions: map[string]string{
				"msg": `a\nb`,
			},
		},
		{
			name:    "unescaped equals inside value does not start a key",
			message: `CEF:0|V|P|1|S|N|5|request=http://x/?a=b&c=d src=1.2.3.4`,
			vendor:  "V",
			evName:  "N",
			extensions: map[string]string{
				"request": "http://x/?a=b&c=d",
				"src":     "1.2.3.4",
			},
			absentKeys: []string{"a", "c"},
		},
		{
			name:    "pipe in extension value",
			message: `CEF:0|V|P|1|S|N|5|msg=a|b src=1.2.3.4`,
			vendor:  "V",
			evName:  "N",
			extensions: map[string]string{
				"msg": "a|b",
				"src": "1.2.3.4",
			},
		},
		{
			name:    "dotted vendor extension key",
			message: `CEF:0|V|P|1|S|N|5|ad.user=alice msg=hi`,
			vendor:  "V",
			evName:  "N",
			extensions: map[string]string{
				"ad.user": "alice",
				"msg":     "hi",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := parser.Parse(tt.message)
			if err != nil {
				t.Fatalf("Parse() unexpected error: %v", err)
			}
			if event.DeviceVendor != tt.vendor {
				t.Errorf("DeviceVendor = %q, want %q", event.DeviceVendor, tt.vendor)
			}
			if event.Name != tt.evName {
				t.Errorf("Name = %q, want %q", event.Name, tt.evName)
			}
			for key, want := range tt.extensions {
				if got, ok := event.Extensions[key]; !ok || got != want {
					t.Errorf("Extensions[%q] = %q (present=%v), want %q", key, got, ok, want)
				}
			}
			for _, key := range tt.absentKeys {
				if v, ok := event.Extensions[key]; ok {
					t.Errorf("unexpected extension key %q = %q", key, v)
				}
			}
		})
	}
}

// TestParser_SyslogFramed is a regression test for CEF messages carrying a
// syslog header ("<PRI>timestamp host CEF:...") being rejected.
func TestParser_SyslogFramed(t *testing.T) {
	parser := NewParser(DefaultParserConfig())
	const body = "CEF:0|Acme|FW|1.0|100|Session Created|5|src=10.0.0.1 suser=bob"

	tests := []struct {
		name     string
		message  string
		wantErr  bool
		wantHost string
		wantTS   string
	}{
		{
			name:    "bare CEF",
			message: body,
		},
		{
			name:     "RFC3164 header",
			message:  "<134>Sep 30 10:15:00 fw01 " + body,
			wantHost: "fw01",
			wantTS:   "Sep 30 10:15:00",
		},
		{
			name:     "RFC3164 header with single digit day and tag",
			message:  "<134>Sep  3 10:15:00 fw01 app[123]: " + body,
			wantHost: "fw01",
			wantTS:   "Sep 3 10:15:00",
		},
		{
			name:    "RFC3164 header with tag but no host",
			message: "<134>Sep 30 10:15:00 app: " + body,
			wantTS:  "Sep 30 10:15:00",
		},
		{
			name:     "RFC3164 header with year",
			message:  "<134>Sep 30 2026 10:15:00 fw01 " + body,
			wantHost: "fw01",
			wantTS:   "Sep 30 2026 10:15:00",
		},
		{
			name:     "RFC3164 header without PRI",
			message:  "Sep 30 10:15:00 fw01 " + body,
			wantHost: "fw01",
			wantTS:   "Sep 30 10:15:00",
		},
		{
			name:     "RFC5424 header",
			message:  "<134>1 2026-09-30T10:15:00Z fw01 app - - - " + body,
			wantHost: "fw01",
			wantTS:   "2026-09-30T10:15:00Z",
		},
		{
			name:    "RFC5424 header with nil fields",
			message: "<134>1 - - - - - - " + body,
		},
		{
			name:     "ISO timestamp header",
			message:  "<134>2026-09-30T10:15:00.123+02:00 fw01 app: " + body,
			wantHost: "fw01",
			wantTS:   "2026-09-30T10:15:00.123+02:00",
		},
		{
			name:    "no CEF marker",
			message: "<134>Sep 30 10:15:00 fw01 app: hello world",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := parser.Parse(tt.message)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidCEF) {
					t.Fatalf("Parse() error = %v, want ErrInvalidCEF", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() unexpected error: %v", err)
			}
			if event.DeviceVendor != "Acme" || event.DeviceProduct != "FW" || event.SignatureID != "100" {
				t.Errorf("header = %q/%q/%q, want Acme/FW/100", event.DeviceVendor, event.DeviceProduct, event.SignatureID)
			}
			if event.Extensions["suser"] != "bob" {
				t.Errorf("Extensions[suser] = %q, want bob", event.Extensions["suser"])
			}
			if event.SyslogHost != tt.wantHost {
				t.Errorf("SyslogHost = %q, want %q", event.SyslogHost, tt.wantHost)
			}
			if event.SyslogTimestamp != tt.wantTS {
				t.Errorf("SyslogTimestamp = %q, want %q", event.SyslogTimestamp, tt.wantTS)
			}
			if event.RawMessage != tt.message {
				t.Errorf("RawMessage = %q, want the full original message", event.RawMessage)
			}
		})
	}
}

// TestParser_StringSeverity is a regression test for the CEF string
// severities (Unknown/Low/Medium/High/Very-High) all mapping to 5.
func TestParser_StringSeverity(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"Low", 3},
		{"low", 3},
		{"Medium", 6},
		{"High", 8},
		{"HIGH", 8},
		{"Very-High", 10},
		{"very-high", 10},
		{"Very High", 10},
		{"Unknown", 5},
		{" 7 ", 7},
		{"0", 0},
		{"10", 10},
	}

	for _, strict := range []bool{false, true} {
		parser := NewParser(ParserConfig{StrictMode: strict, MaxExtensions: 100})
		for _, tt := range tests {
			t.Run(fmt.Sprintf("strict=%v/%s", strict, tt.severity), func(t *testing.T) {
				event, err := parser.Parse("CEF:0|V|P|1|S|N|" + tt.severity + "|src=1.2.3.4")
				if err != nil {
					t.Fatalf("Parse() unexpected error: %v", err)
				}
				if event.Severity != tt.want {
					t.Errorf("Severity = %d, want %d", event.Severity, tt.want)
				}
			})
		}
	}

	// Out-of-range and unknown strings keep the previous behaviour.
	strictParser := NewParser(ParserConfig{StrictMode: true, MaxExtensions: 100})
	for _, sev := range []string{"11", "-1", "Critical"} {
		if _, err := strictParser.Parse("CEF:0|V|P|1|S|N|" + sev + "|"); !errors.Is(err, ErrInvalidSeverity) {
			t.Errorf("strict Parse(severity=%q) error = %v, want ErrInvalidSeverity", sev, err)
		}
	}
}

func BenchmarkParser_Parse(b *testing.B) {
	parser := NewParser(DefaultParserConfig())
	message := "CEF:0|Boundary|boundary-daemon|1.0.0|100|Session Created|3|src=192.168.1.10 suser=admin dhost=db-prod-01 outcome=success"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.Parse(message)
	}
}

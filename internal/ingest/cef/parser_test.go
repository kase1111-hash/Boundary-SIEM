package cef

import (
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

func BenchmarkParser_Parse(b *testing.B) {
	parser := NewParser(DefaultParserConfig())
	message := "CEF:0|Boundary|boundary-daemon|1.0.0|100|Session Created|3|src=192.168.1.10 suser=admin dhost=db-prod-01 outcome=success"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.Parse(message)
	}
}

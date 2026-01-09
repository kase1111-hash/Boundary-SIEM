package errors

import (
	"errors"
	"strings"
	"testing"
)

func TestSanitizeError_ProductionMode(t *testing.T) {
	// Enable production mode for these tests
	originalMode := ProductionMode
	ProductionMode = true
	defer func() { ProductionMode = originalMode }()

	tests := []struct {
		name        string
		input       error
		contains    string
		notContains string
	}{
		{
			name:        "file path removal",
			input:       errors.New("failed to open /var/lib/boundary-siem/secrets.db"),
			contains:    "secrets.db",
			notContains: "/var/lib/boundary-siem",
		},
		{
			name:        "IP address masking",
			input:       errors.New("connection failed to 192.168.1.100:5432"),
			contains:    "192.168.x.x",
			notContains: "192.168.1.100",
		},
		{
			name:        "SQL error sanitization",
			input:       errors.New("SQL: connection string contains password=secret123"),
			contains:    "database operation failed",
			notContains: "password=secret123",
		},
		{
			name:     "nil error",
			input:    nil,
			contains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeError(tt.input)

			if tt.input == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}

			resultStr := result.Error()

			if tt.contains != "" && !strings.Contains(resultStr, tt.contains) {
				t.Errorf("expected result to contain %q, got %q", tt.contains, resultStr)
			}

			if tt.notContains != "" && strings.Contains(resultStr, tt.notContains) {
				t.Errorf("expected result to NOT contain %q, but it does: %q", tt.notContains, resultStr)
			}
		})
	}
}

func TestSanitizeError_DevelopmentMode(t *testing.T) {
	// Ensure development mode
	originalMode := ProductionMode
	ProductionMode = false
	defer func() { ProductionMode = originalMode }()

	input := errors.New("failed to open /var/lib/boundary-siem/secrets.db")
	result := SanitizeError(input)

	// In development mode, error should be unchanged
	if result.Error() != input.Error() {
		t.Errorf("expected error to be unchanged in development mode, got %q", result.Error())
	}
}

func TestSanitizeString(t *testing.T) {
	originalMode := ProductionMode
	ProductionMode = true
	defer func() { ProductionMode = originalMode }()

	tests := []struct {
		name        string
		input       string
		contains    string
		notContains string
	}{
		{
			name:        "Linux path sanitization",
			input:       "error opening /etc/boundary-siem/secrets/api-key.txt",
			contains:    "api-key.txt",
			notContains: "/etc/boundary-siem/secrets",
		},
		{
			name:        "Multiple IPs",
			input:       "failed to connect from 10.0.1.5 to 172.16.20.100",
			contains:    "10.0.x.x",
			notContains: "10.0.1.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)

			if tt.contains != "" && !strings.Contains(result, tt.contains) {
				t.Errorf("expected result to contain %q, got %q", tt.contains, result)
			}

			if tt.notContains != "" && strings.Contains(result, tt.notContains) {
				t.Errorf("expected result to NOT contain %q, but it does: %q", tt.notContains, result)
			}
		})
	}
}

func TestSafeErrorMessage(t *testing.T) {
	originalMode := ProductionMode
	ProductionMode = true
	defer func() { ProductionMode = originalMode }()

	tests := []struct {
		name     string
		input    error
		expected string
	}{
		{
			name:     "user-facing error passes through",
			input:    errors.New("invalid username or password"),
			expected: "invalid username or password",
		},
		{
			name:     "internal error gets sanitized",
			input:    errors.New("failed to connect to database at /var/lib/db"),
			expected: "db", // path removed
		},
		{
			name:     "nil error",
			input:    nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SafeErrorMessage(tt.input)

			if tt.input == nil {
				if result != "" {
					t.Errorf("expected empty string for nil error, got %q", result)
				}
				return
			}

			if !strings.Contains(result, tt.expected) {
				t.Errorf("expected result to contain %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestWrapSanitized(t *testing.T) {
	originalMode := ProductionMode
	ProductionMode = true
	defer func() { ProductionMode = originalMode }()

	baseErr := errors.New("connection failed to /var/lib/boundary/db")
	wrapped := WrapSanitized(baseErr, "database operation failed")

	result := wrapped.Error()

	// Should contain the wrapper message
	if !strings.Contains(result, "database operation failed") {
		t.Errorf("expected wrapped message in result, got %q", result)
	}

	// Should NOT contain full path
	if strings.Contains(result, "/var/lib/boundary") {
		t.Errorf("expected path to be sanitized, got %q", result)
	}
}

func TestSetProductionMode(t *testing.T) {
	originalMode := ProductionMode
	defer func() { ProductionMode = originalMode }()

	SetProductionMode(true)
	if !IsProduction() {
		t.Error("expected production mode to be true")
	}

	SetProductionMode(false)
	if IsProduction() {
		t.Error("expected production mode to be false")
	}
}

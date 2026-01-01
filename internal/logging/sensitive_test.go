package logging

import (
	"testing"
)

func TestMaskSensitiveValue(t *testing.T) {
	tests := []struct {
		name      string
		fieldName string
		value     string
		expected  string
	}{
		{
			name:      "password field",
			fieldName: "password",
			value:     "mysecretpassword",
			expected:  MaskedValue,
		},
		{
			name:      "api_key field",
			fieldName: "api_key",
			value:     "sk_live_12345",
			expected:  MaskedValue,
		},
		{
			name:      "db_password field",
			fieldName: "db_password",
			value:     "dbpass123",
			expected:  MaskedValue,
		},
		{
			name:      "normal field",
			fieldName: "username",
			value:     "admin",
			expected:  "admin",
		},
		{
			name:      "empty value",
			fieldName: "password",
			value:     "",
			expected:  "",
		},
		{
			name:      "mixed case sensitive field",
			fieldName: "API_KEY",
			value:     "secret123",
			expected:  MaskedValue,
		},
		{
			name:      "contains sensitive keyword",
			fieldName: "smtp_password_field",
			value:     "smtppass",
			expected:  MaskedValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskSensitiveValue(tt.fieldName, tt.value)
			if result != tt.expected {
				t.Errorf("MaskSensitiveValue(%q, %q) = %q, want %q",
					tt.fieldName, tt.value, result, tt.expected)
			}
		})
	}
}

func TestIsSensitiveField(t *testing.T) {
	tests := []struct {
		fieldName string
		sensitive bool
	}{
		{"password", true},
		{"Password", true},
		{"api_key", true},
		{"token", true},
		{"secret", true},
		{"username", false},
		{"email", false},
		{"host", false},
		{"db_password", true},
		{"smtp_password", true},
		{"access_token", true},
	}

	for _, tt := range tests {
		t.Run(tt.fieldName, func(t *testing.T) {
			result := IsSensitiveField(tt.fieldName)
			if result != tt.sensitive {
				t.Errorf("IsSensitiveField(%q) = %v, want %v",
					tt.fieldName, result, tt.sensitive)
			}
		})
	}
}

func TestMaskString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		showFirst int
		showLast  int
		expected  string
	}{
		{
			name:      "normal string",
			input:     "secretpassword123",
			showFirst: 3,
			showLast:  3,
			expected:  "sec***123",
		},
		{
			name:      "short string",
			input:     "short",
			showFirst: 2,
			showLast:  2,
			expected:  MaskedValue,
		},
		{
			name:      "empty string",
			input:     "",
			showFirst: 2,
			showLast:  2,
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskString(tt.input, tt.showFirst, tt.showLast)
			if result != tt.expected {
				t.Errorf("MaskString(%q, %d, %d) = %q, want %q",
					tt.input, tt.showFirst, tt.showLast, result, tt.expected)
			}
		})
	}
}

func TestMaskPassword(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"password123", MaskedValue},
		{"", ""},
		{"short", MaskedValue},
	}

	for _, tt := range tests {
		result := MaskPassword(tt.input)
		if result != tt.expected {
			t.Errorf("MaskPassword(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMaskAPIKey(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sk_live_12345678901234567890", "sk_l****7890"},
		{"short", MaskedValue},
		{"", ""},
	}

	for _, tt := range tests {
		result := MaskAPIKey(tt.input)
		if result != tt.expected {
			t.Errorf("MaskAPIKey(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"admin@example.com", "a***n@example.com"},
		{"ab@test.com", MaskedValue + "@test.com"},
		{"", ""},
		{"noemail", MaskedValue},
	}

	for _, tt := range tests {
		result := MaskEmail(tt.input)
		if result != tt.expected {
			t.Errorf("MaskEmail(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMaskSensitivePatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{
			name:     "bearer token",
			input:    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			contains: MaskedValue,
		},
		{
			name:     "api key in string",
			input:    `config: {"api_key": "sk_live_12345"}`,
			contains: MaskedValue,
		},
		{
			name:     "no sensitive data",
			input:    "This is a normal log message",
			contains: "This is a normal log message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskSensitivePatterns(tt.input)
			if result != tt.contains && result == tt.input {
				// If result didn't change but we expected masking
				if tt.contains == MaskedValue {
					t.Errorf("MaskSensitivePatterns did not mask sensitive data in: %q", tt.input)
				}
			}
		})
	}
}

func TestSafeLogValue(t *testing.T) {
	tests := []struct {
		name      string
		fieldName string
		value     interface{}
		expected  interface{}
	}{
		{
			name:      "sensitive string",
			fieldName: "password",
			value:     "secret123",
			expected:  MaskedValue,
		},
		{
			name:      "non-sensitive string",
			fieldName: "username",
			value:     "admin",
			expected:  "admin",
		},
		{
			name:      "sensitive string slice",
			fieldName: "api_keys",
			value:     []string{"key1", "key2"},
			expected:  []string{MaskedValue, MaskedValue},
		},
		{
			name:      "nil value",
			fieldName: "password",
			value:     nil,
			expected:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SafeLogValue(tt.fieldName, tt.value)

			// Special handling for slices
			if expSlice, ok := tt.expected.([]string); ok {
				resSlice, ok := result.([]string)
				if !ok {
					t.Errorf("SafeLogValue returned unexpected type")
					return
				}
				if len(resSlice) != len(expSlice) {
					t.Errorf("SafeLogValue returned slice of wrong length")
					return
				}
				for i := range expSlice {
					if resSlice[i] != expSlice[i] {
						t.Errorf("SafeLogValue slice element %d = %q, want %q",
							i, resSlice[i], expSlice[i])
					}
				}
				return
			}

			if result != tt.expected {
				t.Errorf("SafeLogValue(%q, %v) = %v, want %v",
					tt.fieldName, tt.value, result, tt.expected)
			}
		})
	}
}

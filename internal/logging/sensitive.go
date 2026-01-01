// Package logging provides logging utilities for the SIEM.
package logging

import (
	"regexp"
	"strings"
)

// SensitiveFields contains field names that should be masked in logs.
var SensitiveFields = map[string]bool{
	"password":       true,
	"passwd":         true,
	"pass":           true,
	"secret":         true,
	"token":          true,
	"api_key":        true,
	"apikey":         true,
	"access_token":   true,
	"refresh_token":  true,
	"private_key":    true,
	"client_secret":  true,
	"credentials":    true,
	"auth":           true,
	"authorization":  true,
	"bearer":         true,
	"jwt":            true,
	"session_id":     true,
	"cookie":         true,
	"x-api-key":      true,
	"smtp_password":  true,
	"db_password":    true,
	"routing_key":    true,
	"bot_token":      true,
	"webhook_url":    true,
	"webhook":        true,
}

// MaskedValue is the string used to replace sensitive values.
const MaskedValue = "[REDACTED]"

// MaskSensitiveValue masks a value if the field name is sensitive.
func MaskSensitiveValue(fieldName, value string) string {
	if value == "" {
		return value
	}

	lowerField := strings.ToLower(fieldName)

	// Check exact match
	if SensitiveFields[lowerField] {
		return MaskedValue
	}

	// Check if field name contains any sensitive keywords
	for sensitive := range SensitiveFields {
		if strings.Contains(lowerField, sensitive) {
			return MaskedValue
		}
	}

	return value
}

// IsSensitiveField checks if a field name is sensitive.
func IsSensitiveField(fieldName string) bool {
	lowerField := strings.ToLower(fieldName)

	if SensitiveFields[lowerField] {
		return true
	}

	for sensitive := range SensitiveFields {
		if strings.Contains(lowerField, sensitive) {
			return true
		}
	}

	return false
}

// MaskString masks a portion of a sensitive string, showing only first/last chars.
// Useful for partial visibility in debugging while protecting the value.
func MaskString(s string, showFirst, showLast int) string {
	if s == "" {
		return s
	}

	length := len(s)

	// If string is too short, mask completely
	if length <= showFirst+showLast+3 {
		return MaskedValue
	}

	masked := s[:showFirst] + "***" + s[length-showLast:]
	return masked
}

// MaskPassword completely masks a password value.
func MaskPassword(password string) string {
	if password == "" {
		return ""
	}
	return MaskedValue
}

// MaskAPIKey masks an API key, showing only first 4 characters.
func MaskAPIKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return MaskedValue
	}
	return key[:4] + "****" + key[len(key)-4:]
}

// MaskEmail partially masks an email address.
func MaskEmail(email string) string {
	if email == "" {
		return ""
	}

	atIdx := strings.Index(email, "@")
	if atIdx <= 0 {
		return MaskedValue
	}

	local := email[:atIdx]
	domain := email[atIdx:]

	if len(local) <= 2 {
		return MaskedValue + domain
	}

	return local[:1] + "***" + local[len(local)-1:] + domain
}

// SensitivePatterns contains regex patterns for sensitive data in raw strings.
var SensitivePatterns = []*regexp.Regexp{
	// API keys and tokens (common formats)
	regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password|passwd|auth)['":\s]*[=:]\s*['"]?([a-zA-Z0-9_\-\.]+)['"]?`),
	// Bearer tokens
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]+`),
	// Basic auth
	regexp.MustCompile(`(?i)basic\s+[a-zA-Z0-9+/=]+`),
	// AWS keys
	regexp.MustCompile(`(?i)(AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|AKIA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}`),
	// Generic secrets with common prefixes
	regexp.MustCompile(`(?i)(sk_live_|pk_live_|sk_test_|pk_test_)[a-zA-Z0-9]+`),
}

// MaskSensitivePatterns masks sensitive patterns in a raw string.
func MaskSensitivePatterns(s string) string {
	result := s

	for _, pattern := range SensitivePatterns {
		result = pattern.ReplaceAllString(result, MaskedValue)
	}

	return result
}

// SafeLogValue returns a safe-to-log version of a value based on field name.
func SafeLogValue(fieldName string, value interface{}) interface{} {
	if value == nil {
		return nil
	}

	if !IsSensitiveField(fieldName) {
		return value
	}

	switch v := value.(type) {
	case string:
		return MaskedValue
	case []byte:
		return MaskedValue
	case []string:
		masked := make([]string, len(v))
		for i := range v {
			masked[i] = MaskedValue
		}
		return masked
	default:
		return MaskedValue
	}
}

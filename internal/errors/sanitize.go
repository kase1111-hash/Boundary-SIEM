// Package errors provides secure error handling utilities that prevent information disclosure.
package errors

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// Pattern to match file paths (Linux and Windows)
	filePathPattern = regexp.MustCompile(`(/[a-zA-Z0-9_\-./]+)|([A-Z]:\\[a-zA-Z0-9_\-\\ ./]+)`)

	// Pattern to match IP addresses
	ipPattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	// Pattern to match common internal error details
	internalErrorPattern = regexp.MustCompile(`(?i)(sql:|database:|connection string|password=|secret=|token=|api[_-]?key=)`)
)

// ProductionMode determines whether to use sanitized errors.
// Set to true in production deployments.
var ProductionMode = false

// SanitizeError removes sensitive information from error messages before returning to users.
// In development mode (ProductionMode=false), returns original errors for debugging.
// In production mode (ProductionMode=true), sanitizes errors to prevent information disclosure.
func SanitizeError(err error) error {
	if err == nil {
		return nil
	}

	// In development mode, return original error for debugging
	if !ProductionMode {
		return err
	}

	// Sanitize the error message
	sanitized := SanitizeString(err.Error())
	return errors.New(sanitized)
}

// SanitizeString removes sensitive information from a string.
func SanitizeString(s string) string {
	if !ProductionMode {
		return s
	}

	// Remove absolute file paths, keep only filename
	s = filePathPattern.ReplaceAllStringFunc(s, func(match string) string {
		return filepath.Base(match)
	})

	// Mask IP addresses (keep first two octets for debugging context)
	s = ipPattern.ReplaceAllStringFunc(s, func(match string) string {
		parts := strings.Split(match, ".")
		if len(parts) == 4 {
			return fmt.Sprintf("%s.%s.x.x", parts[0], parts[1])
		}
		return "x.x.x.x"
	})

	// Remove SQL and database-related details
	if internalErrorPattern.MatchString(s) {
		s = "database operation failed"
	}

	// Replace long stack traces with generic message
	if strings.Contains(s, "goroutine") || strings.Count(s, "\n") > 3 {
		s = "internal server error - operation failed"
	}

	return s
}

// WrapSanitized wraps an error with additional context and sanitizes the result.
func WrapSanitized(err error, message string) error {
	if err == nil {
		return nil
	}

	wrapped := fmt.Errorf("%s: %w", message, err)
	return SanitizeError(wrapped)
}

// NewSanitized creates a sanitized error with the given message.
func NewSanitized(format string, args ...interface{}) error {
	err := fmt.Errorf(format, args...)
	return SanitizeError(err)
}

// IsProduction returns true if running in production mode.
func IsProduction() bool {
	return ProductionMode
}

// SetProductionMode sets the production mode flag.
// Should be called during application initialization.
func SetProductionMode(production bool) {
	ProductionMode = production
}

// SafeErrorMessage returns a user-safe error message.
// Internal errors get generic messages, user errors pass through.
func SafeErrorMessage(err error) string {
	if err == nil {
		return ""
	}

	msg := err.Error()

	// Known user-facing errors can pass through
	userFacingErrors := []string{
		"invalid username or password",
		"account is temporarily locked",
		"user account is disabled",
		"password is required",
		"username is required",
		"invalid request",
		"unauthorized",
		"forbidden",
		"not found",
	}

	lowerMsg := strings.ToLower(msg)
	for _, safe := range userFacingErrors {
		if strings.Contains(lowerMsg, safe) {
			return msg
		}
	}

	// Everything else gets sanitized
	return SanitizeString(msg)
}

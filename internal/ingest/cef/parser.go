// Package cef provides Common Event Format (CEF) parsing and normalization.
package cef

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	// ErrInvalidCEF indicates the message is not valid CEF format.
	ErrInvalidCEF = errors.New("invalid CEF format")
	// ErrMissingVersion indicates the CEF version is missing or invalid.
	ErrMissingVersion = errors.New("missing CEF version")
	// ErrInvalidSeverity indicates the severity value is invalid.
	ErrInvalidSeverity = errors.New("invalid severity value")
)

// CEFEvent represents a parsed CEF message.
type CEFEvent struct {
	Version       int
	DeviceVendor  string
	DeviceProduct string
	DeviceVersion string
	SignatureID   string
	Name          string
	Severity      int
	Extensions    map[string]string
	RawMessage    string
}

// Parser handles CEF message parsing.
type Parser struct {
	strictMode     bool
	maxExtensions  int
	extensionRegex *regexp.Regexp
}

// ParserConfig holds configuration for the CEF parser.
type ParserConfig struct {
	StrictMode    bool
	MaxExtensions int
}

// DefaultParserConfig returns the default parser configuration.
func DefaultParserConfig() ParserConfig {
	return ParserConfig{
		StrictMode:    false,
		MaxExtensions: 100,
	}
}

// NewParser creates a new CEF parser with the given configuration.
func NewParser(cfg ParserConfig) *Parser {
	return &Parser{
		strictMode:     cfg.StrictMode,
		maxExtensions:  cfg.MaxExtensions,
		extensionRegex: regexp.MustCompile(`(\w+)=`),
	}
}

// Parse parses a CEF message string into a CEFEvent.
func (p *Parser) Parse(message string) (*CEFEvent, error) {
	message = strings.TrimSpace(message)

	// Check for CEF prefix
	if !strings.HasPrefix(message, "CEF:") {
		return nil, ErrInvalidCEF
	}

	// Remove CEF: prefix
	content := message[4:]

	// Split into header and extension parts
	// Header has 7 pipe-delimited fields, extension is everything after
	parts := p.splitHeader(content)
	if len(parts) < 7 {
		return nil, fmt.Errorf("%w: expected 7 header fields, got %d", ErrInvalidCEF, len(parts))
	}

	// Parse version
	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMissingVersion, err)
	}

	// Parse severity (field 6, after Name which is field 5)
	severity, err := strconv.Atoi(parts[6])
	if err != nil || severity < 0 || severity > 10 {
		if p.strictMode {
			return nil, fmt.Errorf("%w: %s", ErrInvalidSeverity, parts[6])
		}
		severity = 5 // Default to medium if not strict
	}

	// Parse extensions
	extensions := make(map[string]string)
	if len(parts) > 7 && parts[7] != "" {
		extensions = p.parseExtensions(parts[7])
	}

	return &CEFEvent{
		Version:       version,
		DeviceVendor:  p.unescapeField(parts[1]),
		DeviceProduct: p.unescapeField(parts[2]),
		DeviceVersion: p.unescapeField(parts[3]),
		SignatureID:   p.unescapeField(parts[4]),
		Name:          p.unescapeField(parts[5]),
		Severity:      severity,
		Extensions:    extensions,
		RawMessage:    message,
	}, nil
}

// splitHeader splits the CEF header respecting escaped pipes.
func (p *Parser) splitHeader(content string) []string {
	var parts []string
	var current strings.Builder
	escaped := false
	pipeCount := 0

	for i, char := range content {
		if escaped {
			current.WriteRune(char)
			escaped = false
			continue
		}

		if char == '\\' && i+1 < len(content) {
			next := content[i+1]
			if next == '|' || next == '\\' || next == '=' {
				escaped = true
				continue
			}
		}

		if char == '|' && pipeCount < 7 {
			parts = append(parts, current.String())
			current.Reset()
			pipeCount++
			continue
		}

		current.WriteRune(char)
	}

	// Add the remaining content (extensions)
	parts = append(parts, current.String())

	return parts
}

// parseExtensions parses the CEF extension key=value pairs.
func (p *Parser) parseExtensions(extStr string) map[string]string {
	extensions := make(map[string]string)

	// Find all key positions
	matches := p.extensionRegex.FindAllStringIndex(extStr, -1)
	if len(matches) == 0 {
		return extensions
	}

	for i, match := range matches {
		keyStart := match[0]
		keyEnd := match[1] - 1 // Exclude the '='
		key := extStr[keyStart:keyEnd]

		// Value goes from after '=' to the start of next key (or end)
		valueStart := match[1]
		var valueEnd int
		if i+1 < len(matches) {
			// Find the last space before the next key
			valueEnd = matches[i+1][0]
			for valueEnd > valueStart && extStr[valueEnd-1] == ' ' {
				valueEnd--
			}
		} else {
			valueEnd = len(extStr)
		}

		value := strings.TrimSpace(extStr[valueStart:valueEnd])
		extensions[key] = p.unescapeValue(value)

		if len(extensions) >= p.maxExtensions {
			break
		}
	}

	return extensions
}

// unescapeField unescapes CEF header field values.
func (p *Parser) unescapeField(s string) string {
	s = strings.ReplaceAll(s, `\|`, "|")
	s = strings.ReplaceAll(s, `\\`, "\\")
	return s
}

// unescapeValue unescapes CEF extension values.
func (p *Parser) unescapeValue(s string) string {
	s = strings.ReplaceAll(s, `\=`, "=")
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\r`, "\r")
	s = strings.ReplaceAll(s, `\\`, "\\")
	return s
}

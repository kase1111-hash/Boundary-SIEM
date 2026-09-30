// Package cef provides Common Event Format (CEF) parsing and normalization.
package cef

import (
	"errors"
	"fmt"
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

// cefMarker starts the CEF payload. Anything before it is a syslog header.
const cefMarker = "CEF:"

// defaultSeverity is used for "Unknown" and, outside strict mode, for
// severities that cannot be interpreted.
const defaultSeverity = 5

// severityNames maps the string severities allowed by the CEF standard
// (compared case-insensitively, ignoring '-', '_' and spaces) to a value at
// the top of the numeric band each one stands for.
var severityNames = map[string]int{
	"unknown":  defaultSeverity,
	"low":      3,
	"medium":   6,
	"high":     8,
	"veryhigh": 10,
}

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

	// SyslogHost and SyslogTimestamp are taken from the syslog header that
	// precedes "CEF:" when the message is syslog framed. They are empty for
	// bare CEF messages or when the header does not carry them.
	SyslogHost      string
	SyslogTimestamp string
}

// Parser handles CEF message parsing.
type Parser struct {
	strictMode    bool
	maxExtensions int
}

// ParserConfig holds configuration for the CEF parser.
type ParserConfig struct {
	StrictMode bool
	// MaxExtensions caps the number of extension fields kept per message.
	// Zero or a negative value selects the default.
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
	if cfg.MaxExtensions <= 0 {
		cfg.MaxExtensions = DefaultParserConfig().MaxExtensions
	}
	return &Parser{
		strictMode:    cfg.StrictMode,
		maxExtensions: cfg.MaxExtensions,
	}
}

// Parse parses a CEF message string into a CEFEvent. The message may be bare
// ("CEF:0|...") or carry a syslog header ("<134>Sep 30 10:15:00 host CEF:0|...").
func (p *Parser) Parse(message string) (*CEFEvent, error) {
	message = strings.TrimSpace(message)

	idx := strings.Index(message, cefMarker)
	if idx < 0 {
		return nil, ErrInvalidCEF
	}

	header, extStr, ok := splitHeader(message[idx+len(cefMarker):])
	if !ok {
		return nil, fmt.Errorf("%w: expected 7 header fields, got %d", ErrInvalidCEF, len(header))
	}

	version, err := strconv.Atoi(strings.TrimSpace(header[0]))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMissingVersion, err)
	}

	severity, err := p.parseSeverity(header[6])
	if err != nil {
		return nil, err
	}

	event := &CEFEvent{
		Version:       version,
		DeviceVendor:  header[1],
		DeviceProduct: header[2],
		DeviceVersion: header[3],
		SignatureID:   header[4],
		Name:          header[5],
		Severity:      severity,
		Extensions:    p.parseExtensions(extStr),
		RawMessage:    message,
	}
	if idx > 0 {
		event.SyslogTimestamp, event.SyslogHost = parseSyslogHeader(message[:idx])
	}
	return event, nil
}

// parseSeverity accepts the numeric severities 0-10 and the CEF string
// severities (Unknown, Low, Medium, High, Very-High).
func (p *Parser) parseSeverity(raw string) (int, error) {
	s := strings.TrimSpace(raw)
	if n, err := strconv.Atoi(s); err == nil {
		if n >= 0 && n <= 10 {
			return n, nil
		}
	} else {
		key := strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToLower(s))
		if n, ok := severityNames[key]; ok {
			return n, nil
		}
	}
	if p.strictMode {
		return 0, fmt.Errorf("%w: %s", ErrInvalidSeverity, raw)
	}
	return defaultSeverity, nil
}

// splitHeader splits the CEF payload (the text after "CEF:") into the seven
// header fields and the raw extension string. Header fields are unescaped
// once ("\|" and "\\"); the extension string is returned verbatim so that
// parseExtensions applies the extension escapes exactly once. A payload
// without the pipe that ends the header (and so without extensions) is
// accepted.
func splitHeader(content string) (fields []string, ext string, ok bool) {
	fields = make([]string, 0, 7)
	var cur strings.Builder

	for i := 0; i < len(content); i++ {
		c := content[i]
		if c == '\\' && i+1 < len(content) && (content[i+1] == '|' || content[i+1] == '\\') {
			cur.WriteByte(content[i+1])
			i++
			continue
		}
		if c == '|' {
			fields = append(fields, cur.String())
			cur.Reset()
			if len(fields) == 7 {
				return fields, content[i+1:], true
			}
			continue
		}
		cur.WriteByte(c)
	}

	fields = append(fields, cur.String())
	return fields, "", len(fields) == 7
}

// parseExtensions parses the CEF extension key=value pairs.
//
// A key is a run of letters, digits, '_' or '.' that starts the string or
// follows a space and ends at an unescaped '='. The value runs up to the space
// before the next key, so values may contain spaces and unescaped '=' that is
// not preceded by a space-delimited key. Escapes are applied once, after the
// value has been delimited.
func (p *Parser) parseExtensions(ext string) map[string]string {
	extensions := make(map[string]string)

	type keySpan struct{ start, eq int }
	var keys []keySpan
	for i := 0; i < len(ext); i++ {
		switch ext[i] {
		case '\\':
			i++ // the next byte is escaped and cannot end a key
		case '=':
			start := i
			for start > 0 && isKeyChar(ext[start-1]) {
				start--
			}
			if start == i || (start > 0 && ext[start-1] != ' ') {
				continue // part of a value
			}
			keys = append(keys, keySpan{start: start, eq: i})
		}
	}

	for i, k := range keys {
		end := len(ext)
		if i+1 < len(keys) {
			end = keys[i+1].start
		}
		extensions[ext[k.start:k.eq]] = unescapeValue(strings.TrimSpace(ext[k.eq+1 : end]))

		if len(extensions) >= p.maxExtensions {
			break
		}
	}

	return extensions
}

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.'
}

// unescapeValue applies the CEF extension escapes ("\\", "\=", "\n", "\r") in
// a single left-to-right pass. Other backslashes are kept literally.
func unescapeValue(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\', '=':
				b.WriteByte(s[i+1])
				i++
				continue
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			case 'r':
				b.WriteByte('\r')
				i++
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// parseSyslogHeader extracts the timestamp and hostname from the syslog header
// that precedes "CEF:". It understands RFC 5424 ("<PRI>1 TIMESTAMP HOST APP
// PROCID MSGID SD"), RFC 3164 ("<PRI>Mmm dd hh:mm:ss HOST TAG:"), the common
// variants with a year or an RFC 3339 timestamp, and headers without a PRI.
// Fields it cannot identify are returned empty; the host is only taken when a
// timestamp was recognised, so arbitrary text before "CEF:" is not mistaken
// for a hostname.
func parseSyslogHeader(prefix string) (timestamp, host string) {
	s := strings.TrimSpace(prefix)
	if strings.HasPrefix(s, "<") {
		end := strings.IndexByte(s, '>')
		if end < 0 {
			return "", ""
		}
		s = s[end+1:]
	}

	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "", ""
	}

	switch {
	case len(fields[0]) <= 2 && isDigits(fields[0]):
		// RFC 5424: VERSION TIMESTAMP HOSTNAME ...; "-" is the nil value.
		if len(fields) > 1 && fields[1] != "-" {
			timestamp = fields[1]
		}
		if len(fields) > 2 && fields[2] != "-" && isHostname(fields[2]) {
			host = fields[2]
		}
		return timestamp, host

	case isMonth(fields[0]) && len(fields) >= 3:
		// RFC 3164: Mmm dd [yyyy] hh:mm:ss HOSTNAME
		n := 3
		if len(fields) >= 4 && len(fields[2]) == 4 && isDigits(fields[2]) {
			n = 4
		}
		timestamp = strings.Join(fields[:n], " ")
		fields = fields[n:]

	case isISOTimestamp(fields[0]):
		timestamp = fields[0]
		fields = fields[1:]

	default:
		return "", ""
	}

	if len(fields) > 0 && isHostname(fields[0]) {
		host = fields[0]
	}
	return timestamp, host
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isMonth(s string) bool {
	switch strings.ToLower(s) {
	case "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec":
		return true
	}
	return false
}

// isISOTimestamp reports whether s starts like "2006-01-02T".
func isISOTimestamp(s string) bool {
	return len(s) >= 19 && isDigits(s[:4]) && s[4] == '-' && s[7] == '-' && (s[10] == 'T' || s[10] == 't')
}

// isHostname reports whether s can be a syslog HOSTNAME field rather than a
// TAG ("app:" or "app[123]:").
func isHostname(s string) bool {
	if s == "" || len(s) > 255 || strings.HasSuffix(s, ":") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isKeyChar(c) && c != '-' && c != ':' {
			return false
		}
	}
	return true
}

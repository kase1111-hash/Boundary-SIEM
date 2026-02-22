// Package ethereum provides parsing for Ethereum execution client logs.
package ethereum

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// GethLogLevel represents Geth log levels.
type GethLogLevel string

const (
	LevelTrace GethLogLevel = "TRACE"
	LevelDebug GethLogLevel = "DEBUG"
	LevelInfo  GethLogLevel = "INFO"
	LevelWarn  GethLogLevel = "WARN"
	LevelError GethLogLevel = "ERROR"
	LevelCrit  GethLogLevel = "CRIT"
)

// GethLogEntry represents a parsed Geth log entry.
type GethLogEntry struct {
	Timestamp time.Time
	Level     GethLogLevel
	Component string
	Message   string
	Fields    map[string]string
}

// GethParser parses go-ethereum (Geth) logs.
type GethParser struct {
	// Regex patterns for Geth log formats
	jsonPattern  *regexp.Regexp
	textPattern  *regexp.Regexp
	fieldPattern *regexp.Regexp
}

// NewGethParser creates a new Geth log parser.
func NewGethParser() *GethParser {
	return &GethParser{
		// JSON log format: {"t":"2024-01-01T00:00:00Z","lvl":"info","msg":"..."}
		jsonPattern: regexp.MustCompile(`^\{.*"lvl".*\}$`),
		// Text log format: INFO [01-01|00:00:00.000] Message key=value
		textPattern: regexp.MustCompile(`^(TRACE|DEBUG|INFO|WARN|ERROR|CRIT)\s+\[([^\]]+)\]\s+(.+?)(\s+\w+=.+)?$`),
		// Key-value fields: key=value or key="quoted value"
		fieldPattern: regexp.MustCompile(`(\w+)=(?:"([^"]+)"|(\S+))`),
	}
}

// Parse parses a Geth log line into a structured entry.
func (p *GethParser) Parse(line string) (*GethLogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty line")
	}

	// Try JSON format first
	if p.jsonPattern.MatchString(line) {
		return p.parseJSON(line)
	}

	// Try text format
	return p.parseText(line)
}

func (p *GethParser) parseJSON(line string) (*GethLogEntry, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	entry := &GethLogEntry{
		Fields: make(map[string]string),
	}

	// Extract timestamp
	if t, ok := raw["t"].(string); ok {
		if ts, err := time.Parse(time.RFC3339Nano, t); err == nil {
			entry.Timestamp = ts
		}
	}
	if entry.Timestamp.IsZero() {
		if t, ok := raw["time"].(string); ok {
			if ts, err := time.Parse(time.RFC3339Nano, t); err == nil {
				entry.Timestamp = ts
			}
		}
	}

	// Extract level
	if lvl, ok := raw["lvl"].(string); ok {
		entry.Level = GethLogLevel(strings.ToUpper(lvl))
	} else if lvl, ok := raw["level"].(string); ok {
		entry.Level = GethLogLevel(strings.ToUpper(lvl))
	}

	// Extract message
	if msg, ok := raw["msg"].(string); ok {
		entry.Message = msg
	} else if msg, ok := raw["message"].(string); ok {
		entry.Message = msg
	}

	// Extract other fields
	for k, v := range raw {
		if k != "t" && k != "time" && k != "lvl" && k != "level" && k != "msg" && k != "message" {
			entry.Fields[k] = fmt.Sprintf("%v", v)
		}
	}

	return entry, nil
}

func (p *GethParser) parseText(line string) (*GethLogEntry, error) {
	matches := p.textPattern.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("unrecognized format")
	}

	entry := &GethLogEntry{
		Level:   GethLogLevel(matches[1]),
		Message: strings.TrimSpace(matches[3]),
		Fields:  make(map[string]string),
	}

	// Parse timestamp [01-01|00:00:00.000]
	if ts, err := p.parseGethTimestamp(matches[2]); err == nil {
		entry.Timestamp = ts
	} else {
		entry.Timestamp = time.Now()
	}

	// Parse key=value fields
	if len(matches) > 4 && matches[4] != "" {
		fieldMatches := p.fieldPattern.FindAllStringSubmatch(matches[4], -1)
		for _, fm := range fieldMatches {
			key := fm[1]
			value := fm[2]
			if value == "" {
				value = fm[3]
			}
			entry.Fields[key] = value
		}
	}

	// Extract component from message
	if idx := strings.Index(entry.Message, " "); idx > 0 {
		potentialComponent := entry.Message[:idx]
		if strings.HasPrefix(potentialComponent, "eth") ||
			strings.HasPrefix(potentialComponent, "core") ||
			strings.HasPrefix(potentialComponent, "miner") ||
			strings.HasPrefix(potentialComponent, "p2p") ||
			strings.HasPrefix(potentialComponent, "rpc") {
			entry.Component = potentialComponent
			entry.Message = strings.TrimSpace(entry.Message[idx:])
		}
	}

	return entry, nil
}

func (p *GethParser) parseGethTimestamp(ts string) (time.Time, error) {
	// Format: 01-01|00:00:00.000
	parts := strings.Split(ts, "|")
	if len(parts) != 2 {
		return time.Time{}, fmt.Errorf("invalid timestamp format")
	}

	now := time.Now()
	dateParts := strings.Split(parts[0], "-")
	if len(dateParts) != 2 {
		return time.Time{}, fmt.Errorf("invalid date format")
	}

	month, err := strconv.Atoi(dateParts[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid month %q: %w", dateParts[0], err)
	}
	day, err := strconv.Atoi(dateParts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid day %q: %w", dateParts[1], err)
	}

	timeParts := strings.Split(parts[1], ":")
	if len(timeParts) < 3 {
		return time.Time{}, fmt.Errorf("invalid time format")
	}

	hour, err := strconv.Atoi(timeParts[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid hour %q: %w", timeParts[0], err)
	}
	minute, err := strconv.Atoi(timeParts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid minute %q: %w", timeParts[1], err)
	}

	secParts := strings.Split(timeParts[2], ".")
	second, err := strconv.Atoi(secParts[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid second %q: %w", secParts[0], err)
	}
	var milli int
	if len(secParts) > 1 {
		milli, err = strconv.Atoi(secParts[1])
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid millisecond %q: %w", secParts[1], err)
		}
	}

	return time.Date(now.Year(), time.Month(month), day, hour, minute, second, milli*1000000, time.UTC), nil
}

// Normalize converts a Geth log entry to a canonical event.
func (p *GethParser) Normalize(entry *GethLogEntry, sourceIP string) (*schema.Event, error) {
	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     entry.Timestamp,
		ReceivedAt:    time.Now(),
		SchemaVersion: "1.0.0",
		TenantID:      "default",
		Source: schema.Source{
			Product: "geth",
			Host:    sourceIP,
			Version: entry.Fields["version"],
		},
		Metadata: make(map[string]interface{}),
		Raw:      fmt.Sprintf("[%s] %s", entry.Level, entry.Message),
	}

	// Map log level to severity
	event.Severity = p.mapSeverity(entry.Level)

	// Classify the event action based on message patterns
	event.Action, event.Outcome = p.classifyEvent(entry)

	// Copy fields to metadata
	for k, v := range entry.Fields {
		event.Metadata["geth_"+k] = v
	}

	// Extract actor information if available
	if peer, ok := entry.Fields["peer"]; ok {
		event.Actor = &schema.Actor{
			Type: schema.ActorService,
			ID:   peer,
		}
	}

	// Set target for relevant events
	if hash, ok := entry.Fields["hash"]; ok {
		event.Target = hash
	} else if number, ok := entry.Fields["number"]; ok {
		event.Target = "block:" + number
	}

	return event, nil
}

func (p *GethParser) mapSeverity(level GethLogLevel) int {
	switch level {
	case LevelCrit:
		return 10
	case LevelError:
		return 8
	case LevelWarn:
		return 5
	case LevelInfo:
		return 3
	case LevelDebug:
		return 2
	case LevelTrace:
		return 1
	default:
		return 3
	}
}

func (p *GethParser) classifyEvent(entry *GethLogEntry) (action string, outcome schema.Outcome) {
	msg := strings.ToLower(entry.Message)

	// Block events
	if strings.Contains(msg, "imported new chain segment") ||
		strings.Contains(msg, "block reached canonical chain") {
		return "block.imported", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "mining block") || strings.Contains(msg, "commit new mining work") {
		return "block.mining", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "mined potential block") {
		return "block.mined", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "block import failed") {
		return "block.import_failed", schema.OutcomeFailure
	}

	// Sync events
	if strings.Contains(msg, "starting sync") || strings.Contains(msg, "synchronisation started") {
		return "sync.started", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "state sync") || strings.Contains(msg, "syncing") {
		return "sync.progress", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "sync complete") || strings.Contains(msg, "synchronisation completed") {
		return "sync.completed", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "sync failed") || strings.Contains(msg, "synchronisation failed") {
		return "sync.failed", schema.OutcomeFailure
	}

	// Peer events
	if strings.Contains(msg, "peer connected") || strings.Contains(msg, "adding p2p peer") {
		return "peer.connected", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "peer disconnected") || strings.Contains(msg, "removing p2p peer") {
		return "peer.disconnected", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "peer dropped") {
		return "peer.dropped", schema.OutcomeFailure
	}

	// Transaction events
	if strings.Contains(msg, "submitted transaction") || strings.Contains(msg, "pooled new") {
		return "tx.submitted", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "transaction failed") || strings.Contains(msg, "tx rejected") {
		return "tx.rejected", schema.OutcomeFailure
	}

	// Engine API events (for merge)
	if strings.Contains(msg, "forkchoice update") || strings.Contains(msg, "forkchoiceupdated") {
		return "engine.forkchoice_updated", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "new payload") || strings.Contains(msg, "newpayload") {
		return "engine.new_payload", schema.OutcomeSuccess
	}

	// RPC events
	if strings.Contains(msg, "http server") || strings.Contains(msg, "rpc server") {
		if strings.Contains(msg, "started") {
			return "rpc.started", schema.OutcomeSuccess
		}
		if strings.Contains(msg, "stopped") {
			return "rpc.stopped", schema.OutcomeSuccess
		}
	}

	// Database events
	if strings.Contains(msg, "database") {
		if strings.Contains(msg, "opened") {
			return "db.opened", schema.OutcomeSuccess
		}
		if strings.Contains(msg, "closed") {
			return "db.closed", schema.OutcomeSuccess
		}
		if strings.Contains(msg, "compaction") {
			return "db.compaction", schema.OutcomeSuccess
		}
	}

	// Error/warning patterns
	if entry.Level == LevelError || entry.Level == LevelCrit {
		if strings.Contains(msg, "database") {
			return "error.database", schema.OutcomeFailure
		}
		if strings.Contains(msg, "network") || strings.Contains(msg, "peer") {
			return "error.network", schema.OutcomeFailure
		}
		if strings.Contains(msg, "rpc") {
			return "error.rpc", schema.OutcomeFailure
		}
		return "error.general", schema.OutcomeFailure
	}

	// Default: use component or generic
	if entry.Component != "" {
		return "geth." + strings.ToLower(entry.Component), schema.OutcomeUnknown
	}
	return "geth.log", schema.OutcomeUnknown
}

// EventPatterns contains regex patterns for security-relevant events.
var EventPatterns = map[string]*regexp.Regexp{
	"reorg":           regexp.MustCompile(`(?i)chain reorg|reorgani[sz]`),
	"fork":            regexp.MustCompile(`(?i)fork detected|chain split`),
	"invalid_block":   regexp.MustCompile(`(?i)invalid block|bad block`),
	"consensus_error": regexp.MustCompile(`(?i)consensus error|validation failed`),
	"eclipse":         regexp.MustCompile(`(?i)no peers|peer count.*0|isolated`),
	"dos_attack":      regexp.MustCompile(`(?i)rate limit|too many requests`),
}

// IsSecurityRelevant checks if an entry is security-relevant.
func (p *GethParser) IsSecurityRelevant(entry *GethLogEntry) (bool, string) {
	msg := entry.Message

	for eventType, pattern := range EventPatterns {
		if pattern.MatchString(msg) {
			return true, eventType
		}
	}

	// High severity logs are always relevant
	if entry.Level == LevelError || entry.Level == LevelCrit {
		return true, "high_severity"
	}

	return false, ""
}

// Package consensus provides parsing for Ethereum consensus client logs.
package consensus

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

// ClientType represents the consensus client type.
type ClientType string

const (
	ClientPrysm      ClientType = "prysm"
	ClientLighthouse ClientType = "lighthouse"
	ClientTeku       ClientType = "teku"
	ClientLodestar   ClientType = "lodestar"
	ClientNimbus     ClientType = "nimbus"
)

// LogEntry represents a parsed consensus client log entry.
type LogEntry struct {
	Timestamp      time.Time
	Level          string
	Component      string
	Message        string
	Fields         map[string]interface{}
	Client         ClientType
	ValidatorIndex int64
	Slot           int64
	Epoch          int64
}

// Parser parses consensus client logs.
type Parser struct {
	client         ClientType
	prysmPattern   *regexp.Regexp
	lighthouseJSON *regexp.Regexp
	tekuPattern    *regexp.Regexp
	fieldPattern   *regexp.Regexp
}

// NewParser creates a new consensus client parser.
func NewParser(client ClientType) *Parser {
	return &Parser{
		client: client,
		// Prysm: time="2024-01-01 00:00:00" level=info msg="Message" field=value
		prysmPattern: regexp.MustCompile(`time="([^"]+)"\s+level=(\w+)\s+msg="([^"]+)"(.*)$`),
		// Lighthouse uses JSON format
		lighthouseJSON: regexp.MustCompile(`^\{.*\}$`),
		// Teku: 00:00:00.000 INFO - Message
		tekuPattern: regexp.MustCompile(`^(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\w+)\s+-\s+(.+)$`),
		// Key-value fields
		fieldPattern: regexp.MustCompile(`(\w+)=(?:"([^"]+)"|(\S+))`),
	}
}

// Parse parses a log line based on the client type.
func (p *Parser) Parse(line string) (*LogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty line")
	}

	switch p.client {
	case ClientPrysm:
		return p.parsePrysm(line)
	case ClientLighthouse:
		return p.parseLighthouse(line)
	case ClientTeku:
		return p.parseTeku(line)
	case ClientLodestar:
		return p.parseLodestar(line)
	case ClientNimbus:
		return p.parseNimbus(line)
	default:
		return p.parseGeneric(line)
	}
}

func (p *Parser) parsePrysm(line string) (*LogEntry, error) {
	matches := p.prysmPattern.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("unrecognized Prysm format")
	}

	entry := &LogEntry{
		Client:  ClientPrysm,
		Level:   strings.ToUpper(matches[2]),
		Message: matches[3],
		Fields:  make(map[string]interface{}),
	}

	// Parse timestamp
	if ts, err := time.Parse("2006-01-02 15:04:05", matches[1]); err == nil {
		entry.Timestamp = ts
	} else {
		entry.Timestamp = time.Now()
	}

	// Parse fields
	if len(matches) > 4 && matches[4] != "" {
		fieldMatches := p.fieldPattern.FindAllStringSubmatch(matches[4], -1)
		for _, fm := range fieldMatches {
			key := fm[1]
			value := fm[2]
			if value == "" {
				value = fm[3]
			}
			entry.Fields[key] = value

			// Extract special fields
			switch key {
			case "validatorIndex", "validator_index":
				if idx, err := strconv.ParseInt(value, 10, 64); err == nil {
					entry.ValidatorIndex = idx
				}
			case "slot":
				if slot, err := strconv.ParseInt(value, 10, 64); err == nil {
					entry.Slot = slot
				}
			case "epoch":
				if epoch, err := strconv.ParseInt(value, 10, 64); err == nil {
					entry.Epoch = epoch
				}
			}
		}
	}

	return entry, nil
}

func (p *Parser) parseLighthouse(line string) (*LogEntry, error) {
	if !p.lighthouseJSON.MatchString(line) {
		return nil, fmt.Errorf("unrecognized Lighthouse format")
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	entry := &LogEntry{
		Client: ClientLighthouse,
		Fields: make(map[string]interface{}),
	}

	// Extract standard fields
	if ts, ok := raw["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			entry.Timestamp = t
		}
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	if lvl, ok := raw["level"].(string); ok {
		entry.Level = strings.ToUpper(lvl)
	}
	if msg, ok := raw["msg"].(string); ok {
		entry.Message = msg
	} else if msg, ok := raw["message"].(string); ok {
		entry.Message = msg
	}

	// Copy all other fields
	for k, v := range raw {
		if k != "timestamp" && k != "level" && k != "msg" && k != "message" {
			entry.Fields[k] = v

			// Extract special fields
			switch k {
			case "validator_index", "validatorIndex":
				if idx, ok := v.(float64); ok {
					entry.ValidatorIndex = int64(idx)
				}
			case "slot":
				if slot, ok := v.(float64); ok {
					entry.Slot = int64(slot)
				}
			case "epoch":
				if epoch, ok := v.(float64); ok {
					entry.Epoch = int64(epoch)
				}
			}
		}
	}

	return entry, nil
}

func (p *Parser) parseTeku(line string) (*LogEntry, error) {
	matches := p.tekuPattern.FindStringSubmatch(line)
	if matches == nil {
		// Try JSON format
		if p.lighthouseJSON.MatchString(line) {
			entry, err := p.parseLighthouse(line)
			if err == nil {
				entry.Client = ClientTeku
			}
			return entry, err
		}
		return nil, fmt.Errorf("unrecognized Teku format")
	}

	entry := &LogEntry{
		Client:  ClientTeku,
		Level:   strings.ToUpper(matches[2]),
		Message: matches[3],
		Fields:  make(map[string]interface{}),
	}

	// Parse time (HH:MM:SS.mmm)
	now := time.Now()
	timeParts := strings.Split(matches[1], ":")
	if len(timeParts) >= 3 {
		hour, _ := strconv.Atoi(timeParts[0])
		minute, _ := strconv.Atoi(timeParts[1])
		secParts := strings.Split(timeParts[2], ".")
		second, _ := strconv.Atoi(secParts[0])
		var milli int
		if len(secParts) > 1 {
			milli, _ = strconv.Atoi(secParts[1])
		}
		entry.Timestamp = time.Date(now.Year(), now.Month(), now.Day(), hour, minute, second, milli*1000000, time.UTC)
	} else {
		entry.Timestamp = now
	}

	return entry, nil
}

func (p *Parser) parseLodestar(line string) (*LogEntry, error) {
	// Lodestar uses JSON format
	if p.lighthouseJSON.MatchString(line) {
		entry, err := p.parseLighthouse(line)
		if err == nil {
			entry.Client = ClientLodestar
		}
		return entry, err
	}
	return nil, fmt.Errorf("unrecognized Lodestar format")
}

func (p *Parser) parseNimbus(line string) (*LogEntry, error) {
	// Nimbus: WRN 2024-01-01 00:00:00.000+00:00 message topics="component" ...
	pattern := regexp.MustCompile(`^(\w+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})\s+(.+)$`)
	matches := pattern.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("unrecognized Nimbus format")
	}

	entry := &LogEntry{
		Client:  ClientNimbus,
		Level:   p.mapNimbusLevel(matches[1]),
		Message: matches[3],
		Fields:  make(map[string]interface{}),
	}

	// Parse timestamp
	if ts, err := time.Parse("2006-01-02 15:04:05.000-07:00", matches[2]); err == nil {
		entry.Timestamp = ts
	} else {
		entry.Timestamp = time.Now()
	}

	return entry, nil
}

func (p *Parser) mapNimbusLevel(lvl string) string {
	switch strings.ToUpper(lvl) {
	case "TRC":
		return "TRACE"
	case "DBG":
		return "DEBUG"
	case "INF":
		return "INFO"
	case "WRN":
		return "WARN"
	case "ERR":
		return "ERROR"
	case "FAT":
		return "FATAL"
	default:
		return lvl
	}
}

func (p *Parser) parseGeneric(line string) (*LogEntry, error) {
	// Try JSON first
	if p.lighthouseJSON.MatchString(line) {
		return p.parseLighthouse(line)
	}

	// Try Prysm format
	if entry, err := p.parsePrysm(line); err == nil {
		return entry, nil
	}

	// Generic fallback
	return &LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   line,
		Fields:    make(map[string]interface{}),
	}, nil
}

// Normalize converts a log entry to a canonical event.
func (p *Parser) Normalize(entry *LogEntry, sourceIP string) (*schema.Event, error) {
	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     entry.Timestamp,
		ReceivedAt:    time.Now(),
		SchemaVersion: "1.0.0",
		TenantID:      "default",
		Source: schema.Source{
			Product: string(entry.Client),
			Host:    sourceIP,
		},
		Metadata: make(map[string]interface{}),
	}

	// Map log level to severity
	event.Severity = p.mapSeverity(entry.Level)

	// Classify the event
	event.Action, event.Outcome = p.classifyEvent(entry)

	// Copy fields to metadata
	for k, v := range entry.Fields {
		event.Metadata["beacon_"+k] = v
	}

	// Add validator info if present
	if entry.ValidatorIndex > 0 {
		event.Metadata["validator_index"] = entry.ValidatorIndex
		event.Actor = &schema.Actor{
			Type: schema.ActorService,
			ID:   fmt.Sprintf("validator:%d", entry.ValidatorIndex),
		}
	}

	// Add slot/epoch info
	if entry.Slot > 0 {
		event.Metadata["slot"] = entry.Slot
	}
	if entry.Epoch > 0 {
		event.Metadata["epoch"] = entry.Epoch
	}

	event.Raw = fmt.Sprintf("[%s] %s", entry.Level, entry.Message)

	return event, nil
}

func (p *Parser) mapSeverity(level string) int {
	switch strings.ToUpper(level) {
	case "FATAL", "CRIT":
		return 10
	case "ERROR", "ERR":
		return 8
	case "WARN", "WARNING":
		return 5
	case "INFO":
		return 3
	case "DEBUG", "DBG":
		return 2
	case "TRACE", "TRC":
		return 1
	default:
		return 3
	}
}

func (p *Parser) classifyEvent(entry *LogEntry) (action string, outcome schema.Outcome) {
	msg := strings.ToLower(entry.Message)

	// Attestation events
	if strings.Contains(msg, "submitted attestation") || strings.Contains(msg, "attestation submitted") {
		return "validator.attestation_submitted", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "attestation included") {
		return "validator.attestation_included", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "missed attestation") || strings.Contains(msg, "attestation missed") {
		return "validator.attestation_missed", schema.OutcomeFailure
	}
	if strings.Contains(msg, "attestation failed") {
		return "validator.attestation_failed", schema.OutcomeFailure
	}

	// Proposal events
	if strings.Contains(msg, "proposed block") || strings.Contains(msg, "block proposed") {
		return "validator.block_proposed", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "proposal duty") {
		if strings.Contains(msg, "missed") || strings.Contains(msg, "failed") {
			return "validator.proposal_missed", schema.OutcomeFailure
		}
		return "validator.proposal_duty", schema.OutcomeSuccess
	}

	// Sync committee events
	if strings.Contains(msg, "sync committee") {
		if strings.Contains(msg, "contribution") || strings.Contains(msg, "submitted") {
			return "validator.sync_committee_submitted", schema.OutcomeSuccess
		}
		if strings.Contains(msg, "missed") || strings.Contains(msg, "failed") {
			return "validator.sync_committee_missed", schema.OutcomeFailure
		}
		return "validator.sync_committee", schema.OutcomeSuccess
	}

	// Slashing events - CRITICAL
	if strings.Contains(msg, "slashing") || strings.Contains(msg, "slashed") {
		return "validator.slashing_detected", schema.OutcomeFailure
	}
	if strings.Contains(msg, "double vote") || strings.Contains(msg, "double voting") {
		return "validator.double_vote", schema.OutcomeFailure
	}
	if strings.Contains(msg, "surround vote") || strings.Contains(msg, "surround voting") {
		return "validator.surround_vote", schema.OutcomeFailure
	}

	// Sync events
	if strings.Contains(msg, "synced") || strings.Contains(msg, "sync complete") {
		return "beacon.synced", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "syncing") {
		return "beacon.syncing", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "sync failed") {
		return "beacon.sync_failed", schema.OutcomeFailure
	}

	// Peer events
	if strings.Contains(msg, "peer connected") {
		return "peer.connected", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "peer disconnected") {
		return "peer.disconnected", schema.OutcomeSuccess
	}

	// Block events
	if strings.Contains(msg, "processed block") || strings.Contains(msg, "block processed") {
		return "beacon.block_processed", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "new block") || strings.Contains(msg, "received block") {
		return "beacon.block_received", schema.OutcomeSuccess
	}

	// Finality events
	if strings.Contains(msg, "finalized") || strings.Contains(msg, "finality") {
		return "beacon.finalized", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "justified") || strings.Contains(msg, "justification") {
		return "beacon.justified", schema.OutcomeSuccess
	}

	// Validator lifecycle
	if strings.Contains(msg, "validator activated") {
		return "validator.activated", schema.OutcomeSuccess
	}
	if strings.Contains(msg, "validator exited") || strings.Contains(msg, "exit") {
		return "validator.exited", schema.OutcomeSuccess
	}

	// High severity fallback
	if entry.Level == "ERROR" || entry.Level == "FATAL" || entry.Level == "CRIT" {
		return "beacon.error", schema.OutcomeFailure
	}

	return "beacon.log", schema.OutcomeUnknown
}

// SecurityPatterns for detecting security-relevant events.
var SecurityPatterns = map[string]*regexp.Regexp{
	"slashing":          regexp.MustCompile(`(?i)slashing|slashed|double.?vote|surround.?vote`),
	"missed_duty":       regexp.MustCompile(`(?i)missed.*attestation|missed.*proposal|missed.*sync`),
	"sync_issue":        regexp.MustCompile(`(?i)sync failed|not synced|behind|lagging`),
	"peer_issue":        regexp.MustCompile(`(?i)no peers|peer.*disconnect|isolated`),
	"validator_offline": regexp.MustCompile(`(?i)validator.*offline|validator.*inactive`),
	"key_access":        regexp.MustCompile(`(?i)signing.*key|keystore|withdrawal.*key`),
}

// IsSecurityRelevant checks if an entry is security-relevant.
func (p *Parser) IsSecurityRelevant(entry *LogEntry) (bool, string) {
	msg := entry.Message

	for eventType, pattern := range SecurityPatterns {
		if pattern.MatchString(msg) {
			return true, eventType
		}
	}

	// High severity logs are always relevant
	if entry.Level == "ERROR" || entry.Level == "FATAL" || entry.Level == "CRIT" {
		return true, "high_severity"
	}

	return false, ""
}

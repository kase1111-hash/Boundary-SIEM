package cef

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/schema"
)

// DefaultActionMappings maps CEF signature IDs to canonical action names.
var DefaultActionMappings = map[string]string{
	// Boundary-daemon mappings
	"100": "session.created",
	"101": "session.terminated",
	"102": "session.expired",
	"200": "auth.login",
	"201": "auth.logout",
	"400": "auth.failure",
	"401": "auth.mfa_failure",
	"500": "access.granted",
	"501": "access.denied",

	// Generic mappings
	"TRAFFIC": "network.connection",
	"THREAT":  "threat.detected",
	"SYSTEM":  "system.event",
	"LOGIN":   "auth.login",
	"LOGOUT":  "auth.logout",
	"DENY":    "access.denied",
	"ALLOW":   "access.granted",
}

// NormalizerConfig holds configuration for the normalizer.
type NormalizerConfig struct {
	DefaultTenantID string
	ActionMappings  map[string]string
}

// DefaultNormalizerConfig returns the default normalizer configuration.
func DefaultNormalizerConfig() NormalizerConfig {
	return NormalizerConfig{
		DefaultTenantID: "default",
		ActionMappings:  DefaultActionMappings,
	}
}

// Normalizer converts CEF events to canonical schema.
type Normalizer struct {
	config NormalizerConfig
}

// NewNormalizer creates a new normalizer with the given configuration.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	// Merge default mappings with custom ones
	mappings := make(map[string]string)
	for k, v := range DefaultActionMappings {
		mappings[k] = v
	}
	for k, v := range cfg.ActionMappings {
		mappings[k] = v
	}
	cfg.ActionMappings = mappings

	return &Normalizer{
		config: cfg,
	}
}

// Normalize converts a CEFEvent to a canonical schema Event.
func (n *Normalizer) Normalize(cef *CEFEvent, sourceIP string) (*schema.Event, error) {
	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     n.extractTimestamp(cef),
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: "1.0.0",
		TenantID:      n.config.DefaultTenantID,

		Source: schema.Source{
			Product:    cef.DeviceProduct,
			Host:       n.extractSourceHost(cef, sourceIP),
			InstanceID: cef.SignatureID,
			Version:    cef.DeviceVersion,
		},

		Action:   n.mapAction(cef),
		Target:   n.extractTarget(cef),
		Outcome:  n.extractOutcome(cef),
		Severity: n.mapSeverity(cef.Severity),
		Raw:      cef.RawMessage,

		Metadata: n.buildMetadata(cef),
	}

	// Extract actor information
	event.Actor = n.extractActor(cef)

	return event, nil
}

// extractTimestamp extracts timestamp from CEF extensions or uses current time.
func (n *Normalizer) extractTimestamp(cef *CEFEvent) time.Time {
	// Try receipt time first
	if rt, ok := cef.Extensions["rt"]; ok {
		if t, err := n.parseTimestamp(rt); err == nil {
			return t
		}
	}

	// Try start time
	if start, ok := cef.Extensions["start"]; ok {
		if t, err := n.parseTimestamp(start); err == nil {
			return t
		}
	}

	// Default to now
	return time.Now().UTC()
}

// parseTimestamp handles various CEF timestamp formats.
func (n *Normalizer) parseTimestamp(s string) (time.Time, error) {
	// CEF uses milliseconds since epoch
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.UnixMilli(ms).UTC(), nil
	}

	// Try common formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"Jan 02 2006 15:04:05",
		"Jan 02 15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", s)
}

// extractSourceHost gets the source host from extensions or falls back to source IP.
func (n *Normalizer) extractSourceHost(cef *CEFEvent, sourceIP string) string {
	if host, ok := cef.Extensions["dvchost"]; ok {
		return host
	}
	if host, ok := cef.Extensions["shost"]; ok {
		return host
	}
	if ip, ok := cef.Extensions["dvc"]; ok {
		return ip
	}
	return sourceIP
}

// mapAction maps CEF signature ID to canonical action.
func (n *Normalizer) mapAction(cef *CEFEvent) string {
	// Check explicit mappings first
	if action, ok := n.config.ActionMappings[cef.SignatureID]; ok {
		return action
	}

	// Check act extension
	if act, ok := cef.Extensions["act"]; ok {
		return n.normalizeActionString(act)
	}

	// Build action from event name
	return n.normalizeActionString(cef.Name)
}

// normalizeActionString converts a string to action format (lowercase, dots).
func (n *Normalizer) normalizeActionString(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")

	// Ensure it matches action pattern
	if !strings.Contains(s, ".") {
		s = "event." + s
	}

	return s
}

// extractTarget determines the target from CEF extensions.
func (n *Normalizer) extractTarget(cef *CEFEvent) string {
	// Build target from destination info
	var parts []string

	if host, ok := cef.Extensions["dhost"]; ok {
		parts = append(parts, "host:"+host)
	} else if ip, ok := cef.Extensions["dst"]; ok {
		parts = append(parts, "ip:"+ip)
	}

	if user, ok := cef.Extensions["duser"]; ok {
		parts = append(parts, "user:"+user)
	}

	if path, ok := cef.Extensions["filePath"]; ok {
		parts = append(parts, "file:"+path)
	}

	if url, ok := cef.Extensions["request"]; ok {
		parts = append(parts, "url:"+url)
	}

	if len(parts) == 0 {
		return ""
	}

	return strings.Join(parts, ",")
}

// extractOutcome determines the outcome from CEF extensions.
func (n *Normalizer) extractOutcome(cef *CEFEvent) schema.Outcome {
	if outcome, ok := cef.Extensions["outcome"]; ok {
		switch strings.ToLower(outcome) {
		case "success", "succeeded", "allowed", "permit":
			return schema.OutcomeSuccess
		case "failure", "failed", "denied", "blocked", "reject":
			return schema.OutcomeFailure
		}
	}

	// Check action for hints
	if act, ok := cef.Extensions["act"]; ok {
		actLower := strings.ToLower(act)
		if strings.Contains(actLower, "block") || strings.Contains(actLower, "deny") {
			return schema.OutcomeFailure
		}
		if strings.Contains(actLower, "allow") || strings.Contains(actLower, "permit") {
			return schema.OutcomeSuccess
		}
	}

	return schema.OutcomeUnknown
}

// mapSeverity maps CEF severity (0-10) to canonical severity (1-10).
func (n *Normalizer) mapSeverity(cefSeverity int) int {
	if cefSeverity < 1 {
		return 1
	}
	if cefSeverity > 10 {
		return 10
	}
	return cefSeverity
}

// extractActor extracts actor information from CEF extensions.
func (n *Normalizer) extractActor(cef *CEFEvent) *schema.Actor {
	actor := &schema.Actor{
		Type: schema.ActorUnknown,
	}

	// Source user
	if user, ok := cef.Extensions["suser"]; ok {
		actor.Type = schema.ActorUser
		actor.Name = user
	}

	if uid, ok := cef.Extensions["suid"]; ok {
		actor.ID = uid
	}

	// Source IP
	if ip, ok := cef.Extensions["src"]; ok {
		actor.IPAddress = ip
	}

	// If no actor info found, return nil
	if actor.Name == "" && actor.ID == "" && actor.IPAddress == "" {
		return nil
	}

	return actor
}

// buildMetadata builds the metadata map from CEF extensions.
func (n *Normalizer) buildMetadata(cef *CEFEvent) map[string]any {
	metadata := make(map[string]any)

	// Add CEF-specific metadata
	metadata["cef_version"] = cef.Version
	metadata["device_vendor"] = cef.DeviceVendor
	metadata["signature_id"] = cef.SignatureID
	metadata["event_name"] = cef.Name

	// Add useful extensions to metadata
	interestingFields := []string{
		"msg", "reason", "cat", "filePath", "fname", "fsize",
		"request", "requestMethod", "spt", "dpt",
		"cs1", "cs2", "cs3", "cs4", "cs5", "cs6",
	}

	for _, field := range interestingFields {
		if val, ok := cef.Extensions[field]; ok {
			metadata["cef_"+field] = val
		}
	}

	return metadata
}

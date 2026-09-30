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
	now    func() time.Time // for tests; nil means time.Now
}

// timestampLayouts are the CEF date formats for rt/start (see the CEF
// implementation standard) plus RFC 3339 and ISO forms. time.Parse accepts a
// fractional second after the seconds field even when the layout has none,
// so the ".SSS" variants need no entries of their own.
var timestampLayouts = []string{
	time.RFC3339,
	"Jan _2 2006 15:04:05 MST",
	"Jan _2 2006 15:04:05 Z07:00",
	"Jan _2 2006 15:04:05 -0700",
	"Jan _2 2006 15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
}

// yearlessLayouts are the CEF and RFC 3164 formats without a year; the year
// is inferred by resolveYear.
var yearlessLayouts = []string{
	"Jan _2 15:04:05 MST",
	"Jan _2 15:04:05 Z07:00",
	"Jan _2 15:04:05 -0700",
	"Jan _2 15:04:05",
}

// zoneOffsets resolves the time zone abbreviations commonly found in CEF
// timestamps. time.Parse only knows the abbreviations of the local zone and
// would otherwise treat any other one as UTC. Ambiguous abbreviations (IST,
// BST) are left out; CST is taken as US Central, as in ArcSight.
var zoneOffsets = map[string]int{
	"UTC": 0, "UT": 0, "GMT": 0, "Z": 0, "WET": 0,
	"WEST": 1 * 3600, "CET": 1 * 3600, "CEST": 2 * 3600, "EET": 2 * 3600, "EEST": 3 * 3600, "MSK": 3 * 3600,
	"EST": -5 * 3600, "EDT": -4 * 3600, "CST": -6 * 3600, "CDT": -5 * 3600,
	"MST": -7 * 3600, "MDT": -6 * 3600, "PST": -8 * 3600, "PDT": -7 * 3600,
	"AKST": -9 * 3600, "AKDT": -8 * 3600, "HST": -10 * 3600,
	"JST": 9 * 3600, "KST": 9 * 3600, "AWST": 8 * 3600, "ACST": 9*3600 + 1800,
	"AEST": 10 * 3600, "AEDT": 11 * 3600, "NZST": 12 * 3600, "NZDT": 13 * 3600,
}

// yearlessSlack is how far in the future a year-less timestamp may lie before
// it is attributed to the previous year, and how close to now a timestamp
// just after New Year must be to be attributed to the next year.
const yearlessSlack = 24 * time.Hour

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
		now:    time.Now,
	}
}

func (n *Normalizer) currentTime() time.Time {
	if n.now != nil {
		return n.now()
	}
	return time.Now()
}

// Normalize converts a CEFEvent to a canonical schema Event.
func (n *Normalizer) Normalize(cef *CEFEvent, sourceIP string) (*schema.Event, error) {
	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     n.extractTimestamp(cef),
		ReceivedAt:    n.currentTime().UTC(),
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

// extractTimestamp takes the event time from the rt or start extension, then
// from the syslog header, and falls back to the current time.
func (n *Normalizer) extractTimestamp(cef *CEFEvent) time.Time {
	candidates := []string{cef.Extensions["rt"], cef.Extensions["start"], cef.SyslogTimestamp}
	for _, s := range candidates {
		if s == "" {
			continue
		}
		if t, err := n.parseTimestamp(s); err == nil {
			return t
		}
	}

	return n.currentTime().UTC()
}

// parseTimestamp handles the CEF timestamp formats: milliseconds since the
// epoch and "MMM dd [yyyy] HH:mm:ss[.SSS] [zzz]", plus RFC 3339.
func (n *Normalizer) parseTimestamp(s string) (time.Time, error) {
	s = strings.TrimSpace(s)

	// CEF uses milliseconds since epoch
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.UnixMilli(ms).UTC(), nil
	}

	for _, layout := range timestampLayouts {
		if parsed, err := time.Parse(layout, s); err == nil {
			if t, ok := resolveZone(parsed); ok {
				return t.UTC(), nil
			}
		}
	}

	for _, layout := range yearlessLayouts {
		if parsed, err := time.Parse(layout, s); err == nil {
			if t, ok := resolveZone(parsed); ok {
				return resolveYear(t, n.currentTime()).UTC(), nil
			}
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", s)
}

// resolveZone gives a time parsed with a zone abbreviation its real offset.
// It reports false for an abbreviation it does not know, which time.Parse
// would otherwise have treated as UTC.
func resolveZone(t time.Time) (time.Time, bool) {
	name, offset := t.Zone()
	if name == "" || !isAlpha(name) {
		return t, true // no abbreviation, or a numeric offset
	}
	if known, ok := zoneOffsets[strings.ToUpper(name)]; ok {
		if known == offset {
			return t, true
		}
		return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(),
			time.FixedZone(name, known)), true
	}
	// Unknown abbreviation: trust it only if the local zone defined it.
	return t, offset != 0
}

func isAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// resolveYear sets the year of a timestamp parsed without one (time.Parse
// yields year 0). It uses the current year unless that puts the time more than
// yearlessSlack in the future (an event from late December received in
// January), or the next year is within yearlessSlack of now (an event from
// just after New Year received from a sender whose clock is ahead).
func resolveYear(t, now time.Time) time.Time {
	withYear := func(year int) time.Time {
		return time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
	}

	year := now.In(t.Location()).Year()
	switch cur := withYear(year); {
	case cur.Sub(now) > yearlessSlack:
		return withYear(year - 1)
	case withYear(year+1).Sub(now) <= yearlessSlack:
		return withYear(year + 1)
	default:
		return cur
	}
}

// extractSourceHost gets the reporting host from the extensions, then from the
// syslog header, and falls back to the peer address.
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
	if cef.SyslogHost != "" {
		return cef.SyslogHost
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

// normalizeActionString converts a free-form name to the schema's action format
// (lowercase dot-separated segments of [a-z0-9_], each starting with a letter).
// Other characters become '_', runs of '_' collapse, empty segments are
// dropped and a segment starting with a digit gets an "n" prefix. A name
// without a dot is placed under "event.".
func (n *Normalizer) normalizeActionString(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	underscore := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' {
			b.WriteRune(r)
			underscore = false
			continue
		}
		if !underscore {
			b.WriteByte('_')
			underscore = true
		}
	}

	segments := strings.Split(b.String(), ".")
	kept := segments[:0]
	for _, seg := range segments {
		seg = strings.Trim(seg, "_")
		if seg == "" {
			continue
		}
		if seg[0] >= '0' && seg[0] <= '9' {
			seg = "n" + seg
		}
		kept = append(kept, seg)
	}

	switch len(kept) {
	case 0:
		return "event.unknown"
	case 1:
		return "event." + kept[0]
	default:
		return strings.Join(kept, ".")
	}
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

	if cef.SyslogHost != "" {
		metadata["syslog_host"] = cef.SyslogHost
	}
	if cef.SyslogTimestamp != "" {
		metadata["syslog_timestamp"] = cef.SyslogTimestamp
	}

	return metadata
}

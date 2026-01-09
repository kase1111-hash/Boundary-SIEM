package boundarydaemon

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/schema"
)

// ActionMappings maps Boundary Daemon event types to canonical action names.
var ActionMappings = map[string]string{
	// Session events
	"session.created":    "bd.session.created",
	"session.terminated": "bd.session.terminated",
	"session.expired":    "bd.session.expired",

	// Authentication events
	"auth.login":       "bd.auth.login",
	"auth.logout":      "bd.auth.logout",
	"auth.failure":     "bd.auth.failure",
	"auth.mfa_failure": "bd.auth.mfa_failure",
	"auth.mfa_success": "bd.auth.mfa_success",

	// Access control events
	"access.granted": "bd.access.granted",
	"access.denied":  "bd.access.denied",

	// Threat events
	"threat.detected":    "bd.threat.detected",
	"threat.blocked":     "bd.threat.blocked",
	"threat.quarantined": "bd.threat.quarantined",

	// Policy events
	"policy.applied":  "bd.policy.applied",
	"policy.violated": "bd.policy.violated",
	"policy.changed":  "bd.policy.changed",

	// Audit events
	"audit.log.created":  "bd.audit.created",
	"audit.log.verified": "bd.audit.verified",
}

// Normalizer converts Boundary Daemon events to canonical SIEM schema.
type Normalizer struct {
	defaultTenantID string
	sourceProduct   string
	sourceHost      string
	sourceVersion   string
}

// NormalizerConfig holds configuration for the normalizer.
type NormalizerConfig struct {
	DefaultTenantID string `yaml:"default_tenant_id"`
	SourceHost      string `yaml:"source_host"`
	SourceVersion   string `yaml:"source_version"`
}

// DefaultNormalizerConfig returns the default normalizer configuration.
func DefaultNormalizerConfig() NormalizerConfig {
	return NormalizerConfig{
		DefaultTenantID: "default",
		SourceHost:      "localhost",
		SourceVersion:   "1.0.0",
	}
}

// NewNormalizer creates a new Boundary Daemon normalizer.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	return &Normalizer{
		defaultTenantID: cfg.DefaultTenantID,
		sourceProduct:   "boundary-daemon",
		sourceHost:      cfg.SourceHost,
		sourceVersion:   cfg.SourceVersion,
	}
}

// NormalizeSessionEvent converts a session event to a canonical SIEM event.
func (n *Normalizer) NormalizeSessionEvent(ev *SessionEvent) (*schema.Event, error) {
	action := n.mapAction(ev.EventType)
	severity := n.calculateSessionSeverity(ev)
	outcome := n.determineSessionOutcome(ev)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     ev.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: ev.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", ev.SessionID),
		Outcome:  outcome,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   ev.UserID,
			Name: ev.Username,
		},

		Network: &schema.Network{
			SourceIP: ev.SourceIP,
			DestIP:   ev.DestIP,
			Protocol: ev.Protocol,
			Port:     ev.Port,
		},

		Metadata: map[string]any{
			"bd_event_id":     ev.ID,
			"bd_session_id":   ev.SessionID,
			"bd_event_type":   ev.EventType,
			"bd_source_ip":    ev.SourceIP,
			"bd_dest_ip":      ev.DestIP,
			"bd_protocol":     ev.Protocol,
			"bd_port":         ev.Port,
		},
	}

	if ev.Duration > 0 {
		event.Metadata["bd_duration_ms"] = ev.Duration
	}
	if ev.TermReason != "" {
		event.Metadata["bd_termination_reason"] = ev.TermReason
	}

	return event, nil
}

// NormalizeAuthEvent converts an authentication event to a canonical SIEM event.
func (n *Normalizer) NormalizeAuthEvent(ev *AuthEvent) (*schema.Event, error) {
	action := n.mapAction(ev.EventType)
	severity := n.calculateAuthSeverity(ev)
	outcome := n.determineAuthOutcome(ev)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     ev.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: ev.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("user:%s", ev.UserID),
		Outcome:  outcome,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   ev.UserID,
			Name: ev.Username,
		},

		Network: &schema.Network{
			SourceIP: ev.SourceIP,
		},

		Metadata: map[string]any{
			"bd_event_id":    ev.ID,
			"bd_event_type":  ev.EventType,
			"bd_auth_method": ev.AuthMethod,
			"bd_success":     ev.Success,
			"bd_source_ip":   ev.SourceIP,
		},
	}

	if ev.SessionID != "" {
		event.Metadata["bd_session_id"] = ev.SessionID
	}
	if ev.FailReason != "" {
		event.Metadata["bd_failure_reason"] = ev.FailReason
	}
	if ev.MFAType != "" {
		event.Metadata["bd_mfa_type"] = ev.MFAType
	}

	return event, nil
}

// NormalizeAccessEvent converts an access control event to a canonical SIEM event.
func (n *Normalizer) NormalizeAccessEvent(ev *AccessEvent) (*schema.Event, error) {
	action := n.mapAction(ev.EventType)
	severity := n.calculateAccessSeverity(ev)
	outcome := n.determineAccessOutcome(ev)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     ev.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: ev.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   ev.Resource,
		Outcome:  outcome,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   ev.UserID,
			Name: ev.Username,
		},

		Metadata: map[string]any{
			"bd_event_id":     ev.ID,
			"bd_event_type":   ev.EventType,
			"bd_session_id":   ev.SessionID,
			"bd_resource":     ev.Resource,
			"bd_action":       ev.Action,
			"bd_granted":      ev.Granted,
		},
	}

	if ev.DenyReason != "" {
		event.Metadata["bd_deny_reason"] = ev.DenyReason
	}
	if ev.PolicyID != "" {
		event.Metadata["bd_policy_id"] = ev.PolicyID
	}
	if ev.RuleID != "" {
		event.Metadata["bd_rule_id"] = ev.RuleID
	}

	return event, nil
}

// NormalizeThreatEvent converts a threat detection event to a canonical SIEM event.
func (n *Normalizer) NormalizeThreatEvent(ev *ThreatEvent) (*schema.Event, error) {
	action := n.mapAction(ev.EventType)
	severity := n.mapThreatSeverity(ev.Severity)
	outcome := n.determineThreatOutcome(ev)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     ev.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: ev.ID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   n.determineThreatTarget(ev),
		Outcome:  outcome,
		Severity: severity,

		Metadata: map[string]any{
			"bd_event_id":     ev.ID,
			"bd_event_type":   ev.EventType,
			"bd_threat_type":  ev.ThreatType,
			"bd_severity":     ev.Severity,
			"bd_description":  ev.Description,
			"bd_action_taken": ev.ActionTaken,
			"bd_blocked":      ev.Blocked,
		},

		Raw: ev.Description,
	}

	// Add network info if available
	if ev.SourceIP != "" || ev.DestIP != "" {
		event.Network = &schema.Network{
			SourceIP: ev.SourceIP,
			DestIP:   ev.DestIP,
		}
		event.Metadata["bd_source_ip"] = ev.SourceIP
		event.Metadata["bd_dest_ip"] = ev.DestIP
	}

	// Add user info if available
	if ev.UserID != "" {
		event.Actor = &schema.Actor{
			Type: schema.ActorUser,
			ID:   ev.UserID,
		}
	}

	// Add process info if available
	if ev.ProcessName != "" {
		event.Metadata["bd_process_name"] = ev.ProcessName
		event.Metadata["bd_process_path"] = ev.ProcessPath
	}

	// Add threat indicators
	if len(ev.Indicators) > 0 {
		event.Metadata["bd_indicators"] = ev.Indicators
	}
	if len(ev.MITREAttack) > 0 {
		event.Metadata["bd_mitre_attack"] = ev.MITREAttack
	}

	return event, nil
}

// NormalizePolicyEvent converts a policy enforcement event to a canonical SIEM event.
func (n *Normalizer) NormalizePolicyEvent(ev *PolicyEvent) (*schema.Event, error) {
	action := n.mapAction(ev.EventType)
	severity := n.calculatePolicySeverity(ev)
	outcome := n.determinePolicyOutcome(ev)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     ev.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: ev.PolicyID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   ev.Target,
		Outcome:  outcome,
		Severity: severity,

		Metadata: map[string]any{
			"bd_event_id":    ev.ID,
			"bd_event_type":  ev.EventType,
			"bd_policy_id":   ev.PolicyID,
			"bd_policy_name": ev.PolicyName,
			"bd_policy_type": ev.PolicyType,
			"bd_action":      ev.Action,
			"bd_target":      ev.Target,
			"bd_enforced":    ev.Enforced,
		},
	}

	if ev.UserID != "" {
		event.Actor = &schema.Actor{
			Type: schema.ActorUser,
			ID:   ev.UserID,
		}
	}

	return event, nil
}

// NormalizeAuditLog converts a cryptographic audit log to a canonical SIEM event.
func (n *Normalizer) NormalizeAuditLog(log *AuditLogEntry) (*schema.Event, error) {
	action := n.mapAction("audit.log.created")
	if log.Verified {
		action = n.mapAction("audit.log.verified")
	}

	severity := 2 // Informational
	outcome := schema.OutcomeSuccess
	if log.Outcome == "failure" {
		outcome = schema.OutcomeFailure
		severity = 4
	} else if log.Outcome == "partial" {
		outcome = schema.OutcomeUnknown
		severity = 3
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     log.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: log.ID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   log.Target,
		Outcome:  outcome,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   log.Actor,
			Name: log.Actor,
		},

		Metadata: map[string]any{
			"bd_log_id":         log.ID,
			"bd_event_type":     log.EventType,
			"bd_action":         log.Action,
			"bd_outcome":        log.Outcome,
			"bd_content_hash":   log.ContentHash,
			"bd_previous_hash":  log.PreviousHash,
			"bd_signature":      log.Signature,
			"bd_signature_algo": log.SignatureAlgo,
			"bd_verified":       log.Verified,
		},
	}

	return event, nil
}

// mapAction maps an event type to a canonical action.
func (n *Normalizer) mapAction(eventType string) string {
	if action, ok := ActionMappings[eventType]; ok {
		return action
	}
	return "bd.event." + eventType
}

// calculateSessionSeverity determines severity based on session event type.
func (n *Normalizer) calculateSessionSeverity(ev *SessionEvent) int {
	switch ev.EventType {
	case "session.created":
		return 2 // Informational
	case "session.terminated":
		if ev.TermReason == "forced" || ev.TermReason == "security" {
			return 5 // Warning
		}
		return 2
	case "session.expired":
		return 3 // Notice
	default:
		return 3
	}
}

// calculateAuthSeverity determines severity based on auth event type.
func (n *Normalizer) calculateAuthSeverity(ev *AuthEvent) int {
	if !ev.Success {
		switch ev.EventType {
		case "auth.failure":
			return 5 // Warning
		case "auth.mfa_failure":
			return 6 // High
		}
	}
	return 2 // Informational for success
}

// calculateAccessSeverity determines severity based on access event type.
func (n *Normalizer) calculateAccessSeverity(ev *AccessEvent) int {
	if !ev.Granted {
		return 5 // Warning for denied access
	}
	return 2 // Informational for granted access
}

// calculatePolicySeverity determines severity based on policy event type.
func (n *Normalizer) calculatePolicySeverity(ev *PolicyEvent) int {
	switch ev.EventType {
	case "policy.violated":
		return 6 // High
	case "policy.changed":
		return 4 // Medium
	case "policy.applied":
		return 2 // Informational
	default:
		return 3
	}
}

// mapThreatSeverity maps threat severity string to numeric severity.
func (n *Normalizer) mapThreatSeverity(severity string) int {
	switch severity {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 5
	}
}

// determineSessionOutcome determines the outcome for a session event.
func (n *Normalizer) determineSessionOutcome(ev *SessionEvent) schema.Outcome {
	switch ev.EventType {
	case "session.created":
		return schema.OutcomeSuccess
	case "session.terminated":
		if ev.TermReason == "error" || ev.TermReason == "security" {
			return schema.OutcomeFailure
		}
		return schema.OutcomeSuccess
	case "session.expired":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// determineAuthOutcome determines the outcome for an auth event.
func (n *Normalizer) determineAuthOutcome(ev *AuthEvent) schema.Outcome {
	if ev.Success {
		return schema.OutcomeSuccess
	}
	return schema.OutcomeFailure
}

// determineAccessOutcome determines the outcome for an access event.
func (n *Normalizer) determineAccessOutcome(ev *AccessEvent) schema.Outcome {
	if ev.Granted {
		return schema.OutcomeSuccess
	}
	return schema.OutcomeFailure
}

// determineThreatOutcome determines the outcome for a threat event.
func (n *Normalizer) determineThreatOutcome(ev *ThreatEvent) schema.Outcome {
	if ev.Blocked {
		return schema.OutcomeSuccess // Successfully blocked
	}
	return schema.OutcomeFailure // Threat not blocked
}

// determinePolicyOutcome determines the outcome for a policy event.
func (n *Normalizer) determinePolicyOutcome(ev *PolicyEvent) schema.Outcome {
	switch ev.EventType {
	case "policy.violated":
		return schema.OutcomeFailure
	case "policy.applied", "policy.changed":
		if ev.Enforced {
			return schema.OutcomeSuccess
		}
		return schema.OutcomeUnknown
	default:
		return schema.OutcomeUnknown
	}
}

// determineThreatTarget constructs a target string for a threat event.
func (n *Normalizer) determineThreatTarget(ev *ThreatEvent) string {
	if ev.ProcessName != "" {
		return fmt.Sprintf("process:%s", ev.ProcessName)
	}
	if ev.DestIP != "" {
		return fmt.Sprintf("host:%s", ev.DestIP)
	}
	if ev.UserID != "" {
		return fmt.Sprintf("user:%s", ev.UserID)
	}
	return fmt.Sprintf("threat:%s", ev.ID)
}

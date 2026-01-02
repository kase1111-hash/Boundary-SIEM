package synthmind

import (
	"boundary-siem/internal/core/schema"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Normalizer converts Synth Mind events to canonical SIEM events.
type Normalizer struct{}

// NewNormalizer creates a new Synth Mind normalizer.
func NewNormalizer() *Normalizer {
	return &Normalizer{}
}

// NormalizeEmotionalState converts an emotional state to a canonical event.
func (n *Normalizer) NormalizeEmotionalState(state EmotionalState) schema.CanonicalEvent {
	outcome := "success"
	if state.Anomaly {
		outcome = "anomaly"
	}

	severity := 3
	if state.Valence < -0.5 {
		severity = 6
	} else if state.Valence < 0 {
		severity = 4
	}
	if state.Anomaly {
		severity = 7
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: state.Timestamp,
		Actor:     state.AgentID,
		Action:    "sm.emotional.state",
		Target:    state.AgentID,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"sm_agent_id":   state.AgentID,
			"sm_valence":    state.Valence,
			"sm_arousal":    state.Arousal,
			"sm_dominance":  state.Dominance,
			"sm_primary":    state.Primary,
			"sm_intensity":  state.Intensity,
			"sm_anomaly":    state.Anomaly,
			"sm_session_id": state.SessionID,
			"source":        "synthmind",
		},
		Source:    "synthmind",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeModuleEvent converts a module event to a canonical event.
func (n *Normalizer) NormalizeModuleEvent(event ModuleEvent) schema.CanonicalEvent {
	outcome := "success"
	if !event.Success {
		outcome = "failure"
	}

	severity := 3
	if !event.Success {
		severity = 5
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.AgentID,
		Action:    fmt.Sprintf("sm.module.%s", event.EventType),
		Target:    event.Module,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"sm_agent_id":       event.AgentID,
			"sm_module":         event.Module,
			"sm_event_type":     event.EventType,
			"sm_success":        event.Success,
			"sm_processing_ms":  event.ProcessingTime,
			"sm_input_tokens":   event.InputTokens,
			"sm_output_tokens":  event.OutputTokens,
			"sm_error":          event.Error,
			"source":            "synthmind",
		},
		Source:    "synthmind",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeDreamingEvent converts a dreaming event to a canonical event.
func (n *Normalizer) NormalizeDreamingEvent(event DreamingEvent) schema.CanonicalEvent {
	outcome := "success"
	severity := 3

	if event.ValidationGap > 0.7 {
		outcome = "mismatch"
		severity = 5
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.AgentID,
		Action:    fmt.Sprintf("sm.dreaming.%s", event.EventType),
		Target:    event.AgentID,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"sm_agent_id":        event.AgentID,
			"sm_session_id":      event.SessionID,
			"sm_event_type":      event.EventType,
			"sm_scenario":        event.Scenario,
			"sm_predicted":       event.PredictedOutcome,
			"sm_actual":          event.ActualOutcome,
			"sm_validation_gap":  event.ValidationGap,
			"sm_duration_ms":     event.Duration.Milliseconds(),
			"source":             "synthmind",
		},
		Source:    "synthmind",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeReflectionEvent converts a reflection event to a canonical event.
func (n *Normalizer) NormalizeReflectionEvent(event ReflectionEvent) schema.CanonicalEvent {
	severity := 3
	if event.Severity == "significant" {
		severity = 6
	} else if event.Severity == "critical" {
		severity = 8
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.AgentID,
		Action:    fmt.Sprintf("sm.reflection.%s", event.ReflectionType),
		Target:    event.AgentID,
		Outcome:   "success",
		Severity:  severity,
		Metadata: map[string]any{
			"sm_agent_id":        event.AgentID,
			"sm_reflection_type": event.ReflectionType,
			"sm_trigger":         event.Trigger,
			"sm_summary":         event.Summary,
			"sm_insights":        event.Insights,
			"sm_severity":        event.Severity,
			"sm_action_items":    event.ActionItems,
			"source":             "synthmind",
		},
		Source:    "synthmind",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeSocialEvent converts a social event to a canonical event.
func (n *Normalizer) NormalizeSocialEvent(event SocialEvent) schema.CanonicalEvent {
	outcome := "success"
	if !event.Success {
		outcome = "failure"
	}

	severity := 3
	if !event.Success {
		severity = 5
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.AgentID,
		Action:    fmt.Sprintf("sm.social.%s", event.EventType),
		Target:    event.PeerAgentID,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"sm_agent_id":      event.AgentID,
			"sm_peer_agent_id": event.PeerAgentID,
			"sm_event_type":    event.EventType,
			"sm_channel":       event.Channel,
			"sm_message_type":  event.MessageType,
			"sm_success":       event.Success,
			"sm_latency_ms":    event.Latency.Milliseconds(),
			"source":           "synthmind",
		},
		Source:    "synthmind",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeToolUsageEvent converts a tool usage event to a canonical event.
func (n *Normalizer) NormalizeToolUsageEvent(event ToolUsageEvent) schema.CanonicalEvent {
	outcome := "success"
	if !event.Success {
		outcome = "failure"
	}
	if event.Sandboxed {
		outcome = "sandboxed"
	}

	severity := 3
	if !event.Success {
		severity = 5
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.AgentID,
		Action:    fmt.Sprintf("sm.tool.%s", event.ToolName),
		Target:    event.ToolName,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"sm_agent_id":      event.AgentID,
			"sm_tool_name":     event.ToolName,
			"sm_tool_version":  event.ToolVersion,
			"sm_sandboxed":     event.Sandboxed,
			"sm_success":       event.Success,
			"sm_execution_ms":  event.ExecutionTime.Milliseconds(),
			"sm_error":         event.Error,
			"source":           "synthmind",
		},
		Source:    "synthmind",
		CreatedAt: time.Now().UTC(),
	}
}

// NormalizeSafetyEvent converts a safety event to a canonical event.
func (n *Normalizer) NormalizeSafetyEvent(event SafetyEvent) schema.CanonicalEvent {
	outcome := "success"
	if event.Triggered {
		outcome = "triggered"
	}

	severity := 4
	if event.Triggered {
		severity = 8
	}

	return schema.CanonicalEvent{
		ID:        uuid.New().String(),
		Timestamp: event.Timestamp,
		Actor:     event.AgentID,
		Action:    fmt.Sprintf("sm.safety.%s", event.EventType),
		Target:    event.GuardrailID,
		Outcome:   outcome,
		Severity:  severity,
		Metadata: map[string]any{
			"sm_agent_id":     event.AgentID,
			"sm_guardrail_id": event.GuardrailID,
			"sm_event_type":   event.EventType,
			"sm_triggered":    event.Triggered,
			"sm_action_taken": event.ActionTaken,
			"sm_context":      event.Context,
			"source":          "synthmind",
		},
		Source:    "synthmind",
		CreatedAt: time.Now().UTC(),
	}
}

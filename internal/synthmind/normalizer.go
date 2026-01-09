package synthmind

import (
	"boundary-siem/internal/schema"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// NormalizerConfig holds configuration for the normalizer.
type NormalizerConfig struct {
	SourceProduct string
	SourceHost    string
	TenantID      string
}

// Normalizer converts Synth Mind events to canonical SIEM events.
type Normalizer struct {
	sourceProduct   string
	sourceHost      string
	defaultTenantID string
}

// NewNormalizer creates a new Synth Mind normalizer.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	product := cfg.SourceProduct
	if product == "" {
		product = "synthmind"
	}
	return &Normalizer{
		sourceProduct:   product,
		sourceHost:      cfg.SourceHost,
		defaultTenantID: cfg.TenantID,
	}
}

// outcomeFromBool converts a success boolean to schema.Outcome.
func outcomeFromBool(success bool) schema.Outcome {
	if success {
		return schema.OutcomeSuccess
	}
	return schema.OutcomeFailure
}

// NormalizeEmotionalState converts an emotional state to a canonical event.
func (n *Normalizer) NormalizeEmotionalState(state *EmotionalState) (*schema.Event, error) {
	if state == nil {
		return nil, fmt.Errorf("emotional state is nil")
	}

	outcome := schema.OutcomeSuccess
	if state.Anomaly {
		outcome = schema.OutcomeUnknown
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

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     state.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: state.ID,
		},
		Action:   "sm.emotional.state",
		Target:   fmt.Sprintf("agent:%s", state.AgentID),
		Outcome:  outcome,
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   state.AgentID,
			Name: "synthmind-agent",
		},
		Metadata: map[string]any{
			"sm_agent_id":    state.AgentID,
			"sm_valence":     state.Valence,
			"sm_arousal":     state.Arousal,
			"sm_dominance":   state.Dominance,
			"sm_uncertainty": state.Uncertainty,
			"sm_flow_state":  state.FlowState,
			"sm_anomaly":     state.Anomaly,
		},
	}, nil
}

// NormalizeModuleEvent converts a module event to a canonical event.
func (n *Normalizer) NormalizeModuleEvent(event *ModuleEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("module event is nil")
	}

	severity := 3
	if !event.Success {
		severity = 5
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     event.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: event.ID,
		},
		Action:   fmt.Sprintf("sm.module.%s", event.EventType),
		Target:   fmt.Sprintf("module:%s", event.Module),
		Outcome:  outcomeFromBool(event.Success),
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   event.AgentID,
			Name: "synthmind-agent",
		},
		Metadata: map[string]any{
			"sm_agent_id":    event.AgentID,
			"sm_module":      event.Module,
			"sm_event_type":  event.EventType,
			"sm_description": event.Description,
			"sm_success":     event.Success,
			"sm_metadata":    event.Metadata,
		},
	}, nil
}

// NormalizeDreamingEvent converts a dreaming event to a canonical event.
func (n *Normalizer) NormalizeDreamingEvent(event *DreamingEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("dreaming event is nil")
	}

	outcome := schema.OutcomeSuccess
	severity := 3

	if event.ValidationGap > 0.7 {
		outcome = schema.OutcomeUnknown
		severity = 5
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     event.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: event.ID,
		},
		Action:   "sm.dreaming.prediction",
		Target:   fmt.Sprintf("prediction:%s", event.PredictionID),
		Outcome:  outcome,
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   event.AgentID,
			Name: "synthmind-agent",
		},
		Metadata: map[string]any{
			"sm_agent_id":       event.AgentID,
			"sm_prediction_id":  event.PredictionID,
			"sm_confidence":     event.Confidence,
			"sm_validated":      event.Validated,
			"sm_validation_gap": event.ValidationGap,
		},
	}, nil
}

// NormalizeReflectionEvent converts a reflection event to a canonical event.
func (n *Normalizer) NormalizeReflectionEvent(event *ReflectionEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("reflection event is nil")
	}

	severity := 3
	if event.Severity == "moderate" {
		severity = 5
	} else if event.Severity == "significant" {
		severity = 7
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     event.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: event.ID,
		},
		Action:   fmt.Sprintf("sm.reflection.%s", event.ReflectionType),
		Target:   fmt.Sprintf("agent:%s", event.AgentID),
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   event.AgentID,
			Name: "synthmind-agent",
		},
		Metadata: map[string]any{
			"sm_agent_id":        event.AgentID,
			"sm_reflection_type": event.ReflectionType,
			"sm_insight":         event.Insight,
			"sm_action_taken":    event.ActionTaken,
			"sm_severity":        event.Severity,
		},
	}, nil
}

// NormalizeSocialEvent converts a social event to a canonical event.
func (n *Normalizer) NormalizeSocialEvent(event *SocialEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("social event is nil")
	}

	severity := 3
	if !event.Success {
		severity = 5
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     event.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: event.ID,
		},
		Action:   fmt.Sprintf("sm.social.%s", event.EventType),
		Target:   fmt.Sprintf("peer:%s", event.PeerID),
		Outcome:  outcomeFromBool(event.Success),
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   event.AgentID,
			Name: "synthmind-agent",
		},
		Metadata: map[string]any{
			"sm_agent_id":     event.AgentID,
			"sm_peer_id":      event.PeerID,
			"sm_event_type":   event.EventType,
			"sm_success":      event.Success,
			"sm_message_hash": event.MessageHash,
		},
	}, nil
}

// NormalizeToolUsageEvent converts a tool usage event to a canonical event.
func (n *Normalizer) NormalizeToolUsageEvent(event *ToolUsageEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("tool usage event is nil")
	}

	outcome := schema.OutcomeSuccess
	if !event.Success {
		outcome = schema.OutcomeFailure
	} else if event.Sandboxed {
		outcome = schema.OutcomeUnknown
	}

	severity := 3
	if !event.Success {
		severity = 5
	}
	if event.Sandboxed {
		severity = 4
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     event.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: event.ID,
		},
		Action:   fmt.Sprintf("sm.tool.%s", event.Operation),
		Target:   fmt.Sprintf("tool:%s", event.ToolName),
		Outcome:  outcome,
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   event.AgentID,
			Name: "synthmind-agent",
		},
		Metadata: map[string]any{
			"sm_agent_id":    event.AgentID,
			"sm_tool_name":   event.ToolName,
			"sm_operation":   event.Operation,
			"sm_success":     event.Success,
			"sm_sandboxed":   event.Sandboxed,
			"sm_duration_ms": event.Duration.Milliseconds(),
			"sm_metadata":    event.Metadata,
		},
	}, nil
}

// NormalizeSafetyEvent converts a safety event to a canonical event.
func (n *Normalizer) NormalizeSafetyEvent(event *SafetyEvent) (*schema.Event, error) {
	if event == nil {
		return nil, fmt.Errorf("safety event is nil")
	}

	outcome := schema.OutcomeSuccess
	if event.Triggered {
		outcome = schema.OutcomeUnknown
	}

	severity := 4
	if event.Triggered {
		severity = 8
	}

	return &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     event.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,
		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: event.ID,
		},
		Action:   fmt.Sprintf("sm.safety.%s", event.EventType),
		Target:   fmt.Sprintf("rule:%s", event.Rule),
		Outcome:  outcome,
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   event.AgentID,
			Name: "synthmind-agent",
		},
		Metadata: map[string]any{
			"sm_agent_id":    event.AgentID,
			"sm_event_type":  event.EventType,
			"sm_triggered":   event.Triggered,
			"sm_rule":        event.Rule,
			"sm_description": event.Description,
			"sm_metadata":    event.Metadata,
		},
	}, nil
}

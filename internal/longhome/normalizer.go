package longhome

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/schema"
)

// ActionMappings maps Long-Home event types to canonical action names.
var ActionMappings = map[string]string{
	// Session events
	"session.started":  "lh.session.started",
	"session.ended":    "lh.session.ended",
	"session.descent":  "lh.session.descent",
	"session.planning": "lh.session.planning",

	// State transitions
	"state.game_state":     "lh.state.game",
	"state.movement_state": "lh.state.movement",
	"state.slide_state":    "lh.state.slide",

	// Fatal events
	"fatal.fall":               "lh.fatal.fall",
	"fatal.hypothermia":        "lh.fatal.hypothermia",
	"fatal.exhaustion":         "lh.fatal.exhaustion",
	"fatal.slide_uncontrolled": "lh.fatal.slide",

	// Slide events
	"slide.start":        "lh.slide.start",
	"slide.control_lost": "lh.slide.control_lost",
	"slide.end":          "lh.slide.end",

	// Rope events
	"rope.deploy":     "lh.rope.deploy",
	"rope.rappel":     "lh.rope.rappel",
	"rope.anchor_set": "lh.rope.anchor",
	"rope.break":      "lh.rope.break",

	// Body condition events
	"body.critical":  "lh.body.critical",
	"body.injured":   "lh.body.injured",
	"body.exhausted": "lh.body.exhausted",

	// Input events
	"input.valid":   "lh.input.valid",
	"input.invalid": "lh.input.invalid",
	"input.risky":   "lh.input.risky",

	// Save events
	"save.created":   "lh.save.created",
	"save.loaded":    "lh.save.loaded",
	"save.modified":  "lh.save.modified",
	"save.corrupted": "lh.save.corrupted",

	// Physics anomalies
	"physics.velocity_violation":  "lh.physics.velocity_violation",
	"physics.terrain_clip":        "lh.physics.terrain_clip",
	"physics.impossible_position": "lh.physics.impossible_position",

	// Signal events
	"signal.unusual": "lh.signal.unusual",
}

// Normalizer converts Long-Home events to canonical SIEM schema.
type Normalizer struct {
	defaultTenantID string
	sourceProduct   string
	sourceHost      string
	sourceVersion   string
}

// NormalizerConfig holds configuration for the normalizer.
type NormalizerConfig struct {
	DefaultTenantID string
	SourceHost      string
	SourceVersion   string
}

// DefaultNormalizerConfig returns the default normalizer configuration.
func DefaultNormalizerConfig() NormalizerConfig {
	return NormalizerConfig{
		DefaultTenantID: "default",
		SourceHost:      "localhost",
		SourceVersion:   "1.0.0",
	}
}

// NewNormalizer creates a new Long-Home normalizer.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	return &Normalizer{
		defaultTenantID: cfg.DefaultTenantID,
		sourceProduct:   "long-home",
		sourceHost:      cfg.SourceHost,
		sourceVersion:   cfg.SourceVersion,
	}
}

// NormalizeSession converts a session to a canonical event.
func (n *Normalizer) NormalizeSession(session *GameSession, eventType string) (*schema.Event, error) {
	action := n.mapAction(eventType)

	timestamp := session.StartedAt
	if session.EndedAt != nil {
		timestamp = *session.EndedAt
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: session.ID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", session.ID),
		Outcome:  schema.OutcomeSuccess,
		Severity: 2,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   session.PlayerID,
			Name: session.PlayerID,
		},

		Metadata: map[string]any{
			"lh_session_id":  session.ID,
			"lh_player_id":   session.PlayerID,
			"lh_game_state":  session.GameState,
			"lh_mountain_id": session.MountainID,
			"lh_difficulty":  session.Difficulty,
		},
	}

	return event, nil
}

// NormalizeStateTransition converts a state transition to a canonical event.
func (n *Normalizer) NormalizeStateTransition(trans *StateTransition) (*schema.Event, error) {
	eventType := "state." + trans.StateType
	action := n.mapAction(eventType)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     trans.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: trans.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", trans.SessionID),
		Outcome:  schema.OutcomeSuccess,
		Severity: 2,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   trans.PlayerID,
			Name: trans.PlayerID,
		},

		Metadata: map[string]any{
			"lh_transition_id": trans.ID,
			"lh_session_id":    trans.SessionID,
			"lh_state_type":    trans.StateType,
			"lh_from_state":    trans.FromState,
			"lh_to_state":      trans.ToState,
			"lh_trigger":       trans.Trigger,
		},
	}

	return event, nil
}

// NormalizeFatal converts a fatal event to a canonical event.
func (n *Normalizer) NormalizeFatal(fatal *FatalEvent) (*schema.Event, error) {
	eventType := "fatal." + fatal.Cause
	action := n.mapAction(eventType)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     fatal.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: fatal.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", fatal.SessionID),
		Outcome:  schema.OutcomeFailure,
		Severity: 4,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   fatal.PlayerID,
			Name: fatal.PlayerID,
		},

		Metadata: map[string]any{
			"lh_fatal_id":   fatal.ID,
			"lh_session_id": fatal.SessionID,
			"lh_player_id":  fatal.PlayerID,
			"lh_phase":      fatal.Phase,
			"lh_cause":      fatal.Cause,
			"lh_altitude":   fatal.Altitude,
			"lh_duration":   fatal.Duration,
			"lh_has_replay": fatal.ReplayData != "",
		},
	}

	return event, nil
}

// NormalizeSlide converts a slide event to a canonical event.
func (n *Normalizer) NormalizeSlide(slide *SlideEvent) (*schema.Event, error) {
	eventType := "slide." + slide.EventType
	action := n.mapAction(eventType)

	severity := 2
	outcome := schema.OutcomeSuccess
	if slide.ControlLevel == "lost" || slide.ControlLevel == "tumbling" {
		severity = 5
		outcome = schema.OutcomeFailure
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     slide.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: slide.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", slide.SessionID),
		Outcome:  outcome,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   slide.PlayerID,
			Name: slide.PlayerID,
		},

		Metadata: map[string]any{
			"lh_slide_id":      slide.ID,
			"lh_session_id":    slide.SessionID,
			"lh_event_type":    slide.EventType,
			"lh_control_level": slide.ControlLevel,
			"lh_velocity":      slide.Velocity,
			"lh_terrain":       slide.TerrainType,
		},
	}

	return event, nil
}

// NormalizeRope converts a rope event to a canonical event.
func (n *Normalizer) NormalizeRope(rope *RopeEvent) (*schema.Event, error) {
	eventType := "rope." + rope.EventType
	action := n.mapAction(eventType)

	severity := 3
	outcome := schema.OutcomeSuccess
	if rope.EventType == "rope_break" {
		severity = 7
		outcome = schema.OutcomeFailure
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     rope.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: rope.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", rope.SessionID),
		Outcome:  outcome,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   rope.PlayerID,
			Name: rope.PlayerID,
		},

		Metadata: map[string]any{
			"lh_rope_id":        rope.ID,
			"lh_session_id":     rope.SessionID,
			"lh_event_type":     rope.EventType,
			"lh_rope_length":    rope.RopeLength,
			"lh_anchor_quality": rope.AnchorQuality,
			"lh_stress":         rope.Stress,
		},
	}

	return event, nil
}

// NormalizeBodyCondition converts a body condition to a canonical event.
func (n *Normalizer) NormalizeBodyCondition(body *BodyCondition) (*schema.Event, error) {
	eventType := "body.critical"
	if !body.Critical {
		if len(body.Injuries) > 0 {
			eventType = "body.injured"
		} else if body.Fatigue > 0.8 {
			eventType = "body.exhausted"
		}
	}
	action := n.mapAction(eventType)

	severity := 3
	if body.Critical {
		severity = 6
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     body.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: body.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", body.SessionID),
		Outcome:  schema.OutcomeUnknown,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   body.PlayerID,
			Name: body.PlayerID,
		},

		Metadata: map[string]any{
			"lh_body_id":       body.ID,
			"lh_session_id":    body.SessionID,
			"lh_fatigue":       body.Fatigue,
			"lh_cold_exposure": body.ColdExposure,
			"lh_injuries":      body.Injuries,
			"lh_hydration":     body.Hydration,
			"lh_altitude":      body.Altitude,
			"lh_heart_rate":    body.HeartRate,
			"lh_critical":      body.Critical,
		},
	}

	return event, nil
}

// NormalizeInput converts an input validation to a canonical event.
func (n *Normalizer) NormalizeInput(input *InputValidation) (*schema.Event, error) {
	eventType := "input.valid"
	if !input.InputValid {
		eventType = "input.invalid"
	} else if input.RiskLevel == "high" || input.RiskLevel == "critical" {
		eventType = "input.risky"
	}
	action := n.mapAction(eventType)

	severity := 2
	outcome := schema.OutcomeSuccess
	if !input.InputValid {
		severity = 5
		outcome = schema.OutcomeFailure
	} else if input.RiskLevel == "critical" {
		severity = 6
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     input.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: input.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", input.SessionID),
		Outcome:  outcome,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   input.PlayerID,
			Name: input.PlayerID,
		},

		Metadata: map[string]any{
			"lh_input_id":    input.ID,
			"lh_session_id":  input.SessionID,
			"lh_action_type": input.ActionType,
			"lh_input_valid": input.InputValid,
			"lh_risk_level":  input.RiskLevel,
			"lh_anomalies":   input.Anomalies,
		},
	}

	return event, nil
}

// NormalizeSave converts a save event to a canonical event.
func (n *Normalizer) NormalizeSave(save *SaveEvent) (*schema.Event, error) {
	eventType := "save." + save.EventType
	if save.Modified {
		eventType = "save.modified"
	}
	if !save.Valid {
		eventType = "save.corrupted"
	}
	action := n.mapAction(eventType)

	severity := 2
	outcome := schema.OutcomeSuccess
	if !save.Valid {
		severity = 6
		outcome = schema.OutcomeFailure
	} else if save.Modified {
		severity = 7
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     save.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: save.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", save.SessionID),
		Outcome:  outcome,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   save.PlayerID,
			Name: save.PlayerID,
		},

		Metadata: map[string]any{
			"lh_save_id":    save.ID,
			"lh_session_id": save.SessionID,
			"lh_event_type": save.EventType,
			"lh_data_hash":  save.DataHash,
			"lh_data_size":  save.DataSize,
			"lh_valid":      save.Valid,
			"lh_modified":   save.Modified,
			"lh_error":      save.ErrorMessage,
		},
	}

	return event, nil
}

// NormalizePhysicsAnomaly converts a physics anomaly to a canonical event.
func (n *Normalizer) NormalizePhysicsAnomaly(anomaly *PhysicsAnomaly) (*schema.Event, error) {
	eventType := "physics." + anomaly.AnomalyType
	action := n.mapAction(eventType)
	severity := n.mapSeverity(anomaly.Severity)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     anomaly.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: anomaly.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", anomaly.SessionID),
		Outcome:  schema.OutcomeFailure,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   anomaly.PlayerID,
			Name: anomaly.PlayerID,
		},

		Metadata: map[string]any{
			"lh_anomaly_id":   anomaly.ID,
			"lh_session_id":   anomaly.SessionID,
			"lh_anomaly_type": anomaly.AnomalyType,
			"lh_expected":     anomaly.Expected,
			"lh_actual":       anomaly.Actual,
			"lh_severity":     anomaly.Severity,
		},
	}

	return event, nil
}

// NormalizeSignal converts an event bus signal to a canonical event.
func (n *Normalizer) NormalizeSignal(signal *EventBusSignal) (*schema.Event, error) {
	action := n.mapAction("signal.unusual")

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     signal.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: signal.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", signal.SessionID),
		Outcome:  schema.OutcomeUnknown,
		Severity: 4,

		Metadata: map[string]any{
			"lh_signal_id":    signal.ID,
			"lh_session_id":   signal.SessionID,
			"lh_signal_name":  signal.SignalName,
			"lh_emitter_type": signal.EmitterType,
			"lh_unusual":      signal.Unusual,
			"lh_parameters":   signal.Parameters,
		},
	}

	return event, nil
}

// mapAction maps an event type to a canonical action.
func (n *Normalizer) mapAction(eventType string) string {
	if action, ok := ActionMappings[eventType]; ok {
		return action
	}
	return "lh.event." + eventType
}

// mapSeverity maps severity string to numeric.
func (n *Normalizer) mapSeverity(severity string) int {
	switch severity {
	case "critical":
		return 9
	case "high":
		return 7
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 4
	}
}

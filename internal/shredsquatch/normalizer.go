package shredsquatch

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/schema"
)

// ActionMappings maps Shredsquatch event types to canonical action names.
var ActionMappings = map[string]string{
	// Session events
	"session.started":   "ss.session.started",
	"session.completed": "ss.session.completed",
	"session.crashed":   "ss.session.crashed",
	"session.abandoned": "ss.session.abandoned",

	// Run events
	"run.start":               "ss.run.start",
	"run.end":                 "ss.run.end",
	"run.caught_by_sasquatch": "ss.run.caught",
	"run.crash":               "ss.run.crash",

	// Trick events
	"trick.spin":       "ss.trick.spin",
	"trick.grab":       "ss.trick.grab",
	"trick.flip":       "ss.trick.flip",
	"trick.combo":      "ss.trick.combo",
	"trick.rail_grind": "ss.trick.rail_grind",
	"trick.landed":     "ss.trick.landed",
	"trick.failed":     "ss.trick.failed",

	// Input anomalies
	"anomaly.rapid_input":      "ss.anomaly.rapid_input",
	"anomaly.impossible_trick": "ss.anomaly.impossible_trick",
	"anomaly.timing_exploit":   "ss.anomaly.timing_exploit",

	// Leaderboard events
	"leaderboard.submitted":  "ss.leaderboard.submitted",
	"leaderboard.verified":   "ss.leaderboard.verified",
	"leaderboard.suspicious": "ss.leaderboard.suspicious",

	// Performance events
	"performance.metric":         "ss.performance.metric",
	"performance.frame_drop":     "ss.performance.frame_drop",
	"performance.memory_spike":   "ss.performance.memory_spike",
	"performance.shader_compile": "ss.performance.shader_compile",

	// Asset events
	"asset.load_complete": "ss.asset.loaded",
	"asset.load_failed":   "ss.asset.failed",

	// Powerup events
	"powerup.collected": "ss.powerup.collected",

	// Sasquatch events
	"sasquatch.spawn":       "ss.sasquatch.spawn",
	"sasquatch.chase_start": "ss.sasquatch.chase",
	"sasquatch.caught":      "ss.sasquatch.caught",
	"sasquatch.escaped":     "ss.sasquatch.escaped",

	// Collision events
	"collision.tree":      "ss.collision.tree",
	"collision.rock":      "ss.collision.rock",
	"collision.rail":      "ss.collision.rail",
	"collision.sasquatch": "ss.collision.sasquatch",
}

// Normalizer converts Shredsquatch events to canonical SIEM schema.
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

// NewNormalizer creates a new Shredsquatch normalizer.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	return &Normalizer{
		defaultTenantID: cfg.DefaultTenantID,
		sourceProduct:   "shredsquatch",
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
			Version:    session.GameVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", session.ID),
		Outcome:  n.determineSessionOutcome(session),
		Severity: 2,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   session.PlayerID,
			Name: session.PlayerID,
		},

		Metadata: map[string]any{
			"ss_session_id":     session.ID,
			"ss_player_id":      session.PlayerID,
			"ss_platform":       session.Platform,
			"ss_game_version":   session.GameVersion,
			"ss_terrain_seed":   session.Seed,
			"ss_session_status": session.Status,
		},
	}

	return event, nil
}

// NormalizeRun converts a run event to a canonical event.
func (n *Normalizer) NormalizeRun(run *RunEvent) (*schema.Event, error) {
	eventType := "run." + run.EventType
	action := n.mapAction(eventType)

	outcome := schema.OutcomeSuccess
	if run.EventType == "crash" || run.EventType == "caught_by_sasquatch" {
		outcome = schema.OutcomeFailure
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     run.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: run.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", run.SessionID),
		Outcome:  outcome,
		Severity: 3,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   run.PlayerID,
			Name: run.PlayerID,
		},

		Metadata: map[string]any{
			"ss_run_id":      run.ID,
			"ss_session_id":  run.SessionID,
			"ss_event_type":  run.EventType,
			"ss_distance":    run.Distance,
			"ss_score":       run.Score,
			"ss_trick_score": run.TrickScore,
			"ss_duration":    run.Duration,
			"ss_max_speed":   run.MaxSpeed,
		},
	}

	return event, nil
}

// NormalizeTrick converts a trick event to a canonical event.
func (n *Normalizer) NormalizeTrick(trick *TrickEvent) (*schema.Event, error) {
	eventType := "trick." + trick.TrickType
	if !trick.Landed {
		eventType = "trick.failed"
	}
	action := n.mapAction(eventType)

	outcome := schema.OutcomeSuccess
	if !trick.Landed {
		outcome = schema.OutcomeFailure
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     trick.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: trick.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", trick.SessionID),
		Outcome:  outcome,
		Severity: 2,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   trick.PlayerID,
			Name: trick.PlayerID,
		},

		Metadata: map[string]any{
			"ss_trick_id":     trick.ID,
			"ss_session_id":   trick.SessionID,
			"ss_trick_type":   trick.TrickType,
			"ss_trick_name":   trick.TrickName,
			"ss_points":       trick.Points,
			"ss_multiplier":   trick.Multiplier,
			"ss_combo_length": trick.ComboLength,
			"ss_landed":       trick.Landed,
			"ss_air_time":     trick.AirTime,
		},
	}

	return event, nil
}

// NormalizeInputAnomaly converts an input anomaly to a canonical event.
func (n *Normalizer) NormalizeInputAnomaly(anomaly *InputAnomaly) (*schema.Event, error) {
	eventType := "anomaly." + anomaly.AnomalyType
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
			"ss_anomaly_id":    anomaly.ID,
			"ss_session_id":    anomaly.SessionID,
			"ss_anomaly_type":  anomaly.AnomalyType,
			"ss_severity":      anomaly.Severity,
			"ss_confidence":    anomaly.Confidence,
			"ss_input_pattern": anomaly.InputPattern,
		},

		Raw: anomaly.InputPattern,
	}

	return event, nil
}

// NormalizeLeaderboard converts a leaderboard submission to a canonical event.
func (n *Normalizer) NormalizeLeaderboard(lb *LeaderboardSubmission) (*schema.Event, error) {
	eventType := "leaderboard.submitted"
	if lb.Verified {
		eventType = "leaderboard.verified"
	}
	for _, flag := range lb.Flags {
		if flag == "suspicious_score" {
			eventType = "leaderboard.suspicious"
			break
		}
	}
	action := n.mapAction(eventType)

	severity := 2
	if eventType == "leaderboard.suspicious" {
		severity = 7
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     lb.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: lb.LeaderboardID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("leaderboard:%s", lb.LeaderboardID),
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   lb.PlayerID,
			Name: lb.PlayerID,
		},

		Metadata: map[string]any{
			"ss_submission_id":  lb.ID,
			"ss_player_id":      lb.PlayerID,
			"ss_run_id":         lb.RunID,
			"ss_leaderboard_id": lb.LeaderboardID,
			"ss_distance":       lb.Distance,
			"ss_score":          lb.Score,
			"ss_trick_score":    lb.TrickScore,
			"ss_verified":       lb.Verified,
			"ss_rank":           lb.Rank,
			"ss_flags":          lb.Flags,
		},
	}

	return event, nil
}

// NormalizePerformance converts a performance metric to a canonical event.
func (n *Normalizer) NormalizePerformance(perf *PerformanceMetric) (*schema.Event, error) {
	eventType := "performance.metric"
	if len(perf.Anomalies) > 0 {
		eventType = "performance." + perf.Anomalies[0]
	}
	action := n.mapAction(eventType)

	severity := 2
	if len(perf.Anomalies) > 0 {
		severity = 4
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     perf.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: perf.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", perf.SessionID),
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,

		Metadata: map[string]any{
			"ss_metric_id":      perf.ID,
			"ss_session_id":     perf.SessionID,
			"ss_frame_rate":     perf.FrameRate,
			"ss_memory_usage":   perf.MemoryUsage,
			"ss_draw_calls":     perf.DrawCalls,
			"ss_terrain_chunks": perf.TerrainChunks,
			"ss_shader_compile": perf.ShaderCompile,
			"ss_anomalies":      perf.Anomalies,
		},
	}

	return event, nil
}

// NormalizeAsset converts an asset event to a canonical event.
func (n *Normalizer) NormalizeAsset(asset *AssetEvent) (*schema.Event, error) {
	eventType := "asset." + asset.EventType
	action := n.mapAction(eventType)

	outcome := schema.OutcomeSuccess
	severity := 2
	if !asset.Success {
		outcome = schema.OutcomeFailure
		severity = 5
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     asset.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: asset.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("asset:%s", asset.AssetName),
		Outcome:  outcome,
		Severity: severity,

		Metadata: map[string]any{
			"ss_asset_id":   asset.ID,
			"ss_session_id": asset.SessionID,
			"ss_event_type": asset.EventType,
			"ss_asset_type": asset.AssetType,
			"ss_asset_name": asset.AssetName,
			"ss_load_time":  asset.LoadTime,
			"ss_success":    asset.Success,
			"ss_error":      asset.ErrorMessage,
		},
	}

	return event, nil
}

// NormalizePowerup converts a powerup event to a canonical event.
func (n *Normalizer) NormalizePowerup(powerup *PowerupEvent) (*schema.Event, error) {
	action := n.mapAction("powerup.collected")

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     powerup.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: powerup.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("powerup:%s", powerup.PowerupType),
		Outcome:  schema.OutcomeSuccess,
		Severity: 2,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   powerup.PlayerID,
			Name: powerup.PlayerID,
		},

		Metadata: map[string]any{
			"ss_powerup_id":   powerup.ID,
			"ss_session_id":   powerup.SessionID,
			"ss_powerup_type": powerup.PowerupType,
			"ss_effect":       powerup.Effect,
			"ss_duration":     powerup.Duration,
			"ss_location":     powerup.Location,
		},
	}

	return event, nil
}

// NormalizeSasquatch converts a Sasquatch event to a canonical event.
func (n *Normalizer) NormalizeSasquatch(sq *SasquatchEvent) (*schema.Event, error) {
	eventType := "sasquatch." + sq.EventType
	action := n.mapAction(eventType)

	outcome := schema.OutcomeUnknown
	severity := 3
	if sq.EventType == "caught" {
		outcome = schema.OutcomeFailure
		severity = 4
	} else if sq.EventType == "escaped" {
		outcome = schema.OutcomeSuccess
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     sq.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: sq.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", sq.SessionID),
		Outcome:  outcome,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   sq.PlayerID,
			Name: sq.PlayerID,
		},

		Metadata: map[string]any{
			"ss_sasquatch_id": sq.ID,
			"ss_session_id":   sq.SessionID,
			"ss_event_type":   sq.EventType,
			"ss_distance":     sq.Distance,
			"ss_chase_time":   sq.ChaseTime,
		},
	}

	return event, nil
}

// NormalizeCollision converts a collision event to a canonical event.
func (n *Normalizer) NormalizeCollision(col *CollisionEvent) (*schema.Event, error) {
	eventType := "collision." + col.CollisionType
	action := n.mapAction(eventType)

	severity := 3
	if col.Ragdoll {
		severity = 4
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     col.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: col.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", col.SessionID),
		Outcome:  schema.OutcomeFailure,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   col.PlayerID,
			Name: col.PlayerID,
		},

		Metadata: map[string]any{
			"ss_collision_id":   col.ID,
			"ss_session_id":     col.SessionID,
			"ss_collision_type": col.CollisionType,
			"ss_impact_force":   col.Impact,
			"ss_ragdoll":        col.Ragdoll,
			"ss_damage":         col.Damage,
		},
	}

	return event, nil
}

// mapAction maps an event type to a canonical action.
func (n *Normalizer) mapAction(eventType string) string {
	if action, ok := ActionMappings[eventType]; ok {
		return action
	}
	return "ss.event." + eventType
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

// determineSessionOutcome determines outcome for session events.
func (n *Normalizer) determineSessionOutcome(session *GameSession) schema.Outcome {
	switch session.Status {
	case "completed":
		return schema.OutcomeSuccess
	case "crashed", "abandoned":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

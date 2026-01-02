package midnightpulse

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"boundary-siem/internal/schema"
)

// ActionMappings maps Midnight Pulse event types to canonical action names.
var ActionMappings = map[string]string{
	// Session events
	"session.started":      "mp.session.started",
	"session.completed":    "mp.session.completed",
	"session.crashed":      "mp.session.crashed",
	"session.disconnected": "mp.session.disconnected",

	// Crash events
	"crash.traffic":   "mp.crash.traffic",
	"crash.hazard":    "mp.crash.hazard",
	"crash.obstacle":  "mp.crash.obstacle",
	"crash.guardrail": "mp.crash.guardrail",

	// Multiplayer events
	"multiplayer.ghost_race_start":    "mp.multiplayer.ghost_race_start",
	"multiplayer.ghost_race_complete": "mp.multiplayer.ghost_race_complete",
	"multiplayer.spectator_join":      "mp.multiplayer.spectator_join",
	"multiplayer.spectator_leave":     "mp.multiplayer.spectator_leave",

	// Input anomalies
	"anomaly.rapid_input":        "mp.anomaly.rapid_input",
	"anomaly.impossible_sequence": "mp.anomaly.impossible_sequence",
	"anomaly.macro_detected":     "mp.anomaly.macro_detected",
	"anomaly.timing_anomaly":     "mp.anomaly.timing_anomaly",

	// Save/Load events
	"saveload.save":       "mp.saveload.save",
	"saveload.load":       "mp.saveload.load",
	"saveload.auto_save":  "mp.saveload.auto_save",
	"saveload.cloud_sync": "mp.saveload.cloud_sync",
	"saveload.corrupted":  "mp.saveload.corrupted",

	// Performance events
	"performance.frame_drop":     "mp.performance.frame_drop",
	"performance.memory_spike":   "mp.performance.memory_spike",
	"performance.shader_compile": "mp.performance.shader_compile",
	"performance.metric":         "mp.performance.metric",

	// Leaderboard events
	"leaderboard.submitted":  "mp.leaderboard.submitted",
	"leaderboard.verified":   "mp.leaderboard.verified",
	"leaderboard.suspicious": "mp.leaderboard.suspicious",

	// Difficulty events
	"difficulty.adjusted": "mp.difficulty.adjusted",
}

// Normalizer converts Midnight Pulse events to canonical SIEM schema.
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

// NewNormalizer creates a new Midnight Pulse normalizer.
func NewNormalizer(cfg NormalizerConfig) *Normalizer {
	return &Normalizer{
		defaultTenantID: cfg.DefaultTenantID,
		sourceProduct:   "midnight-pulse",
		sourceHost:      cfg.SourceHost,
		sourceVersion:   cfg.SourceVersion,
	}
}

// NormalizeSession converts a session event to a canonical event.
func (n *Normalizer) NormalizeSession(session *PlayerSession, eventType string) (*schema.Event, error) {
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
		Severity: n.calculateSessionSeverity(session),

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   session.PlayerID,
			Name: session.PlayerID,
		},

		Metadata: map[string]any{
			"mp_session_id":    session.ID,
			"mp_player_id":     session.PlayerID,
			"mp_platform":      session.Platform,
			"mp_game_version":  session.GameVersion,
			"mp_duration":      session.Duration,
			"mp_session_status": session.Status,
		},
	}

	return event, nil
}

// NormalizeCrash converts a crash event to a canonical event.
func (n *Normalizer) NormalizeCrash(crash *CrashEvent) (*schema.Event, error) {
	eventType := "crash." + crash.CrashType
	action := n.mapAction(eventType)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     crash.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: crash.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", crash.SessionID),
		Outcome:  schema.OutcomeFailure,
		Severity: 3,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   crash.PlayerID,
			Name: crash.PlayerID,
		},

		Metadata: map[string]any{
			"mp_crash_id":       crash.ID,
			"mp_session_id":     crash.SessionID,
			"mp_player_id":      crash.PlayerID,
			"mp_distance":       crash.Distance,
			"mp_final_score":    crash.FinalScore,
			"mp_speed_at_crash": crash.Speed,
			"mp_crash_type":     crash.CrashType,
			"mp_cause_object":   crash.CauseObject,
		},
	}

	return event, nil
}

// NormalizeMultiplayer converts a multiplayer event to a canonical event.
func (n *Normalizer) NormalizeMultiplayer(mp *MultiplayerEvent) (*schema.Event, error) {
	eventType := "multiplayer." + mp.EventType
	action := n.mapAction(eventType)

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     mp.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: mp.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", mp.SessionID),
		Outcome:  n.determineMultiplayerOutcome(mp),
		Severity: 2,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   mp.PlayerID,
			Name: mp.PlayerID,
		},

		Metadata: map[string]any{
			"mp_event_id":     mp.ID,
			"mp_session_id":   mp.SessionID,
			"mp_player_id":    mp.PlayerID,
			"mp_event_type":   mp.EventType,
			"mp_opponent_id":  mp.OpponentID,
			"mp_outcome":      mp.Outcome,
		},
	}

	return event, nil
}

// NormalizeInputAnomaly converts an input anomaly to a canonical event.
func (n *Normalizer) NormalizeInputAnomaly(anomaly *InputAnomaly) (*schema.Event, error) {
	eventType := "anomaly." + anomaly.AnomalyType
	action := n.mapAction(eventType)
	severity := n.mapAnomalySeverity(anomaly.Severity)

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
			"mp_anomaly_id":    anomaly.ID,
			"mp_session_id":    anomaly.SessionID,
			"mp_player_id":     anomaly.PlayerID,
			"mp_anomaly_type":  anomaly.AnomalyType,
			"mp_severity":      anomaly.Severity,
			"mp_confidence":    anomaly.Confidence,
			"mp_input_pattern": anomaly.InputPattern,
		},

		Raw: anomaly.InputPattern,
	}

	return event, nil
}

// NormalizeSaveLoad converts a save/load event to a canonical event.
func (n *Normalizer) NormalizeSaveLoad(sl *SaveLoadEvent) (*schema.Event, error) {
	eventType := "saveload." + sl.EventType
	if !sl.Valid {
		eventType = "saveload.corrupted"
	}
	action := n.mapAction(eventType)

	outcome := schema.OutcomeSuccess
	severity := 2
	if !sl.Valid {
		outcome = schema.OutcomeFailure
		severity = 6
	}

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     sl.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: sl.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", sl.SessionID),
		Outcome:  outcome,
		Severity: severity,

		Actor: &schema.Actor{
			Type: schema.ActorUser,
			ID:   sl.PlayerID,
			Name: sl.PlayerID,
		},

		Metadata: map[string]any{
			"mp_event_id":     sl.ID,
			"mp_session_id":   sl.SessionID,
			"mp_player_id":    sl.PlayerID,
			"mp_event_type":   sl.EventType,
			"mp_data_size":    sl.DataSize,
			"mp_checksum":     sl.Checksum,
			"mp_valid":        sl.Valid,
			"mp_error":        sl.ErrorMessage,
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
			"mp_metric_id":    perf.ID,
			"mp_session_id":   perf.SessionID,
			"mp_frame_rate":   perf.FrameRate,
			"mp_memory_usage": perf.MemoryUsage,
			"mp_cpu_usage":    perf.CPUUsage,
			"mp_gpu_usage":    perf.GPUUsage,
			"mp_draw_calls":   perf.DrawCalls,
			"mp_load_time":    perf.LoadTime,
			"mp_anomalies":    perf.Anomalies,
		},
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
			"mp_submission_id":  lb.ID,
			"mp_player_id":      lb.PlayerID,
			"mp_session_id":     lb.SessionID,
			"mp_leaderboard_id": lb.LeaderboardID,
			"mp_score":          lb.Score,
			"mp_distance":       lb.Distance,
			"mp_verified":       lb.Verified,
			"mp_rank":           lb.Rank,
			"mp_flags":          lb.Flags,
		},
	}

	return event, nil
}

// NormalizeDifficulty converts a difficulty event to a canonical event.
func (n *Normalizer) NormalizeDifficulty(diff *DifficultyEvent) (*schema.Event, error) {
	action := n.mapAction("difficulty.adjusted")

	event := &schema.Event{
		EventID:       uuid.New(),
		Timestamp:     diff.Timestamp,
		ReceivedAt:    time.Now().UTC(),
		SchemaVersion: schema.SchemaVersionCurrent,
		TenantID:      n.defaultTenantID,

		Source: schema.Source{
			Product:    n.sourceProduct,
			Host:       n.sourceHost,
			InstanceID: diff.SessionID,
			Version:    n.sourceVersion,
		},

		Action:   action,
		Target:   fmt.Sprintf("session:%s", diff.SessionID),
		Outcome:  schema.OutcomeSuccess,
		Severity: 2,

		Actor: &schema.Actor{
			Type: schema.ActorSystem,
			ID:   "difficulty-system",
			Name: "difficulty-system",
		},

		Metadata: map[string]any{
			"mp_event_id":    diff.ID,
			"mp_session_id":  diff.SessionID,
			"mp_player_id":   diff.PlayerID,
			"mp_event_type":  diff.EventType,
			"mp_old_value":   diff.OldValue,
			"mp_new_value":   diff.NewValue,
			"mp_reason":      diff.Reason,
		},
	}

	return event, nil
}

// mapAction maps an event type to a canonical action.
func (n *Normalizer) mapAction(eventType string) string {
	if action, ok := ActionMappings[eventType]; ok {
		return action
	}
	return "mp.event." + eventType
}

// mapAnomalySeverity maps severity string to numeric.
func (n *Normalizer) mapAnomalySeverity(severity string) int {
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

// calculateSessionSeverity determines severity for session events.
func (n *Normalizer) calculateSessionSeverity(session *PlayerSession) int {
	switch session.Status {
	case "disconnected":
		return 4
	case "crashed":
		return 3
	default:
		return 2
	}
}

// determineSessionOutcome determines outcome for session events.
func (n *Normalizer) determineSessionOutcome(session *PlayerSession) schema.Outcome {
	switch session.Status {
	case "completed":
		return schema.OutcomeSuccess
	case "crashed", "disconnected":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

// determineMultiplayerOutcome determines outcome for multiplayer events.
func (n *Normalizer) determineMultiplayerOutcome(mp *MultiplayerEvent) schema.Outcome {
	switch mp.Outcome {
	case "win":
		return schema.OutcomeSuccess
	case "loss", "abandoned":
		return schema.OutcomeFailure
	default:
		return schema.OutcomeUnknown
	}
}

package medicagent

import (
	"fmt"
	"time"

	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// ActionMappings maps Medic-Agent events to canonical actions.
var ActionMappings = map[string]string{
	// Kill notification events
	"kill.received":    "ma.kill.received",
	"kill.processed":   "ma.kill.processed",
	"kill.validated":   "ma.kill.validated",
	"kill.rejected":    "ma.kill.rejected",

	// Risk assessment events
	"assessment.started":   "ma.assessment.started",
	"assessment.completed": "ma.assessment.completed",
	"assessment.failed":    "ma.assessment.failed",
	"verdict.legitimate":   "ma.verdict.legitimate",
	"verdict.suspicious":   "ma.verdict.suspicious",
	"verdict.invalid":      "ma.verdict.invalid",

	// Resurrection events
	"resurrection.initiated":  "ma.resurrection.initiated",
	"resurrection.approved":   "ma.resurrection.approved",
	"resurrection.rejected":   "ma.resurrection.rejected",
	"resurrection.completed":  "ma.resurrection.completed",
	"resurrection.failed":     "ma.resurrection.failed",
	"resurrection.rolled_back": "ma.resurrection.rolled_back",

	// Approval workflow events
	"approval.requested":  "ma.approval.requested",
	"approval.approved":   "ma.approval.approved",
	"approval.rejected":   "ma.approval.rejected",
	"approval.escalated":  "ma.approval.escalated",
	"approval.timeout":    "ma.approval.timeout",

	// Anomaly events
	"anomaly.kill_pattern":        "ma.anomaly.kill_pattern",
	"anomaly.resurrection_abuse":  "ma.anomaly.resurrection_abuse",
	"anomaly.threshold_violation": "ma.anomaly.threshold_violation",
	"anomaly.detected":            "ma.anomaly.detected",

	// Threshold events
	"threshold.adjusted":  "ma.threshold.adjusted",
	"threshold.auto":      "ma.threshold.auto_adjusted",
	"threshold.manual":    "ma.threshold.manual_adjusted",
	"threshold.policy":    "ma.threshold.policy_adjusted",

	// Rollback events
	"rollback.initiated": "ma.rollback.initiated",
	"rollback.completed": "ma.rollback.completed",
	"rollback.failed":    "ma.rollback.failed",

	// Smith integration events
	"smith.connected":    "ma.smith.connected",
	"smith.disconnected": "ma.smith.disconnected",
	"smith.event_recv":   "ma.smith.event_received",
	"smith.event_sent":   "ma.smith.event_sent",
	"smith.error":        "ma.smith.error",
}

// Normalizer converts Medic-Agent events to the canonical schema.
type Normalizer struct {
	source string
}

// NewNormalizer creates a new Medic-Agent normalizer.
func NewNormalizer(source string) *Normalizer {
	if source == "" {
		source = "medic-agent"
	}
	return &Normalizer{source: source}
}

// NormalizeKillNotification normalizes a kill notification event.
func (n *Normalizer) NormalizeKillNotification(k *KillNotification) (*schema.Event, error) {
	action := ActionMappings["kill.received"]
	if k.Metadata != nil {
		if status, ok := k.Metadata["status"].(string); ok {
			if mapped, exists := ActionMappings["kill."+status]; exists {
				action = mapped
			}
		}
	}

	severity := n.mapSeverity(k.Severity)

	event := &schema.Event{
		EventID:   uuid.New().String(),
		Timestamp: k.Timestamp,
		Source:    n.source,
		Action:    action,
		Outcome:   "success",
		Severity:  severity,
		Actor: schema.Actor{
			ID:   k.SmithNodeID,
			Type: "smith_node",
		},
		Target: schema.Target{
			ID:   k.ProcessID,
			Type: "process",
			Name: k.ProcessName,
		},
		Metadata: map[string]interface{}{
			"ma_kill_id":       k.ID,
			"ma_kill_reason":   k.KillReason,
			"ma_smith_node_id": k.SmithNodeID,
			"ma_resource_usage": k.ResourceUsage,
		},
	}

	// Add original metadata
	for key, val := range k.Metadata {
		event.Metadata["ma_"+key] = val
	}

	return event, nil
}

// NormalizeRiskAssessment normalizes a risk assessment event.
func (n *Normalizer) NormalizeRiskAssessment(r *RiskAssessment) (*schema.Event, error) {
	action := ActionMappings["assessment.completed"]
	if mapped, exists := ActionMappings["verdict."+r.Verdict]; exists {
		action = mapped
	}

	severity := n.riskScoreToSeverity(r.RiskScore)

	event := &schema.Event{
		EventID:   uuid.New().String(),
		Timestamp: r.Timestamp,
		Source:    n.source,
		Action:    action,
		Outcome:   "success",
		Severity:  severity,
		Actor: schema.Actor{
			ID:   n.source,
			Type: "medic_agent",
		},
		Target: schema.Target{
			ID:   r.ProcessID,
			Type: "process",
		},
		Metadata: map[string]interface{}{
			"ma_assessment_id":      r.ID,
			"ma_kill_id":            r.KillID,
			"ma_risk_score":         r.RiskScore,
			"ma_verdict":            r.Verdict,
			"ma_recommended_action": r.RecommendedAction,
			"ma_risk_factors":       r.Factors,
		},
	}

	for key, val := range r.Metadata {
		event.Metadata["ma_"+key] = val
	}

	return event, nil
}

// NormalizeResurrection normalizes a resurrection event.
func (n *Normalizer) NormalizeResurrection(r *ResurrectionEvent) (*schema.Event, error) {
	action := ActionMappings["resurrection."+r.Status]
	if action == "" {
		action = "ma.resurrection." + r.Status
	}

	outcome := "success"
	severity := 5
	if r.Status == "failed" || r.Status == "rolled_back" {
		outcome = "failure"
		severity = 7
	} else if r.Status == "rejected" {
		outcome = "denied"
		severity = 6
	}

	event := &schema.Event{
		EventID:   uuid.New().String(),
		Timestamp: r.Timestamp,
		Source:    n.source,
		Action:    action,
		Outcome:   outcome,
		Severity:  severity,
		Actor: schema.Actor{
			ID:   n.source,
			Type: "medic_agent",
		},
		Target: schema.Target{
			ID:   r.ProcessID,
			Type: "process",
			Name: r.ProcessName,
		},
		Metadata: map[string]interface{}{
			"ma_resurrection_id":  r.ID,
			"ma_kill_id":          r.KillID,
			"ma_status":           r.Status,
			"ma_resurrection_ttl": r.ResurrectionTTL,
			"ma_attempts":         r.Attempts,
			"ma_approval_chain":   r.ApprovalChain,
		},
	}

	if r.ErrorMessage != "" {
		event.Metadata["ma_error_message"] = r.ErrorMessage
	}

	for key, val := range r.Metadata {
		event.Metadata["ma_"+key] = val
	}

	return event, nil
}

// NormalizeAnomaly normalizes an anomaly event.
func (n *Normalizer) NormalizeAnomaly(a *AnomalyEvent) (*schema.Event, error) {
	action := ActionMappings["anomaly."+a.Type]
	if action == "" {
		action = "ma.anomaly." + a.Type
	}

	severity := n.mapSeverity(a.Severity)

	event := &schema.Event{
		EventID:   uuid.New().String(),
		Timestamp: a.Timestamp,
		Source:    n.source,
		Action:    action,
		Outcome:   "success",
		Severity:  severity,
		Actor: schema.Actor{
			ID:   n.source,
			Type: "medic_agent",
		},
		Target: schema.Target{
			ID:   fmt.Sprintf("anomaly-%s", a.ID),
			Type: "anomaly",
		},
		Metadata: map[string]interface{}{
			"ma_anomaly_id":    a.ID,
			"ma_anomaly_type":  a.Type,
			"ma_description":   a.Description,
			"ma_affected_ids":  a.AffectedIDs,
			"ma_indicators":    a.Indicators,
			"ma_auto_response": a.AutoResponse,
		},
	}

	for key, val := range a.Metadata {
		event.Metadata["ma_"+key] = val
	}

	return event, nil
}

// NormalizeThresholdAdjustment normalizes a threshold adjustment event.
func (n *Normalizer) NormalizeThresholdAdjustment(t *ThresholdAdjustment) (*schema.Event, error) {
	action := ActionMappings["threshold."+t.Triggeredby]
	if action == "" {
		action = ActionMappings["threshold.adjusted"]
	}

	event := &schema.Event{
		EventID:   uuid.New().String(),
		Timestamp: t.Timestamp,
		Source:    n.source,
		Action:    action,
		Outcome:   "success",
		Severity:  4,
		Actor: schema.Actor{
			ID:   t.Triggeredby,
			Type: "threshold_trigger",
		},
		Target: schema.Target{
			ID:   t.ThresholdKey,
			Type: "threshold",
		},
		Metadata: map[string]interface{}{
			"ma_adjustment_id": t.ID,
			"ma_threshold_key": t.ThresholdKey,
			"ma_old_value":     t.OldValue,
			"ma_new_value":     t.NewValue,
			"ma_reason":        t.Reason,
			"ma_triggered_by":  t.Triggeredby,
			"ma_applied_to":    t.AppliedTo,
		},
	}

	for key, val := range t.Metadata {
		event.Metadata["ma_"+key] = val
	}

	return event, nil
}

// NormalizeRollback normalizes a rollback event.
func (n *Normalizer) NormalizeRollback(r *RollbackEvent) (*schema.Event, error) {
	action := "ma.rollback." + r.RollbackStatus
	if mapped, exists := ActionMappings["rollback."+r.RollbackStatus]; exists {
		action = mapped
	}

	outcome := "success"
	severity := 6
	if r.RollbackStatus == "failed" {
		outcome = "failure"
		severity = 8
	}

	event := &schema.Event{
		EventID:   uuid.New().String(),
		Timestamp: r.Timestamp,
		Source:    n.source,
		Action:    action,
		Outcome:   outcome,
		Severity:  severity,
		Actor: schema.Actor{
			ID:   r.InitiatedBy,
			Type: "rollback_initiator",
		},
		Target: schema.Target{
			ID:   r.ProcessID,
			Type: "process",
		},
		Metadata: map[string]interface{}{
			"ma_rollback_id":      r.ID,
			"ma_resurrection_id":  r.ResurrectionID,
			"ma_reason":           r.Reason,
			"ma_rollback_status":  r.RollbackStatus,
			"ma_recovery_actions": r.RecoveryActions,
		},
	}

	if r.StateSnapshot != "" {
		event.Metadata["ma_state_snapshot"] = r.StateSnapshot
	}

	for key, val := range r.Metadata {
		event.Metadata["ma_"+key] = val
	}

	return event, nil
}

// NormalizeApproval normalizes an approval workflow event.
func (n *Normalizer) NormalizeApproval(a *ApprovalWorkflowEvent) (*schema.Event, error) {
	action := ActionMappings["approval."+a.Action]
	if action == "" {
		action = "ma.approval." + a.Action
	}

	outcome := "success"
	severity := 4
	if a.Action == "rejected" {
		outcome = "denied"
		severity = 5
	} else if a.Action == "timeout" {
		outcome = "failure"
		severity = 6
	} else if a.Action == "escalated" {
		severity = 5
	}

	event := &schema.Event{
		EventID:   uuid.New().String(),
		Timestamp: a.Timestamp,
		Source:    n.source,
		Action:    action,
		Outcome:   outcome,
		Severity:  severity,
		Actor: schema.Actor{
			ID:   a.Approver,
			Type: "approver",
		},
		Target: schema.Target{
			ID:   a.ResurrectionID,
			Type: "resurrection",
		},
		Metadata: map[string]interface{}{
			"ma_approval_id":      a.ID,
			"ma_workflow_id":      a.WorkflowID,
			"ma_resurrection_id":  a.ResurrectionID,
			"ma_step":             a.Step,
			"ma_action":           a.Action,
			"ma_time_to_decision": a.TimeToDecision,
		},
	}

	if a.Reason != "" {
		event.Metadata["ma_reason"] = a.Reason
	}

	for key, val := range a.Metadata {
		event.Metadata["ma_"+key] = val
	}

	return event, nil
}

// NormalizeSmithIntegration normalizes a Smith integration event.
func (n *Normalizer) NormalizeSmithIntegration(s *SmithIntegrationEvent) (*schema.Event, error) {
	action := "ma.smith." + s.EventType
	if s.Direction == "inbound" {
		action = ActionMappings["smith.event_recv"]
	} else if s.Direction == "outbound" {
		action = ActionMappings["smith.event_sent"]
	}
	if s.ErrorMessage != "" {
		action = ActionMappings["smith.error"]
	}

	outcome := "success"
	severity := 3
	if s.Status != "success" && s.Status != "ok" {
		outcome = "failure"
		severity = 6
	}

	event := &schema.Event{
		EventID:   uuid.New().String(),
		Timestamp: s.Timestamp,
		Source:    n.source,
		Action:    action,
		Outcome:   outcome,
		Severity:  severity,
		Actor: schema.Actor{
			ID:   s.SmithNodeID,
			Type: "smith_node",
		},
		Target: schema.Target{
			ID:   n.source,
			Type: "medic_agent",
		},
		Metadata: map[string]interface{}{
			"ma_integration_id": s.ID,
			"ma_event_type":     s.EventType,
			"ma_smith_node_id":  s.SmithNodeID,
			"ma_direction":      s.Direction,
			"ma_status":         s.Status,
			"ma_payload_size":   s.PayloadSize,
			"ma_latency_ms":     s.Latency,
		},
	}

	if s.ErrorMessage != "" {
		event.Metadata["ma_error_message"] = s.ErrorMessage
	}

	for key, val := range s.Metadata {
		event.Metadata["ma_"+key] = val
	}

	return event, nil
}

func (n *Normalizer) mapSeverity(severity string) int {
	switch severity {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	case "info":
		return 1
	default:
		return 5
	}
}

func (n *Normalizer) riskScoreToSeverity(score float64) int {
	switch {
	case score >= 0.9:
		return 10
	case score >= 0.8:
		return 8
	case score >= 0.6:
		return 6
	case score >= 0.4:
		return 4
	default:
		return 2
	}
}

// GetLastEventTime returns current time as placeholder.
func (n *Normalizer) GetLastEventTime() time.Time {
	return time.Now()
}

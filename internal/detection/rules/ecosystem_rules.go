// Package rules provides pre-built detection rules for ecosystem security.
// This file contains cross-system correlation rules that detect patterns
// spanning multiple integrations in the Agent-OS ecosystem.
package rules

import (
	"time"

	"boundary-siem/internal/correlation"
)

// GetEcosystemRules returns all cross-system ecosystem detection rules.
func GetEcosystemRules() []*correlation.Rule {
	var rules []*correlation.Rule

	rules = append(rules, GetCrossSystemSecurityRules()...)
	rules = append(rules, GetDataExfiltrationRules()...)
	rules = append(rules, GetChainIntegrityRules()...)
	rules = append(rules, GetAgentCompromiseRules()...)
	rules = append(rules, GetFinancialFraudRules()...)
	rules = append(rules, GetTrustManipulationRules()...)
	rules = append(rules, GetCoordinatedAttackRules()...)

	return rules
}

// GetCrossSystemSecurityRules returns rules detecting attacks across multiple systems.
func GetCrossSystemSecurityRules() []*correlation.Rule {
	return []*correlation.Rule{
		// ECO-001: Multi-System Authentication Failure
		{
			ID:          "eco-001",
			Name:        "Multi-System Authentication Failure",
			Description: "Same actor failing authentication across multiple ecosystem systems",
			Type:        correlation.RuleTypeAggregate,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"cross-system", "authentication", "brute-force"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0006",
				TacticName:  "Credential Access",
				TechniqueID: "T1110",
			},
			Conditions: []correlation.Condition{
				{Field: "outcome", Operator: "eq", Value: "failure"},
				{Field: "action", Operator: "contains", Value: "auth"},
			},
			GroupBy: []string{"actor.ip"},
			Window:  15 * time.Minute,
			Aggregate: &correlation.AggregateConfig{
				Function: "count_distinct",
				Field:    "source.product",
				Operator: "gte",
				Value:    3, // Attacks spanning 3+ systems
			},
		},

		// ECO-002: Cross-System Privilege Escalation Attempt
		{
			ID:          "eco-002",
			Name:        "Cross-System Privilege Escalation",
			Description: "Sequential privilege escalation attempts across ecosystem services",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"cross-system", "privilege-escalation", "lateral-movement"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0004",
				TacticName:  "Privilege Escalation",
				TechniqueID: "T1068",
			},
			Conditions: []correlation.Condition{
				{Field: "actor.ip", Operator: "exists", Value: true},
			},
			GroupBy: []string{"actor.ip"},
			Window:  30 * time.Minute,
			Sequence: &correlation.SequenceConfig{
				Ordered: true,
				MaxSpan: 30 * time.Minute,
				Steps: []correlation.SequenceStep{
					{
						Name: "initial_access",
						Conditions: []correlation.Condition{
							{Field: "action", Operator: "contains", Value: "auth.login"},
							{Field: "outcome", Operator: "eq", Value: "success"},
						},
					},
					{
						Name: "escalation_attempt",
						Conditions: []correlation.Condition{
							{Field: "action", Operator: "contains", Value: "admin"},
							{Field: "outcome", Operator: "eq", Value: "failure"},
						},
					},
					{
						Name: "different_system_access",
						Conditions: []correlation.Condition{
							{Field: "action", Operator: "contains", Value: "access"},
							{Field: "outcome", Operator: "eq", Value: "success"},
						},
					},
				},
			},
		},

		// ECO-003: Rate Limit Evasion Across Systems
		{
			ID:          "eco-003",
			Name:        "Rate Limit Evasion Pattern",
			Description: "Actor being rate limited on one system then moving to another",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityMedium,
			Tags:        []string{"cross-system", "rate-limit", "evasion"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0005",
				TacticName:  "Defense Evasion",
				TechniqueID: "T1090",
			},
			Conditions: []correlation.Condition{
				{Field: "actor.ip", Operator: "exists", Value: true},
			},
			GroupBy: []string{"actor.ip"},
			Window:  10 * time.Minute,
			Sequence: &correlation.SequenceConfig{
				Ordered: true,
				MaxSpan: 10 * time.Minute,
				Steps: []correlation.SequenceStep{
					{
						Name: "rate_limited",
						Conditions: []correlation.Condition{
							{Field: "action", Operator: "contains", Value: "rate_limit"},
						},
					},
					{
						Name: "different_system_activity",
						Conditions: []correlation.Condition{
							{Field: "outcome", Operator: "eq", Value: "success"},
						},
					},
				},
			},
		},
	}
}

// GetDataExfiltrationRules returns rules detecting data exfiltration patterns.
func GetDataExfiltrationRules() []*correlation.Rule {
	return []*correlation.Rule{
		// ECO-010: Memory Vault to IntentLog Export Chain
		{
			ID:          "eco-010",
			Name:        "Memory Vault Data Export Chain",
			Description: "High-classification memory accessed then exported via IntentLog",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"cross-system", "data-exfiltration", "memory-vault", "intentlog"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0010",
				TacticName:  "Exfiltration",
				TechniqueID: "T1567",
			},
			Conditions: []correlation.Condition{
				{Field: "actor.id", Operator: "exists", Value: true},
			},
			GroupBy: []string{"actor.id"},
			Window:  1 * time.Hour,
			Sequence: &correlation.SequenceConfig{
				Ordered: true,
				MaxSpan: 1 * time.Hour,
				Steps: []correlation.SequenceStep{
					{
						Name: "high_classification_access",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "memoryvault"},
							{Field: "metadata.mv_classification", Operator: "gte", Value: float64(4)},
						},
					},
					{
						Name: "export_requested",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "intentlog"},
							{Field: "action", Operator: "contains", Value: "export"},
						},
					},
				},
			},
		},

		// ECO-011: Cross-System Data Staging
		{
			ID:          "eco-011",
			Name:        "Cross-System Data Staging",
			Description: "Data accessed from multiple systems by same actor in short window",
			Type:        correlation.RuleTypeAggregate,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"cross-system", "data-staging", "reconnaissance"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0009",
				TacticName:  "Collection",
				TechniqueID: "T1074",
			},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "access"},
				{Field: "outcome", Operator: "eq", Value: "success"},
			},
			GroupBy: []string{"actor.id"},
			Window:  30 * time.Minute,
			Aggregate: &correlation.AggregateConfig{
				Function: "count_distinct",
				Field:    "source.product",
				Operator: "gte",
				Value:    4, // Accessing 4+ different systems
			},
		},

		// ECO-012: RRA Repository Knowledge Extraction
		{
			ID:          "eco-012",
			Name:        "Bulk Repository Knowledge Extraction",
			Description: "Rapid queries to RRA-Module agents indicating knowledge extraction",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"rra-module", "knowledge-extraction", "data-theft"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0009",
				TacticName:  "Collection",
				TechniqueID: "T1213",
			},
			Conditions: []correlation.Condition{
				{Field: "source.product", Operator: "eq", Value: "rramodule"},
				{Field: "action", Operator: "contains", Value: "query"},
			},
			GroupBy:   []string{"actor.ip", "metadata.rra_agent_id"},
			Window:    5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{Count: 50, Operator: "gte"},
		},
	}
}

// GetChainIntegrityRules returns rules detecting chain/ledger integrity issues.
func GetChainIntegrityRules() []*correlation.Rule {
	return []*correlation.Rule{
		// ECO-020: Multi-Chain Integrity Failure
		{
			ID:          "eco-020",
			Name:        "Multi-Chain Integrity Failure",
			Description: "Integrity failures detected across NatLangChain and IntentLog simultaneously",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"cross-system", "chain-integrity", "natlangchain", "intentlog"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1565.001",
			},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "chain"},
				{Field: "outcome", Operator: "eq", Value: "failure"},
			},
			GroupBy:   []string{"source.host"},
			Window:    5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{Count: 2, Operator: "gte"},
		},

		// ECO-021: Value Ledger + NatLangChain Merkle Mismatch
		{
			ID:          "eco-021",
			Name:        "Cross-Ledger Merkle Verification Failure",
			Description: "Merkle proof failures across Value Ledger and NatLangChain",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"cross-system", "merkle", "tampering", "valueledger", "natlangchain"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1565",
			},
			Conditions: []correlation.Condition{
				{Field: "outcome", Operator: "eq", Value: "failure"},
			},
			GroupBy: []string{"source.host"},
			Window:  10 * time.Minute,
			Sequence: &correlation.SequenceConfig{
				Ordered: false, // Can occur in any order
				MaxSpan: 10 * time.Minute,
				Steps: []correlation.SequenceStep{
					{
						Name: "valueledger_merkle_fail",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "valueledger"},
							{Field: "action", Operator: "contains", Value: "merkle"},
						},
					},
					{
						Name: "natlangchain_verification_fail",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "natlangchain"},
							{Field: "action", Operator: "contains", Value: "verification"},
						},
					},
				},
			},
		},

		// ECO-022: IntentLog Signature + ILR Dispute Correlation
		{
			ID:          "eco-022",
			Name:        "Signature Failure Preceding Dispute",
			Description: "IntentLog signature failures followed by ILR-Module dispute escalation",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"cross-system", "signature", "dispute", "intentlog", "ilrmodule"},
			Conditions: []correlation.Condition{
				{Field: "actor.id", Operator: "exists", Value: true},
			},
			GroupBy: []string{"actor.id"},
			Window:  2 * time.Hour,
			Sequence: &correlation.SequenceConfig{
				Ordered: true,
				MaxSpan: 2 * time.Hour,
				Steps: []correlation.SequenceStep{
					{
						Name: "signature_failure",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "intentlog"},
							{Field: "action", Operator: "contains", Value: "signature"},
							{Field: "outcome", Operator: "eq", Value: "failure"},
						},
					},
					{
						Name: "dispute_filed",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "ilrmodule"},
							{Field: "action", Operator: "contains", Value: "dispute"},
						},
					},
				},
			},
		},
	}
}

// GetAgentCompromiseRules returns rules detecting AI agent compromise patterns.
func GetAgentCompromiseRules() []*correlation.Rule {
	return []*correlation.Rule{
		// ECO-030: Synth Mind Anomaly + Security Event Correlation
		{
			ID:          "eco-030",
			Name:        "Agent Anomaly with Security Event",
			Description: "Synth Mind emotional/behavioral anomaly coinciding with security events",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"cross-system", "agent-compromise", "synthmind", "security"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1499",
			},
			Conditions: []correlation.Condition{
				{Field: "metadata.sm_agent_id", Operator: "exists", Value: true},
			},
			GroupBy: []string{"metadata.sm_agent_id"},
			Window:  15 * time.Minute,
			Sequence: &correlation.SequenceConfig{
				Ordered: false,
				MaxSpan: 15 * time.Minute,
				Steps: []correlation.SequenceStep{
					{
						Name: "emotional_anomaly",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "synthmind"},
							{Field: "metadata.sm_anomaly", Operator: "eq", Value: true},
						},
					},
					{
						Name: "security_event",
						Conditions: []correlation.Condition{
							{Field: "action", Operator: "contains", Value: "security"},
							{Field: "metadata.rra_blocked", Operator: "eq", Value: true},
						},
					},
				},
			},
		},

		// ECO-031: Safety Guardrail + Suspicious Query Pattern
		{
			ID:          "eco-031",
			Name:        "Safety Bypass Attempt Pattern",
			Description: "Safety guardrails triggered followed by suspicious queries to RRA agents",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"cross-system", "safety-bypass", "synthmind", "rramodule"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0005",
				TacticName:  "Defense Evasion",
				TechniqueID: "T1562",
			},
			Conditions: []correlation.Condition{
				{Field: "metadata.sm_agent_id", Operator: "exists", Value: true},
			},
			GroupBy: []string{"metadata.sm_agent_id"},
			Window:  30 * time.Minute,
			Sequence: &correlation.SequenceConfig{
				Ordered: true,
				MaxSpan: 30 * time.Minute,
				Steps: []correlation.SequenceStep{
					{
						Name: "safety_triggered",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "synthmind"},
							{Field: "metadata.sm_triggered", Operator: "eq", Value: true},
						},
					},
					{
						Name: "suspicious_query",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "rramodule"},
							{Field: "metadata.rra_event_type", Operator: "eq", Value: "suspicious_query"},
						},
					},
				},
			},
		},

		// ECO-032: Agent Dreaming Prediction Failures
		{
			ID:          "eco-032",
			Name:        "Agent Reality Mismatch Pattern",
			Description: "Multiple large prediction mismatches indicating potential agent manipulation",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"synthmind", "dreaming", "manipulation"},
			Conditions: []correlation.Condition{
				{Field: "source.product", Operator: "eq", Value: "synthmind"},
				{Field: "metadata.sm_validation_gap", Operator: "gte", Value: float64(0.8)},
			},
			GroupBy:   []string{"metadata.sm_agent_id"},
			Window:    1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{Count: 5, Operator: "gte"},
		},

		// ECO-033: Multi-Agent Coordinated Anomaly
		{
			ID:          "eco-033",
			Name:        "Multi-Agent Coordinated Anomaly",
			Description: "Multiple agents showing anomalies simultaneously suggesting coordinated attack",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"synthmind", "multi-agent", "coordinated-attack"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1498",
			},
			Conditions: []correlation.Condition{
				{Field: "source.product", Operator: "eq", Value: "synthmind"},
				{Field: "metadata.sm_anomaly", Operator: "eq", Value: true},
			},
			GroupBy:   []string{"source.host"},
			Window:    5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{Count: 3, Operator: "gte"},
		},
	}
}

// GetFinancialFraudRules returns rules detecting financial fraud across systems.
func GetFinancialFraudRules() []*correlation.Rule {
	return []*correlation.Rule{
		// ECO-040: Value Ledger + RRA Revenue Manipulation
		{
			ID:          "eco-040",
			Name:        "Revenue Manipulation Pattern",
			Description: "Value ledger entries modified followed by large RRA revenue events",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"cross-system", "financial-fraud", "valueledger", "rramodule"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1565",
			},
			Conditions: []correlation.Condition{
				{Field: "actor.id", Operator: "exists", Value: true},
			},
			GroupBy: []string{"actor.id"},
			Window:  1 * time.Hour,
			Sequence: &correlation.SequenceConfig{
				Ordered: true,
				MaxSpan: 1 * time.Hour,
				Steps: []correlation.SequenceStep{
					{
						Name: "value_modification",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "valueledger"},
							{Field: "action", Operator: "contains", Value: "update"},
						},
					},
					{
						Name: "large_revenue",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "rramodule"},
							{Field: "metadata.rra_amount", Operator: "gte", Value: float64(10000)},
						},
					},
				},
			},
		},

		// ECO-041: Cross-Contract High-Value Movement
		{
			ID:          "eco-041",
			Name:        "Cross-Contract Value Flow Anomaly",
			Description: "High-value transactions across RRA and NatLangChain contracts",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"cross-system", "high-value", "contracts"},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "contract"},
				{Field: "metadata.rra_value", Operator: "gte", Value: float64(50000)},
			},
			GroupBy:   []string{"actor.id"},
			Window:    30 * time.Minute,
			Threshold: &correlation.ThresholdConfig{Count: 3, Operator: "gte"},
		},

		// ECO-042: Learning Contract Violation + Revenue Event
		{
			ID:          "eco-042",
			Name:        "Contract Violation with Revenue",
			Description: "Learning contract violations preceding revenue distribution",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"cross-system", "contract-violation", "learningcontracts", "rramodule"},
			Conditions: []correlation.Condition{
				{Field: "actor.id", Operator: "exists", Value: true},
			},
			GroupBy: []string{"actor.id"},
			Window:  2 * time.Hour,
			Sequence: &correlation.SequenceConfig{
				Ordered: true,
				MaxSpan: 2 * time.Hour,
				Steps: []correlation.SequenceStep{
					{
						Name: "violation_detected",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "learningcontracts"},
							{Field: "action", Operator: "contains", Value: "violation"},
						},
					},
					{
						Name: "revenue_distributed",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "rramodule"},
							{Field: "action", Operator: "contains", Value: "revenue"},
						},
					},
				},
			},
		},

		// ECO-043: Mass Entry Revocation
		{
			ID:          "eco-043",
			Name:        "Mass Value Ledger Revocation",
			Description: "Large number of value ledger entries revoked in short time",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"valueledger", "mass-revocation", "manipulation"},
			Conditions: []correlation.Condition{
				{Field: "source.product", Operator: "eq", Value: "valueledger"},
				{Field: "action", Operator: "contains", Value: "revoked"},
			},
			GroupBy:   []string{"actor.id"},
			Window:    15 * time.Minute,
			Threshold: &correlation.ThresholdConfig{Count: 10, Operator: "gte"},
		},
	}
}

// GetTrustManipulationRules returns rules detecting reputation/trust manipulation.
func GetTrustManipulationRules() []*correlation.Rule {
	return []*correlation.Rule{
		// ECO-050: Mediator Reputation + ILR Dispute Pattern
		{
			ID:          "eco-050",
			Name:        "Reputation Gaming via Disputes",
			Description: "Filing disputes after receiving negative reputation in mediation",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityMedium,
			Tags:        []string{"cross-system", "reputation-gaming", "mediatornode", "ilrmodule"},
			Conditions: []correlation.Condition{
				{Field: "actor.id", Operator: "exists", Value: true},
			},
			GroupBy: []string{"actor.id"},
			Window:  24 * time.Hour,
			Sequence: &correlation.SequenceConfig{
				Ordered: true,
				MaxSpan: 24 * time.Hour,
				Steps: []correlation.SequenceStep{
					{
						Name: "negative_reputation",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "mediatornode"},
							{Field: "metadata.mn_impact", Operator: "lt", Value: float64(0)},
						},
					},
					{
						Name: "dispute_filed",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "ilrmodule"},
							{Field: "action", Operator: "contains", Value: "dispute.filed"},
						},
					},
				},
			},
		},

		// ECO-051: Rapid Consent Revocation Pattern
		{
			ID:          "eco-051",
			Name:        "Consent Manipulation Pattern",
			Description: "Rapid consent granting and revoking in Learning Contracts",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityMedium,
			Tags:        []string{"learningcontracts", "consent-manipulation"},
			Conditions: []correlation.Condition{
				{Field: "source.product", Operator: "eq", Value: "learningcontracts"},
				{Field: "action", Operator: "contains", Value: "consent"},
			},
			GroupBy:   []string{"actor.id"},
			Window:    1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{Count: 20, Operator: "gte"},
		},

		// ECO-052: Mediation Flag Storm
		{
			ID:          "eco-052",
			Name:        "Coordinated Mediation Flags",
			Description: "Multiple parties flagging same target in short window",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"mediatornode", "coordinated-flagging", "harassment"},
			Conditions: []correlation.Condition{
				{Field: "source.product", Operator: "eq", Value: "mediatornode"},
				{Field: "action", Operator: "contains", Value: "flag"},
			},
			GroupBy:   []string{"target"},
			Window:    30 * time.Minute,
			Threshold: &correlation.ThresholdConfig{Count: 5, Operator: "gte"},
		},

		// ECO-053: Negotiation Rejection Spike with Reputation Drop
		{
			ID:          "eco-053",
			Name:        "Negotiation Attack Pattern",
			Description: "High rejection rate in RRA negotiations causing reputation damage",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityMedium,
			Tags:        []string{"cross-system", "negotiation-attack", "rramodule", "mediatornode"},
			Conditions: []correlation.Condition{
				{Field: "metadata.rra_agent_id", Operator: "exists", Value: true},
			},
			GroupBy: []string{"metadata.rra_agent_id"},
			Window:  2 * time.Hour,
			Sequence: &correlation.SequenceConfig{
				Ordered: true,
				MaxSpan: 2 * time.Hour,
				Steps: []correlation.SequenceStep{
					{
						Name: "rejections",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "rramodule"},
							{Field: "metadata.rra_event_type", Operator: "eq", Value: "rejected"},
						},
					},
					{
						Name: "reputation_impact",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "mediatornode"},
							{Field: "metadata.mn_impact", Operator: "lt", Value: float64(-0.1)},
						},
					},
				},
			},
		},
	}
}

// GetCoordinatedAttackRules returns rules detecting coordinated ecosystem attacks.
func GetCoordinatedAttackRules() []*correlation.Rule {
	return []*correlation.Rule{
		// ECO-060: Distributed Ecosystem Attack
		{
			ID:          "eco-060",
			Name:        "Distributed Ecosystem Attack",
			Description: "Failures across multiple systems from different IPs in coordinated pattern",
			Type:        correlation.RuleTypeAggregate,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"cross-system", "distributed-attack", "coordinated"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0040",
				TacticName:  "Impact",
				TechniqueID: "T1499",
			},
			Conditions: []correlation.Condition{
				{Field: "outcome", Operator: "eq", Value: "failure"},
			},
			GroupBy: []string{"source.product"},
			Window:  5 * time.Minute,
			Aggregate: &correlation.AggregateConfig{
				Function: "count_distinct",
				Field:    "actor.ip",
				Operator: "gte",
				Value:    10, // 10+ different IPs attacking
			},
		},

		// ECO-061: Governance Manipulation Across Systems
		{
			ID:          "eco-061",
			Name:        "Cross-System Governance Attack",
			Description: "Governance proposals in RRA followed by ILR proposal activity",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"cross-system", "governance", "rramodule", "ilrmodule"},
			Conditions: []correlation.Condition{
				{Field: "actor.id", Operator: "exists", Value: true},
			},
			GroupBy: []string{"actor.id"},
			Window:  24 * time.Hour,
			Sequence: &correlation.SequenceConfig{
				Ordered: true,
				MaxSpan: 24 * time.Hour,
				Steps: []correlation.SequenceStep{
					{
						Name: "rra_governance",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "rramodule"},
							{Field: "action", Operator: "contains", Value: "governance"},
						},
					},
					{
						Name: "ilr_proposal",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "ilrmodule"},
							{Field: "action", Operator: "contains", Value: "proposal"},
						},
					},
				},
			},
		},

		// ECO-062: Multi-System Lockdown Cascade
		{
			ID:          "eco-062",
			Name:        "Ecosystem Lockdown Cascade",
			Description: "Lockdowns triggered across multiple systems indicating major incident",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"cross-system", "lockdown", "cascade", "incident"},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "lockdown"},
			},
			GroupBy:   []string{"source.host"},
			Window:    10 * time.Minute,
			Threshold: &correlation.ThresholdConfig{Count: 2, Operator: "gte"},
		},

		// ECO-063: FIDO2 + Memory Vault Physical Token Attack
		{
			ID:          "eco-063",
			Name:        "Physical Token Compromise Attempt",
			Description: "FIDO2 auth failures with physical token events in Memory Vault",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"cross-system", "physical-security", "rramodule", "memoryvault"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0006",
				TacticName:  "Credential Access",
				TechniqueID: "T1078.004",
			},
			Conditions: []correlation.Condition{
				{Field: "actor.id", Operator: "exists", Value: true},
			},
			GroupBy: []string{"actor.id"},
			Window:  30 * time.Minute,
			Sequence: &correlation.SequenceConfig{
				Ordered: false,
				MaxSpan: 30 * time.Minute,
				Steps: []correlation.SequenceStep{
					{
						Name: "fido2_failure",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "rramodule"},
							{Field: "metadata.rra_event_type", Operator: "eq", Value: "fido2_challenge"},
							{Field: "metadata.rra_blocked", Operator: "eq", Value: true},
						},
					},
					{
						Name: "token_event",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "memoryvault"},
							{Field: "action", Operator: "contains", Value: "token"},
						},
					},
				},
			},
		},

		// ECO-064: Semantic Drift Propagation
		{
			ID:          "eco-064",
			Name:        "Cross-System Semantic Drift",
			Description: "Semantic drift in NatLangChain correlating with IntentLog contradictions",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"cross-system", "semantic-drift", "natlangchain", "intentlog"},
			Conditions: []correlation.Condition{
				{Field: "actor.id", Operator: "exists", Value: true},
			},
			GroupBy: []string{"actor.id"},
			Window:  1 * time.Hour,
			Sequence: &correlation.SequenceConfig{
				Ordered: false,
				MaxSpan: 1 * time.Hour,
				Steps: []correlation.SequenceStep{
					{
						Name: "semantic_drift",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "natlangchain"},
							{Field: "action", Operator: "contains", Value: "drift"},
						},
					},
					{
						Name: "contradiction",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "intentlog"},
							{Field: "metadata.il_change_type", Operator: "eq", Value: "contradiction"},
						},
					},
				},
			},
		},

		// ECO-065: Succession Event During Security Incident
		{
			ID:          "eco-065",
			Name:        "Suspicious Succession Timing",
			Description: "Memory Vault succession events during active security incidents",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"cross-system", "succession", "memoryvault", "security"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0003",
				TacticName:  "Persistence",
				TechniqueID: "T1098",
			},
			Conditions: []correlation.Condition{
				{Field: "target", Operator: "exists", Value: true},
			},
			GroupBy: []string{"target"},
			Window:  1 * time.Hour,
			Sequence: &correlation.SequenceConfig{
				Ordered: true,
				MaxSpan: 1 * time.Hour,
				Steps: []correlation.SequenceStep{
					{
						Name: "security_incident",
						Conditions: []correlation.Condition{
							{Field: "action", Operator: "contains", Value: "security"},
							{Field: "severity", Operator: "gte", Value: 7},
						},
					},
					{
						Name: "succession_triggered",
						Conditions: []correlation.Condition{
							{Field: "source.product", Operator: "eq", Value: "memoryvault"},
							{Field: "action", Operator: "contains", Value: "succession"},
						},
					},
				},
			},
		},
	}
}

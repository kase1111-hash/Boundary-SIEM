package correlation

import "time"

// BuiltinRules returns the built-in correlation rules.
func BuiltinRules() []*Rule {
	return []*Rule{
		// Authentication rules
		BruteForceRule(),
		CredentialStuffingRule(),
		AccountLockoutRule(),

		// Blockchain-specific rules
		ValidatorMissedAttestationsRule(),
		SlashingRiskRule(),
		LargeTransferRule(),
		SuspiciousWithdrawalRule(),

		// Infrastructure rules
		DDoSDetectionRule(),
		RPCAbuseRule(),
		UnauthorizedAccessRule(),
	}
}

// BruteForceRule detects brute force login attempts.
func BruteForceRule() *Rule {
	return &Rule{
		ID:          "builtin-brute-force",
		Name:        "Brute Force Attack Detected",
		Description: "Multiple failed login attempts from the same source",
		Type:        RuleTypeThreshold,
		Enabled:     true,
		Severity:    7,
		Category:    "Authentication",
		Tags:        []string{"authentication", "attack", "brute-force"},
		MITRE: &MITREMapping{
			TacticID:    "TA0006",
			TacticName:  "Credential Access",
			TechniqueID: "T1110",
		},
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "eq", Value: "auth.failure"},
			},
		},
		GroupBy: []string{"actor.ip"},
		Window:  5 * time.Minute,
		Threshold: &ThresholdConfig{
			Count:    10,
			Operator: "gte",
		},
	}
}

// CredentialStuffingRule detects credential stuffing attacks.
func CredentialStuffingRule() *Rule {
	return &Rule{
		ID:          "builtin-credential-stuffing",
		Name:        "Credential Stuffing Attack",
		Description: "Multiple failed logins for different users from same source",
		Type:        RuleTypeAggregate,
		Enabled:     true,
		Severity:    7,
		Category:    "Authentication",
		Tags:        []string{"authentication", "attack", "credential-stuffing"},
		MITRE: &MITREMapping{
			TacticID:    "TA0006",
			TacticName:  "Credential Access",
			TechniqueID: "T1110.004",
		},
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "eq", Value: "auth.failure"},
			},
		},
		GroupBy: []string{"actor.ip"},
		Window:  10 * time.Minute,
		Aggregate: &AggregateConfig{
			Function: "count_distinct",
			Field:    "actor.name",
			Operator: "gte",
			Value:    5,
		},
	}
}

// AccountLockoutRule detects repeated account lockouts.
func AccountLockoutRule() *Rule {
	return &Rule{
		ID:          "builtin-account-lockout",
		Name:        "Account Lockout Storm",
		Description: "Multiple accounts locked out in short period",
		Type:        RuleTypeThreshold,
		Enabled:     true,
		Severity:    5,
		Category:    "Authentication",
		Tags:        []string{"authentication", "lockout"},
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "eq", Value: "account.locked"},
			},
		},
		GroupBy: []string{"tenant_id"},
		Window:  15 * time.Minute,
		Threshold: &ThresholdConfig{
			Count:    5,
			Operator: "gte",
		},
	}
}

// ValidatorMissedAttestationsRule detects missed attestations.
func ValidatorMissedAttestationsRule() *Rule {
	return &Rule{
		ID:          "builtin-validator-missed-attestations",
		Name:        "Validator Missing Attestations",
		Description: "Validator has missed multiple attestations",
		Type:        RuleTypeThreshold,
		Enabled:     true,
		Severity:    7,
		Category:    "Blockchain",
		Tags:        []string{"blockchain", "validator", "attestation"},
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "eq", Value: "validator.attestation_missed"},
			},
		},
		GroupBy: []string{"metadata.validator_index"},
		Window:  1 * time.Hour,
		Threshold: &ThresholdConfig{
			Count:    3,
			Operator: "gte",
		},
	}
}

// SlashingRiskRule detects potential slashing conditions.
func SlashingRiskRule() *Rule {
	return &Rule{
		ID:          "builtin-slashing-risk",
		Name:        "Slashing Risk Detected",
		Description: "Potential slashing condition detected for validator",
		Type:        RuleTypeSequence,
		Enabled:     true,
		Severity:    10,
		Category:    "Blockchain",
		Tags:        []string{"blockchain", "validator", "slashing", "critical"},
		MITRE: &MITREMapping{
			TacticID:   "TA0040",
			TacticName: "Impact",
		},
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "source.product", Operator: "contains", Value: "validator"},
			},
		},
		GroupBy: []string{"metadata.validator_index"},
		Window:  5 * time.Minute,
		Sequence: &SequenceConfig{
			Ordered: false,
			MaxSpan: 5 * time.Minute,
			Steps: []SequenceStep{
				{
					Name: "double_vote",
					Conditions: []Condition{
						{Field: "action", Operator: "eq", Value: "validator.double_vote"},
					},
					Required: true,
				},
				{
					Name: "surround_vote",
					Conditions: []Condition{
						{Field: "action", Operator: "eq", Value: "validator.surround_vote"},
					},
					Required: false,
				},
			},
		},
	}
}

// LargeTransferRule detects large token transfers.
func LargeTransferRule() *Rule {
	return &Rule{
		ID:          "builtin-large-transfer",
		Name:        "Large Token Transfer",
		Description: "Unusually large token transfer detected",
		Type:        RuleTypeAggregate,
		Enabled:     true,
		Severity:    5,
		Category:    "Blockchain",
		Tags:        []string{"blockchain", "transaction", "transfer"},
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "eq", Value: "token.transfer"},
			},
		},
		GroupBy: []string{"metadata.token_address"},
		Window:  1 * time.Hour,
		Aggregate: &AggregateConfig{
			Function: "max",
			Field:    "metadata.amount",
			Operator: "gte",
			Value:    1000000, // 1M tokens
		},
	}
}

// SuspiciousWithdrawalRule detects suspicious withdrawal patterns.
func SuspiciousWithdrawalRule() *Rule {
	return &Rule{
		ID:          "builtin-suspicious-withdrawal",
		Name:        "Suspicious Withdrawal Pattern",
		Description: "Multiple withdrawals in short period",
		Type:        RuleTypeThreshold,
		Enabled:     true,
		Severity:    7,
		Category:    "Blockchain",
		Tags:        []string{"blockchain", "withdrawal", "suspicious"},
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "eq", Value: "funds.withdrawn"},
			},
		},
		GroupBy: []string{"actor.id"},
		Window:  15 * time.Minute,
		Threshold: &ThresholdConfig{
			Count:    5,
			Operator: "gte",
		},
	}
}

// DDoSDetectionRule detects potential DDoS attacks.
func DDoSDetectionRule() *Rule {
	return &Rule{
		ID:          "builtin-ddos-detection",
		Name:        "DDoS Attack Detected",
		Description: "High volume of requests from single source",
		Type:        RuleTypeThreshold,
		Enabled:     true,
		Severity:    7,
		Category:    "Infrastructure",
		Tags:        []string{"infrastructure", "ddos", "network"},
		MITRE: &MITREMapping{
			TacticID:    "TA0040",
			TacticName:  "Impact",
			TechniqueID: "T1498",
		},
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "contains", Value: "request"},
			},
		},
		GroupBy: []string{"actor.ip"},
		Window:  1 * time.Minute,
		Threshold: &ThresholdConfig{
			Count:    1000,
			Operator: "gte",
		},
	}
}

// RPCAbuseRule detects RPC endpoint abuse.
func RPCAbuseRule() *Rule {
	return &Rule{
		ID:          "builtin-rpc-abuse",
		Name:        "RPC Endpoint Abuse",
		Description: "Excessive RPC calls or sensitive method access",
		Type:        RuleTypeThreshold,
		Enabled:     true,
		Severity:    5,
		Category:    "Blockchain",
		Tags:        []string{"blockchain", "rpc", "abuse"},
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "contains", Value: "rpc."},
				{Field: "outcome", Operator: "eq", Value: "failure"},
			},
		},
		GroupBy: []string{"actor.ip"},
		Window:  5 * time.Minute,
		Threshold: &ThresholdConfig{
			Count:    50,
			Operator: "gte",
		},
	}
}

// UnauthorizedAccessRule detects unauthorized access attempts.
func UnauthorizedAccessRule() *Rule {
	return &Rule{
		ID:          "builtin-unauthorized-access",
		Name:        "Unauthorized Access Attempt",
		Description: "Multiple unauthorized access attempts detected",
		Type:        RuleTypeThreshold,
		Enabled:     true,
		Severity:    7,
		Category:    "Security",
		Tags:        []string{"security", "access", "unauthorized"},
		MITRE: &MITREMapping{
			TacticID:    "TA0001",
			TacticName:  "Initial Access",
			TechniqueID: "T1190",
		},
		Conditions: Conditions{
			Match: []MatchCondition{
				{Field: "action", Operator: "in", Value: []string{"access.denied", "auth.unauthorized"}},
			},
		},
		GroupBy: []string{"actor.ip"},
		Window:  10 * time.Minute,
		Threshold: &ThresholdConfig{
			Count:    5,
			Operator: "gte",
		},
	}
}

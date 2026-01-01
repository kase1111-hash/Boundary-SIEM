// Package keys provides key management security monitoring.
package keys

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// KeyType represents the type of cryptographic key.
type KeyType string

const (
	KeyTypeValidator  KeyType = "validator"
	KeyTypeWithdrawal KeyType = "withdrawal"
	KeyTypeSigning    KeyType = "signing"
	KeyTypeEncryption KeyType = "encryption"
	KeyTypeHSM        KeyType = "hsm"
)

// OperationType represents a key operation.
type OperationType string

const (
	OpSign           OperationType = "sign"
	OpVerify         OperationType = "verify"
	OpEncrypt        OperationType = "encrypt"
	OpDecrypt        OperationType = "decrypt"
	OpGenerate       OperationType = "generate"
	OpImport         OperationType = "import"
	OpExport         OperationType = "export"
	OpRotate         OperationType = "rotate"
	OpRevoke         OperationType = "revoke"
	OpAccess         OperationType = "access"
)

// KeyOperation represents a cryptographic key operation.
type KeyOperation struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	KeyID       string                 `json:"key_id"`
	KeyType     KeyType                `json:"key_type"`
	Operation   OperationType          `json:"operation"`
	Source      string                 `json:"source"` // HSM, Vault, Software
	Actor       string                 `json:"actor"`
	SourceIP    string                 `json:"source_ip,omitempty"`
	Success     bool                   `json:"success"`
	ErrorCode   string                 `json:"error_code,omitempty"`
	DataSize    int64                  `json:"data_size,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// VaultAuditLog represents a HashiCorp Vault audit log entry.
type VaultAuditLog struct {
	Time      time.Time `json:"time"`
	Type      string    `json:"type"`
	Auth      struct {
		ClientToken   string            `json:"client_token"`
		Accessor      string            `json:"accessor"`
		DisplayName   string            `json:"display_name"`
		Policies      []string          `json:"policies"`
		TokenPolicies []string          `json:"token_policies"`
		Metadata      map[string]string `json:"metadata"`
		EntityID      string            `json:"entity_id"`
	} `json:"auth"`
	Request struct {
		ID           string                 `json:"id"`
		Operation    string                 `json:"operation"`
		ClientToken  string                 `json:"client_token"`
		Path         string                 `json:"path"`
		Data         map[string]interface{} `json:"data"`
		RemoteAddr   string                 `json:"remote_address"`
		WrapTTL      int                    `json:"wrap_ttl"`
	} `json:"request"`
	Response struct {
		Data map[string]interface{} `json:"data"`
	} `json:"response"`
	Error string `json:"error"`
}

// HSMLog represents an HSM audit log entry.
type HSMLog struct {
	Timestamp   time.Time `json:"timestamp"`
	SessionID   string    `json:"session_id"`
	UserID      string    `json:"user_id"`
	Operation   string    `json:"operation"`
	KeyHandle   string    `json:"key_handle"`
	KeyLabel    string    `json:"key_label"`
	Mechanism   string    `json:"mechanism"`
	Result      int       `json:"result"`
	SourceIP    string    `json:"source_ip"`
}

// Alert represents a key management alert.
type Alert struct {
	ID          uuid.UUID              `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	KeyID       string                 `json:"key_id"`
	Operation   string                 `json:"operation"`
	Actor       string                 `json:"actor"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertHandler processes key management alerts.
type AlertHandler func(context.Context, *Alert) error

// SigningPattern represents detected signing patterns.
type SigningPattern struct {
	KeyID           string        `json:"key_id"`
	AverageRate     float64       `json:"average_rate"` // signings per minute
	PeakRate        float64       `json:"peak_rate"`
	TotalSignings   int64         `json:"total_signings"`
	LastSigning     time.Time     `json:"last_signing"`
	UniqueActors    int           `json:"unique_actors"`
	TypicalTimeSlot string        `json:"typical_time_slot"` // "business_hours", "24x7", etc.
	Anomalies       int           `json:"anomalies"`
}

// MonitorConfig configures the key management monitor.
type MonitorConfig struct {
	EnablePatternAnalysis  bool
	EnableAnomalyDetection bool
	SigningRateThreshold   float64       // signings per minute
	AnomalyWindow          time.Duration
	SensitiveOperations    []OperationType
	HighRiskKeyTypes       []KeyType
}

// DefaultMonitorConfig returns default configuration.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		EnablePatternAnalysis:  true,
		EnableAnomalyDetection: true,
		SigningRateThreshold:   100, // 100 signings per minute
		AnomalyWindow:          5 * time.Minute,
		SensitiveOperations: []OperationType{
			OpExport, OpImport, OpRotate, OpRevoke, OpGenerate,
		},
		HighRiskKeyTypes: []KeyType{
			KeyTypeValidator, KeyTypeWithdrawal,
		},
	}
}

// Monitor monitors key management operations.
type Monitor struct {
	config   MonitorConfig
	handlers []AlertHandler
	mu       sync.RWMutex

	// Operation tracking
	operations map[string][]*KeyOperation // keyID -> operations

	// Signing patterns
	patterns map[string]*SigningPattern

	// Statistics
	totalOperations    int64
	sensitiveOps       int64
	failedOperations   int64
	anomaliesDetected  int64
}

// NewMonitor creates a new key management monitor.
func NewMonitor(config MonitorConfig) *Monitor {
	return &Monitor{
		config:     config,
		operations: make(map[string][]*KeyOperation),
		patterns:   make(map[string]*SigningPattern),
	}
}

// AddHandler adds an alert handler.
func (m *Monitor) AddHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// ProcessOperation processes a key operation.
func (m *Monitor) ProcessOperation(op *KeyOperation) {
	m.mu.Lock()
	m.totalOperations++
	if !op.Success {
		m.failedOperations++
	}
	m.mu.Unlock()

	ctx := context.Background()

	// Track operation
	m.mu.Lock()
	m.operations[op.KeyID] = append(m.operations[op.KeyID], op)
	m.mu.Unlock()

	// Check for sensitive operations
	if m.isSensitiveOperation(op.Operation) {
		m.mu.Lock()
		m.sensitiveOps++
		m.mu.Unlock()

		severity := "medium"
		if m.isHighRiskKey(op.KeyType) {
			severity = "high"
		}

		m.emitAlert(ctx, &Alert{
			ID:        uuid.New(),
			Type:      "sensitive_key_operation",
			Severity:  severity,
			KeyID:     op.KeyID,
			Operation: string(op.Operation),
			Actor:     op.Actor,
			Title:     fmt.Sprintf("Sensitive Key Operation: %s", op.Operation),
			Description: fmt.Sprintf("%s operation on key %s by %s",
				op.Operation, op.KeyID, op.Actor),
			Timestamp: op.Timestamp,
			Metadata: map[string]interface{}{
				"key_type": op.KeyType,
				"source":   op.Source,
				"success":  op.Success,
			},
		})
	}

	// Update signing patterns
	if op.Operation == OpSign && m.config.EnablePatternAnalysis {
		m.updateSigningPattern(op)
	}

	// Check for anomalies
	if m.config.EnableAnomalyDetection {
		m.detectAnomalies(ctx, op)
	}

	// Alert on failures
	if !op.Success {
		m.emitAlert(ctx, &Alert{
			ID:        uuid.New(),
			Type:      "key_operation_failed",
			Severity:  "medium",
			KeyID:     op.KeyID,
			Operation: string(op.Operation),
			Actor:     op.Actor,
			Title:     fmt.Sprintf("Key Operation Failed: %s", op.Operation),
			Description: fmt.Sprintf("%s operation failed on key %s: %s",
				op.Operation, op.KeyID, op.ErrorCode),
			Timestamp: op.Timestamp,
			Metadata: map[string]interface{}{
				"error_code": op.ErrorCode,
			},
		})
	}
}

func (m *Monitor) isSensitiveOperation(op OperationType) bool {
	for _, sensitive := range m.config.SensitiveOperations {
		if op == sensitive {
			return true
		}
	}
	return false
}

func (m *Monitor) isHighRiskKey(kt KeyType) bool {
	for _, risk := range m.config.HighRiskKeyTypes {
		if kt == risk {
			return true
		}
	}
	return false
}

func (m *Monitor) updateSigningPattern(op *KeyOperation) {
	m.mu.Lock()
	defer m.mu.Unlock()

	pattern, exists := m.patterns[op.KeyID]
	if !exists {
		pattern = &SigningPattern{
			KeyID: op.KeyID,
		}
		m.patterns[op.KeyID] = pattern
	}

	pattern.TotalSignings++
	pattern.LastSigning = op.Timestamp

	// Calculate rate
	cutoff := time.Now().Add(-m.config.AnomalyWindow)
	var recentOps int
	for _, o := range m.operations[op.KeyID] {
		if o.Timestamp.After(cutoff) && o.Operation == OpSign {
			recentOps++
		}
	}
	currentRate := float64(recentOps) / m.config.AnomalyWindow.Minutes()

	if currentRate > pattern.PeakRate {
		pattern.PeakRate = currentRate
	}
	pattern.AverageRate = (pattern.AverageRate*0.9 + currentRate*0.1) // Exponential moving average
}

func (m *Monitor) detectAnomalies(ctx context.Context, op *KeyOperation) {
	m.mu.RLock()
	pattern := m.patterns[op.KeyID]
	m.mu.RUnlock()

	if pattern == nil {
		return
	}

	// Rate anomaly
	if pattern.AverageRate > 0 {
		cutoff := time.Now().Add(-m.config.AnomalyWindow)
		var recentOps int
		m.mu.RLock()
		for _, o := range m.operations[op.KeyID] {
			if o.Timestamp.After(cutoff) {
				recentOps++
			}
		}
		m.mu.RUnlock()

		currentRate := float64(recentOps) / m.config.AnomalyWindow.Minutes()

		// Alert if rate is 3x average or exceeds threshold
		if currentRate > pattern.AverageRate*3 || currentRate > m.config.SigningRateThreshold {
			m.mu.Lock()
			m.anomaliesDetected++
			pattern.Anomalies++
			m.mu.Unlock()

			m.emitAlert(ctx, &Alert{
				ID:        uuid.New(),
				Type:      "signing_rate_anomaly",
				Severity:  "high",
				KeyID:     op.KeyID,
				Operation: string(op.Operation),
				Actor:     op.Actor,
				Title:     "Anomalous Signing Rate Detected",
				Description: fmt.Sprintf("Key %s signing rate %.2f/min (average: %.2f/min)",
					op.KeyID, currentRate, pattern.AverageRate),
				Timestamp: op.Timestamp,
				Metadata: map[string]interface{}{
					"current_rate": currentRate,
					"average_rate": pattern.AverageRate,
					"threshold":    m.config.SigningRateThreshold,
				},
			})
		}
	}
}

func (m *Monitor) emitAlert(ctx context.Context, alert *Alert) {
	m.mu.RLock()
	handlers := m.handlers
	m.mu.RUnlock()

	for _, handler := range handlers {
		go func(h AlertHandler) {
			if err := h(ctx, alert); err != nil {
				slog.Error("key management alert handler failed", "error", err)
			}
		}(handler)
	}
}

// ParseVaultAuditLog parses a HashiCorp Vault audit log line.
func ParseVaultAuditLog(line string) (*VaultAuditLog, error) {
	var log VaultAuditLog
	if err := json.Unmarshal([]byte(line), &log); err != nil {
		return nil, fmt.Errorf("invalid Vault audit log: %w", err)
	}
	return &log, nil
}

// VaultLogToOperation converts a Vault audit log to a KeyOperation.
func VaultLogToOperation(log *VaultAuditLog) *KeyOperation {
	op := &KeyOperation{
		ID:        log.Request.ID,
		Timestamp: log.Time,
		Actor:     log.Auth.DisplayName,
		SourceIP:  log.Request.RemoteAddr,
		Source:    "vault",
		Success:   log.Error == "",
		ErrorCode: log.Error,
		Metadata:  make(map[string]interface{}),
	}

	// Determine key ID and type from path
	path := log.Request.Path
	op.KeyID = path

	// Classify operation based on Vault operation
	switch log.Request.Operation {
	case "read":
		op.Operation = OpAccess
	case "create", "update":
		if strings.Contains(path, "sign") {
			op.Operation = OpSign
		} else if strings.Contains(path, "encrypt") {
			op.Operation = OpEncrypt
		} else if strings.Contains(path, "decrypt") {
			op.Operation = OpDecrypt
		} else if strings.Contains(path, "keys") {
			op.Operation = OpGenerate
		} else {
			op.Operation = OpAccess
		}
	case "delete":
		op.Operation = OpRevoke
	default:
		op.Operation = OpAccess
	}

	// Classify key type based on path
	if strings.Contains(path, "validator") {
		op.KeyType = KeyTypeValidator
	} else if strings.Contains(path, "withdrawal") {
		op.KeyType = KeyTypeWithdrawal
	} else if strings.Contains(path, "transit") || strings.Contains(path, "sign") {
		op.KeyType = KeyTypeSigning
	} else {
		op.KeyType = KeyTypeEncryption
	}

	// Add metadata
	op.Metadata["path"] = path
	op.Metadata["policies"] = log.Auth.Policies
	op.Metadata["entity_id"] = log.Auth.EntityID

	return op
}

// ParseHSMLog parses an HSM audit log line.
func ParseHSMLog(line string) (*HSMLog, error) {
	var log HSMLog
	if err := json.Unmarshal([]byte(line), &log); err != nil {
		return nil, fmt.Errorf("invalid HSM audit log: %w", err)
	}
	return &log, nil
}

// HSMLogToOperation converts an HSM log to a KeyOperation.
func HSMLogToOperation(log *HSMLog) *KeyOperation {
	op := &KeyOperation{
		ID:        log.SessionID,
		Timestamp: log.Timestamp,
		KeyID:     log.KeyHandle,
		Actor:     log.UserID,
		SourceIP:  log.SourceIP,
		Source:    "hsm",
		Success:   log.Result == 0,
		Metadata:  make(map[string]interface{}),
	}

	if log.Result != 0 {
		op.ErrorCode = fmt.Sprintf("HSM_ERROR_%d", log.Result)
	}

	// Map HSM operations
	opLower := strings.ToLower(log.Operation)
	switch {
	case strings.Contains(opLower, "sign"):
		op.Operation = OpSign
	case strings.Contains(opLower, "verify"):
		op.Operation = OpVerify
	case strings.Contains(opLower, "encrypt"):
		op.Operation = OpEncrypt
	case strings.Contains(opLower, "decrypt"):
		op.Operation = OpDecrypt
	case strings.Contains(opLower, "generate"):
		op.Operation = OpGenerate
	case strings.Contains(opLower, "import"):
		op.Operation = OpImport
	case strings.Contains(opLower, "export"):
		op.Operation = OpExport
	default:
		op.Operation = OpAccess
	}

	op.KeyType = KeyTypeHSM
	op.Metadata["key_label"] = log.KeyLabel
	op.Metadata["mechanism"] = log.Mechanism

	return op
}

// GetStats returns monitor statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"total_operations":   m.totalOperations,
		"sensitive_ops":      m.sensitiveOps,
		"failed_operations":  m.failedOperations,
		"anomalies_detected": m.anomaliesDetected,
		"tracked_keys":       len(m.operations),
		"patterns":           len(m.patterns),
	}
}

// GetPattern returns the signing pattern for a key.
func (m *Monitor) GetPattern(keyID string) (*SigningPattern, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.patterns[keyID]
	return p, ok
}

// NormalizeToEvent converts a key operation to a schema.Event.
func (m *Monitor) NormalizeToEvent(op *KeyOperation, tenantID string) *schema.Event {
	outcome := schema.OutcomeSuccess
	if !op.Success {
		outcome = schema.OutcomeFailure
	}

	severity := 3
	if m.isSensitiveOperation(op.Operation) {
		severity = 6
	}
	if m.isHighRiskKey(op.KeyType) {
		severity += 2
	}
	if !op.Success {
		severity += 1
	}

	metadata := map[string]interface{}{
		"key_id":    op.KeyID,
		"key_type":  string(op.KeyType),
		"operation": string(op.Operation),
		"source":    op.Source,
	}

	if op.ErrorCode != "" {
		metadata["error_code"] = op.ErrorCode
	}
	if op.DataSize > 0 {
		metadata["data_size"] = op.DataSize
	}
	for k, v := range op.Metadata {
		metadata[k] = v
	}

	return &schema.Event{
		EventID:   uuid.New(),
		Timestamp: op.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: "key-monitor",
			Host:    op.Source,
			Version: "1.0",
		},
		Action:   fmt.Sprintf("key.%s", op.Operation),
		Outcome:  outcome,
		Severity: severity,
		Target:   op.KeyID,
		Actor: &schema.Actor{
			ID:        op.Actor,
			Type:      schema.ActorService,
			IPAddress: op.SourceIP,
		},
		Metadata: metadata,
	}
}

// Cleanup removes old operation data.
func (m *Monitor) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour)

	for keyID, ops := range m.operations {
		var kept []*KeyOperation
		for _, op := range ops {
			if op.Timestamp.After(cutoff) {
				kept = append(kept, op)
			}
		}
		if len(kept) > 0 {
			m.operations[keyID] = kept
		} else {
			delete(m.operations, keyID)
		}
	}
}

// CreateCorrelationRules creates key management correlation rules.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "key-export-attempt",
			Name:        "Key Export Attempt",
			Description: "Attempt to export a cryptographic key",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"keys", "export", "critical"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0010",
				TacticName:  "Exfiltration",
				TechniqueID: "T1552",
			},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "key.export"},
			},
			GroupBy: []string{"target"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "key-signing-anomaly",
			Name:        "Anomalous Signing Activity",
			Description: "Unusually high rate of signing operations",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"keys", "signing", "anomaly"},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "key.sign"},
			},
			GroupBy: []string{"target"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    500,
				Operator: "gte",
			},
		},
		{
			ID:          "key-operation-failures",
			Name:        "Key Operation Failures",
			Description: "Multiple failed key operations",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityMedium,
			Tags:        []string{"keys", "failures"},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "key."},
				{Field: "outcome", Operator: "eq", Value: "failure"},
			},
			GroupBy: []string{"actor.id"},
			Window:  10 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    10,
				Operator: "gte",
			},
		},
		{
			ID:          "key-validator-access",
			Name:        "Validator Key Access",
			Description: "Access to validator signing keys",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"keys", "validator", "access"},
			Conditions: []correlation.Condition{
				{Field: "metadata.key_type", Operator: "eq", Value: "validator"},
				{Field: "action", Operator: "in", Values: []string{"key.access", "key.sign"}},
			},
			GroupBy: []string{"target", "actor.id"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "key-unauthorized-actor",
			Name:        "Unauthorized Key Access",
			Description: "Key access from unusual actor",
			Type:        correlation.RuleTypeAggregate,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"keys", "unauthorized", "access"},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "key."},
			},
			GroupBy: []string{"target"},
			Window:  1 * time.Hour,
			Aggregate: &correlation.AggregateConfig{
				Function: "count_distinct",
				Field:    "actor.id",
				Operator: "gte",
				Value:    3, // More than 3 distinct actors accessing same key
			},
		},
		{
			ID:          "key-rotation-event",
			Name:        "Key Rotation Event",
			Description: "Cryptographic key was rotated",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityMedium,
			Tags:        []string{"keys", "rotation"},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "key.rotate"},
			},
			GroupBy: []string{"target"},
			Window:  24 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
	}
}

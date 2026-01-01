// Package rpc provides RPC and API security monitoring.
package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// RPCType represents the type of RPC protocol.
type RPCType string

const (
	RPCTypeJSONRPC   RPCType = "jsonrpc"
	RPCTypeGRPC      RPCType = "grpc"
	RPCTypeREST      RPCType = "rest"
	RPCTypeWebSocket RPCType = "websocket"
)

// RiskLevel categorizes method risk.
type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
)

// RPCRequest represents a parsed RPC request.
type RPCRequest struct {
	ID          string                 `json:"id"`
	Type        RPCType                `json:"type"`
	Method      string                 `json:"method"`
	Params      interface{}            `json:"params,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	SourceIP    string                 `json:"source_ip"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Duration    time.Duration          `json:"duration,omitempty"`
	StatusCode  int                    `json:"status_code,omitempty"`
	Error       string                 `json:"error,omitempty"`
	ResponseSize int64                 `json:"response_size,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// MethodPolicy defines access policy for an RPC method.
type MethodPolicy struct {
	Method      string    `json:"method"`
	RiskLevel   RiskLevel `json:"risk_level"`
	Blocked     bool      `json:"blocked"`
	RateLimit   int       `json:"rate_limit"`  // requests per minute
	RequireAuth bool      `json:"require_auth"`
	LogLevel    string    `json:"log_level"`   // debug, info, warn, error
}

// Alert represents an RPC security alert.
type Alert struct {
	ID          uuid.UUID              `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	SourceIP    string                 `json:"source_ip"`
	Method      string                 `json:"method"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AlertHandler processes RPC alerts.
type AlertHandler func(context.Context, *Alert) error

// MonitorConfig configures the RPC monitor.
type MonitorConfig struct {
	EnableRateLimiting    bool
	EnableEnumDetection   bool
	EnableMethodBlocking  bool
	DefaultRateLimit      int           // requests per minute per IP
	EnumThreshold         int           // number of distinct methods to trigger alert
	EnumWindow            time.Duration
	BlockedMethods        []string
	SensitiveMethods      []string
	MethodPolicies        map[string]*MethodPolicy
}

// DefaultMonitorConfig returns default configuration.
func DefaultMonitorConfig() MonitorConfig {
	return MonitorConfig{
		EnableRateLimiting:   true,
		EnableEnumDetection:  true,
		EnableMethodBlocking: true,
		DefaultRateLimit:     60,
		EnumThreshold:        20,
		EnumWindow:           5 * time.Minute,
		BlockedMethods: []string{
			// Ethereum sensitive methods
			"admin_addPeer", "admin_removePeer", "admin_nodeInfo",
			"admin_startRPC", "admin_stopRPC", "admin_startWS", "admin_stopWS",
			"debug_setHead", "debug_traceTransaction", "debug_setBlockProfileRate",
			"personal_importRawKey", "personal_unlockAccount", "personal_sendTransaction",
			"miner_start", "miner_stop", "miner_setGasPrice", "miner_setEtherbase",
			// Sensitive debug methods
			"debug_dumpBlock", "debug_gcStats", "debug_memStats",
			"debug_seedHash", "debug_setMutexProfileFraction",
		},
		SensitiveMethods: []string{
			"eth_accounts", "eth_sign", "eth_signTransaction",
			"eth_sendTransaction", "personal_listAccounts",
			"personal_newAccount", "personal_lockAccount",
		},
	}
}

// Monitor monitors RPC security.
type Monitor struct {
	config   MonitorConfig
	handlers []AlertHandler
	mu       sync.RWMutex

	// Rate limiting state
	rateLimits map[string]*rateLimitState // IP -> state

	// Enumeration detection
	methodCalls map[string]map[string]time.Time // IP -> method -> last call

	// Statistics
	totalRequests    int64
	blockedRequests  int64
	rateLimitedReqs  int64
	suspiciousReqs   int64
}

type rateLimitState struct {
	count     int
	window    time.Time
	blocked   bool
	unblockAt time.Time
}

// NewMonitor creates a new RPC monitor.
func NewMonitor(config MonitorConfig) *Monitor {
	m := &Monitor{
		config:      config,
		rateLimits:  make(map[string]*rateLimitState),
		methodCalls: make(map[string]map[string]time.Time),
	}

	// Initialize default method policies
	if m.config.MethodPolicies == nil {
		m.config.MethodPolicies = make(map[string]*MethodPolicy)
	}

	// Add blocked methods to policies
	for _, method := range config.BlockedMethods {
		m.config.MethodPolicies[method] = &MethodPolicy{
			Method:    method,
			RiskLevel: RiskCritical,
			Blocked:   true,
			LogLevel:  "error",
		}
	}

	// Add sensitive methods
	for _, method := range config.SensitiveMethods {
		if _, exists := m.config.MethodPolicies[method]; !exists {
			m.config.MethodPolicies[method] = &MethodPolicy{
				Method:      method,
				RiskLevel:   RiskHigh,
				Blocked:     false,
				RequireAuth: true,
				LogLevel:    "warn",
			}
		}
	}

	return m
}

// AddHandler adds an alert handler.
func (m *Monitor) AddHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// ProcessRequest processes an RPC request.
func (m *Monitor) ProcessRequest(req *RPCRequest) *ProcessResult {
	m.mu.Lock()
	m.totalRequests++
	m.mu.Unlock()

	ctx := context.Background()
	result := &ProcessResult{
		Allowed: true,
		Request: req,
	}

	// Check method blocking
	if m.config.EnableMethodBlocking {
		if blocked, reason := m.checkBlocked(req); blocked {
			result.Allowed = false
			result.BlockReason = reason

			m.mu.Lock()
			m.blockedRequests++
			m.mu.Unlock()

			m.emitAlert(ctx, &Alert{
				ID:       uuid.New(),
				Type:     "blocked_method",
				Severity: "critical",
				SourceIP: req.SourceIP,
				Method:   req.Method,
				Title:    "Blocked RPC Method Access Attempt",
				Description: fmt.Sprintf("Attempt to call blocked method %s from %s",
					req.Method, req.SourceIP),
				Timestamp: req.Timestamp,
				Metadata: map[string]interface{}{
					"user_agent": req.UserAgent,
					"params":     req.Params,
				},
			})

			return result
		}
	}

	// Check rate limiting
	if m.config.EnableRateLimiting {
		if limited, reason := m.checkRateLimit(req); limited {
			result.Allowed = false
			result.BlockReason = reason

			m.mu.Lock()
			m.rateLimitedReqs++
			m.mu.Unlock()

			m.emitAlert(ctx, &Alert{
				ID:       uuid.New(),
				Type:     "rate_limit_exceeded",
				Severity: "medium",
				SourceIP: req.SourceIP,
				Method:   req.Method,
				Title:    "RPC Rate Limit Exceeded",
				Description: fmt.Sprintf("IP %s exceeded rate limit for method %s",
					req.SourceIP, req.Method),
				Timestamp: req.Timestamp,
			})

			return result
		}
	}

	// Check for enumeration
	if m.config.EnableEnumDetection {
		if enum := m.checkEnumeration(req); enum {
			m.mu.Lock()
			m.suspiciousReqs++
			m.mu.Unlock()

			m.emitAlert(ctx, &Alert{
				ID:       uuid.New(),
				Type:     "enumeration_detected",
				Severity: "high",
				SourceIP: req.SourceIP,
				Method:   req.Method,
				Title:    "RPC Enumeration Attack Detected",
				Description: fmt.Sprintf("IP %s is enumerating RPC methods",
					req.SourceIP),
				Timestamp: req.Timestamp,
			})
		}
	}

	// Log sensitive method access
	if policy, ok := m.config.MethodPolicies[req.Method]; ok {
		if policy.RiskLevel == RiskHigh || policy.RiskLevel == RiskMedium {
			m.emitAlert(ctx, &Alert{
				ID:       uuid.New(),
				Type:     "sensitive_method_access",
				Severity: string(policy.RiskLevel),
				SourceIP: req.SourceIP,
				Method:   req.Method,
				Title:    "Sensitive RPC Method Access",
				Description: fmt.Sprintf("Sensitive method %s accessed from %s",
					req.Method, req.SourceIP),
				Timestamp: req.Timestamp,
			})
		}
	}

	return result
}

// ProcessResult contains the result of processing an RPC request.
type ProcessResult struct {
	Allowed     bool        `json:"allowed"`
	BlockReason string      `json:"block_reason,omitempty"`
	Request     *RPCRequest `json:"request"`
}

func (m *Monitor) checkBlocked(req *RPCRequest) (bool, string) {
	// Check exact match
	if policy, ok := m.config.MethodPolicies[req.Method]; ok && policy.Blocked {
		return true, fmt.Sprintf("method %s is blocked", req.Method)
	}

	// Check prefix patterns
	for _, blocked := range m.config.BlockedMethods {
		if strings.HasPrefix(req.Method, strings.TrimSuffix(blocked, "*")) {
			return true, fmt.Sprintf("method %s matches blocked pattern", req.Method)
		}
	}

	return false, ""
}

func (m *Monitor) checkRateLimit(req *RPCRequest) (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, exists := m.rateLimits[req.SourceIP]
	now := time.Now()

	// Check if temporarily blocked
	if exists && state.blocked && now.Before(state.unblockAt) {
		return true, "temporarily blocked due to rate limit violations"
	}

	// Reset window if expired
	if !exists || now.Sub(state.window) > time.Minute {
		m.rateLimits[req.SourceIP] = &rateLimitState{
			count:  1,
			window: now,
		}
		return false, ""
	}

	// Increment and check
	state.count++
	limit := m.config.DefaultRateLimit

	// Check method-specific limit
	if policy, ok := m.config.MethodPolicies[req.Method]; ok && policy.RateLimit > 0 {
		limit = policy.RateLimit
	}

	if state.count > limit {
		// Block for escalating duration
		blockDuration := time.Duration(state.count/limit) * time.Minute
		if blockDuration > 30*time.Minute {
			blockDuration = 30 * time.Minute
		}
		state.blocked = true
		state.unblockAt = now.Add(blockDuration)
		return true, fmt.Sprintf("rate limit exceeded (%d/%d)", state.count, limit)
	}

	return false, ""
}

func (m *Monitor) checkEnumeration(req *RPCRequest) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.methodCalls[req.SourceIP] == nil {
		m.methodCalls[req.SourceIP] = make(map[string]time.Time)
	}

	m.methodCalls[req.SourceIP][req.Method] = req.Timestamp

	// Count distinct methods in window
	cutoff := time.Now().Add(-m.config.EnumWindow)
	distinctMethods := 0
	for _, lastCall := range m.methodCalls[req.SourceIP] {
		if lastCall.After(cutoff) {
			distinctMethods++
		}
	}

	return distinctMethods >= m.config.EnumThreshold
}

func (m *Monitor) emitAlert(ctx context.Context, alert *Alert) {
	m.mu.RLock()
	handlers := m.handlers
	m.mu.RUnlock()

	for _, handler := range handlers {
		go func(h AlertHandler) {
			if err := h(ctx, alert); err != nil {
				slog.Error("RPC alert handler failed", "error", err)
			}
		}(handler)
	}
}

// ParseJSONRPC parses a JSON-RPC request.
func ParseJSONRPC(body []byte, sourceIP, userAgent string) (*RPCRequest, error) {
	var raw struct {
		JSONRPC string      `json:"jsonrpc"`
		ID      interface{} `json:"id"`
		Method  string      `json:"method"`
		Params  interface{} `json:"params"`
	}

	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC: %w", err)
	}

	var id string
	switch v := raw.ID.(type) {
	case string:
		id = v
	case float64:
		id = fmt.Sprintf("%.0f", v)
	default:
		id = "unknown"
	}

	return &RPCRequest{
		ID:        id,
		Type:      RPCTypeJSONRPC,
		Method:    raw.Method,
		Params:    raw.Params,
		Timestamp: time.Now(),
		SourceIP:  sourceIP,
		UserAgent: userAgent,
	}, nil
}

// ParseRESTRequest parses a REST API request.
func ParseRESTRequest(method, path, sourceIP, userAgent string) *RPCRequest {
	return &RPCRequest{
		ID:        uuid.New().String(),
		Type:      RPCTypeREST,
		Method:    fmt.Sprintf("%s %s", method, path),
		Timestamp: time.Now(),
		SourceIP:  sourceIP,
		UserAgent: userAgent,
	}
}

// GetStats returns monitor statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"total_requests":     m.totalRequests,
		"blocked_requests":   m.blockedRequests,
		"rate_limited":       m.rateLimitedReqs,
		"suspicious":         m.suspiciousReqs,
		"tracked_ips":        len(m.rateLimits),
		"blocked_methods":    len(m.config.BlockedMethods),
		"sensitive_methods":  len(m.config.SensitiveMethods),
	}
}

// NormalizeToEvent converts an RPC request to a schema.Event.
func (m *Monitor) NormalizeToEvent(req *RPCRequest, result *ProcessResult, tenantID string) *schema.Event {
	outcome := schema.OutcomeSuccess
	if req.Error != "" || !result.Allowed {
		outcome = schema.OutcomeFailure
	}

	severity := 2
	if policy, ok := m.config.MethodPolicies[req.Method]; ok {
		switch policy.RiskLevel {
		case RiskCritical:
			severity = 9
		case RiskHigh:
			severity = 7
		case RiskMedium:
			severity = 5
		}
	}

	if !result.Allowed {
		severity = 8
	}

	metadata := map[string]interface{}{
		"rpc_type":    string(req.Type),
		"method":      req.Method,
		"allowed":     result.Allowed,
		"user_agent":  req.UserAgent,
	}

	if req.Duration > 0 {
		metadata["duration_ms"] = req.Duration.Milliseconds()
	}
	if req.ResponseSize > 0 {
		metadata["response_size"] = req.ResponseSize
	}
	if req.Error != "" {
		metadata["error"] = req.Error
	}
	if result.BlockReason != "" {
		metadata["block_reason"] = result.BlockReason
	}

	return &schema.Event{
		EventID:   uuid.New(),
		Timestamp: req.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: "rpc-monitor",
			Version: "1.0",
		},
		Action:   fmt.Sprintf("rpc.%s", req.Method),
		Outcome:  outcome,
		Severity: severity,
		Target:   req.Method,
		Actor: &schema.Actor{
			ID:        req.SourceIP,
			Type:      schema.ActorUnknown,
			IPAddress: req.SourceIP,
		},
		Metadata: metadata,
	}
}

// Cleanup removes stale rate limit and enumeration data.
func (m *Monitor) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-m.config.EnumWindow * 2)

	// Clean rate limits
	for ip, state := range m.rateLimits {
		if time.Now().Sub(state.window) > 10*time.Minute && !state.blocked {
			delete(m.rateLimits, ip)
		}
	}

	// Clean method calls
	for ip, methods := range m.methodCalls {
		for method, lastCall := range methods {
			if lastCall.Before(cutoff) {
				delete(methods, method)
			}
		}
		if len(methods) == 0 {
			delete(m.methodCalls, ip)
		}
	}
}

// CreateCorrelationRules creates RPC security correlation rules.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "rpc-blocked-method-access",
			Name:        "Blocked RPC Method Access",
			Description: "Attempts to call blocked/sensitive RPC methods",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityCritical,
			Tags:        []string{"rpc", "security", "blocked"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0001",
				TacticName:  "Initial Access",
				TechniqueID: "T1190",
			},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "rpc.admin"},
			},
			GroupBy: []string{"actor.ip"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "rpc-enumeration",
			Name:        "RPC Method Enumeration",
			Description: "Source is enumerating available RPC methods",
			Type:        correlation.RuleTypeAggregate,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"rpc", "enumeration", "reconnaissance"},
			MITRE: &correlation.MITREMapping{
				TacticID:    "TA0007",
				TacticName:  "Discovery",
				TechniqueID: "T1046",
			},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "rpc."},
			},
			GroupBy: []string{"actor.ip"},
			Window:  5 * time.Minute,
			Aggregate: &correlation.AggregateConfig{
				Function: "count_distinct",
				Field:    "target",
				Operator: "gte",
				Value:    20,
			},
		},
		{
			ID:          "rpc-rate-limit-violation",
			Name:        "RPC Rate Limit Violation",
			Description: "Source is making excessive RPC requests",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityMedium,
			Tags:        []string{"rpc", "rate-limit", "abuse"},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "rpc."},
			},
			GroupBy: []string{"actor.ip"},
			Window:  1 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    100,
				Operator: "gte",
			},
		},
		{
			ID:          "rpc-sensitive-method-burst",
			Name:        "Sensitive Method Access Burst",
			Description: "Multiple accesses to sensitive RPC methods",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityHigh,
			Tags:        []string{"rpc", "sensitive", "burst"},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "in", Values: []string{
					"rpc.eth_accounts", "rpc.eth_sign", "rpc.personal_listAccounts",
				}},
			},
			GroupBy: []string{"actor.ip"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    5,
				Operator: "gte",
			},
		},
		{
			ID:          "rpc-error-spike",
			Name:        "RPC Error Spike",
			Description: "High rate of RPC errors from single source",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityMedium,
			Tags:        []string{"rpc", "errors"},
			Conditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "rpc."},
				{Field: "outcome", Operator: "eq", Value: "failure"},
			},
			GroupBy: []string{"actor.ip"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    50,
				Operator: "gte",
			},
		},
	}
}

// Common RPC method patterns for detection
var (
	EthereumMethods = regexp.MustCompile(`^(eth_|net_|web3_|personal_|admin_|debug_|miner_|txpool_)`)
	SolanaMethods   = regexp.MustCompile(`^(get|send|request|simulate)`)
	CosmosMethods   = regexp.MustCompile(`^(abci_|broadcast_|commit|consensus|health|net_|status|subscribe|tx|unsubscribe)`)
)

// IsBlockchainRPC checks if a method is a blockchain RPC method.
func IsBlockchainRPC(method string) bool {
	return EthereumMethods.MatchString(method) ||
		SolanaMethods.MatchString(method) ||
		CosmosMethods.MatchString(method)
}

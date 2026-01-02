// Package contracts provides smart contract event monitoring and decoding.
package contracts

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// EventSignature represents a known event signature.
type EventSignature struct {
	Hash        string   // Keccak256 hash of event signature
	Name        string   // Human-readable name
	Signature   string   // Full signature e.g., Transfer(address,address,uint256)
	Params      []string // Parameter types
	Indexed     []bool   // Which params are indexed
	Contract    string   // Contract type (e.g., "ERC20", "ERC721")
	Severity    int      // Default severity for this event
	Description string
}

// Log represents an Ethereum log/event.
type Log struct {
	Address     string   `json:"address"`
	Topics      []string `json:"topics"`
	Data        string   `json:"data"`
	BlockNumber uint64   `json:"block_number"`
	BlockHash   string   `json:"block_hash"`
	TxHash      string   `json:"tx_hash"`
	TxIndex     int      `json:"tx_index"`
	LogIndex    int      `json:"log_index"`
	Removed     bool     `json:"removed"`
	Timestamp   time.Time `json:"timestamp"`
	Network     string   `json:"network"`
}

// DecodedEvent represents a decoded smart contract event.
type DecodedEvent struct {
	Log
	EventName   string                 `json:"event_name"`
	Signature   string                 `json:"signature"`
	Contract    string                 `json:"contract"`
	Params      map[string]interface{} `json:"params"`
	Severity    int                    `json:"severity"`
	Description string                 `json:"description"`
}

// Alert represents a contract event alert.
type Alert struct {
	ID          uuid.UUID              `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Contract    string                 `json:"contract"`
	TxHash      string                 `json:"tx_hash"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertHandler processes contract event alerts.
type AlertHandler func(context.Context, *Alert) error

// MonitorConfig configures the contract event monitor.
type MonitorConfig struct {
	WatchedContracts    []string          // Contract addresses to monitor
	ContractLabels      map[string]string // address -> label
	AlertOnTransfer     bool
	AlertOnApproval     bool
	AlertOnOwnership    bool
	LargeTransferThreshold *big.Int
}

// DefaultMonitorConfig returns default configuration.
func DefaultMonitorConfig() MonitorConfig {
	threshold := new(big.Int)
	threshold.SetString("1000000000000000000000", 10) // 1000 tokens

	return MonitorConfig{
		WatchedContracts:       []string{},
		ContractLabels:         make(map[string]string),
		AlertOnTransfer:        true,
		AlertOnApproval:        true,
		AlertOnOwnership:       true,
		LargeTransferThreshold: threshold,
	}
}

// Monitor monitors smart contract events.
type Monitor struct {
	config     MonitorConfig
	signatures map[string]*EventSignature
	handlers   []AlertHandler
	mu         sync.RWMutex

	// Statistics
	eventCounts map[string]int64
	lastSeen    map[string]time.Time
}

// NewMonitor creates a new contract event monitor.
func NewMonitor(config MonitorConfig) *Monitor {
	m := &Monitor{
		config:      config,
		signatures:  make(map[string]*EventSignature),
		eventCounts: make(map[string]int64),
		lastSeen:    make(map[string]time.Time),
	}

	// Initialize known event signatures
	m.initSignatures()

	return m
}

func (m *Monitor) initSignatures() {
	// ERC20 Events
	m.signatures["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"] = &EventSignature{
		Hash:        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
		Name:        "Transfer",
		Signature:   "Transfer(address,address,uint256)",
		Params:      []string{"from", "to", "value"},
		Indexed:     []bool{true, true, false},
		Contract:    "ERC20",
		Severity:    1,
		Description: "Token transfer",
	}

	m.signatures["0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"] = &EventSignature{
		Hash:        "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
		Name:        "Approval",
		Signature:   "Approval(address,address,uint256)",
		Params:      []string{"owner", "spender", "value"},
		Indexed:     []bool{true, true, false},
		Contract:    "ERC20",
		Severity:    3,
		Description: "Token approval granted",
	}

	// ERC721 Events
	m.signatures["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"] = &EventSignature{
		Hash:        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
		Name:        "Transfer",
		Signature:   "Transfer(address,address,uint256)",
		Params:      []string{"from", "to", "tokenId"},
		Indexed:     []bool{true, true, true},
		Contract:    "ERC721",
		Severity:    2,
		Description: "NFT transfer",
	}

	m.signatures["0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"] = &EventSignature{
		Hash:        "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31",
		Name:        "ApprovalForAll",
		Signature:   "ApprovalForAll(address,address,bool)",
		Params:      []string{"owner", "operator", "approved"},
		Indexed:     []bool{true, true, false},
		Contract:    "ERC721",
		Severity:    5,
		Description: "Full collection approval granted",
	}

	// Ownership Events
	m.signatures["0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"] = &EventSignature{
		Hash:        "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
		Name:        "OwnershipTransferred",
		Signature:   "OwnershipTransferred(address,address)",
		Params:      []string{"previousOwner", "newOwner"},
		Indexed:     []bool{true, true},
		Contract:    "Ownable",
		Severity:    8,
		Description: "Contract ownership transferred",
	}

	// Proxy Events
	m.signatures["0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"] = &EventSignature{
		Hash:        "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
		Name:        "Upgraded",
		Signature:   "Upgraded(address)",
		Params:      []string{"implementation"},
		Indexed:     []bool{true},
		Contract:    "Proxy",
		Severity:    9,
		Description: "Proxy implementation upgraded",
	}

	m.signatures["0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f"] = &EventSignature{
		Hash:        "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f",
		Name:        "AdminChanged",
		Signature:   "AdminChanged(address,address)",
		Params:      []string{"previousAdmin", "newAdmin"},
		Indexed:     []bool{false, false},
		Contract:    "Proxy",
		Severity:    9,
		Description: "Proxy admin changed",
	}

	// Security Events
	m.signatures["0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258"] = &EventSignature{
		Hash:        "0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258",
		Name:        "Paused",
		Signature:   "Paused(address)",
		Params:      []string{"account"},
		Indexed:     []bool{false},
		Contract:    "Pausable",
		Severity:    7,
		Description: "Contract paused",
	}

	m.signatures["0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa"] = &EventSignature{
		Hash:        "0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa",
		Name:        "Unpaused",
		Signature:   "Unpaused(address)",
		Params:      []string{"account"},
		Indexed:     []bool{false},
		Contract:    "Pausable",
		Severity:    5,
		Description: "Contract unpaused",
	}

	// DeFi Events
	m.signatures["0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"] = &EventSignature{
		Hash:        "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822",
		Name:        "Swap",
		Signature:   "Swap(address,uint256,uint256,uint256,uint256,address)",
		Params:      []string{"sender", "amount0In", "amount1In", "amount0Out", "amount1Out", "to"},
		Indexed:     []bool{true, false, false, false, false, true},
		Contract:    "UniswapV2Pair",
		Severity:    2,
		Description: "DEX swap executed",
	}

	m.signatures["0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1"] = &EventSignature{
		Hash:        "0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1",
		Name:        "Sync",
		Signature:   "Sync(uint112,uint112)",
		Params:      []string{"reserve0", "reserve1"},
		Indexed:     []bool{false, false},
		Contract:    "UniswapV2Pair",
		Severity:    1,
		Description: "Pool reserves synced",
	}

	// Governance Events
	m.signatures["0x789cf55be980739dad1d0699b93b58e806b51c9d96619bfa8fe0a28a05eb1c6a"] = &EventSignature{
		Hash:        "0x789cf55be980739dad1d0699b93b58e806b51c9d96619bfa8fe0a28a05eb1c6a",
		Name:        "ProposalCreated",
		Signature:   "ProposalCreated(uint256,address,address[],uint256[],string[],bytes[],uint256,uint256,string)",
		Params:      []string{"proposalId", "proposer", "targets", "values", "signatures", "calldatas", "startBlock", "endBlock", "description"},
		Indexed:     []bool{false, false, false, false, false, false, false, false, false},
		Contract:    "Governor",
		Severity:    6,
		Description: "Governance proposal created",
	}

	m.signatures["0xb8e138887d0aa13bab447e82de9d5c1777041ecd21ca36ba824ff1e6c07ddda4"] = &EventSignature{
		Hash:        "0xb8e138887d0aa13bab447e82de9d5c1777041ecd21ca36ba824ff1e6c07ddda4",
		Name:        "ProposalExecuted",
		Signature:   "ProposalExecuted(uint256)",
		Params:      []string{"proposalId"},
		Indexed:     []bool{false},
		Contract:    "Governor",
		Severity:    8,
		Description: "Governance proposal executed",
	}

	// Access Control Events
	m.signatures["0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"] = &EventSignature{
		Hash:        "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d",
		Name:        "RoleGranted",
		Signature:   "RoleGranted(bytes32,address,address)",
		Params:      []string{"role", "account", "sender"},
		Indexed:     []bool{true, true, true},
		Contract:    "AccessControl",
		Severity:    7,
		Description: "Role granted to account",
	}

	m.signatures["0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b"] = &EventSignature{
		Hash:        "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b",
		Name:        "RoleRevoked",
		Signature:   "RoleRevoked(bytes32,address,address)",
		Params:      []string{"role", "account", "sender"},
		Indexed:     []bool{true, true, true},
		Contract:    "AccessControl",
		Severity:    6,
		Description: "Role revoked from account",
	}
}

// AddHandler adds an alert handler.
func (m *Monitor) AddHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// AddWatchedContract adds a contract to monitor.
func (m *Monitor) AddWatchedContract(address, label string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	address = strings.ToLower(address)
	m.config.WatchedContracts = append(m.config.WatchedContracts, address)
	m.config.ContractLabels[address] = label
}

// ProcessLog processes a raw log and decodes it.
func (m *Monitor) ProcessLog(log *Log) (*DecodedEvent, error) {
	if len(log.Topics) == 0 {
		return nil, fmt.Errorf("log has no topics")
	}

	log.Address = strings.ToLower(log.Address)
	topic0 := strings.ToLower(log.Topics[0])

	// Look up event signature
	m.mu.RLock()
	sig, known := m.signatures[topic0]
	m.mu.RUnlock()

	event := &DecodedEvent{
		Log:    *log,
		Params: make(map[string]interface{}),
	}

	if known {
		event.EventName = sig.Name
		event.Signature = sig.Signature
		event.Contract = sig.Contract
		event.Severity = sig.Severity
		event.Description = sig.Description

		// Decode parameters
		m.decodeParams(event, sig)
	} else {
		event.EventName = "Unknown"
		event.Signature = topic0
		event.Contract = "Unknown"
		event.Severity = 3
	}

	// Update statistics
	m.mu.Lock()
	m.eventCounts[event.EventName]++
	m.lastSeen[log.Address] = log.Timestamp
	m.mu.Unlock()

	// Check for alerts
	m.checkAlerts(event)

	return event, nil
}

func (m *Monitor) decodeParams(event *DecodedEvent, sig *EventSignature) {
	// Decode indexed parameters from topics
	topicIndex := 1
	for i, param := range sig.Params {
		if i < len(sig.Indexed) && sig.Indexed[i] {
			if topicIndex < len(event.Topics) {
				event.Params[param] = m.decodeTopicValue(event.Topics[topicIndex], param)
				topicIndex++
			}
		}
	}

	// Decode non-indexed parameters from data
	if len(event.Data) > 2 {
		data := event.Data[2:] // Remove 0x prefix
		dataIndex := 0
		for i, param := range sig.Params {
			if i >= len(sig.Indexed) || !sig.Indexed[i] {
				if dataIndex+64 <= len(data) {
					event.Params[param] = m.decodeDataValue(data[dataIndex:dataIndex+64], param)
					dataIndex += 64
				}
			}
		}
	}
}

func (m *Monitor) decodeTopicValue(topic, paramName string) interface{} {
	// Remove 0x prefix
	if strings.HasPrefix(topic, "0x") {
		topic = topic[2:]
	}

	// Address type
	if strings.Contains(paramName, "owner") || strings.Contains(paramName, "spender") ||
		strings.Contains(paramName, "from") || strings.Contains(paramName, "to") ||
		strings.Contains(paramName, "sender") || strings.Contains(paramName, "account") ||
		strings.Contains(paramName, "operator") || strings.Contains(paramName, "Admin") ||
		strings.Contains(paramName, "implementation") {
		if len(topic) >= 40 {
			return "0x" + topic[len(topic)-40:]
		}
	}

	// uint256 type
	value := new(big.Int)
	value.SetString(topic, 16)
	return value.String()
}

func (m *Monitor) decodeDataValue(data, paramName string) interface{} {
	// uint256 type
	value := new(big.Int)
	value.SetString(data, 16)
	return value.String()
}

func (m *Monitor) checkAlerts(event *DecodedEvent) {
	ctx := context.Background()

	// Check if contract is watched
	isWatched := false
	contractLabel := event.Address
	m.mu.RLock()
	for _, addr := range m.config.WatchedContracts {
		if addr == event.Address {
			isWatched = true
			if label, ok := m.config.ContractLabels[addr]; ok {
				contractLabel = label
			}
			break
		}
	}
	m.mu.RUnlock()

	// High severity events always alert
	if event.Severity >= 7 {
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     fmt.Sprintf("contract_%s", strings.ToLower(event.EventName)),
			Severity: m.severityString(event.Severity),
			Title:    fmt.Sprintf("%s: %s", event.Contract, event.EventName),
			Description: fmt.Sprintf("%s on contract %s",
				event.Description, contractLabel),
			Timestamp: event.Timestamp,
			Contract:  event.Address,
			TxHash:    event.TxHash,
			Metadata: map[string]interface{}{
				"event_name": event.EventName,
				"signature":  event.Signature,
				"params":     event.Params,
				"block":      event.BlockNumber,
				"network":    event.Network,
			},
		})
		return
	}

	// Watched contracts get more alerts
	if isWatched {
		if m.config.AlertOnTransfer && event.EventName == "Transfer" {
			// Check for large transfers
			if valueStr, ok := event.Params["value"].(string); ok {
				value := new(big.Int)
				value.SetString(valueStr, 10)
				if m.config.LargeTransferThreshold != nil &&
					value.Cmp(m.config.LargeTransferThreshold) > 0 {
					m.emitAlert(ctx, &Alert{
						ID:          uuid.New(),
						Type:        "large_transfer",
						Severity:    "high",
						Title:       fmt.Sprintf("Large Transfer on %s", contractLabel),
						Description: fmt.Sprintf("Transfer of %s tokens", valueStr),
						Timestamp:   event.Timestamp,
						Contract:    event.Address,
						TxHash:      event.TxHash,
						Metadata: map[string]interface{}{
							"from":    event.Params["from"],
							"to":      event.Params["to"],
							"value":   valueStr,
							"network": event.Network,
						},
					})
				}
			}
		}

		if m.config.AlertOnApproval && event.EventName == "Approval" {
			m.emitAlert(ctx, &Alert{
				ID:          uuid.New(),
				Type:        "token_approval",
				Severity:    "medium",
				Title:       fmt.Sprintf("Token Approval on %s", contractLabel),
				Description: event.Description,
				Timestamp:   event.Timestamp,
				Contract:    event.Address,
				TxHash:      event.TxHash,
				Metadata: map[string]interface{}{
					"owner":   event.Params["owner"],
					"spender": event.Params["spender"],
					"value":   event.Params["value"],
					"network": event.Network,
				},
			})
		}

		if m.config.AlertOnApproval && event.EventName == "ApprovalForAll" {
			m.emitAlert(ctx, &Alert{
				ID:          uuid.New(),
				Type:        "nft_approval_all",
				Severity:    "high",
				Title:       fmt.Sprintf("Full Collection Approval on %s", contractLabel),
				Description: "Operator granted access to all tokens",
				Timestamp:   event.Timestamp,
				Contract:    event.Address,
				TxHash:      event.TxHash,
				Metadata: map[string]interface{}{
					"owner":    event.Params["owner"],
					"operator": event.Params["operator"],
					"approved": event.Params["approved"],
					"network":  event.Network,
				},
			})
		}
	}
}

func (m *Monitor) severityString(sev int) string {
	switch {
	case sev >= 9:
		return "critical"
	case sev >= 7:
		return "high"
	case sev >= 4:
		return "medium"
	default:
		return "low"
	}
}

func (m *Monitor) emitAlert(ctx context.Context, alert *Alert) {
	m.mu.RLock()
	handlers := m.handlers
	m.mu.RUnlock()

	for _, handler := range handlers {
		go func(h AlertHandler) {
			if err := h(ctx, alert); err != nil {
				slog.Error("contract alert handler failed", "error", err)
			}
		}(handler)
	}
}

// NormalizeToEvent converts a decoded event to a schema.Event.
func (m *Monitor) NormalizeToEvent(event *DecodedEvent, tenantID string) *schema.Event {
	action := fmt.Sprintf("contract.%s.%s",
		strings.ToLower(event.Contract),
		strings.ToLower(event.EventName))

	outcome := schema.OutcomeSuccess
	if event.Removed {
		outcome = schema.OutcomeFailure
	}

	metadata := map[string]interface{}{
		"contract_address": event.Address,
		"event_name":       event.EventName,
		"signature":        event.Signature,
		"tx_hash":          event.TxHash,
		"block_number":     event.BlockNumber,
		"log_index":        event.LogIndex,
		"network":          event.Network,
	}

	// Add decoded params
	for k, v := range event.Params {
		metadata[k] = v
	}

	var actor *schema.Actor
	if from, ok := event.Params["from"].(string); ok {
		actor = &schema.Actor{
			ID:   from,
			Type: "address",
		}
	} else if sender, ok := event.Params["sender"].(string); ok {
		actor = &schema.Actor{
			ID:   sender,
			Type: "address",
		}
	}

	target := event.Address
	if to, ok := event.Params["to"].(string); ok {
		target = to
	}

	return &schema.Event{
		EventID:   uuid.New(),
		Timestamp: event.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product:  "contract-monitor",
			Host:     event.Network,
			Version:  "1.0",
		},
		Action:   action,
		Outcome:  outcome,
		Severity: event.Severity,
		Target:   target,
		Actor:    actor,
		Metadata: metadata,
	}
}

// GetStats returns monitoring statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"known_signatures":   len(m.signatures),
		"watched_contracts":  len(m.config.WatchedContracts),
		"event_counts":       m.eventCounts,
		"handler_count":      len(m.handlers),
	}
}

// AddSignature adds a custom event signature to monitor.
func (m *Monitor) AddSignature(sig *EventSignature) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.signatures[strings.ToLower(sig.Hash)] = sig
}

// ParseLogFromHex parses a log from hex-encoded data.
func ParseLogFromHex(address string, topicsHex []string, dataHex string) (*Log, error) {
	log := &Log{
		Address:   address,
		Topics:    topicsHex,
		Data:      dataHex,
		Timestamp: time.Now(),
	}
	return log, nil
}

// CreateCorrelationRules creates contract-related correlation rules.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "contract-ownership-change",
			Name:        "Contract Ownership Change",
			Description: "Detects ownership transfers in smart contracts",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"blockchain", "contract", "ownership", "security"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "contract.ownable.ownershiptransferred"},
			},
			GroupBy: []string{"metadata.contract_address"},
			Window:  24 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "contract-proxy-upgrade",
			Name:        "Proxy Contract Upgrade",
			Description: "Detects upgrades to proxy contract implementations",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityCritical),
			Tags:        []string{"blockchain", "contract", "proxy", "upgrade"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "contract.proxy.upgraded"},
			},
			GroupBy: []string{"metadata.contract_address"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "contract-paused",
			Name:        "Contract Paused",
			Description: "Contract has been paused - may indicate emergency",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "contract", "pause", "emergency"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "contract.pausable.paused"},
			},
			GroupBy: []string{"metadata.contract_address"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "contract-role-changes",
			Name:        "Multiple Role Changes",
			Description: "Multiple access control role changes in short period",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "contract", "access-control"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "contract.accesscontrol.role"},
			},
			GroupBy: []string{"metadata.contract_address"},
			Window:  15 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    3,
				Operator: "gte",
			},
		},
		{
			ID:          "contract-governance-executed",
			Name:        "Governance Proposal Executed",
			Description: "Governance proposal has been executed",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "governance", "execution"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "contract.governor.proposalexecuted"},
			},
			GroupBy: []string{"metadata.contract_address"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    1,
				Operator: "gte",
			},
		},
		{
			ID:          "contract-unlimited-approval",
			Name:        "Unlimited Token Approval",
			Description: "Detects unlimited token approvals (potential phishing)",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityMedium),
			Tags:        []string{"blockchain", "token", "approval", "security"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "contract.erc20.approval"},
			},
			GroupBy: []string{"actor.id", "metadata.spender"},
			Window:  1 * time.Hour,
			Threshold: &correlation.ThresholdConfig{
				Count:    5,
				Operator: "gte",
			},
		},
	}
}

// WebSocketSubscriber provides real-time contract event subscription.
type WebSocketSubscriber struct {
	endpoint  string
	contracts []string
	monitor   *Monitor
	stopCh    chan struct{}
}

// NewWebSocketSubscriber creates a new WebSocket subscriber.
func NewWebSocketSubscriber(endpoint string, monitor *Monitor) *WebSocketSubscriber {
	return &WebSocketSubscriber{
		endpoint:  endpoint,
		contracts: make([]string, 0),
		monitor:   monitor,
		stopCh:    make(chan struct{}),
	}
}

// Subscribe starts subscribing to contract events.
// This is a placeholder - actual implementation would use go-ethereum or similar.
func (s *WebSocketSubscriber) Subscribe(ctx context.Context, addresses []string) error {
	s.contracts = addresses
	slog.Info("contract event subscription started",
		"endpoint", s.endpoint,
		"contracts", len(addresses))

	// In production, this would connect to an Ethereum node via WebSocket
	// and subscribe to logs for the specified contract addresses.
	// Example using go-ethereum:
	//   client, _ := ethclient.Dial(s.endpoint)
	//   query := ethereum.FilterQuery{Addresses: addresses}
	//   logs := make(chan types.Log)
	//   sub, _ := client.SubscribeFilterLogs(ctx, query, logs)

	return nil
}

// Stop stops the subscription.
func (s *WebSocketSubscriber) Stop() {
	close(s.stopCh)
}

// GetContractLabel gets the label for a contract address.
func GetContractLabel(address string) string {
	address = strings.ToLower(address)

	// Known contract labels
	labels := map[string]string{
		"0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
		"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
		"0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
		"0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
		"0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": "WBTC",
		"0x7d1afa7b718fb893db30a3abc0cfc608aacfebb0": "MATIC",
		"0x514910771af9ca656af840dff83e8264ecf986ca": "LINK",
		"0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": "UNI",
		"0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9": "AAVE",
	}

	if label, ok := labels[address]; ok {
		return label
	}

	// Return abbreviated address
	if len(address) > 10 {
		return address[:6] + "..." + address[len(address)-4:]
	}
	return address
}

// HexToBytes converts a hex string to bytes.
func HexToBytes(hexStr string) ([]byte, error) {
	if strings.HasPrefix(hexStr, "0x") {
		hexStr = hexStr[2:]
	}
	return hex.DecodeString(hexStr)
}

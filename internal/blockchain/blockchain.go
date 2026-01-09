// Package blockchain provides unified blockchain security monitoring.
package blockchain

import (
	"context"
	"log/slog"
	"sync"

	"boundary-siem/internal/blockchain/consensus"
	"boundary-siem/internal/blockchain/contracts"
	"boundary-siem/internal/blockchain/ethereum"
	"boundary-siem/internal/blockchain/mempool"
	"boundary-siem/internal/blockchain/validator"
	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"
)

// NetworkType represents the blockchain network type.
type NetworkType string

const (
	NetworkEthereum  NetworkType = "ethereum"
	NetworkPolygon   NetworkType = "polygon"
	NetworkArbitrum  NetworkType = "arbitrum"
	NetworkOptimism  NetworkType = "optimism"
	NetworkBSC       NetworkType = "bsc"
	NetworkAvalanche NetworkType = "avalanche"
	NetworkSolana    NetworkType = "solana"
	NetworkCosmos    NetworkType = "cosmos"
)

// Config configures the unified blockchain monitor.
type Config struct {
	Network         NetworkType
	EnableValidator bool
	EnableMempool   bool
	EnableContracts bool
	ValidatorConfig validator.MonitorConfig
	MempoolConfig   mempool.MonitorConfig
	ContractConfig  contracts.MonitorConfig
}

// DefaultConfig returns default configuration for Ethereum.
func DefaultConfig() Config {
	return Config{
		Network:         NetworkEthereum,
		EnableValidator: true,
		EnableMempool:   true,
		EnableContracts: true,
		ValidatorConfig: validator.DefaultMonitorConfig(),
		MempoolConfig:   mempool.DefaultMonitorConfig(),
		ContractConfig:  contracts.DefaultMonitorConfig(),
	}
}

// Monitor provides unified blockchain security monitoring.
type Monitor struct {
	config Config

	// Sub-monitors
	gethParser      *ethereum.GethParser
	consensusParser *consensus.Parser
	validatorMon    *validator.Monitor
	mempoolMon      *mempool.Monitor
	contractMon     *contracts.Monitor

	// Event processing
	eventCh  chan *schema.Event
	handlers []func(context.Context, *schema.Event) error
	stopCh   chan struct{}
	wg       sync.WaitGroup
	mu       sync.RWMutex
}

// NewMonitor creates a new unified blockchain monitor.
func NewMonitor(config Config) *Monitor {
	m := &Monitor{
		config:  config,
		eventCh: make(chan *schema.Event, 10000),
		stopCh:  make(chan struct{}),
	}

	// Initialize parsers
	m.gethParser = ethereum.NewGethParser()

	// Initialize sub-monitors
	if config.EnableValidator {
		m.validatorMon = validator.NewMonitor(config.ValidatorConfig)
	}

	if config.EnableMempool {
		m.mempoolMon = mempool.NewMonitor(config.MempoolConfig)
	}

	if config.EnableContracts {
		m.contractMon = contracts.NewMonitor(config.ContractConfig)
	}

	return m
}

// Start starts the blockchain monitor.
func (m *Monitor) Start(ctx context.Context) {
	m.wg.Add(1)
	go m.eventProcessor(ctx)

	slog.Info("blockchain monitor started",
		"network", m.config.Network,
		"validator", m.config.EnableValidator,
		"mempool", m.config.EnableMempool,
		"contracts", m.config.EnableContracts)
}

// Stop stops the blockchain monitor.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	slog.Info("blockchain monitor stopped")
}

// AddEventHandler adds a handler for normalized events.
func (m *Monitor) AddEventHandler(handler func(context.Context, *schema.Event) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// ProcessGethLog processes a Geth execution client log line.
func (m *Monitor) ProcessGethLog(line, sourceIP, tenantID string) (*schema.Event, error) {
	entry, err := m.gethParser.Parse(line)
	if err != nil {
		return nil, err
	}

	event, err := m.gethParser.Normalize(entry, sourceIP)
	if err != nil {
		return nil, err
	}

	event.TenantID = tenantID

	// Forward to validator monitor if relevant
	if m.validatorMon != nil {
		m.validatorMon.ProcessEvent(event)
	}

	m.emitEvent(event)
	return event, nil
}

// ProcessConsensusLog processes a consensus client log line.
func (m *Monitor) ProcessConsensusLog(clientType consensus.ClientType, line, sourceIP, tenantID string) (*schema.Event, error) {
	parser := consensus.NewParser(clientType)
	entry, err := parser.Parse(line)
	if err != nil {
		return nil, err
	}

	event, err := parser.Normalize(entry, sourceIP)
	if err != nil {
		return nil, err
	}

	event.TenantID = tenantID

	// Forward to validator monitor
	if m.validatorMon != nil {
		m.validatorMon.ProcessEvent(event)
	}

	m.emitEvent(event)
	return event, nil
}

// ProcessTransaction processes a blockchain transaction.
func (m *Monitor) ProcessTransaction(tx *mempool.Transaction, tenantID string) (*schema.Event, error) {
	if m.mempoolMon == nil {
		return nil, nil
	}

	if tx.BlockNumber == 0 {
		m.mempoolMon.ProcessPendingTx(tx)
	} else {
		m.mempoolMon.ProcessConfirmedTx(tx)
	}

	event := m.mempoolMon.NormalizeToEvent(tx, tenantID)
	m.emitEvent(event)
	return event, nil
}

// ProcessContractLog processes a smart contract event log.
func (m *Monitor) ProcessContractLog(log *contracts.Log, tenantID string) (*schema.Event, error) {
	if m.contractMon == nil {
		return nil, nil
	}

	decoded, err := m.contractMon.ProcessLog(log)
	if err != nil {
		return nil, err
	}

	event := m.contractMon.NormalizeToEvent(decoded, tenantID)
	m.emitEvent(event)
	return event, nil
}

// AddWatchedContract adds a contract to monitor.
func (m *Monitor) AddWatchedContract(address, label string) {
	if m.contractMon != nil {
		m.contractMon.AddWatchedContract(address, label)
	}
}

// AddWatchedValidator adds a validator to monitor.
func (m *Monitor) AddWatchedValidator(index int64, pubkey string) {
	if m.validatorMon != nil {
		m.validatorMon.AddWatchedValidator(index, pubkey)
	}
}

func (m *Monitor) emitEvent(event *schema.Event) {
	select {
	case m.eventCh <- event:
	default:
		slog.Warn("blockchain event channel full")
	}
}

func (m *Monitor) eventProcessor(ctx context.Context) {
	defer m.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case event := <-m.eventCh:
			m.mu.RLock()
			handlers := m.handlers
			m.mu.RUnlock()

			for _, handler := range handlers {
				if err := handler(ctx, event); err != nil {
					slog.Error("event handler failed", "error", err)
				}
			}
		}
	}
}

// GetStats returns combined statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"network":     m.config.Network,
		"event_queue": len(m.eventCh),
	}

	if m.validatorMon != nil {
		stats["validator"] = m.validatorMon.GetStats()
	}

	if m.mempoolMon != nil {
		stats["mempool"] = m.mempoolMon.GetStats()
	}

	if m.contractMon != nil {
		stats["contracts"] = m.contractMon.GetStats()
	}

	return stats
}

// GetCorrelationRules returns all blockchain-related correlation rules.
func GetCorrelationRules() []*correlation.Rule {
	var rules []*correlation.Rule

	// Validator rules
	rules = append(rules, validator.CreateCorrelationRules()...)

	// Mempool/MEV rules
	rules = append(rules, mempool.CreateCorrelationRules()...)

	// Contract rules
	rules = append(rules, contracts.CreateCorrelationRules()...)

	return rules
}

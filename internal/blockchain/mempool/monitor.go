// Package mempool provides mempool and transaction monitoring capabilities.
package mempool

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// TransactionType categorizes transaction types.
type TransactionType string

const (
	TxTypeTransfer  TransactionType = "transfer"
	TxTypeSwap      TransactionType = "swap"
	TxTypeFlashLoan TransactionType = "flash_loan"
	TxTypeLiquidity TransactionType = "liquidity"
	TxTypeArbitrage TransactionType = "arbitrage"
	TxTypeSandwich  TransactionType = "sandwich"
	TxTypeMEV       TransactionType = "mev"
	TxTypeContract  TransactionType = "contract"
	TxTypeUnknown   TransactionType = "unknown"
)

// Transaction represents a blockchain transaction.
type Transaction struct {
	Hash        string          `json:"hash"`
	From        string          `json:"from"`
	To          string          `json:"to"`
	Value       *big.Int        `json:"value"`
	GasPrice    *big.Int        `json:"gas_price"`
	GasLimit    uint64          `json:"gas_limit"`
	GasUsed     uint64          `json:"gas_used,omitempty"`
	Nonce       uint64          `json:"nonce"`
	Data        []byte          `json:"data"`
	BlockNumber uint64          `json:"block_number,omitempty"`
	BlockHash   string          `json:"block_hash,omitempty"`
	TxIndex     int             `json:"tx_index,omitempty"`
	Timestamp   time.Time       `json:"timestamp"`
	Type        TransactionType `json:"type"`
	Network     string          `json:"network"`
	// Decoded fields
	MethodID   string   `json:"method_id,omitempty"`
	MethodName string   `json:"method_name,omitempty"`
	TokenIn    string   `json:"token_in,omitempty"`
	TokenOut   string   `json:"token_out,omitempty"`
	AmountIn   *big.Int `json:"amount_in,omitempty"`
	AmountOut  *big.Int `json:"amount_out,omitempty"`
	// MEV-related
	IsMEV          bool     `json:"is_mev"`
	MEVProfit      *big.Int `json:"mev_profit,omitempty"`
	SandwichVictim string   `json:"sandwich_victim,omitempty"`
}

// PendingTx represents a transaction in the mempool.
type PendingTx struct {
	Transaction
	FirstSeen   time.Time `json:"first_seen"`
	LastUpdated time.Time `json:"last_updated"`
	SeenCount   int       `json:"seen_count"`
	Replaced    bool      `json:"replaced"`
	Dropped     bool      `json:"dropped"`
}

// MonitorConfig configures the mempool monitor.
type MonitorConfig struct {
	MEVDetection           bool
	SandwichDetection      bool
	FlashLoanDetection     bool
	LargeTransferThreshold *big.Int
	GasPriceThreshold      *big.Int
	WindowDuration         time.Duration
	MaxPendingTxs          int
}

// DefaultMonitorConfig returns default configuration.
func DefaultMonitorConfig() MonitorConfig {
	largeThreshold := new(big.Int)
	largeThreshold.SetString("1000000000000000000000", 10) // 1000 ETH

	gasThreshold := new(big.Int)
	gasThreshold.SetString("500000000000", 10) // 500 Gwei

	return MonitorConfig{
		MEVDetection:           true,
		SandwichDetection:      true,
		FlashLoanDetection:     true,
		LargeTransferThreshold: largeThreshold,
		GasPriceThreshold:      gasThreshold,
		WindowDuration:         5 * time.Minute,
		MaxPendingTxs:          100000,
	}
}

// Alert represents a mempool security alert.
type Alert struct {
	ID          uuid.UUID              `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	TxHashes    []string               `json:"tx_hashes"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AlertHandler processes mempool alerts.
type AlertHandler func(context.Context, *Alert) error

// Monitor monitors the mempool for suspicious activity.
type Monitor struct {
	config    MonitorConfig
	pending   map[string]*PendingTx
	txByBlock map[uint64][]*Transaction
	handlers  []AlertHandler
	mu        sync.RWMutex

	// Detection state
	swapsByPair map[string][]*Transaction // DEX pair -> recent swaps
	flashLoans  map[string]time.Time      // Recent flash loan sources
	mevBots     map[string]int            // Known MEV bot addresses -> count

	// Known addresses
	knownDEXRouters map[string]string // address -> name
	knownFlashLoan  map[string]string // address -> protocol
	knownMEVBots    map[string]bool
}

// NewMonitor creates a new mempool monitor.
func NewMonitor(config MonitorConfig) *Monitor {
	m := &Monitor{
		config:          config,
		pending:         make(map[string]*PendingTx),
		txByBlock:       make(map[uint64][]*Transaction),
		swapsByPair:     make(map[string][]*Transaction),
		flashLoans:      make(map[string]time.Time),
		mevBots:         make(map[string]int),
		knownDEXRouters: make(map[string]string),
		knownFlashLoan:  make(map[string]string),
		knownMEVBots:    make(map[string]bool),
	}

	// Initialize known addresses
	m.initKnownAddresses()

	return m
}

func (m *Monitor) initKnownAddresses() {
	// Known DEX routers (Ethereum mainnet)
	m.knownDEXRouters = map[string]string{
		"0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
		"0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
		"0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 Router 2",
		"0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
		"0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange",
		"0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch V4",
		"0x1111111254eeb25477b68fb85ed929f73a960582": "1inch V5",
	}

	// Known flash loan providers
	m.knownFlashLoan = map[string]string{
		"0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9": "Aave V2 Pool",
		"0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": "Aave V3 Pool",
		"0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f": "Uniswap V2 Factory",
		"0x1f98431c8ad98523631ae4a59f267346ea31f984": "Uniswap V3 Factory",
		"0x6bdec92e7ff66fed64a1d34c2bccf69d9b3f8a09": "dYdX",
	}
}

// AddHandler adds an alert handler.
func (m *Monitor) AddHandler(handler AlertHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers = append(m.handlers, handler)
}

// ProcessPendingTx processes a pending transaction from the mempool.
func (m *Monitor) ProcessPendingTx(tx *Transaction) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Classify transaction
	tx.Type = m.classifyTransaction(tx)

	// Track pending tx
	if existing, ok := m.pending[tx.Hash]; ok {
		existing.LastUpdated = now
		existing.SeenCount++
		// Check for replacement (same nonce, higher gas)
		if existing.GasPrice.Cmp(tx.GasPrice) < 0 {
			existing.Replaced = true
		}
	} else {
		m.pending[tx.Hash] = &PendingTx{
			Transaction: *tx,
			FirstSeen:   now,
			LastUpdated: now,
			SeenCount:   1,
		}
	}

	// Run detection if enabled
	m.detectThreats(tx)
}

// ProcessConfirmedTx processes a confirmed transaction.
func (m *Monitor) ProcessConfirmedTx(tx *Transaction) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from pending
	delete(m.pending, tx.Hash)

	// Track by block for analysis
	m.txByBlock[tx.BlockNumber] = append(m.txByBlock[tx.BlockNumber], tx)

	// Classify if not already
	if tx.Type == TxTypeUnknown {
		tx.Type = m.classifyTransaction(tx)
	}

	// Run post-confirmation analysis
	m.analyzeConfirmedTx(tx)
}

func (m *Monitor) classifyTransaction(tx *Transaction) TransactionType {
	// Check if it's a simple transfer (no data)
	if len(tx.Data) == 0 || (len(tx.Data) == 1 && tx.Data[0] == 0) {
		return TxTypeTransfer
	}

	// Extract method ID (first 4 bytes)
	if len(tx.Data) >= 4 {
		tx.MethodID = fmt.Sprintf("0x%x", tx.Data[:4])
	}

	// Check known DEX routers
	if _, ok := m.knownDEXRouters[tx.To]; ok {
		return m.classifyDEXTx(tx)
	}

	// Check flash loan providers
	if _, ok := m.knownFlashLoan[tx.To]; ok {
		return TxTypeFlashLoan
	}

	// Check known method signatures
	switch tx.MethodID {
	// Uniswap V2
	case "0x38ed1739", "0x8803dbee", "0x7ff36ab5", "0xfb3bdb41":
		tx.MethodName = "swapExactTokensForTokens"
		return TxTypeSwap
	case "0x18cbafe5", "0x4a25d94a":
		tx.MethodName = "swapExactTokensForETH"
		return TxTypeSwap
	// Uniswap V3
	case "0x414bf389":
		tx.MethodName = "exactInputSingle"
		return TxTypeSwap
	case "0xc04b8d59":
		tx.MethodName = "exactInput"
		return TxTypeSwap
	// Flash loans
	case "0xab9c4b5d", "0x5cffe9de":
		tx.MethodName = "flashLoan"
		return TxTypeFlashLoan
	// Liquidity
	case "0xe8e33700", "0xf305d719":
		tx.MethodName = "addLiquidity"
		return TxTypeLiquidity
	case "0xbaa2abde", "0x02751cec":
		tx.MethodName = "removeLiquidity"
		return TxTypeLiquidity
	}

	return TxTypeContract
}

func (m *Monitor) classifyDEXTx(tx *Transaction) TransactionType {
	switch tx.MethodID {
	case "0x38ed1739", "0x8803dbee", "0x7ff36ab5", "0xfb3bdb41",
		"0x18cbafe5", "0x4a25d94a", "0x414bf389", "0xc04b8d59":
		return TxTypeSwap
	case "0xe8e33700", "0xf305d719", "0xbaa2abde", "0x02751cec":
		return TxTypeLiquidity
	default:
		return TxTypeSwap // Default to swap for DEX interactions
	}
}

func (m *Monitor) detectThreats(tx *Transaction) {
	ctx := context.Background()

	// Large transfer detection
	if tx.Value != nil && m.config.LargeTransferThreshold != nil {
		if tx.Value.Cmp(m.config.LargeTransferThreshold) > 0 {
			m.emitAlert(ctx, &Alert{
				ID:       uuid.New(),
				Type:     "large_transfer",
				Severity: "high",
				Title:    "Large Transfer Detected",
				Description: fmt.Sprintf("Transfer of %s wei from %s to %s",
					tx.Value.String(), tx.From, tx.To),
				Timestamp: time.Now(),
				TxHashes:  []string{tx.Hash},
				Metadata: map[string]interface{}{
					"from":    tx.From,
					"to":      tx.To,
					"value":   tx.Value.String(),
					"network": tx.Network,
				},
			})
		}
	}

	// High gas price detection (potential MEV)
	if tx.GasPrice != nil && m.config.GasPriceThreshold != nil {
		if tx.GasPrice.Cmp(m.config.GasPriceThreshold) > 0 {
			m.mevBots[tx.From]++
			if m.mevBots[tx.From] >= 3 {
				m.knownMEVBots[tx.From] = true
			}
		}
	}

	// Flash loan detection
	if m.config.FlashLoanDetection && tx.Type == TxTypeFlashLoan {
		m.flashLoans[tx.From] = time.Now()
		m.emitAlert(ctx, &Alert{
			ID:       uuid.New(),
			Type:     "flash_loan",
			Severity: "medium",
			Title:    "Flash Loan Initiated",
			Description: fmt.Sprintf("Flash loan from %s via %s",
				tx.From, m.knownFlashLoan[tx.To]),
			Timestamp: time.Now(),
			TxHashes:  []string{tx.Hash},
			Metadata: map[string]interface{}{
				"from":     tx.From,
				"provider": tx.To,
				"network":  tx.Network,
			},
		})
	}

	// Track swaps for sandwich detection
	if tx.Type == TxTypeSwap {
		pair := tx.To // Simplified - would need full decode
		m.swapsByPair[pair] = append(m.swapsByPair[pair], tx)

		// Cleanup old swaps
		cutoff := time.Now().Add(-m.config.WindowDuration)
		var recent []*Transaction
		for _, s := range m.swapsByPair[pair] {
			if s.Timestamp.After(cutoff) {
				recent = append(recent, s)
			}
		}
		m.swapsByPair[pair] = recent
	}
}

func (m *Monitor) analyzeConfirmedTx(tx *Transaction) {
	ctx := context.Background()

	// Sandwich attack detection
	if m.config.SandwichDetection && tx.Type == TxTypeSwap {
		m.detectSandwichAttack(ctx, tx)
	}

	// MEV detection
	if m.config.MEVDetection {
		m.detectMEV(ctx, tx)
	}
}

func (m *Monitor) detectSandwichAttack(ctx context.Context, tx *Transaction) {
	// Get transactions in the same block
	blockTxs := m.txByBlock[tx.BlockNumber]
	if len(blockTxs) < 3 {
		return
	}

	// Look for sandwich pattern: frontrun -> victim -> backrun
	// Where frontrun and backrun are from the same address
	for i := 0; i < len(blockTxs)-2; i++ {
		frontrun := blockTxs[i]
		victim := blockTxs[i+1]
		backrun := blockTxs[i+2]

		// Check if sandwich pattern
		if frontrun.From == backrun.From &&
			frontrun.From != victim.From &&
			frontrun.Type == TxTypeSwap &&
			victim.Type == TxTypeSwap &&
			backrun.Type == TxTypeSwap &&
			frontrun.To == victim.To && victim.To == backrun.To {

			// Mark as sandwich attack
			frontrun.IsMEV = true
			frontrun.Type = TxTypeSandwich
			backrun.IsMEV = true
			backrun.Type = TxTypeSandwich
			victim.SandwichVictim = frontrun.From

			m.emitAlert(ctx, &Alert{
				ID:       uuid.New(),
				Type:     "sandwich_attack",
				Severity: "high",
				Title:    "Sandwich Attack Detected",
				Description: fmt.Sprintf("Victim %s sandwiched by %s in block %d",
					victim.From, frontrun.From, tx.BlockNumber),
				Timestamp: time.Now(),
				TxHashes:  []string{frontrun.Hash, victim.Hash, backrun.Hash},
				Metadata: map[string]interface{}{
					"attacker":    frontrun.From,
					"victim":      victim.From,
					"block":       tx.BlockNumber,
					"dex":         frontrun.To,
					"frontrun_tx": frontrun.Hash,
					"victim_tx":   victim.Hash,
					"backrun_tx":  backrun.Hash,
					"network":     tx.Network,
				},
			})
		}
	}
}

func (m *Monitor) detectMEV(ctx context.Context, tx *Transaction) {
	// Check if from known MEV bot
	if m.knownMEVBots[tx.From] {
		tx.IsMEV = true
		tx.Type = TxTypeMEV
	}

	// Arbitrage detection: same block, multiple swaps, profit
	if tx.Type == TxTypeSwap {
		blockTxs := m.txByBlock[tx.BlockNumber]
		sameAddressTxs := 0
		for _, btx := range blockTxs {
			if btx.From == tx.From && btx.Type == TxTypeSwap {
				sameAddressTxs++
			}
		}

		if sameAddressTxs >= 2 {
			tx.IsMEV = true
			tx.Type = TxTypeArbitrage

			m.emitAlert(ctx, &Alert{
				ID:       uuid.New(),
				Type:     "arbitrage",
				Severity: "low",
				Title:    "Potential Arbitrage Detected",
				Description: fmt.Sprintf("Address %s executed %d swaps in block %d",
					tx.From, sameAddressTxs, tx.BlockNumber),
				Timestamp: time.Now(),
				TxHashes:  []string{tx.Hash},
				Metadata: map[string]interface{}{
					"address":    tx.From,
					"swap_count": sameAddressTxs,
					"block":      tx.BlockNumber,
					"network":    tx.Network,
				},
			})
		}
	}
}

func (m *Monitor) emitAlert(ctx context.Context, alert *Alert) {
	for _, handler := range m.handlers {
		go func(h AlertHandler) {
			if err := h(ctx, alert); err != nil {
				slog.Error("mempool alert handler failed", "error", err)
			}
		}(handler)
	}
}

// GetPendingCount returns the number of pending transactions.
func (m *Monitor) GetPendingCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.pending)
}

// GetStats returns monitoring statistics.
func (m *Monitor) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	typeCount := make(map[string]int)
	for _, tx := range m.pending {
		typeCount[string(tx.Type)]++
	}

	return map[string]interface{}{
		"pending_count":  len(m.pending),
		"blocks_tracked": len(m.txByBlock),
		"known_mev_bots": len(m.knownMEVBots),
		"active_pairs":   len(m.swapsByPair),
		"tx_by_type":     typeCount,
	}
}

// NormalizeToEvent converts a transaction to a schema.Event.
func (m *Monitor) NormalizeToEvent(tx *Transaction, tenantID string) *schema.Event {
	action := fmt.Sprintf("tx.%s", tx.Type)

	outcome := schema.OutcomeSuccess
	if tx.BlockNumber == 0 {
		outcome = schema.OutcomeUnknown
	}

	severity := 1
	switch tx.Type {
	case TxTypeSandwich:
		severity = 8
	case TxTypeMEV, TxTypeArbitrage:
		severity = 5
	case TxTypeFlashLoan:
		severity = 6
	}

	metadata := map[string]interface{}{
		"tx_hash":   tx.Hash,
		"from":      tx.From,
		"to":        tx.To,
		"gas_price": tx.GasPrice.String(),
		"gas_limit": tx.GasLimit,
		"nonce":     tx.Nonce,
		"network":   tx.Network,
		"tx_type":   string(tx.Type),
	}

	if tx.Value != nil {
		metadata["value"] = tx.Value.String()
	}
	if tx.MethodID != "" {
		metadata["method_id"] = tx.MethodID
	}
	if tx.MethodName != "" {
		metadata["method_name"] = tx.MethodName
	}
	if tx.IsMEV {
		metadata["is_mev"] = true
	}
	if tx.SandwichVictim != "" {
		metadata["sandwich_attacker"] = tx.SandwichVictim
	}

	return &schema.Event{
		EventID:   uuid.New(),
		Timestamp: tx.Timestamp,
		TenantID:  tenantID,
		Source: schema.Source{
			Product: "mempool-monitor",
			Host:    tx.Network,
			Version: "1.0",
		},
		Action:   action,
		Outcome:  outcome,
		Severity: severity,
		Target:   tx.To,
		Actor: &schema.Actor{
			ID:   tx.From,
			Type: "address",
		},
		Metadata: metadata,
	}
}

// Cleanup removes old data.
func (m *Monitor) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-m.config.WindowDuration * 2)

	// Clean pending
	for hash, tx := range m.pending {
		if tx.LastUpdated.Before(cutoff) {
			delete(m.pending, hash)
		}
	}

	// Clean block data (keep last 100 blocks)
	if len(m.txByBlock) > 100 {
		var blocks []uint64
		for b := range m.txByBlock {
			blocks = append(blocks, b)
		}
		// Sort and remove oldest
		for i := 0; i < len(blocks)-100; i++ {
			delete(m.txByBlock, blocks[i])
		}
	}

	// Clean flash loans
	for addr, t := range m.flashLoans {
		if t.Before(cutoff) {
			delete(m.flashLoans, addr)
		}
	}
}

// CreateCorrelationRules creates mempool-related correlation rules.
func CreateCorrelationRules() []*correlation.Rule {
	return []*correlation.Rule{
		{
			ID:          "mempool-sandwich-attack",
			Name:        "Sandwich Attack Pattern",
			Description: "Detects sandwich attack patterns in confirmed transactions",
			Type:        correlation.RuleTypeSequence,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "mev", "sandwich", "attack"},
			MITRE: &correlation.MITREMapping{
				TacticID:   "TA0040",
				TacticName: "Impact",
			},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "contains", Value: "tx.swap"},
			},
			GroupBy: []string{"metadata.to"},
			Window:  1 * time.Minute,
			Sequence: &correlation.SequenceConfig{
				Ordered: true,
				MaxSpan: 30 * time.Second,
				Steps: []correlation.SequenceStep{
					{
						Name: "frontrun",
						Conditions: []correlation.Condition{
							{Field: "action", Operator: "eq", Value: "tx.swap"},
						},
					},
					{
						Name: "victim",
						Conditions: []correlation.Condition{
							{Field: "action", Operator: "eq", Value: "tx.swap"},
						},
					},
					{
						Name: "backrun",
						Conditions: []correlation.Condition{
							{Field: "action", Operator: "eq", Value: "tx.swap"},
						},
					},
				},
			},
		},
		{
			ID:          "mempool-flash-loan-attack",
			Name:        "Flash Loan Attack Pattern",
			Description: "Multiple flash loans from same source in short period",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityHigh),
			Tags:        []string{"blockchain", "flash-loan", "attack"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "tx.flash_loan"},
			},
			GroupBy: []string{"actor.id"},
			Window:  10 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    3,
				Operator: "gte",
			},
		},
		{
			ID:          "mempool-mev-bot-activity",
			Name:        "MEV Bot Activity",
			Description: "High frequency trading activity indicating MEV extraction",
			Type:        correlation.RuleTypeThreshold,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityMedium),
			Tags:        []string{"blockchain", "mev", "bot"},
			EventConditions: []correlation.Condition{
				{Field: "metadata.is_mev", Operator: "eq", Value: true},
			},
			GroupBy: []string{"actor.id"},
			Window:  5 * time.Minute,
			Threshold: &correlation.ThresholdConfig{
				Count:    10,
				Operator: "gte",
			},
		},
		{
			ID:          "mempool-large-transfer",
			Name:        "Large Value Transfer",
			Description: "Unusually large value transfer detected",
			Type:        correlation.RuleTypeAggregate,
			Enabled:     true,
			Severity:    correlation.SeverityToInt(correlation.SeverityMedium),
			Tags:        []string{"blockchain", "transfer", "whale"},
			EventConditions: []correlation.Condition{
				{Field: "action", Operator: "eq", Value: "tx.transfer"},
			},
			GroupBy: []string{"actor.id"},
			Window:  1 * time.Hour,
			Aggregate: &correlation.AggregateConfig{
				Function: "count",
				Operator: "gte",
				Value:    5,
			},
		},
	}
}

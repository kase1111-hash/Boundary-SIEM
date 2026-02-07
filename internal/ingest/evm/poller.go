// Package evm provides an EVM JSON-RPC poller that ingests blockchain events
// and normalizes them to the canonical SIEM event schema.
package evm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

// Config holds EVM poller configuration.
type Config struct {
	Enabled      bool          `yaml:"enabled"`
	Chains       []ChainConfig `yaml:"chains"`
	PollInterval time.Duration `yaml:"poll_interval"`
	BatchSize    int           `yaml:"batch_size"`    // max blocks per poll
	StartBlock   string        `yaml:"start_block"`   // "latest", "earliest", or block number
}

// ChainConfig defines a single EVM chain to poll.
type ChainConfig struct {
	Name     string `yaml:"name"`     // e.g., "ethereum", "polygon"
	ChainID  int64  `yaml:"chain_id"` // e.g., 1, 137
	RPCURL   string `yaml:"rpc_url"`
	Enabled  bool   `yaml:"enabled"`
}

// Poller polls EVM JSON-RPC endpoints for blocks and logs.
type Poller struct {
	config     Config
	queue      *queue.RingBuffer
	client     *http.Client
	chains     []chainState
	mu         sync.Mutex
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

type chainState struct {
	config    ChainConfig
	lastBlock uint64
}

// NewPoller creates a new EVM poller.
func NewPoller(cfg Config, q *queue.RingBuffer) *Poller {
	chains := make([]chainState, 0, len(cfg.Chains))
	for _, c := range cfg.Chains {
		if c.Enabled {
			chains = append(chains, chainState{config: c})
		}
	}

	return &Poller{
		config: cfg,
		queue:  q,
		client: &http.Client{Timeout: 30 * time.Second},
		chains: chains,
		stopCh: make(chan struct{}),
	}
}

// Start begins polling all configured chains.
func (p *Poller) Start(ctx context.Context) {
	for i := range p.chains {
		p.wg.Add(1)
		go p.pollChain(ctx, i)
	}
	slog.Info("EVM poller started", "chains", len(p.chains))
}

// Stop halts all polling goroutines.
func (p *Poller) Stop() {
	close(p.stopCh)
	p.wg.Wait()
	slog.Info("EVM poller stopped")
}

func (p *Poller) pollChain(ctx context.Context, idx int) {
	defer p.wg.Done()

	chain := &p.chains[idx]
	interval := p.config.PollInterval
	if interval <= 0 {
		interval = 12 * time.Second // ~1 Ethereum block
	}

	// Resolve starting block
	startBlock, err := p.resolveStartBlock(ctx, chain)
	if err != nil {
		slog.Error("failed to resolve start block", "chain", chain.config.Name, "error", err)
		return
	}
	chain.lastBlock = startBlock
	slog.Info("EVM polling started", "chain", chain.config.Name, "start_block", startBlock)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.poll(ctx, chain)
		}
	}
}

func (p *Poller) resolveStartBlock(ctx context.Context, chain *chainState) (uint64, error) {
	switch p.config.StartBlock {
	case "", "latest":
		return p.getBlockNumber(ctx, chain)
	case "earliest":
		return 0, nil
	default:
		n, err := strconv.ParseUint(p.config.StartBlock, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid start_block %q: %w", p.config.StartBlock, err)
		}
		return n, nil
	}
}

func (p *Poller) poll(ctx context.Context, chain *chainState) {
	latest, err := p.getBlockNumber(ctx, chain)
	if err != nil {
		slog.Warn("failed to get block number", "chain", chain.config.Name, "error", err)
		return
	}

	if latest <= chain.lastBlock {
		return
	}

	batchSize := p.config.BatchSize
	if batchSize <= 0 {
		batchSize = 10
	}

	endBlock := chain.lastBlock + uint64(batchSize)
	if endBlock > latest {
		endBlock = latest
	}

	for blockNum := chain.lastBlock + 1; blockNum <= endBlock; blockNum++ {
		block, err := p.getBlock(ctx, chain, blockNum)
		if err != nil {
			slog.Warn("failed to get block", "chain", chain.config.Name, "block", blockNum, "error", err)
			return
		}

		events := p.normalizeBlock(chain, block)
		for _, event := range events {
			if err := p.queue.Push(event); err != nil {
				slog.Warn("failed to queue EVM event", "chain", chain.config.Name, "error", err)
			}
		}

		chain.lastBlock = blockNum
	}

	slog.Debug("EVM poll complete",
		"chain", chain.config.Name,
		"from_block", chain.lastBlock-uint64(endBlock-chain.lastBlock)+1,
		"to_block", chain.lastBlock,
		"events", 0,
	)
}

// --- JSON-RPC methods ---

type rpcRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (p *Poller) rpcCall(ctx context.Context, chain *chainState, method string, params []interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", chain.config.RPCURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		return nil, err
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC response: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}

func (p *Poller) getBlockNumber(ctx context.Context, chain *chainState) (uint64, error) {
	result, err := p.rpcCall(ctx, chain, "eth_blockNumber", nil)
	if err != nil {
		return 0, err
	}
	var hexNum string
	if err := json.Unmarshal(result, &hexNum); err != nil {
		return 0, err
	}
	return parseHexUint64(hexNum)
}

type blockResult struct {
	Number       string        `json:"number"`
	Hash         string        `json:"hash"`
	Timestamp    string        `json:"timestamp"`
	Miner        string        `json:"miner"`
	GasUsed      string        `json:"gasUsed"`
	GasLimit     string        `json:"gasLimit"`
	Transactions []transaction `json:"transactions"`
}

type transaction struct {
	Hash     string `json:"hash"`
	From     string `json:"from"`
	To       string `json:"to"`
	Value    string `json:"value"`
	Gas      string `json:"gas"`
	GasPrice string `json:"gasPrice"`
	Input    string `json:"input"`
	Nonce    string `json:"nonce"`
}

func (p *Poller) getBlock(ctx context.Context, chain *chainState, blockNum uint64) (*blockResult, error) {
	hexBlock := fmt.Sprintf("0x%x", blockNum)
	result, err := p.rpcCall(ctx, chain, "eth_getBlockByNumber", []interface{}{hexBlock, true})
	if err != nil {
		return nil, err
	}
	if string(result) == "null" {
		return nil, fmt.Errorf("block %d not found", blockNum)
	}
	var block blockResult
	if err := json.Unmarshal(result, &block); err != nil {
		return nil, err
	}
	return &block, nil
}

// --- Normalization ---

func (p *Poller) normalizeBlock(chain *chainState, block *blockResult) []*schema.Event {
	blockNum, _ := parseHexUint64(block.Number)
	blockTime, _ := parseHexUint64(block.Timestamp)
	ts := time.Unix(int64(blockTime), 0).UTC()

	var events []*schema.Event

	// Block event
	gasUsed, _ := parseHexUint64(block.GasUsed)
	gasLimit, _ := parseHexUint64(block.GasLimit)
	gasUtilization := float64(0)
	if gasLimit > 0 {
		gasUtilization = float64(gasUsed) / float64(gasLimit) * 100
	}

	blockEvent := &schema.Event{
		EventID:   uuid.New(),
		Timestamp: ts,
		Source: schema.Source{
			Product: fmt.Sprintf("evm-%s", chain.config.Name),
			Host:    chain.config.RPCURL,
		},
		Action:   "evm.block.mined",
		Outcome:  schema.OutcomeSuccess,
		Severity: 1,
		Target:   block.Hash,
		Metadata: map[string]any{
			"chain_id":        chain.config.ChainID,
			"chain_name":      chain.config.Name,
			"block_number":    blockNum,
			"block_hash":      block.Hash,
			"miner":           block.Miner,
			"gas_used":        gasUsed,
			"gas_limit":       gasLimit,
			"gas_utilization": gasUtilization,
			"tx_count":        len(block.Transactions),
		},
		SchemaVersion: schema.SchemaVersionCurrent,
		ReceivedAt:    time.Now(),
		TenantID:      "evm",
	}
	events = append(events, blockEvent)

	// Transaction events
	for _, tx := range block.Transactions {
		event := p.normalizeTx(chain, &tx, ts, blockNum)
		events = append(events, event)
	}

	return events
}

func (p *Poller) normalizeTx(chain *chainState, tx *transaction, blockTime time.Time, blockNum uint64) *schema.Event {
	value := parseHexBigInt(tx.Value)
	action := "evm.transaction"
	severity := 1

	// Detect contract creation (no To address)
	if tx.To == "" || tx.To == "0x" {
		action = "evm.contract.created"
		severity = 3
	} else if len(tx.Input) > 2 {
		// Contract call (input data present beyond "0x")
		action = "evm.contract.call"
		severity = 2
	}

	// High-value transfer detection
	ethValue := new(big.Float).Quo(new(big.Float).SetInt(value), big.NewFloat(1e18))
	ethFloat, _ := ethValue.Float64()
	if ethFloat > 100 {
		severity = 5
	}
	if ethFloat > 1000 {
		severity = 7
	}

	return &schema.Event{
		EventID:   uuid.New(),
		Timestamp: blockTime,
		Source: schema.Source{
			Product: fmt.Sprintf("evm-%s", chain.config.Name),
			Host:    chain.config.RPCURL,
		},
		Action:   action,
		Outcome:  schema.OutcomeSuccess,
		Severity: severity,
		Actor: &schema.Actor{
			Type: schema.ActorService,
			ID:   strings.ToLower(tx.From),
			Name: tx.From,
		},
		Target: strings.ToLower(tx.To),
		Metadata: map[string]any{
			"chain_id":     chain.config.ChainID,
			"chain_name":   chain.config.Name,
			"tx_hash":      tx.Hash,
			"block_number": blockNum,
			"from":         strings.ToLower(tx.From),
			"to":           strings.ToLower(tx.To),
			"value_wei":    value.String(),
			"value_eth":    ethFloat,
			"gas":          tx.Gas,
			"gas_price":    tx.GasPrice,
			"input_size":   len(tx.Input),
			"nonce":        tx.Nonce,
		},
		SchemaVersion: schema.SchemaVersionCurrent,
		ReceivedAt:    time.Now(),
		TenantID:      "evm",
	}
}

// --- Helpers ---

func parseHexUint64(s string) (uint64, error) {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, 16, 64)
}

func parseHexBigInt(s string) *big.Int {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return big.NewInt(0)
	}
	n := new(big.Int)
	n.SetString(s, 16)
	return n
}

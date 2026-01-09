package blockchain

import (
	"context"
	"math/big"
	"testing"
	"time"

	"boundary-siem/internal/blockchain/contracts"
	"boundary-siem/internal/blockchain/ethereum"
	"boundary-siem/internal/blockchain/mempool"
	"boundary-siem/internal/blockchain/validator"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

func TestGethParserTextFormat(t *testing.T) {
	parser := ethereum.NewGethParser()

	line := "INFO [01-01|12:00:00.000] Looking for peers peercount=5 tried=10"
	entry, err := parser.Parse(line)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if entry.Level != ethereum.LevelInfo {
		t.Errorf("Level = %v, want INFO", entry.Level)
	}

	if entry.Message != "Looking for peers" {
		t.Errorf("Message = %v, want 'Looking for peers'", entry.Message)
	}
}

func TestGethNormalize(t *testing.T) {
	parser := ethereum.NewGethParser()

	entry := &ethereum.GethLogEntry{
		Timestamp: time.Now(),
		Level:     ethereum.LevelInfo,
		Message:   "Imported new chain segment",
		Fields: map[string]string{
			"blocks": "1",
			"txs":    "10",
		},
	}

	event, err := parser.Normalize(entry, "192.168.1.1")
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if event.Action != "block.imported" {
		t.Errorf("Action = %v, want block.imported", event.Action)
	}

	if event.Source.Product != "geth" {
		t.Errorf("Source.Product = %v, want geth", event.Source.Product)
	}
}

func TestValidatorMonitor(t *testing.T) {
	config := validator.DefaultMonitorConfig()
	monitor := validator.NewMonitor(config)

	// Add a watched validator
	monitor.AddWatchedValidator(12345, "0xabcdef")

	// Create test events with proper Source
	events := []*schema.Event{
		{
			EventID:   uuid.New(),
			Timestamp: time.Now(),
			Source:    schema.Source{Product: "test"},
			Action:    "validator.attestation_submitted",
			Outcome:   schema.OutcomeSuccess,
			Severity:  3,
			Metadata: map[string]interface{}{
				"validator_index": int64(12345),
				"slot":            uint64(1234567),
			},
		},
	}

	// Process events
	for _, event := range events {
		monitor.ProcessEvent(event)
	}

	// Check that monitor processes events
	v, found := monitor.GetValidator(12345)
	if !found {
		t.Errorf("Validator 12345 not found")
	} else if v.AttestationsSubmitted != 1 {
		t.Errorf("AttestationsSubmitted = %d, want 1", v.AttestationsSubmitted)
	}
}

func TestMempoolMonitor(t *testing.T) {
	config := mempool.DefaultMonitorConfig()
	monitor := mempool.NewMonitor(config)

	// Test pending transaction
	tx := &mempool.Transaction{
		Hash:      "0xabc123",
		From:      "0x1234",
		To:        "0x5678",
		Value:     big.NewInt(1000000000000000000),
		GasPrice:  big.NewInt(50000000000),
		GasLimit:  21000,
		Nonce:     1,
		Data:      nil,
		Timestamp: time.Now(),
		Network:   "ethereum",
	}

	monitor.ProcessPendingTx(tx)

	if monitor.GetPendingCount() != 1 {
		t.Errorf("pending count = %d, want 1", monitor.GetPendingCount())
	}

	// Test confirmed transaction
	tx.BlockNumber = 18500000
	tx.BlockHash = "0xblock123"
	monitor.ProcessConfirmedTx(tx)

	if monitor.GetPendingCount() != 0 {
		t.Errorf("pending count after confirm = %d, want 0", monitor.GetPendingCount())
	}
}

func TestMempoolTransactionClassification(t *testing.T) {
	config := mempool.DefaultMonitorConfig()
	monitor := mempool.NewMonitor(config)

	// Simple transfer
	tx := &mempool.Transaction{
		Hash:      "0x1",
		From:      "0xsender",
		To:        "0xreceiver",
		Value:     big.NewInt(1e18),
		GasPrice:  big.NewInt(20e9),
		Data:      nil,
		Timestamp: time.Now(),
	}

	monitor.ProcessPendingTx(tx)

	if tx.Type != mempool.TxTypeTransfer {
		t.Errorf("tx.Type = %v, want transfer", tx.Type)
	}
}

func TestContractEventMonitor(t *testing.T) {
	config := contracts.DefaultMonitorConfig()
	monitor := contracts.NewMonitor(config)

	// Add a watched contract
	monitor.AddWatchedContract("0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT")

	// Test Transfer event
	log := &contracts.Log{
		Address: "0xdac17f958d2ee523a2206206994597c13d831ec7",
		Topics: []string{
			"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // Transfer
			"0x0000000000000000000000001234567890123456789012345678901234567890", // from
			"0x0000000000000000000000000987654321098765432109876543210987654321", // to
		},
		Data:        "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000", // 1e18
		BlockNumber: 18500000,
		TxHash:      "0xtx123",
		Timestamp:   time.Now(),
		Network:     "ethereum",
	}

	event, err := monitor.ProcessLog(log)
	if err != nil {
		t.Fatalf("ProcessLog() error = %v", err)
	}

	if event.EventName != "Transfer" {
		t.Errorf("EventName = %v, want Transfer", event.EventName)
	}

	// Note: Transfer event topic is the same for ERC20/ERC721, so contract type may vary
	if event.Contract != "ERC20" && event.Contract != "ERC721" {
		t.Errorf("Contract = %v, want ERC20 or ERC721", event.Contract)
	}
}

func TestContractEventNormalize(t *testing.T) {
	config := contracts.DefaultMonitorConfig()
	monitor := contracts.NewMonitor(config)

	decoded := &contracts.DecodedEvent{
		Log: contracts.Log{
			Address:     "0xcontract",
			BlockNumber: 18500000,
			TxHash:      "0xtx",
			Timestamp:   time.Now(),
			Network:     "ethereum",
		},
		EventName: "Transfer",
		Signature: "Transfer(address,address,uint256)",
		Contract:  "ERC20",
		Params: map[string]interface{}{
			"from":  "0xsender",
			"to":    "0xreceiver",
			"value": "1000000000000000000",
		},
		Severity: 1,
	}

	event := monitor.NormalizeToEvent(decoded, "tenant-1")

	if event.Action != "contract.erc20.transfer" {
		t.Errorf("Action = %v, want contract.erc20.transfer", event.Action)
	}

	if event.TenantID != "tenant-1" {
		t.Errorf("TenantID = %v, want tenant-1", event.TenantID)
	}
}

func TestUnifiedMonitor(t *testing.T) {
	config := DefaultConfig()
	monitor := NewMonitor(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Track events
	eventCount := 0
	monitor.AddEventHandler(func(ctx context.Context, event *schema.Event) error {
		eventCount++
		return nil
	})

	monitor.Start(ctx)
	defer monitor.Stop()

	// Process a Geth log
	_, err := monitor.ProcessGethLog(
		"INFO [01-01|12:00:00.000] Imported new chain segment blocks=1 txs=10",
		"192.168.1.1",
		"tenant-1",
	)
	if err != nil {
		t.Fatalf("ProcessGethLog() error = %v", err)
	}

	// Give time for async processing
	time.Sleep(100 * time.Millisecond)

	stats := monitor.GetStats()
	if stats["network"] != NetworkEthereum {
		t.Errorf("network = %v, want ethereum", stats["network"])
	}
}

func TestGetCorrelationRules(t *testing.T) {
	rules := GetCorrelationRules()

	if len(rules) == 0 {
		t.Error("expected correlation rules, got none")
	}

	// Check for specific rule types
	ruleTypes := make(map[string]bool)
	for _, rule := range rules {
		ruleTypes[rule.ID] = true
	}

	expectedRules := []string{
		"validator-missed-attestations",
		"validator-slashing-sequence",
		"mempool-sandwich-attack",
		"contract-ownership-change",
	}

	for _, expected := range expectedRules {
		if !ruleTypes[expected] {
			t.Errorf("expected rule %s not found", expected)
		}
	}
}

func TestMempoolStats(t *testing.T) {
	config := mempool.DefaultMonitorConfig()
	monitor := mempool.NewMonitor(config)

	stats := monitor.GetStats()
	if stats["pending_count"].(int) != 0 {
		t.Errorf("initial pending_count should be 0")
	}
}

func TestContractStats(t *testing.T) {
	config := contracts.DefaultMonitorConfig()
	monitor := contracts.NewMonitor(config)

	stats := monitor.GetStats()
	if stats["known_signatures"].(int) == 0 {
		t.Errorf("should have known signatures")
	}
}

func BenchmarkGethParser(b *testing.B) {
	parser := ethereum.NewGethParser()
	line := "INFO [01-01|12:00:00.000] Imported new chain segment blocks=1 txs=150 mgas=12.5"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parser.Parse(line)
	}
}

func BenchmarkMempoolProcess(b *testing.B) {
	config := mempool.DefaultMonitorConfig()
	monitor := mempool.NewMonitor(config)

	tx := &mempool.Transaction{
		Hash:      "0xabc123",
		From:      "0x1234",
		To:        "0x5678",
		Value:     big.NewInt(1e18),
		GasPrice:  big.NewInt(50e9),
		GasLimit:  21000,
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx.Hash = "0x" + string(rune('a'+i%26))
		monitor.ProcessPendingTx(tx)
	}
}

func BenchmarkContractEventDecode(b *testing.B) {
	config := contracts.DefaultMonitorConfig()
	monitor := contracts.NewMonitor(config)

	log := &contracts.Log{
		Address: "0xcontract",
		Topics: []string{
			"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
			"0x0000000000000000000000001234567890123456789012345678901234567890",
			"0x0000000000000000000000000987654321098765432109876543210987654321",
		},
		Data:      "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		monitor.ProcessLog(log)
	}
}

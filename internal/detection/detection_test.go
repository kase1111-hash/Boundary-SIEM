package detection

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"boundary-siem/internal/detection/playbook"
	"boundary-siem/internal/detection/rules"
	"boundary-siem/internal/detection/threat"
	"boundary-siem/internal/schema"

	"github.com/google/uuid"
)

func TestThreatIntelService(t *testing.T) {
	config := threat.DefaultIntelConfig()
	service := threat.NewIntelService(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := service.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer service.Stop()

	// Check stats
	stats := service.GetStats()
	if stats["ofac_addresses"].(int) == 0 {
		t.Error("expected OFAC addresses to be loaded")
	}
}

func TestThreatScreenAddress(t *testing.T) {
	config := threat.DefaultIntelConfig()
	service := threat.NewIntelService(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	service.Start(ctx)
	defer service.Stop()

	// Test known sanctioned address (Tornado Cash)
	result, err := service.ScreenAddress(ctx, "0x8589427373d6d84e98730d7795d8f6f8731fda16")
	if err != nil {
		t.Fatalf("ScreenAddress() error = %v", err)
	}

	if !result.IsMatch {
		t.Error("expected match for OFAC sanctioned address")
	}

	if result.Risk != threat.RiskCritical {
		t.Errorf("Risk = %v, want critical", result.Risk)
	}
}

func TestThreatScreenCleanAddress(t *testing.T) {
	config := threat.DefaultIntelConfig()
	service := threat.NewIntelService(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	service.Start(ctx)
	defer service.Stop()

	// Test random clean address
	result, err := service.ScreenAddress(ctx, "0x742d35cc6634c0532925a3b844bc454e4438f44e")
	if err != nil {
		t.Fatalf("ScreenAddress() error = %v", err)
	}

	if result.IsMatch {
		t.Error("expected no match for clean address")
	}
}

func TestAddCustomIndicator(t *testing.T) {
	config := threat.DefaultIntelConfig()
	service := threat.NewIntelService(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	service.Start(ctx)
	defer service.Stop()

	// Add custom indicator
	service.AddIndicator(&threat.ThreatIndicator{
		Type:        threat.ThreatScam,
		Value:       "0x1234567890123456789012345678901234567890",
		Risk:        threat.RiskHigh,
		Source:      "custom",
		Description: "Known scam address",
	})

	// Screen the address
	result, err := service.ScreenAddress(ctx, "0x1234567890123456789012345678901234567890")
	if err != nil {
		t.Fatalf("ScreenAddress() error = %v", err)
	}

	if !result.IsMatch {
		t.Error("expected match for custom indicator")
	}
}

func TestThreatAlertHandler(t *testing.T) {
	config := threat.DefaultIntelConfig()
	service := threat.NewIntelService(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var alertCount int32
	service.AddHandler(func(ctx context.Context, alert *threat.Alert) error {
		atomic.AddInt32(&alertCount, 1)
		return nil
	})

	service.Start(ctx)
	defer service.Stop()

	// Screen a sanctioned address
	service.ScreenAddress(ctx, "0x8589427373d6d84e98730d7795d8f6f8731fda16")

	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&alertCount) == 0 {
		t.Error("expected alert for sanctioned address")
	}
}

func TestThreatNormalization(t *testing.T) {
	config := threat.DefaultIntelConfig()
	service := threat.NewIntelService(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	service.Start(ctx)
	defer service.Stop()

	result, _ := service.ScreenAddress(ctx, "0x8589427373d6d84e98730d7795d8f6f8731fda16")

	event := service.NormalizeToEvent(result, "tenant-1")

	if event.Action != "threat.screening" {
		t.Errorf("Action = %v, want threat.screening", event.Action)
	}

	if event.TenantID != "tenant-1" {
		t.Errorf("TenantID = %v, want tenant-1", event.TenantID)
	}

	if event.Severity < 8 {
		t.Errorf("expected high severity for critical risk, got %d", event.Severity)
	}
}

func TestPlaybookEngine(t *testing.T) {
	config := playbook.DefaultEngineConfig()
	engine := playbook.NewEngine(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx)
	defer engine.Stop()

	stats := engine.GetStats()
	if stats["playbook_count"].(int) == 0 {
		t.Error("expected built-in playbooks to be loaded")
	}
}

func TestPlaybookTrigger(t *testing.T) {
	config := playbook.DefaultEngineConfig()
	engine := playbook.NewEngine(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx)
	defer engine.Stop()

	// Create test event that matches validator slashing playbook
	event := &schema.Event{
		EventID:   uuid.New(),
		Timestamp: time.Now(),
		Action:    "validator.slashing_detected",
		Severity:  9,
		Outcome:   schema.OutcomeFailure,
		Metadata: map[string]interface{}{
			"validator_index": 12345,
		},
	}

	incident, err := engine.TriggerPlaybook(ctx, "validator-slashing-detected", event)
	if err != nil {
		t.Fatalf("TriggerPlaybook() error = %v", err)
	}

	if incident == nil {
		t.Fatal("expected incident to be created")
	}

	// Wait for execution with polling to avoid race condition
	var status playbook.ActionStatus
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		inc, found := engine.GetIncident(incident.ID)
		if found {
			status = inc.Status
			if status == playbook.StatusCompleted {
				break
			}
		}
	}

	// Check incident status after loop
	if status != playbook.StatusCompleted {
		t.Errorf("Status = %v, want completed", status)
	}
}

func TestPlaybookProcessEvent(t *testing.T) {
	config := playbook.DefaultEngineConfig()
	engine := playbook.NewEngine(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine.Start(ctx)
	defer engine.Stop()

	// Create test event
	event := &schema.Event{
		EventID:   uuid.New(),
		Timestamp: time.Now(),
		Action:    "validator.attestation_missed",
		Severity:  6,
		Outcome:   schema.OutcomeFailure,
	}

	incidents := engine.ProcessEvent(ctx, event)

	// Should match the "validator-missed-duties" playbook
	if len(incidents) == 0 {
		t.Error("expected at least one incident to be triggered")
	}
}

func TestBuiltInPlaybooks(t *testing.T) {
	playbooks := playbook.GetBuiltInPlaybooks()

	if len(playbooks) == 0 {
		t.Error("expected built-in playbooks")
	}

	// Check for specific playbooks
	playbookIDs := make(map[string]bool)
	for _, pb := range playbooks {
		playbookIDs[pb.ID] = true
	}

	expectedPlaybooks := []string{
		"validator-slashing-detected",
		"validator-missed-duties",
		"sandwich-attack-detected",
		"sanctioned-address-interaction",
		"key-export-attempt",
		"rpc-attack-detected",
	}

	for _, expected := range expectedPlaybooks {
		if !playbookIDs[expected] {
			t.Errorf("expected playbook %s not found", expected)
		}
	}
}

func TestGetAllRules(t *testing.T) {
	allRules := rules.GetAllRules()

	if len(allRules) < 100 {
		t.Errorf("expected at least 100 rules, got %d", len(allRules))
	}

	// Check for unique IDs
	ruleIDs := make(map[string]bool)
	for _, rule := range allRules {
		if ruleIDs[rule.ID] {
			t.Errorf("duplicate rule ID: %s", rule.ID)
		}
		ruleIDs[rule.ID] = true
	}
}

func TestValidatorRules(t *testing.T) {
	validatorRules := rules.GetValidatorRules()

	if len(validatorRules) < 10 {
		t.Errorf("expected at least 10 validator rules, got %d", len(validatorRules))
	}

	// Check for critical slashing rule
	hasSlashingRule := false
	for _, rule := range validatorRules {
		if rule.ID == "val-001" {
			hasSlashingRule = true
			if rule.Name != "Validator Slashing Event" {
				t.Errorf("rule name = %s, want 'Validator Slashing Event'", rule.Name)
			}
		}
	}

	if !hasSlashingRule {
		t.Error("expected validator slashing rule")
	}
}

func TestConsensusRules(t *testing.T) {
	consensusRules := rules.GetConsensusRules()

	if len(consensusRules) < 5 {
		t.Errorf("expected at least 5 consensus rules, got %d", len(consensusRules))
	}
}

func TestTransactionRules(t *testing.T) {
	txRules := rules.GetTransactionRules()

	if len(txRules) < 5 {
		t.Errorf("expected at least 5 transaction rules, got %d", len(txRules))
	}
}

func TestContractRules(t *testing.T) {
	contractRules := rules.GetContractRules()

	if len(contractRules) < 10 {
		t.Errorf("expected at least 10 contract rules, got %d", len(contractRules))
	}
}

func TestMEVRules(t *testing.T) {
	mevRules := rules.GetMEVRules()

	if len(mevRules) < 5 {
		t.Errorf("expected at least 5 MEV rules, got %d", len(mevRules))
	}

	// Check for sandwich attack rule
	hasSandwichRule := false
	for _, rule := range mevRules {
		if rule.ID == "mev-001" && rule.Name == "Sandwich Attack" {
			hasSandwichRule = true
		}
	}

	if !hasSandwichRule {
		t.Error("expected sandwich attack rule")
	}
}

func TestInfrastructureRules(t *testing.T) {
	infraRules := rules.GetInfrastructureRules()

	if len(infraRules) < 5 {
		t.Errorf("expected at least 5 infrastructure rules, got %d", len(infraRules))
	}
}

func TestSecurityRules(t *testing.T) {
	secRules := rules.GetSecurityRules()

	if len(secRules) < 10 {
		t.Errorf("expected at least 10 security rules, got %d", len(secRules))
	}
}

func TestComplianceRules(t *testing.T) {
	compRules := rules.GetComplianceRules()

	if len(compRules) < 5 {
		t.Errorf("expected at least 5 compliance rules, got %d", len(compRules))
	}

	// Check for OFAC rule
	hasOFACRule := false
	for _, rule := range compRules {
		if rule.ID == "comp-001" {
			hasOFACRule = true
		}
	}

	if !hasOFACRule {
		t.Error("expected OFAC sanctions rule")
	}
}

func TestKeyManagementRules(t *testing.T) {
	keyRules := rules.GetKeyManagementRules()

	if len(keyRules) < 5 {
		t.Errorf("expected at least 5 key management rules, got %d", len(keyRules))
	}
}

func TestCloudSecurityRules(t *testing.T) {
	cloudRules := rules.GetCloudSecurityRules()

	if len(cloudRules) < 5 {
		t.Errorf("expected at least 5 cloud security rules, got %d", len(cloudRules))
	}
}

func TestRulesHaveMITREMappings(t *testing.T) {
	allRules := rules.GetAllRules()

	mitreCount := 0
	for _, rule := range allRules {
		if rule.MITRE != nil {
			mitreCount++
		}
	}

	// At least 20% of rules should have MITRE mappings
	minExpected := len(allRules) / 5
	if mitreCount < minExpected {
		t.Errorf("expected at least %d rules with MITRE mappings, got %d", minExpected, mitreCount)
	}
}

func TestAddressValidation(t *testing.T) {
	testCases := []struct {
		address string
		valid   bool
	}{
		{"0x742d35cc6634c0532925a3b844bc454e4438f44e", true},
		{"0x8589427373D6D84E98730D7795D8f6f8731fDA16", true},
		{"0x123", false},
		{"742d35cc6634c0532925a3b844bc454e4438f44e", false},
		{"0xGGGG35cc6634c0532925a3b844bc454e4438f44e", false},
		{"", false},
	}

	for _, tc := range testCases {
		result := threat.IsValidEthereumAddress(tc.address)
		if result != tc.valid {
			t.Errorf("IsValidEthereumAddress(%s) = %v, want %v", tc.address, result, tc.valid)
		}
	}
}

func BenchmarkThreatScreening(b *testing.B) {
	config := threat.DefaultIntelConfig()
	service := threat.NewIntelService(config)

	ctx := context.Background()
	service.Start(ctx)
	defer service.Stop()

	address := "0x742d35cc6634c0532925a3b844bc454e4438f44e"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.ScreenAddress(ctx, address)
	}
}

func BenchmarkPlaybookProcess(b *testing.B) {
	config := playbook.DefaultEngineConfig()
	engine := playbook.NewEngine(config)

	ctx := context.Background()
	engine.Start(ctx)
	defer engine.Stop()

	event := &schema.Event{
		EventID:   uuid.New(),
		Timestamp: time.Now(),
		Action:    "tx.transfer",
		Severity:  3,
		Outcome:   schema.OutcomeSuccess,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.ProcessEvent(ctx, event)
	}
}

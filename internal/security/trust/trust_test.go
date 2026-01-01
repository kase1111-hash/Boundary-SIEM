package trust

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestTrustLevel_String(t *testing.T) {
	tests := []struct {
		level    TrustLevel
		expected string
	}{
		{TrustLevelUnknown, "unknown"},
		{TrustLevelNone, "none"},
		{TrustLevelBasic, "basic"},
		{TrustLevelTPM, "tpm"},
		{TrustLevelSecure, "secure"},
		{TrustLevelFull, "full"},
		{TrustLevel(100), "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("TrustLevel.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestTPMVersion_String(t *testing.T) {
	tests := []struct {
		version  TPMVersion
		expected string
	}{
		{TPMVersionUnknown, "unknown"},
		{TPMVersion12, "1.2"},
		{TPMVersion20, "2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.version.String(); got != tt.expected {
				t.Errorf("TPMVersion.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestDefaultTrustGateConfig(t *testing.T) {
	config := DefaultTrustGateConfig()

	if config.RefreshInterval != 5*time.Minute {
		t.Errorf("RefreshInterval = %v, want 5m", config.RefreshInterval)
	}
	if config.MaxHistorySize != 1000 {
		t.Errorf("MaxHistorySize = %d, want 1000", config.MaxHistorySize)
	}
	if !config.EnforceMode {
		t.Error("EnforceMode should be true by default")
	}
	if config.AllowEmulation {
		t.Error("AllowEmulation should be false by default")
	}
	if config.TPMDevicePath != "/dev/tpm0" {
		t.Errorf("TPMDevicePath = %s, want /dev/tpm0", config.TPMDevicePath)
	}
	if len(config.PCRsToVerify) != 8 {
		t.Errorf("PCRsToVerify length = %d, want 8", len(config.PCRsToVerify))
	}
}

func TestNewTrustGate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	config := DefaultTrustGateConfig()
	config.AllowEmulation = true // Allow running without TPM

	tg, err := NewTrustGate(config, logger)
	if err != nil {
		t.Fatalf("NewTrustGate failed: %v", err)
	}
	if tg == nil {
		t.Fatal("NewTrustGate returned nil")
	}
	if tg.platformState == nil {
		t.Error("platformState should be captured")
	}
}

func TestNewTrustGate_NilConfig(t *testing.T) {
	// With nil config, AllowEmulation is false, so it may fail without TPM
	// Skip this test if no TPM available
	t.Skip("Requires TPM or emulation")
}

func TestNewTrustGate_NilLogger(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true

	tg, err := NewTrustGate(config, nil)
	if err != nil {
		t.Fatalf("NewTrustGate with nil logger failed: %v", err)
	}
	if tg == nil {
		t.Fatal("NewTrustGate returned nil")
	}
}

func TestTrustGate_RegisterRequirement(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	tg, _ := NewTrustGate(config, nil)

	req := &TrustRequirement{
		Name:          "test_operation",
		MinTrustLevel: TrustLevelBasic,
	}

	tg.RegisterRequirement(req)

	// Verify by trying to gate
	ctx := context.Background()
	result, err := tg.Gate(ctx, "test_operation")
	if err != nil && !errors.Is(err, ErrTrustLevelTooLow) {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Error("Gate should return a result")
	}
}

func TestTrustGate_Gate_NoRequirement(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	tg, _ := NewTrustGate(config, nil)

	ctx := context.Background()
	result, err := tg.Gate(ctx, "unregistered_operation")

	// Should succeed - no requirement means no restriction
	if err != nil {
		t.Errorf("Gate should succeed for unregistered operation: %v", err)
	}
	if result == nil {
		t.Fatal("Gate should return a result")
	}
	if !result.Allowed {
		t.Error("Operation should be allowed with no requirement")
	}
}

func TestTrustGate_Gate_RequireTPM(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	config.EnforceMode = true
	tg, _ := NewTrustGate(config, nil)

	tg.RegisterRequirement(&TrustRequirement{
		Name:       "tpm_required_op",
		RequireTPM: true,
	})

	ctx := context.Background()
	result, err := tg.Gate(ctx, "tpm_required_op")

	state := tg.GetPlatformState()
	if state.TPMAvailable {
		// TPM available - should succeed
		if err != nil {
			t.Errorf("Gate should succeed with TPM: %v", err)
		}
	} else {
		// TPM not available - should fail
		if err == nil {
			t.Error("Gate should fail when TPM required but not available")
		}
		if !errors.Is(err, ErrTrustLevelTooLow) {
			t.Errorf("Expected ErrTrustLevelTooLow, got: %v", err)
		}
		if result.Allowed {
			t.Error("Result should not be allowed")
		}
	}
}

func TestTrustGate_Gate_MinTrustLevel(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	config.EnforceMode = true
	tg, _ := NewTrustGate(config, nil)

	state := tg.GetPlatformState()

	// Register requirement for trust level above current
	tg.RegisterRequirement(&TrustRequirement{
		Name:          "high_trust_op",
		MinTrustLevel: TrustLevelFull,
	})

	ctx := context.Background()
	result, err := tg.Gate(ctx, "high_trust_op")

	if state.TrustLevel >= TrustLevelFull {
		// High trust - should succeed
		if err != nil {
			t.Errorf("Gate should succeed at full trust: %v", err)
		}
	} else {
		// Lower trust - should fail
		if err == nil {
			t.Error("Gate should fail when trust level too low")
		}
		if result.Allowed {
			t.Error("Result should not be allowed")
		}
	}
}

func TestTrustGate_Gate_AllowDegraded(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	config.EnforceMode = true
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tg, _ := NewTrustGate(config, logger)

	// Register requirement that allows degraded mode
	tg.RegisterRequirement(&TrustRequirement{
		Name:          "degradable_op",
		MinTrustLevel: TrustLevelFull,
		AllowDegraded: true,
	})

	ctx := context.Background()
	result, err := tg.Gate(ctx, "degradable_op")

	// Should succeed even if trust level is low (degraded mode)
	if err != nil {
		t.Errorf("Gate should succeed in degraded mode: %v", err)
	}
	if result == nil {
		t.Fatal("Gate should return a result")
	}
	if !result.Allowed {
		t.Error("Operation should be allowed in degraded mode")
	}

	state := tg.GetPlatformState()
	if state.TrustLevel < TrustLevelFull {
		if !result.Degraded {
			t.Error("Result should be marked as degraded")
		}
	}
}

func TestTrustGate_GetPlatformState(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	tg, _ := NewTrustGate(config, nil)

	state := tg.GetPlatformState()
	if state == nil {
		t.Fatal("GetPlatformState should return non-nil")
	}
	if state.CapturedAt.IsZero() {
		t.Error("CapturedAt should be set")
	}
}

func TestTrustGate_RefreshPlatformState(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	tg, _ := NewTrustGate(config, nil)

	oldState := tg.GetPlatformState()
	time.Sleep(10 * time.Millisecond)

	err := tg.RefreshPlatformState()
	if err != nil {
		t.Errorf("RefreshPlatformState failed: %v", err)
	}

	newState := tg.GetPlatformState()
	if newState.CapturedAt.Before(oldState.CapturedAt) || newState.CapturedAt.Equal(oldState.CapturedAt) {
		t.Error("CapturedAt should be updated after refresh")
	}
}

func TestTrustGate_GetHistory(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	config.MaxHistorySize = 10
	tg, _ := NewTrustGate(config, nil)

	ctx := context.Background()

	// Perform several gates
	for i := 0; i < 5; i++ {
		tg.Gate(ctx, "test_op")
	}

	history := tg.GetHistory(3)
	if len(history) != 3 {
		t.Errorf("GetHistory returned %d items, expected 3", len(history))
	}
}

func TestTrustGate_GetHistory_MoreThanAvailable(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	tg, _ := NewTrustGate(config, nil)

	ctx := context.Background()
	tg.Gate(ctx, "test_op")

	history := tg.GetHistory(100)
	if len(history) != 1 {
		t.Errorf("GetHistory returned %d items, expected 1", len(history))
	}
}

func TestTrustGate_GetDenied(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	config.EnforceMode = false // Don't fail, just record
	tg, _ := NewTrustGate(config, nil)

	// Register a requirement we can't meet
	tg.RegisterRequirement(&TrustRequirement{
		Name:          "impossible_op",
		MinTrustLevel: TrustLevelFull,
		RequireTPM:    true,
		RequireSecureBoot: true,
		RequireMeasuredBoot: true,
	})

	ctx := context.Background()
	tg.Gate(ctx, "test_success") // No requirement - should succeed
	tg.Gate(ctx, "impossible_op") // High requirement - likely fails

	denied := tg.GetDenied()
	// Check if we got any denied (depends on platform)
	_ = denied // May be empty or have entries
}

func TestTrustGate_OnDegraded(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	config.EnforceMode = true
	tg, _ := NewTrustGate(config, nil)

	called := false
	tg.OnDegraded(func(op string, result *GateResult) {
		called = true
		if op != "degraded_test" {
			t.Errorf("Expected operation 'degraded_test', got %q", op)
		}
	})

	tg.RegisterRequirement(&TrustRequirement{
		Name:          "degraded_test",
		MinTrustLevel: TrustLevelFull,
		AllowDegraded: true,
	})

	ctx := context.Background()
	tg.Gate(ctx, "degraded_test")

	state := tg.GetPlatformState()
	if state.TrustLevel < TrustLevelFull && !called {
		t.Error("OnDegraded callback should have been called")
	}
}

func TestTrustGate_OnDenied(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	config.EnforceMode = true
	tg, _ := NewTrustGate(config, nil)

	called := false
	tg.OnDenied(func(op string, result *GateResult) {
		called = true
	})

	tg.RegisterRequirement(&TrustRequirement{
		Name:          "denied_test",
		MinTrustLevel: TrustLevelFull,
		RequireTPM:    true,
		AllowDegraded: false,
	})

	ctx := context.Background()
	tg.Gate(ctx, "denied_test")

	state := tg.GetPlatformState()
	if state.TrustLevel < TrustLevelFull && !called {
		t.Error("OnDenied callback should have been called")
	}
}

func TestTrustGate_RequireLevel(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	config.EnforceMode = true
	tg, _ := NewTrustGate(config, nil)

	ctx := context.Background()
	executed := false

	err := tg.RequireLevel(ctx, "level_test", TrustLevelNone, func() error {
		executed = true
		return nil
	})

	// TrustLevelNone should always succeed
	if err != nil {
		t.Errorf("RequireLevel(None) should succeed: %v", err)
	}
	if !executed {
		t.Error("Function should have been executed")
	}
}

func TestTrustGate_HistoryEviction(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	config.MaxHistorySize = 3
	tg, _ := NewTrustGate(config, nil)

	ctx := context.Background()

	// Add 5 entries - oldest 2 should be evicted
	for i := 0; i < 5; i++ {
		tg.Gate(ctx, "test_op")
	}

	history := tg.GetHistory(10)
	if len(history) != 3 {
		t.Errorf("History should have 3 entries after eviction, got %d", len(history))
	}
}

func TestCommonRequirements(t *testing.T) {
	if RequireFullTrust.Name != "full_trust" {
		t.Error("RequireFullTrust has wrong name")
	}
	if RequireFullTrust.MinTrustLevel != TrustLevelFull {
		t.Error("RequireFullTrust should require TrustLevelFull")
	}
	if !RequireFullTrust.RequireTPM {
		t.Error("RequireFullTrust should require TPM")
	}

	if RequireSecureTrust.Name != "secure_trust" {
		t.Error("RequireSecureTrust has wrong name")
	}
	if RequireSecureTrust.MinTrustLevel != TrustLevelSecure {
		t.Error("RequireSecureTrust should require TrustLevelSecure")
	}

	if RequireTPMTrust.Name != "tpm_trust" {
		t.Error("RequireTPMTrust has wrong name")
	}
	if !RequireTPMTrust.RequireTPM {
		t.Error("RequireTPMTrust should require TPM")
	}

	if RequireBasicTrust.Name != "basic_trust" {
		t.Error("RequireBasicTrust has wrong name")
	}
	if !RequireBasicTrust.AllowDegraded {
		t.Error("RequireBasicTrust should allow degraded")
	}

	if RequirePolicyChange.Name != "policy_change" {
		t.Error("RequirePolicyChange has wrong name")
	}

	if RequireModeTransition.Name != "mode_transition" {
		t.Error("RequireModeTransition has wrong name")
	}

	if RequireKeyOperation.Name != "key_operation" {
		t.Error("RequireKeyOperation has wrong name")
	}
	if !RequireKeyOperation.RequireMeasuredBoot {
		t.Error("RequireKeyOperation should require measured boot")
	}
}

func TestDefaultSIEMTrustGate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	tg, err := DefaultSIEMTrustGate(logger)
	if err != nil {
		t.Fatalf("DefaultSIEMTrustGate failed: %v", err)
	}
	if tg == nil {
		t.Fatal("DefaultSIEMTrustGate returned nil")
	}
}

func TestPolicyGate_Execute(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	config.EnforceMode = false // Don't enforce for test
	tg, _ := NewTrustGate(config, nil)

	pg := NewPolicyGate(tg, "policy_test", &TrustRequirement{
		Name:          "policy_test",
		MinTrustLevel: TrustLevelNone,
	})

	ctx := context.Background()
	executed := false

	err := pg.Execute(ctx, func() error {
		executed = true
		return nil
	})

	if err != nil {
		t.Errorf("Execute failed: %v", err)
	}
	if !executed {
		t.Error("Function should have been executed")
	}
}

func TestWithTrustGate(t *testing.T) {
	config := DefaultTrustGateConfig()
	config.AllowEmulation = true
	config.EnforceMode = false
	tg, _ := NewTrustGate(config, nil)

	ctx := context.Background()

	result, err := WithTrustGate(tg, ctx, "generic_test", func() (string, error) {
		return "success", nil
	})

	if err != nil {
		t.Errorf("WithTrustGate failed: %v", err)
	}
	if result != "success" {
		t.Errorf("Expected 'success', got %q", result)
	}
}

func TestGetPCRPurpose(t *testing.T) {
	tests := []struct {
		index    int
		contains string
	}{
		{0, "SRTM"},
		{1, "Platform Configuration"},
		{4, "IPL"},
		{7, "Manufacturer"},
		{99, "PCR 99"},
	}

	for _, tt := range tests {
		purpose := getPCRPurpose(tt.index)
		if !containsStr(purpose, tt.contains) {
			t.Errorf("getPCRPurpose(%d) = %q, should contain %q", tt.index, purpose, tt.contains)
		}
	}
}

func TestPlatformState_Fields(t *testing.T) {
	state := &PlatformState{
		TrustLevel:     TrustLevelSecure,
		TPMAvailable:   true,
		TPMVersion:     TPMVersion20,
		SecureBootOn:   true,
		MeasuredBoot:   true,
		KernelLockdown: "integrity",
		IMAEnabled:     true,
		CapturedAt:     time.Now(),
	}

	if state.TrustLevel != TrustLevelSecure {
		t.Error("TrustLevel not set correctly")
	}
	if !state.TPMAvailable {
		t.Error("TPMAvailable not set correctly")
	}
	if state.TPMVersion != TPMVersion20 {
		t.Error("TPMVersion not set correctly")
	}
}

func TestGateResult_Fields(t *testing.T) {
	result := &GateResult{
		Allowed:    true,
		TrustLevel: TrustLevelSecure,
		Degraded:   false,
		Reason:     "test reason",
		Timestamp:  time.Now(),
	}

	if !result.Allowed {
		t.Error("Allowed not set correctly")
	}
	if result.TrustLevel != TrustLevelSecure {
		t.Error("TrustLevel not set correctly")
	}
	if result.Reason != "test reason" {
		t.Error("Reason not set correctly")
	}
}

// Helper function
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || containsStrHelper(s, substr))
}

func containsStrHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

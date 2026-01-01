package privilege

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestCapabilityString(t *testing.T) {
	tests := []struct {
		cap      Capability
		expected string
	}{
		{CAP_NET_BIND_SERVICE, "CAP_NET_BIND_SERVICE"},
		{CAP_NET_ADMIN, "CAP_NET_ADMIN"},
		{CAP_NET_RAW, "CAP_NET_RAW"},
		{CAP_SYS_ADMIN, "CAP_SYS_ADMIN"},
		{CAP_SETUID, "CAP_SETUID"},
		{CAP_SETGID, "CAP_SETGID"},
		{Capability(999), "CAP_999"}, // Unknown capability
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.cap.String(); got != tt.expected {
				t.Errorf("Capability.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestPrivilegeState_String(t *testing.T) {
	state := &PrivilegeState{
		UID:          1000,
		GID:          1000,
		EUID:         1000,
		EGID:         1000,
		Capabilities: []Capability{CAP_NET_BIND_SERVICE, CAP_DAC_READ_SEARCH},
	}

	str := state.String()
	if str == "" {
		t.Error("String() returned empty string")
	}
	if !contains(str, "UID=1000") {
		t.Error("String() missing UID")
	}
	if !contains(str, "CAP_NET_BIND_SERVICE") {
		t.Error("String() missing capability")
	}
}

func TestPrivilegeState_IsRoot(t *testing.T) {
	tests := []struct {
		name     string
		euid     int
		expected bool
	}{
		{"root", 0, true},
		{"non-root", 1000, false},
		{"nobody", 65534, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &PrivilegeState{EUID: tt.euid}
			if got := state.IsRoot(); got != tt.expected {
				t.Errorf("IsRoot() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPrivilegeState_HasCapability(t *testing.T) {
	state := &PrivilegeState{
		Capabilities: []Capability{CAP_NET_BIND_SERVICE, CAP_DAC_READ_SEARCH},
	}

	if !state.HasCapability(CAP_NET_BIND_SERVICE) {
		t.Error("HasCapability should return true for present capability")
	}
	if !state.HasCapability(CAP_DAC_READ_SEARCH) {
		t.Error("HasCapability should return true for present capability")
	}
	if state.HasCapability(CAP_SYS_ADMIN) {
		t.Error("HasCapability should return false for missing capability")
	}
}

func TestDefaultVerifierConfig(t *testing.T) {
	config := DefaultVerifierConfig()

	if config.MaxHistorySize != 1000 {
		t.Errorf("MaxHistorySize = %d, want 1000", config.MaxHistorySize)
	}
	if !config.VerifyOnEachCall {
		t.Error("VerifyOnEachCall should be true by default")
	}
	if !config.StrictMode {
		t.Error("StrictMode should be true by default")
	}
	if !config.AuditAll {
		t.Error("AuditAll should be true by default")
	}
	if !config.DetectChanges {
		t.Error("DetectChanges should be true by default")
	}
}

func TestNewVerifier(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	v, err := NewVerifier(nil, logger)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}
	if v == nil {
		t.Fatal("NewVerifier returned nil")
	}
	if v.initialState == nil {
		t.Error("initialState should be captured")
	}
}

func TestNewVerifier_NilLogger(t *testing.T) {
	v, err := NewVerifier(nil, nil)
	if err != nil {
		t.Fatalf("NewVerifier with nil logger failed: %v", err)
	}
	if v == nil {
		t.Fatal("NewVerifier returned nil")
	}
}

func TestVerifier_CaptureState(t *testing.T) {
	v, _ := NewVerifier(nil, nil)

	state, err := v.CaptureState()
	if err != nil {
		t.Fatalf("CaptureState failed: %v", err)
	}

	// Should have valid values
	if state.UID < 0 {
		t.Error("UID should be non-negative")
	}
	if state.GID < 0 {
		t.Error("GID should be non-negative")
	}
	if state.CapturedAt.IsZero() {
		t.Error("CapturedAt should be set")
	}
}

func TestVerifier_RegisterRequirement(t *testing.T) {
	v, _ := NewVerifier(nil, nil)

	req := &Requirement{
		Name:         "test_operation",
		RequireRoot:  false,
		RequiredCaps: []Capability{CAP_NET_BIND_SERVICE},
	}

	v.RegisterRequirement(req)

	// Try to verify - should work for registered operation
	ctx := context.Background()
	err := v.Verify(ctx, "test_operation")
	// Error expected if we don't have the capability
	// but verify should complete without panic
	_ = err
}

func TestVerifier_Verify_NoRequirement(t *testing.T) {
	config := &VerifierConfig{
		MaxHistorySize:   100,
		VerifyOnEachCall: true,
		StrictMode:       false,
		AuditAll:         false,
		DetectChanges:    false,
	}
	v, _ := NewVerifier(config, nil)

	ctx := context.Background()
	err := v.Verify(ctx, "unregistered_operation")

	// Should succeed - no requirement means no restriction
	if err != nil {
		t.Errorf("Verify should succeed for unregistered operation: %v", err)
	}
}

func TestVerifier_Verify_RequireRoot_NonRoot(t *testing.T) {
	config := &VerifierConfig{
		MaxHistorySize:   100,
		VerifyOnEachCall: true,
		StrictMode:       true,
		DetectChanges:    false,
	}
	v, _ := NewVerifier(config, nil)

	v.RegisterRequirement(&Requirement{
		Name:        "root_op",
		RequireRoot: true,
	})

	ctx := context.Background()

	// Skip if running as root
	state, _ := v.CaptureState()
	if state.IsRoot() {
		t.Skip("Test requires non-root user")
	}

	err := v.Verify(ctx, "root_op")
	if err == nil {
		t.Error("Verify should fail when root required but not root")
	}
	if !errors.Is(err, ErrVerificationFailed) {
		t.Errorf("Expected ErrVerificationFailed, got: %v", err)
	}
}

func TestVerifier_Verify_AllowedUIDs(t *testing.T) {
	config := &VerifierConfig{
		MaxHistorySize: 100,
		StrictMode:     true,
		DetectChanges:  false,
	}
	v, _ := NewVerifier(config, nil)

	state, _ := v.CaptureState()

	// Register requirement that allows current UID
	v.RegisterRequirement(&Requirement{
		Name:        "allowed_uid_op",
		AllowedUIDs: []int{state.EUID},
	})

	ctx := context.Background()
	err := v.Verify(ctx, "allowed_uid_op")
	if err != nil {
		t.Errorf("Verify should succeed for allowed UID: %v", err)
	}

	// Register requirement that doesn't allow current UID
	v.RegisterRequirement(&Requirement{
		Name:        "disallowed_uid_op",
		AllowedUIDs: []int{99999},
	})

	err = v.Verify(ctx, "disallowed_uid_op")
	if err == nil {
		t.Error("Verify should fail for disallowed UID")
	}
}

func TestVerifier_GetHistory(t *testing.T) {
	config := &VerifierConfig{
		MaxHistorySize: 10,
		DetectChanges:  false,
	}
	v, _ := NewVerifier(config, nil)

	ctx := context.Background()

	// Perform several verifications
	for i := 0; i < 5; i++ {
		v.Verify(ctx, "test_op")
	}

	history := v.GetHistory(3)
	if len(history) != 3 {
		t.Errorf("GetHistory returned %d items, expected 3", len(history))
	}
}

func TestVerifier_GetHistory_MoreThanAvailable(t *testing.T) {
	config := &VerifierConfig{
		MaxHistorySize: 10,
		DetectChanges:  false,
	}
	v, _ := NewVerifier(config, nil)

	ctx := context.Background()
	v.Verify(ctx, "test_op")

	history := v.GetHistory(100)
	if len(history) != 1 {
		t.Errorf("GetHistory returned %d items, expected 1", len(history))
	}
}

func TestVerifier_GetFailures(t *testing.T) {
	config := &VerifierConfig{
		MaxHistorySize: 100,
		StrictMode:     true,
		DetectChanges:  false,
	}
	v, _ := NewVerifier(config, nil)

	// Skip if running as root
	state, _ := v.CaptureState()
	if state.IsRoot() {
		t.Skip("Test requires non-root user")
	}

	// Register a requirement we can't meet
	v.RegisterRequirement(&Requirement{
		Name:        "fail_op",
		RequireRoot: true,
	})

	ctx := context.Background()
	v.Verify(ctx, "test_success") // No requirement - should succeed
	v.Verify(ctx, "fail_op")       // Root required - should fail

	failures := v.GetFailures()
	if len(failures) == 0 {
		t.Error("Expected at least one failure")
	}

	found := false
	for _, f := range failures {
		if f.Operation == "fail_op" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected failure for 'fail_op'")
	}
}

func TestVerifier_OnViolation(t *testing.T) {
	config := &VerifierConfig{
		MaxHistorySize: 100,
		StrictMode:     true,
		DetectChanges:  false,
	}
	v, _ := NewVerifier(config, nil)

	// Skip if running as root
	state, _ := v.CaptureState()
	if state.IsRoot() {
		t.Skip("Test requires non-root user")
	}

	called := false
	v.OnViolation(func(op string, required, actual *PrivilegeState) {
		called = true
		if op != "violation_test" {
			t.Errorf("Expected operation 'violation_test', got %q", op)
		}
	})

	v.RegisterRequirement(&Requirement{
		Name:        "violation_test",
		RequireRoot: true,
	})

	ctx := context.Background()
	v.Verify(ctx, "violation_test")

	if !called {
		t.Error("OnViolation callback should have been called")
	}
}

func TestVerifier_RequireRoot(t *testing.T) {
	v, _ := NewVerifier(nil, nil)

	state, _ := v.CaptureState()

	ctx := context.Background()
	executed := false

	err := v.RequireRoot(ctx, "test_root", func() error {
		executed = true
		return nil
	})

	if state.IsRoot() {
		if err != nil {
			t.Errorf("RequireRoot should succeed when root: %v", err)
		}
		if !executed {
			t.Error("Function should have been executed")
		}
	} else {
		if err == nil {
			t.Error("RequireRoot should fail when not root")
		}
		if !errors.Is(err, ErrNotRoot) {
			t.Errorf("Expected ErrNotRoot, got: %v", err)
		}
		if executed {
			t.Error("Function should not have been executed")
		}
	}
}

func TestVerifier_RequireCaps(t *testing.T) {
	v, _ := NewVerifier(nil, nil)

	ctx := context.Background()

	// Request a capability we might not have
	err := v.RequireCaps(ctx, "test_caps", []Capability{CAP_SYS_ADMIN}, func() error {
		return nil
	})

	state, _ := v.CaptureState()
	if state.HasCapability(CAP_SYS_ADMIN) {
		if err != nil {
			t.Errorf("RequireCaps should succeed when capability present: %v", err)
		}
	} else {
		if err == nil {
			t.Error("RequireCaps should fail when capability missing")
		}
		if !errors.Is(err, ErrCapabilityMissing) {
			t.Errorf("Expected ErrCapabilityMissing, got: %v", err)
		}
	}
}

func TestWithPrivilegeCheck(t *testing.T) {
	config := &VerifierConfig{
		MaxHistorySize: 100,
		DetectChanges:  false,
	}
	v, _ := NewVerifier(config, nil)

	ctx := context.Background()

	result, err := WithPrivilegeCheck(v, ctx, "test_generic", func() (string, error) {
		return "success", nil
	})

	if err != nil {
		t.Errorf("WithPrivilegeCheck failed: %v", err)
	}
	if result != "success" {
		t.Errorf("Expected 'success', got %q", result)
	}
}

func TestPrivilegedOperation_Execute(t *testing.T) {
	config := &VerifierConfig{
		MaxHistorySize: 100,
		DetectChanges:  false,
	}
	v, _ := NewVerifier(config, nil)

	po := NewPrivilegedOperation(v, "test_priv_op", nil)

	ctx := context.Background()
	executed := false

	err := po.Execute(ctx, func() error {
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

func TestPrivilegedOperation_Execute_WithRequirement(t *testing.T) {
	config := &VerifierConfig{
		MaxHistorySize: 100,
		StrictMode:     true,
		DetectChanges:  false,
	}
	v, _ := NewVerifier(config, nil)

	// Skip if running as root
	state, _ := v.CaptureState()
	if state.IsRoot() {
		t.Skip("Test requires non-root user")
	}

	po := NewPrivilegedOperation(v, "root_priv_op", &Requirement{
		Name:        "root_priv_op",
		RequireRoot: true,
	})

	ctx := context.Background()
	executed := false

	err := po.Execute(ctx, func() error {
		executed = true
		return nil
	})

	if err == nil {
		t.Error("Execute should fail when requirement not met")
	}
	if executed {
		t.Error("Function should not have been executed")
	}
}

func TestCommonRequirements(t *testing.T) {
	// Test that common requirements are properly defined
	if RequireFirewallAdmin.Name != "firewall_admin" {
		t.Error("RequireFirewallAdmin has wrong name")
	}
	if len(RequireFirewallAdmin.RequiredCaps) != 2 {
		t.Error("RequireFirewallAdmin should require 2 capabilities")
	}

	if RequireBindLowPort.Name != "bind_low_port" {
		t.Error("RequireBindLowPort has wrong name")
	}

	if RequireRootOnly.Name != "root_only" {
		t.Error("RequireRootOnly has wrong name")
	}
	if !RequireRootOnly.RequireRoot {
		t.Error("RequireRootOnly should require root")
	}

	if RequireSecureExec.Name != "secure_exec" {
		t.Error("RequireSecureExec has wrong name")
	}
	if !RequireSecureExec.RequireNoNewPrivs {
		t.Error("RequireSecureExec should require no_new_privs")
	}
}

func TestDefaultFirewallVerifier(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	v, err := DefaultFirewallVerifier(logger)
	if err != nil {
		t.Fatalf("DefaultFirewallVerifier failed: %v", err)
	}
	if v == nil {
		t.Fatal("DefaultFirewallVerifier returned nil")
	}
}

func TestDefaultSIEMVerifier(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	v, err := DefaultSIEMVerifier(logger)
	if err != nil {
		t.Fatalf("DefaultSIEMVerifier failed: %v", err)
	}
	if v == nil {
		t.Fatal("DefaultSIEMVerifier returned nil")
	}
}

func TestVerifier_HistoryEviction(t *testing.T) {
	config := &VerifierConfig{
		MaxHistorySize: 3,
		DetectChanges:  false,
	}
	v, _ := NewVerifier(config, nil)

	ctx := context.Background()

	// Add 5 entries - oldest 2 should be evicted
	for i := 0; i < 5; i++ {
		v.Verify(ctx, "op_"+string(rune('a'+i)))
		time.Sleep(time.Millisecond) // Ensure different timestamps
	}

	history := v.GetHistory(10)
	if len(history) != 3 {
		t.Errorf("History should have 3 entries after eviction, got %d", len(history))
	}
}

func TestVerifier_GetInitialState(t *testing.T) {
	v, _ := NewVerifier(nil, nil)

	state := v.GetInitialState()
	if state == nil {
		t.Error("GetInitialState should return non-nil")
	}
	if state.CapturedAt.IsZero() {
		t.Error("Initial state should have capture time")
	}
}

func TestVerificationResult_Fields(t *testing.T) {
	result := VerificationResult{
		Operation:  "test_op",
		Timestamp:  time.Now(),
		Success:    true,
		CallerFile: "test.go",
		CallerLine: 42,
	}

	if result.Operation != "test_op" {
		t.Error("Operation field not set correctly")
	}
	if result.CallerFile != "test.go" {
		t.Error("CallerFile field not set correctly")
	}
	if result.CallerLine != 42 {
		t.Error("CallerLine field not set correctly")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

package commitment

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testConfig creates a test config with isolated persistence directory.
func testConfig(t *testing.T) *StateManagerConfig {
	t.Helper()
	tmpDir := filepath.Join(os.TempDir(), "commitment-test-"+t.Name())
	os.RemoveAll(tmpDir) // Clean up any previous test data
	t.Cleanup(func() { os.RemoveAll(tmpDir) })
	return &StateManagerConfig{
		PersistPath:                    tmpDir,
		MaxTransitionHistory:           100,
		RequireApprovalForDeescalation: false,
		HashAlgorithm:                  "sha256",
		AutoCheckpoint:                 false,
		CheckpointInterval:             1 * time.Hour,
		RequirePersistence:             true,
		PersistenceVerifyRetries:       3,
		SyncToDisk:                     true,
		// Disable human confirmation for persistence tests
		RequireHumanConfirmation: false,
		ConfirmationCodeLength:   8,
		ConfirmationTimeout:      5 * time.Minute,
		ConfirmationMaxAttempts:  3,
		RequiredApprovers:        1,
		CriticalModeThreshold:    2,
	}
}

// testConfigNoPersistence creates a test config without persistence.
func testConfigNoPersistence(t *testing.T) *StateManagerConfig {
	t.Helper()
	return &StateManagerConfig{
		PersistPath:                    "", // No persistence
		MaxTransitionHistory:           100,
		RequireApprovalForDeescalation: false,
		HashAlgorithm:                  "sha256",
		AutoCheckpoint:                 false,
		CheckpointInterval:             1 * time.Hour,
		RequirePersistence:             false,
		PersistenceVerifyRetries:       0,
		SyncToDisk:                     false,
		// Disable human confirmation for basic tests
		RequireHumanConfirmation: false,
		ConfirmationCodeLength:   8,
		ConfirmationTimeout:      5 * time.Minute,
		ConfirmationMaxAttempts:  3,
		RequiredApprovers:        1,
		CriticalModeThreshold:    2,
	}
}

// testConfigWithConfirmation creates a test config with human confirmation enabled.
func testConfigWithConfirmation(t *testing.T) *StateManagerConfig {
	t.Helper()
	tmpDir := filepath.Join(os.TempDir(), "commitment-confirm-test-"+t.Name())
	os.RemoveAll(tmpDir)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })
	return &StateManagerConfig{
		PersistPath:                    tmpDir,
		MaxTransitionHistory:           100,
		RequireApprovalForDeescalation: false,
		HashAlgorithm:                  "sha256",
		AutoCheckpoint:                 false,
		CheckpointInterval:             1 * time.Hour,
		RequirePersistence:             false, // Disable for cleaner tests
		PersistenceVerifyRetries:       0,
		SyncToDisk:                     false,
		// Enable human confirmation
		RequireHumanConfirmation: true,
		ConfirmationCodeLength:   8,
		ConfirmationTimeout:      5 * time.Minute,
		ConfirmationMaxAttempts:  3,
		RequiredApprovers:        1,
		CriticalModeThreshold:    2,
	}
}

func TestSecurityMode_Level(t *testing.T) {
	tests := []struct {
		mode  SecurityMode
		level int
	}{
		{ModeNormal, 0},
		{ModeElevated, 1},
		{ModeLockdown, 2},
		{ModeColdroom, 3},
		{ModeEmergency, 4},
		{SecurityMode("unknown"), -1},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := tt.mode.Level(); got != tt.level {
				t.Errorf("Level() = %d, want %d", got, tt.level)
			}
		})
	}
}

func TestSecurityMode_String(t *testing.T) {
	mode := ModeNormal
	if got := mode.String(); got != "normal" {
		t.Errorf("String() = %s, want normal", got)
	}
}

func TestState_Hash(t *testing.T) {
	state := &State{
		Mode:    ModeNormal,
		Version: 1,
		Entries: []StateEntry{
			{Key: "key1", Value: "value1", Timestamp: time.Now()},
			{Key: "key2", Value: "value2", Timestamp: time.Now()},
		},
		Timestamp: time.Now(),
		Nonce:     "testnonce",
	}

	hash1 := state.Hash()
	if hash1 == "" {
		t.Error("Hash() returned empty string")
	}

	// Same state should produce same hash
	hash2 := state.Hash()
	if hash1 != hash2 {
		t.Error("Hash() is not deterministic")
	}

	// Different version should produce different hash
	state.Version = 2
	hash3 := state.Hash()
	if hash1 == hash3 {
		t.Error("Different version should produce different hash")
	}
}

func TestState_HashDeterministicOrdering(t *testing.T) {
	// Entries in different order should produce same hash
	state1 := &State{
		Mode:    ModeNormal,
		Version: 1,
		Entries: []StateEntry{
			{Key: "a", Value: "1"},
			{Key: "b", Value: "2"},
		},
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Nonce:     "nonce",
	}

	state2 := &State{
		Mode:    ModeNormal,
		Version: 1,
		Entries: []StateEntry{
			{Key: "b", Value: "2"},
			{Key: "a", Value: "1"},
		},
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Nonce:     "nonce",
	}

	if state1.Hash() != state2.Hash() {
		t.Error("Entry order should not affect hash")
	}
}

func TestCommitment_SignAndVerify(t *testing.T) {
	key := []byte("test-secret-key-32bytes-long!!")

	c := &Commitment{
		ID:             "test-id",
		StateHash:      "abc123",
		PreviousHash:   "prev123",
		Mode:           ModeNormal,
		Version:        1,
		Timestamp:      time.Now(),
		CommitmentType: "checkpoint",
	}

	// Sign
	c.Sign(key)
	if c.Signature == "" {
		t.Error("Sign() did not set signature")
	}

	// Verify with correct key
	if !c.Verify(key) {
		t.Error("Verify() failed with correct key")
	}

	// Verify with wrong key
	wrongKey := []byte("wrong-key-32bytes-long-here!!")
	if c.Verify(wrongKey) {
		t.Error("Verify() should fail with wrong key")
	}
}

func TestCommitment_TamperDetection(t *testing.T) {
	key := []byte("test-secret-key-32bytes-long!!")

	c := &Commitment{
		ID:             "test-id",
		StateHash:      "abc123",
		Mode:           ModeNormal,
		Version:        1,
		Timestamp:      time.Now(),
		CommitmentType: "checkpoint",
	}

	c.Sign(key)

	// Tamper with state hash
	c.StateHash = "tampered"
	if c.Verify(key) {
		t.Error("Verify() should detect tampering")
	}
}

func TestModeTransition_IsEscalation(t *testing.T) {
	tests := []struct {
		from, to     SecurityMode
		isEscalation bool
		isDeesc      bool
	}{
		{ModeNormal, ModeElevated, true, false},
		{ModeNormal, ModeLockdown, true, false},
		{ModeLockdown, ModeNormal, false, true},
		{ModeNormal, ModeNormal, false, false},
	}

	for _, tt := range tests {
		mt := &ModeTransition{FromMode: tt.from, ToMode: tt.to}
		if got := mt.IsEscalation(); got != tt.isEscalation {
			t.Errorf("%s->%s: IsEscalation() = %v, want %v",
				tt.from, tt.to, got, tt.isEscalation)
		}
		if got := mt.IsDeescalation(); got != tt.isDeesc {
			t.Errorf("%s->%s: IsDeescalation() = %v, want %v",
				tt.from, tt.to, got, tt.isDeesc)
		}
	}
}

func TestModeTransition_Duration(t *testing.T) {
	start := time.Now().Add(-5 * time.Second)
	end := time.Now()

	mt := &ModeTransition{StartTime: start, EndTime: &end}
	duration := mt.Duration()

	if duration < 4*time.Second || duration > 6*time.Second {
		t.Errorf("Duration() = %v, expected ~5s", duration)
	}

	// No end time - should return time since start
	mt2 := &ModeTransition{StartTime: start}
	if mt2.Duration() < 4*time.Second {
		t.Errorf("Duration() without end time should be positive")
	}
}

func TestCommitmentChain_Verify(t *testing.T) {
	key := []byte("test-secret-key-32bytes-long!!")
	genesis := "genesis-hash"

	chain := &CommitmentChain{
		GenesisHash: genesis,
		Commitments: make([]Commitment, 0),
	}

	// Empty chain should verify
	if err := chain.Verify(key); err != nil {
		t.Errorf("Empty chain verify failed: %v", err)
	}

	// Add first commitment
	c1 := &Commitment{
		ID:             "1",
		StateHash:      "hash1",
		PreviousHash:   genesis,
		Mode:           ModeNormal,
		Version:        1,
		Timestamp:      time.Now(),
		CommitmentType: "checkpoint",
	}
	c1.Sign(key)
	chain.Commitments = append(chain.Commitments, *c1)

	if err := chain.Verify(key); err != nil {
		t.Errorf("Single commitment verify failed: %v", err)
	}

	// Add second commitment
	c2 := &Commitment{
		ID:             "2",
		StateHash:      "hash2",
		PreviousHash:   "hash1",
		Mode:           ModeNormal,
		Version:        2,
		Timestamp:      time.Now(),
		CommitmentType: "checkpoint",
	}
	c2.Sign(key)
	chain.Commitments = append(chain.Commitments, *c2)

	if err := chain.Verify(key); err != nil {
		t.Errorf("Two commitment verify failed: %v", err)
	}
}

func TestCommitmentChain_VerifyBrokenChain(t *testing.T) {
	key := []byte("test-secret-key-32bytes-long!!")
	genesis := "genesis-hash"

	chain := &CommitmentChain{
		GenesisHash: genesis,
		Commitments: make([]Commitment, 0),
	}

	c1 := &Commitment{
		ID:           "1",
		StateHash:    "hash1",
		PreviousHash: genesis,
		Timestamp:    time.Now(),
	}
	c1.Sign(key)
	chain.Commitments = append(chain.Commitments, *c1)

	// Add commitment with wrong previous hash
	c2 := &Commitment{
		ID:           "2",
		StateHash:    "hash2",
		PreviousHash: "wrong-hash",
		Timestamp:    time.Now(),
	}
	c2.Sign(key)
	chain.Commitments = append(chain.Commitments, *c2)

	if err := chain.Verify(key); err == nil {
		t.Error("Should detect broken chain")
	}
}

func TestCommitmentChain_LatestHash(t *testing.T) {
	chain := &CommitmentChain{
		GenesisHash: "genesis",
	}

	// Empty chain returns genesis
	if got := chain.LatestHash(); got != "genesis" {
		t.Errorf("LatestHash() = %s, want genesis", got)
	}

	// With commitments
	chain.Commitments = []Commitment{
		{StateHash: "hash1"},
		{StateHash: "hash2"},
	}

	if got := chain.LatestHash(); got != "hash2" {
		t.Errorf("LatestHash() = %s, want hash2", got)
	}
}

func TestNewStateManager(t *testing.T) {
	tmpDir := t.TempDir()
	config := &StateManagerConfig{
		PersistPath:          tmpDir,
		MaxTransitionHistory: 100,
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	sm, err := NewStateManager(config, logger)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	if sm.GetCurrentMode() != ModeNormal {
		t.Errorf("Initial mode = %s, want normal", sm.GetCurrentMode())
	}

	// Chain should have initial checkpoint
	chain := sm.GetCommitmentChain()
	if len(chain.Commitments) != 1 {
		t.Errorf("Expected 1 initial commitment, got %d", len(chain.Commitments))
	}
}

func TestNewStateManager_DefaultConfig(t *testing.T) {
	sm, err := NewStateManager(testConfigNoPersistence(t), nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	if sm.GetCurrentMode() != ModeNormal {
		t.Errorf("Initial mode = %s, want normal", sm.GetCurrentMode())
	}
}

func TestStateManager_SetGetState(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)

	sm.SetState("key1", "value1")
	sm.SetState("key2", "value2")

	val, ok := sm.GetState("key1")
	if !ok || val != "value1" {
		t.Errorf("GetState(key1) = %s, %v", val, ok)
	}

	val, ok = sm.GetState("key2")
	if !ok || val != "value2" {
		t.Errorf("GetState(key2) = %s, %v", val, ok)
	}

	// Update existing
	sm.SetState("key1", "updated")
	val, _ = sm.GetState("key1")
	if val != "updated" {
		t.Errorf("Updated value = %s, want updated", val)
	}

	// Non-existent
	_, ok = sm.GetState("nonexistent")
	if ok {
		t.Error("GetState should return false for non-existent key")
	}
}

func TestStateManager_BeginTransition(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	transition, err := sm.BeginTransition(ctx, ModeElevated, "test", "admin")
	if err != nil {
		t.Fatalf("BeginTransition() error = %v", err)
	}

	if transition.FromMode != ModeNormal {
		t.Errorf("FromMode = %s, want normal", transition.FromMode)
	}
	if transition.ToMode != ModeElevated {
		t.Errorf("ToMode = %s, want elevated", transition.ToMode)
	}
	if transition.Status != "pending" {
		t.Errorf("Status = %s, want pending", transition.Status)
	}
	if transition.PreCommitment == nil {
		t.Error("PreCommitment should not be nil")
	}

	// Should not allow second transition
	_, err = sm.BeginTransition(ctx, ModeLockdown, "test2", "admin")
	if err != ErrTransitionInProgress {
		t.Errorf("Expected ErrTransitionInProgress, got %v", err)
	}
}

func TestStateManager_CommitTransition(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	transition, _ := sm.BeginTransition(ctx, ModeElevated, "test", "admin")

	err := sm.CommitTransition(ctx)
	if err != nil {
		t.Fatalf("CommitTransition() error = %v", err)
	}

	if sm.GetCurrentMode() != ModeElevated {
		t.Errorf("Mode = %s, want elevated", sm.GetCurrentMode())
	}

	// Check transition was recorded
	if transition.Status != "completed" {
		t.Errorf("Status = %s, want completed", transition.Status)
	}
	if transition.PostCommitment == nil {
		t.Error("PostCommitment should not be nil")
	}

	// Check chain
	chain := sm.GetCommitmentChain()
	// 1 initial + 1 pre + 1 post = 3
	if len(chain.Commitments) != 3 {
		t.Errorf("Chain length = %d, want 3", len(chain.Commitments))
	}
}

func TestStateManager_CommitTransition_NoActive(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	err := sm.CommitTransition(ctx)
	if err != ErrNoActiveTransition {
		t.Errorf("Expected ErrNoActiveTransition, got %v", err)
	}
}

func TestStateManager_RollbackTransition(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	sm.BeginTransition(ctx, ModeElevated, "test", "admin")

	err := sm.RollbackTransition(ctx, "test cancelled")
	if err != nil {
		t.Fatalf("RollbackTransition() error = %v", err)
	}

	// Mode should remain normal
	if sm.GetCurrentMode() != ModeNormal {
		t.Errorf("Mode = %s, want normal", sm.GetCurrentMode())
	}

	// Should be able to start new transition
	_, err = sm.BeginTransition(ctx, ModeLockdown, "new", "admin")
	if err != nil {
		t.Errorf("Should allow new transition after rollback: %v", err)
	}
}

func TestStateManager_RollbackTransition_NoActive(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	err := sm.RollbackTransition(ctx, "no transition")
	if err != ErrNoActiveTransition {
		t.Errorf("Expected ErrNoActiveTransition, got %v", err)
	}
}

func TestStateManager_DeescalationRequiresApproval(t *testing.T) {
	config := &StateManagerConfig{
		RequireApprovalForDeescalation: true,
	}
	sm, _ := NewStateManager(config, nil)
	ctx := context.Background()

	// First escalate
	sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
	sm.CommitTransition(ctx)

	// Now try to de-escalate without approval
	sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")
	err := sm.CommitTransition(ctx)
	if err == nil {
		t.Error("De-escalation should require approval")
	}
}

func TestStateManager_ApproveTransition(t *testing.T) {
	config := &StateManagerConfig{
		RequireApprovalForDeescalation: true,
	}
	sm, _ := NewStateManager(config, nil)
	ctx := context.Background()

	// Escalate first
	sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
	sm.CommitTransition(ctx)

	// Start de-escalation
	transition, _ := sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")

	// Approve
	err := sm.ApproveTransition(ctx, transition.ID, "supervisor")
	if err != nil {
		t.Fatalf("ApproveTransition() error = %v", err)
	}

	// Now commit should work
	err = sm.CommitTransition(ctx)
	if err != nil {
		t.Errorf("CommitTransition() after approval error = %v", err)
	}
}

func TestStateManager_ApproveTransition_NoActive(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	err := sm.ApproveTransition(ctx, "some-id", "approver")
	if err != ErrNoActiveTransition {
		t.Errorf("Expected ErrNoActiveTransition, got %v", err)
	}
}

func TestStateManager_CreateCheckpoint(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	initialLen := len(sm.GetCommitmentChain().Commitments)

	err := sm.CreateCheckpoint(ctx, "manual checkpoint")
	if err != nil {
		t.Fatalf("CreateCheckpoint() error = %v", err)
	}

	chain := sm.GetCommitmentChain()
	if len(chain.Commitments) != initialLen+1 {
		t.Errorf("Chain length = %d, want %d", len(chain.Commitments), initialLen+1)
	}
}

func TestStateManager_VerifyChain(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	// Do some operations
	sm.SetState("test", "value")
	sm.CreateCheckpoint(ctx, "test")
	sm.BeginTransition(ctx, ModeElevated, "test", "admin")
	sm.CommitTransition(ctx)

	// Verify chain
	err := sm.VerifyChain()
	if err != nil {
		t.Errorf("VerifyChain() error = %v", err)
	}
}

func TestStateManager_VerifyCurrentState(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	// Create checkpoint
	sm.CreateCheckpoint(ctx, "test")

	// Should verify
	err := sm.VerifyCurrentState()
	if err != nil {
		t.Errorf("VerifyCurrentState() error = %v", err)
	}
}

func TestStateManager_GetTransitionHistory(t *testing.T) {
	// Disable approval requirement for this test
	config := &StateManagerConfig{
		RequireApprovalForDeescalation: false,
		MaxTransitionHistory:           100,
	}
	sm, _ := NewStateManager(config, nil)
	ctx := context.Background()

	// Do some transitions
	for i := 0; i < 3; i++ {
		sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
		sm.CommitTransition(ctx)
		sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")
		sm.CommitTransition(ctx)
	}

	history := sm.GetTransitionHistory(5)
	if len(history) != 5 {
		t.Errorf("History length = %d, want 5", len(history))
	}

	// Request more than exists
	history = sm.GetTransitionHistory(100)
	if len(history) != 6 {
		t.Errorf("History length = %d, want 6", len(history))
	}
}

func TestStateManager_ExportChain(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	sm.CreateCheckpoint(ctx, "test")

	data, err := sm.ExportChain()
	if err != nil {
		t.Fatalf("ExportChain() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("ExportChain() returned empty data")
	}
}

func TestStateManager_Callbacks(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	startCalled := false
	endCalled := false

	sm.OnTransitionStart(func(mt *ModeTransition) {
		startCalled = true
	})
	sm.OnTransitionEnd(func(mt *ModeTransition) {
		endCalled = true
	})

	sm.BeginTransition(ctx, ModeElevated, "test", "admin")
	time.Sleep(10 * time.Millisecond) // Allow goroutine to run

	if !startCalled {
		t.Error("OnTransitionStart callback not called")
	}

	sm.CommitTransition(ctx)
	time.Sleep(10 * time.Millisecond)

	if !endCalled {
		t.Error("OnTransitionEnd callback not called")
	}
}

func TestStateManager_GetActiveTransition(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	// No active transition
	if sm.GetActiveTransition() != nil {
		t.Error("Expected nil active transition")
	}

	// Start transition
	sm.BeginTransition(ctx, ModeElevated, "test", "admin")
	active := sm.GetActiveTransition()
	if active == nil {
		t.Error("Expected active transition")
	}
	if active.ToMode != ModeElevated {
		t.Errorf("ToMode = %s, want elevated", active.ToMode)
	}

	// Commit
	sm.CommitTransition(ctx)
	if sm.GetActiveTransition() != nil {
		t.Error("Expected nil after commit")
	}
}

func TestStateManager_GenerateStateProof(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	sm.SetState("key1", "value1")
	sm.SetState("key2", "value2")

	// Without entries
	proof, err := sm.GenerateStateProof(ctx, false)
	if err != nil {
		t.Fatalf("GenerateStateProof() error = %v", err)
	}

	if proof.StateHash == "" {
		t.Error("StateHash is empty")
	}
	if proof.Signature == "" {
		t.Error("Signature is empty")
	}
	if proof.Entries != nil {
		t.Error("Entries should be nil when includeEntries=false")
	}

	// With entries
	proof, err = sm.GenerateStateProof(ctx, true)
	if err != nil {
		t.Fatalf("GenerateStateProof(true) error = %v", err)
	}

	if len(proof.Entries) != 2 {
		t.Errorf("Entries length = %d, want 2", len(proof.Entries))
	}
}

func TestStateManager_VerifyStateProof(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	sm.SetState("test", "value")

	proof, _ := sm.GenerateStateProof(ctx, false)

	// Verify valid proof
	if !sm.VerifyStateProof(proof) {
		t.Error("Valid proof should verify")
	}

	// Tamper with proof
	proof.StateHash = "tampered"
	if sm.VerifyStateProof(proof) {
		t.Error("Tampered proof should not verify")
	}
}

func TestHasher(t *testing.T) {
	tests := []struct {
		algorithm string
		length    int
	}{
		{"sha256", 64},
		{"sha512", 128},
		{"sha384", 96},
		{"unknown", 64}, // defaults to sha256
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			h := NewHasher(tt.algorithm)
			result := h.HashString("test")
			if len(result) != tt.length {
				t.Errorf("Hash length = %d, want %d", len(result), tt.length)
			}
		})
	}
}

func TestHasher_HashBytes(t *testing.T) {
	h := NewHasher("sha256")
	result := h.HashBytes([]byte("test"))
	if result == "" {
		t.Error("HashBytes returned empty string")
	}

	// Same input should produce same output
	result2 := h.HashBytes([]byte("test"))
	if result != result2 {
		t.Error("HashBytes is not deterministic")
	}
}

func TestDefaultStateManagerConfig(t *testing.T) {
	config := DefaultStateManagerConfig()

	if config.PersistPath == "" {
		t.Error("PersistPath should have default value")
	}
	if config.MaxTransitionHistory <= 0 {
		t.Error("MaxTransitionHistory should be positive")
	}
	if !config.RequireApprovalForDeescalation {
		t.Error("RequireApprovalForDeescalation should be true by default")
	}
	if config.HashAlgorithm == "" {
		t.Error("HashAlgorithm should have default value")
	}
	if !config.AutoCheckpoint {
		t.Error("AutoCheckpoint should be true by default")
	}
	if config.CheckpointInterval <= 0 {
		t.Error("CheckpointInterval should be positive")
	}
}

func TestGenerateNonce(t *testing.T) {
	nonce1 := generateNonce()
	nonce2 := generateNonce()

	if nonce1 == "" {
		t.Error("generateNonce returned empty string")
	}
	if nonce1 == nonce2 {
		t.Error("generateNonce should return unique values")
	}
}

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()

	if id1 == "" {
		t.Error("generateID returned empty string")
	}
	if id1 == id2 {
		t.Error("generateID should return unique values")
	}
}

func TestComputeGenesisHash(t *testing.T) {
	hash := computeGenesisHash()
	if hash == "" {
		t.Error("computeGenesisHash returned empty string")
	}
}

func TestStateManager_MerkleRoot(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	// Empty state should have empty merkle root
	proof, _ := sm.GenerateStateProof(ctx, false)
	if proof.MerkleRoot != "" {
		t.Error("Empty state should have empty merkle root")
	}

	// Add entries
	sm.SetState("a", "1")
	sm.SetState("b", "2")
	sm.SetState("c", "3")

	proof, _ = sm.GenerateStateProof(ctx, false)
	if proof.MerkleRoot == "" {
		t.Error("Non-empty state should have merkle root")
	}
}

func TestStateManager_ConcurrentAccess(t *testing.T) {
	sm, _ := NewStateManager(testConfigNoPersistence(t), nil)
	ctx := context.Background()

	done := make(chan bool, 100)

	// Concurrent reads
	for i := 0; i < 50; i++ {
		go func() {
			sm.GetCurrentMode()
			sm.GetState("test")
			sm.GetCommitmentChain()
			done <- true
		}()
	}

	// Concurrent writes
	for i := 0; i < 50; i++ {
		go func(i int) {
			sm.SetState("key", "value")
			sm.CreateCheckpoint(ctx, "test")
			done <- true
		}(i)
	}

	// Wait for all
	for i := 0; i < 100; i++ {
		<-done
	}

	// Verify chain is still valid
	if err := sm.VerifyChain(); err != nil {
		t.Errorf("Chain invalid after concurrent access: %v", err)
	}
}

func TestStateManager_Persistence(t *testing.T) {
	config := testConfig(t)
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Set some state
	sm.SetState("key1", "value1")
	sm.SetState("key2", "value2")

	// Transition to elevated mode
	_, err = sm.BeginTransition(ctx, ModeElevated, "test", "admin")
	if err != nil {
		t.Fatalf("BeginTransition() error = %v", err)
	}

	err = sm.CommitTransition(ctx)
	if err != nil {
		t.Fatalf("CommitTransition() error = %v", err)
	}

	// Force persist
	err = sm.ForcePersist(ctx)
	if err != nil {
		t.Fatalf("ForcePersist() error = %v", err)
	}

	// Check if persisted
	persisted, err := sm.IsPersisted()
	if err != nil {
		t.Fatalf("IsPersisted() error = %v", err)
	}
	if !persisted {
		t.Error("Expected state to be persisted")
	}
}

func TestStateManager_PersistenceRecovery(t *testing.T) {
	config := testConfig(t)
	ctx := context.Background()

	// Create first manager and do some transitions
	sm1, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	sm1.SetState("recovery_key", "recovery_value")

	_, err = sm1.BeginTransition(ctx, ModeLockdown, "test", "admin")
	if err != nil {
		t.Fatalf("BeginTransition() error = %v", err)
	}

	err = sm1.CommitTransition(ctx)
	if err != nil {
		t.Fatalf("CommitTransition() error = %v", err)
	}

	// Get state hash for comparison
	chain1 := sm1.GetCommitmentChain()
	chainLen := len(chain1.Commitments)
	mode1 := sm1.GetCurrentMode()

	// Create second manager - should recover state
	sm2, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() second error = %v", err)
	}

	// Verify recovered state
	if sm2.GetCurrentMode() != mode1 {
		t.Errorf("Recovered mode = %s, want %s", sm2.GetCurrentMode(), mode1)
	}

	chain2 := sm2.GetCommitmentChain()
	if len(chain2.Commitments) != chainLen {
		t.Errorf("Recovered chain length = %d, want %d", len(chain2.Commitments), chainLen)
	}

	val, ok := sm2.GetState("recovery_key")
	if !ok || val != "recovery_value" {
		t.Errorf("Recovered state key = %q, want 'recovery_value'", val)
	}
}

func TestStateManager_PersistenceVerification(t *testing.T) {
	config := testConfig(t)
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Transition with persistence required
	_, err = sm.BeginTransition(ctx, ModeElevated, "test", "admin")
	if err != nil {
		t.Fatalf("BeginTransition() error = %v", err)
	}

	err = sm.CommitTransition(ctx)
	if err != nil {
		t.Fatalf("CommitTransition() error = %v", err)
	}

	// Verify state was persisted
	persisted, err := sm.IsPersisted()
	if err != nil {
		t.Fatalf("IsPersisted() error = %v", err)
	}

	if !persisted {
		t.Error("State should be persisted after commit with RequirePersistence=true")
	}
}

func TestStateManager_CheckpointPersistence(t *testing.T) {
	config := testConfig(t)
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Set state and create checkpoint
	sm.SetState("checkpoint_key", "checkpoint_value")

	err = sm.CreateCheckpoint(ctx, "manual checkpoint")
	if err != nil {
		t.Fatalf("CreateCheckpoint() error = %v", err)
	}

	// Verify chain has checkpoint
	chain := sm.GetCommitmentChain()
	found := false
	for _, c := range chain.Commitments {
		if c.CommitmentType == "checkpoint" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected checkpoint in commitment chain")
	}
}

func TestPersistedState_ChecksumVerification(t *testing.T) {
	config := testConfig(t)
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Create some state
	sm.SetState("checksum_key", "checksum_value")
	err = sm.ForcePersist(ctx)
	if err != nil {
		t.Fatalf("ForcePersist() error = %v", err)
	}

	// Verify checksum is computed
	persisted, err := sm.IsPersisted()
	if err != nil {
		t.Fatalf("IsPersisted() error = %v", err)
	}
	if !persisted {
		t.Error("State should be persisted and verified")
	}
}

// ======================================
// Human Confirmation Tests
// ======================================

func TestStateManager_DeescalationRequiresConfirmation(t *testing.T) {
	config := testConfigWithConfirmation(t)
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// First escalate (no confirmation needed for escalation)
	transition, err := sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
	if err != nil {
		t.Fatalf("BeginTransition() escalation error = %v", err)
	}
	if transition.Status != "pending" {
		t.Errorf("Escalation should have status pending, got %s", transition.Status)
	}
	if transition.Confirmation != nil {
		t.Error("Escalation should not require confirmation")
	}

	err = sm.CommitTransition(ctx)
	if err != nil {
		t.Fatalf("CommitTransition() escalation error = %v", err)
	}

	// Now try to de-escalate (should require confirmation)
	transition, err = sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")
	if err != nil {
		t.Fatalf("BeginTransition() deescalation error = %v", err)
	}

	if transition.Status != "awaiting_confirmation" {
		t.Errorf("Deescalation should have status awaiting_confirmation, got %s", transition.Status)
	}
	if transition.Confirmation == nil {
		t.Fatal("Deescalation should have confirmation set")
	}

	// Try to commit without confirmation - should fail
	err = sm.CommitTransition(ctx)
	if err == nil {
		t.Error("CommitTransition() should fail without confirmation")
	}
}

func TestStateManager_ConfirmationCodeGeneration(t *testing.T) {
	config := testConfigWithConfirmation(t)
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Escalate first
	sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
	sm.CommitTransition(ctx)

	// De-escalate
	transition, _ := sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")

	// Get the confirmation code
	code, err := sm.GetPendingConfirmationCode(transition.ID)
	if err != nil {
		t.Fatalf("GetPendingConfirmationCode() error = %v", err)
	}

	if code == "" {
		t.Error("Confirmation code should not be empty")
	}
	if len(code) != config.ConfirmationCodeLength {
		t.Errorf("Code length = %d, want %d", len(code), config.ConfirmationCodeLength)
	}

	// Code should only be retrievable once
	code2, _ := sm.GetPendingConfirmationCode(transition.ID)
	if code2 != "" {
		t.Error("Confirmation code should be cleared after first retrieval")
	}
}

func TestStateManager_ConfirmTransitionSuccess(t *testing.T) {
	config := testConfigWithConfirmation(t)
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Escalate first
	sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
	sm.CommitTransition(ctx)

	// De-escalate
	transition, _ := sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")
	code, _ := sm.GetPendingConfirmationCode(transition.ID)

	// Confirm with correct code
	err = sm.ConfirmTransition(ctx, transition.ID, code, "supervisor", "code")
	if err != nil {
		t.Fatalf("ConfirmTransition() error = %v", err)
	}

	// Check confirmation status
	status, err := sm.GetConfirmationStatus(transition.ID)
	if err != nil {
		t.Fatalf("GetConfirmationStatus() error = %v", err)
	}
	if !status.Verified {
		t.Error("Confirmation should be verified")
	}
	if len(status.Approvers) != 1 {
		t.Errorf("Should have 1 approver, got %d", len(status.Approvers))
	}

	// Now commit should work
	err = sm.CommitTransition(ctx)
	if err != nil {
		t.Errorf("CommitTransition() after confirmation error = %v", err)
	}

	if sm.GetCurrentMode() != ModeNormal {
		t.Errorf("Mode = %s, want normal", sm.GetCurrentMode())
	}
}

func TestStateManager_ConfirmTransitionInvalidCode(t *testing.T) {
	config := testConfigWithConfirmation(t)
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Escalate and de-escalate
	sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
	sm.CommitTransition(ctx)
	transition, _ := sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")
	sm.GetPendingConfirmationCode(transition.ID) // retrieve and clear

	// Try with wrong code
	err = sm.ConfirmTransition(ctx, transition.ID, "WRONGCODE", "supervisor", "code")
	if err != ErrInvalidConfirmation {
		t.Errorf("Expected ErrInvalidConfirmation, got %v", err)
	}

	// Check attempts were incremented
	status, _ := sm.GetConfirmationStatus(transition.ID)
	if status.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1", status.Attempts)
	}
}

func TestStateManager_ConfirmTransitionTooManyAttempts(t *testing.T) {
	config := testConfigWithConfirmation(t)
	config.ConfirmationMaxAttempts = 2
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Escalate and de-escalate
	sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
	sm.CommitTransition(ctx)
	transition, _ := sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")
	sm.GetPendingConfirmationCode(transition.ID)

	// Exhaust attempts
	sm.ConfirmTransition(ctx, transition.ID, "WRONG1", "supervisor", "code")
	sm.ConfirmTransition(ctx, transition.ID, "WRONG2", "supervisor", "code")

	// Next attempt should fail with too many attempts
	err = sm.ConfirmTransition(ctx, transition.ID, "WRONG3", "supervisor", "code")
	if err != ErrTooManyAttempts {
		t.Errorf("Expected ErrTooManyAttempts, got %v", err)
	}
}

func TestStateManager_ConfirmTransitionExpired(t *testing.T) {
	config := testConfigWithConfirmation(t)
	config.ConfirmationTimeout = 1 * time.Millisecond // Very short timeout
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Escalate and de-escalate
	sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
	sm.CommitTransition(ctx)
	transition, _ := sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")
	code, _ := sm.GetPendingConfirmationCode(transition.ID)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Try to confirm - should fail
	err = sm.ConfirmTransition(ctx, transition.ID, code, "supervisor", "code")
	if err != ErrConfirmationExpired {
		t.Errorf("Expected ErrConfirmationExpired, got %v", err)
	}
}

func TestStateManager_ConfirmTransitionDuplicateApprover(t *testing.T) {
	config := testConfigWithConfirmation(t)
	config.RequiredApprovers = 2
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Escalate and de-escalate
	sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
	sm.CommitTransition(ctx)
	transition, _ := sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")
	code, _ := sm.GetPendingConfirmationCode(transition.ID)

	// First approval
	err = sm.ConfirmTransition(ctx, transition.ID, code, "supervisor1", "code")
	if err != nil {
		t.Fatalf("First approval error = %v", err)
	}

	// Try same approver again
	err = sm.ConfirmTransition(ctx, transition.ID, code, "supervisor1", "code")
	if err != ErrDuplicateApprover {
		t.Errorf("Expected ErrDuplicateApprover, got %v", err)
	}
}

func TestStateManager_MultiApproverConfirmation(t *testing.T) {
	config := testConfigWithConfirmation(t)
	config.RequiredApprovers = 2
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Escalate and de-escalate
	sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
	sm.CommitTransition(ctx)
	transition, _ := sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")
	code, _ := sm.GetPendingConfirmationCode(transition.ID)

	// First approval
	err = sm.ConfirmTransition(ctx, transition.ID, code, "supervisor1", "code")
	if err != nil {
		t.Fatalf("First approval error = %v", err)
	}

	// Should still need more approvals
	status, _ := sm.GetConfirmationStatus(transition.ID)
	if status.Verified {
		t.Error("Should not be verified with only 1 approver")
	}

	// Try to commit - should fail
	err = sm.CommitTransition(ctx)
	if err != ErrInsufficientApprovers {
		t.Errorf("Expected ErrInsufficientApprovers, got %v", err)
	}

	// Second approval
	err = sm.ConfirmTransition(ctx, transition.ID, code, "supervisor2", "code")
	if err != nil {
		t.Fatalf("Second approval error = %v", err)
	}

	// Now should be verified
	status, _ = sm.GetConfirmationStatus(transition.ID)
	if !status.Verified {
		t.Error("Should be verified with 2 approvers")
	}
	if len(status.Approvers) != 2 {
		t.Errorf("Should have 2 approvers, got %d", len(status.Approvers))
	}

	// Now commit should work
	err = sm.CommitTransition(ctx)
	if err != nil {
		t.Errorf("CommitTransition() error = %v", err)
	}
}

func TestStateManager_CriticalModeRequiresMultiApproval(t *testing.T) {
	config := testConfigWithConfirmation(t)
	config.RequiredApprovers = 1        // Normal transitions need 1
	config.CriticalModeThreshold = 2    // Lockdown (level 2) and above are critical
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Escalate to lockdown (level 2)
	sm.BeginTransition(ctx, ModeLockdown, "escalate", "admin")
	sm.CommitTransition(ctx)

	// De-escalate from critical mode
	transition, _ := sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")

	// Should require at least 2 approvers
	status, _ := sm.GetConfirmationStatus(transition.ID)
	if status.RequiredCount < 2 {
		t.Errorf("Critical mode deescalation should require at least 2 approvers, got %d", status.RequiredCount)
	}
}

func TestStateManager_CancelConfirmation(t *testing.T) {
	config := testConfigWithConfirmation(t)
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Escalate and de-escalate
	sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
	sm.CommitTransition(ctx)
	transition, _ := sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")

	// Cancel confirmation
	err = sm.CancelConfirmation(ctx, transition.ID, "test cancellation")
	if err != nil {
		t.Fatalf("CancelConfirmation() error = %v", err)
	}

	// Status should be back to pending
	active := sm.GetActiveTransition()
	if active.Status != "pending" {
		t.Errorf("Status = %s, want pending", active.Status)
	}
	if active.Confirmation != nil {
		t.Error("Confirmation should be nil after cancellation")
	}
}

func TestStateManager_ConfirmationCallback(t *testing.T) {
	callbackCalled := false
	var receivedCode string
	var receivedTransition *ModeTransition

	config := testConfigWithConfirmation(t)
	config.OnConfirmationRequired = func(transition *ModeTransition, code string) {
		callbackCalled = true
		receivedCode = code
		receivedTransition = transition
	}

	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Escalate and de-escalate
	sm.BeginTransition(ctx, ModeElevated, "escalate", "admin")
	sm.CommitTransition(ctx)
	transition, _ := sm.BeginTransition(ctx, ModeNormal, "deescalate", "admin")

	// Give the callback goroutine time to run
	time.Sleep(10 * time.Millisecond)

	if !callbackCalled {
		t.Error("OnConfirmationRequired callback should have been called")
	}
	if receivedCode == "" {
		t.Error("Callback should receive non-empty code")
	}
	if receivedTransition == nil || receivedTransition.ID != transition.ID {
		t.Error("Callback should receive the transition")
	}
}

func TestStateManager_InitiateConfirmation(t *testing.T) {
	config := testConfigNoPersistence(t) // Start without auto-confirmation
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Start a transition
	transition, _ := sm.BeginTransition(ctx, ModeElevated, "test", "admin")

	// Manually initiate confirmation
	code, err := sm.InitiateConfirmation(ctx, transition.ID)
	if err != nil {
		t.Fatalf("InitiateConfirmation() error = %v", err)
	}

	if code == "" {
		t.Error("InitiateConfirmation should return a code")
	}

	// Verify confirmation was created
	status, err := sm.GetConfirmationStatus(transition.ID)
	if err != nil {
		t.Fatalf("GetConfirmationStatus() error = %v", err)
	}
	if status == nil {
		t.Error("Confirmation should exist after InitiateConfirmation")
	}
}

func TestStateManager_ConfirmTransition_NoActiveTransition(t *testing.T) {
	config := testConfigWithConfirmation(t)
	sm, err := NewStateManager(config, nil)
	if err != nil {
		t.Fatalf("NewStateManager() error = %v", err)
	}

	ctx := context.Background()

	// Try to confirm non-existent transition
	err = sm.ConfirmTransition(ctx, "non-existent-id", "CODE1234", "approver", "code")
	if err != ErrNoActiveTransition {
		t.Errorf("Expected ErrNoActiveTransition, got %v", err)
	}
}

func TestDefaultStateManagerConfig_ConfirmationDefaults(t *testing.T) {
	config := DefaultStateManagerConfig()

	if !config.RequireHumanConfirmation {
		t.Error("RequireHumanConfirmation should be true by default")
	}
	if config.ConfirmationCodeLength <= 0 {
		t.Error("ConfirmationCodeLength should be positive")
	}
	if config.ConfirmationTimeout <= 0 {
		t.Error("ConfirmationTimeout should be positive")
	}
	if config.ConfirmationMaxAttempts <= 0 {
		t.Error("ConfirmationMaxAttempts should be positive")
	}
	if config.RequiredApprovers <= 0 {
		t.Error("RequiredApprovers should be positive")
	}
}

package firewall

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

func TestNewChainManager(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()

	cm := NewChainManager(BackendNftables, config, logger)

	if cm == nil {
		t.Fatal("expected non-nil ChainManager")
	}
	if cm.backend != BackendNftables {
		t.Errorf("backend = %v, want %v", cm.backend, BackendNftables)
	}
}

func TestChainState(t *testing.T) {
	if ChainStateUnknown != 0 {
		t.Errorf("ChainStateUnknown = %d, want 0", ChainStateUnknown)
	}
	if ChainStateActive != 2 {
		t.Errorf("ChainStateActive = %d, want 2", ChainStateActive)
	}
	if ChainStateError != 5 {
		t.Errorf("ChainStateError = %d, want 5", ChainStateError)
	}
}

func TestOperationType(t *testing.T) {
	if OpCreateChain != 0 {
		t.Errorf("OpCreateChain = %d, want 0", OpCreateChain)
	}
	if OpAddRule != 2 {
		t.Errorf("OpAddRule = %d, want 2", OpAddRule)
	}
}

func TestChain(t *testing.T) {
	chain := &Chain{
		Name:     "test_chain",
		Table:    "filter",
		Family:   "inet",
		Type:     "filter",
		Hook:     "input",
		Priority: 0,
		Policy:   "drop",
	}

	if chain.Name != "test_chain" {
		t.Errorf("Name = %q, want %q", chain.Name, "test_chain")
	}
	if chain.Family != "inet" {
		t.Errorf("Family = %q, want %q", chain.Family, "inet")
	}
}

func TestChainOperation(t *testing.T) {
	chain := &Chain{Name: "test", Table: "filter", Family: "inet"}
	op := &ChainOperation{
		Type:      OpCreateChain,
		Chain:     chain,
		Timestamp: time.Now(),
	}

	if op.Type != OpCreateChain {
		t.Errorf("Type = %v, want %v", op.Type, OpCreateChain)
	}
	if op.Committed {
		t.Error("expected not committed initially")
	}
}

func TestChainManager_GetChainLock(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	// Get lock for a chain
	lock1 := cm.getChainLock("chain1")
	if lock1 == nil {
		t.Fatal("expected non-nil lock")
	}

	// Get same lock again
	lock2 := cm.getChainLock("chain1")
	if lock1 != lock2 {
		t.Error("expected same lock for same chain")
	}

	// Get lock for different chain
	lock3 := cm.getChainLock("chain2")
	if lock1 == lock3 {
		t.Error("expected different lock for different chain")
	}
}

func TestChainManager_Transaction_NoTransaction(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	ctx := context.Background()

	// Commit without transaction should fail
	err := cm.CommitTransaction(ctx)
	if err == nil {
		t.Error("expected error for commit without transaction")
	}

	// Rollback without transaction should fail
	err = cm.RollbackTransaction(ctx)
	if err == nil {
		t.Error("expected error for rollback without transaction")
	}
}

func TestChainManager_Transaction_DoubleBegin(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	// First begin should succeed
	err := cm.BeginTransaction()
	if err != nil {
		t.Fatalf("BeginTransaction() error = %v", err)
	}

	// Second begin should fail (transaction already in progress)
	err = cm.BeginTransaction()
	if err == nil {
		t.Error("expected error for double begin")
	}

	// Cleanup
	cm.RollbackTransaction(context.Background())
}

func TestChainManager_ListChains_Empty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	chains := cm.ListChains()
	if len(chains) != 0 {
		t.Errorf("expected 0 chains, got %d", len(chains))
	}
}

func TestChainManager_GetChain_NotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	chain := cm.GetChain("inet", "filter", "nonexistent")
	if chain != nil {
		t.Error("expected nil for nonexistent chain")
	}
}

func TestChainManager_OperationToNftables_CreateChain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	chain := &Chain{
		Name:     "test",
		Table:    "filter",
		Family:   "inet",
		Type:     "filter",
		Hook:     "input",
		Priority: 0,
		Policy:   "drop",
	}

	op := &ChainOperation{
		Type:  OpCreateChain,
		Chain: chain,
	}

	cmd := cm.operationToNftables(op)
	if cmd == "" {
		t.Error("expected non-empty command")
	}
	if !contains(cmd, "add chain") {
		t.Errorf("command should contain 'add chain': %s", cmd)
	}
	if !contains(cmd, "inet") {
		t.Errorf("command should contain 'inet': %s", cmd)
	}
}

func TestChainManager_OperationToNftables_DeleteChain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	chain := &Chain{
		Name:   "test",
		Table:  "filter",
		Family: "inet",
	}

	op := &ChainOperation{
		Type:  OpDeleteChain,
		Chain: chain,
	}

	cmd := cm.operationToNftables(op)
	if !contains(cmd, "delete chain") {
		t.Errorf("command should contain 'delete chain': %s", cmd)
	}
}

func TestChainManager_OperationToNftables_FlushChain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	chain := &Chain{
		Name:   "test",
		Table:  "filter",
		Family: "inet",
	}

	op := &ChainOperation{
		Type:  OpFlushChain,
		Chain: chain,
	}

	cmd := cm.operationToNftables(op)
	if !contains(cmd, "flush chain") {
		t.Errorf("command should contain 'flush chain': %s", cmd)
	}
}

func TestChainManager_OperationToNftables_AddRule(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	chain := &Chain{
		Name:   "test",
		Table:  "filter",
		Family: "inet",
	}

	op := &ChainOperation{
		Type:  OpAddRule,
		Chain: chain,
		Rule:  "tcp dport 80 accept",
	}

	cmd := cm.operationToNftables(op)
	if !contains(cmd, "add rule") {
		t.Errorf("command should contain 'add rule': %s", cmd)
	}
	if !contains(cmd, "tcp dport 80 accept") {
		t.Errorf("command should contain rule: %s", cmd)
	}
}

func TestChainManager_UpdateChainState(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	chain := &Chain{
		Name:   "test",
		Table:  "filter",
		Family: "inet",
	}

	// Create chain
	op := &ChainOperation{
		Type:  OpCreateChain,
		Chain: chain,
	}
	cm.updateChainState(op)

	// Check chain was added
	stored := cm.GetChain("inet", "filter", "test")
	if stored == nil {
		t.Fatal("expected chain to be stored")
	}
	if stored.State != ChainStateActive {
		t.Errorf("State = %v, want %v", stored.State, ChainStateActive)
	}

	// Add rule
	op = &ChainOperation{
		Type:  OpAddRule,
		Chain: chain,
		Rule:  "accept",
	}
	cm.updateChainState(op)

	stored = cm.GetChain("inet", "filter", "test")
	if stored.RuleCount != 1 {
		t.Errorf("RuleCount = %d, want 1", stored.RuleCount)
	}

	// Flush chain
	op = &ChainOperation{
		Type:  OpFlushChain,
		Chain: chain,
	}
	cm.updateChainState(op)

	stored = cm.GetChain("inet", "filter", "test")
	if stored.RuleCount != 0 {
		t.Errorf("RuleCount = %d, want 0", stored.RuleCount)
	}

	// Delete chain
	op = &ChainOperation{
		Type:  OpDeleteChain,
		Chain: chain,
	}
	cm.updateChainState(op)

	stored = cm.GetChain("inet", "filter", "test")
	if stored != nil {
		t.Error("expected chain to be deleted")
	}
}

func TestChainManager_ConcurrentLocking(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	// Simulate concurrent access to chain locks
	var wg sync.WaitGroup
	numGoroutines := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Each goroutine gets locks for multiple chains
			for j := 0; j < 5; j++ {
				chainName := "chain_" + string(rune('a'+j))
				lock := cm.getChainLock(chainName)
				lock.Lock()
				// Simulate some work
				time.Sleep(time.Microsecond)
				lock.Unlock()
			}
		}(i)
	}

	wg.Wait()
}

func TestChainManager_WaitForChainReady_Timeout(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	chain := &Chain{
		Name:   "nonexistent",
		Table:  "filter",
		Family: "inet",
	}

	ctx := context.Background()
	err := cm.WaitForChainReady(ctx, chain, 100*time.Millisecond)
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestChainManager_WaitForChainReady_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	chain := &Chain{
		Name:   "test",
		Table:  "filter",
		Family: "inet",
	}

	// Add chain to internal state
	cm.mu.Lock()
	chain.State = ChainStateActive
	cm.chains["inet.filter.test"] = chain
	cm.mu.Unlock()

	ctx := context.Background()
	err := cm.WaitForChainReady(ctx, chain, 100*time.Millisecond)
	if err != nil {
		t.Errorf("WaitForChainReady() error = %v", err)
	}
}

func TestChainManager_WaitForChainReady_ContextCanceled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	chain := &Chain{
		Name:   "nonexistent",
		Table:  "filter",
		Family: "inet",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := cm.WaitForChainReady(ctx, chain, 1*time.Second)
	if err == nil {
		t.Error("expected context canceled error")
	}
}

func TestChainManager_SafeModifyChain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	chain := &Chain{
		Name:   "test",
		Table:  "filter",
		Family: "inet",
	}

	// Add chain to internal state
	cm.mu.Lock()
	chain.State = ChainStateActive
	cm.chains["inet.filter.test"] = chain
	cm.mu.Unlock()

	ctx := context.Background()
	modifyCalled := false

	err := cm.SafeModifyChain(ctx, chain, func() error {
		modifyCalled = true
		return nil
	})

	if err != nil {
		t.Errorf("SafeModifyChain() error = %v", err)
	}
	if !modifyCalled {
		t.Error("modify function was not called")
	}

	// Check state was updated
	stored := cm.GetChain("inet", "filter", "test")
	if stored.State != ChainStateActive {
		t.Errorf("State = %v, want %v", stored.State, ChainStateActive)
	}
}

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

func BenchmarkGetChainLock(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cm.getChainLock("test_chain")
	}
}

func BenchmarkOperationToNftables(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	config := DefaultConfig()
	cm := NewChainManager(BackendNftables, config, logger)

	chain := &Chain{
		Name:     "test",
		Table:    "filter",
		Family:   "inet",
		Type:     "filter",
		Hook:     "input",
		Priority: 0,
		Policy:   "drop",
	}

	op := &ChainOperation{
		Type:  OpCreateChain,
		Chain: chain,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cm.operationToNftables(op)
	}
}

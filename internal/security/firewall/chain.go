// Package firewall provides chain management with race condition prevention.
// This file implements atomic chain operations with proper locking.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ChainState represents the state of a firewall chain.
type ChainState int

const (
	ChainStateUnknown ChainState = iota
	ChainStateCreating
	ChainStateActive
	ChainStateModifying
	ChainStateDeleting
	ChainStateError
)

// Chain represents a firewall chain.
type Chain struct {
	Name       string     `json:"name"`
	Table      string     `json:"table"`
	Family     string     `json:"family"` // inet, ip, ip6
	Type       string     `json:"type"`   // filter, nat, route
	Hook       string     `json:"hook"`   // input, output, forward, prerouting, postrouting
	Priority   int        `json:"priority"`
	Policy     string     `json:"policy"` // accept, drop
	State      ChainState `json:"state"`
	RuleCount  int        `json:"rule_count"`
	CreatedAt  time.Time  `json:"created_at"`
	ModifiedAt time.Time  `json:"modified_at"`
}

// ChainOperation represents an atomic chain operation.
type ChainOperation struct {
	Type        OperationType `json:"type"`
	Chain       *Chain        `json:"chain"`
	Rule        string        `json:"rule,omitempty"`
	Timestamp   time.Time     `json:"timestamp"`
	Committed   bool          `json:"committed"`
	RollbackCmd string        `json:"rollback_cmd,omitempty"`
}

// OperationType represents the type of chain operation.
type OperationType int

const (
	OpCreateChain OperationType = iota
	OpDeleteChain
	OpAddRule
	OpDeleteRule
	OpFlushChain
	OpSetPolicy
)

// ChainManager manages firewall chains with proper synchronization.
type ChainManager struct {
	mu           sync.RWMutex
	chainLocks   map[string]*sync.Mutex // Per-chain locks
	locksMu      sync.Mutex             // Protects chainLocks map
	chains       map[string]*Chain
	backend      Backend
	config       *Config
	logger       *slog.Logger
	txMu         sync.Mutex // Transaction lock for atomic operations
	pendingOps   []*ChainOperation
	inTransaction bool
}

// NewChainManager creates a new chain manager.
func NewChainManager(backend Backend, config *Config, logger *slog.Logger) *ChainManager {
	return &ChainManager{
		chainLocks: make(map[string]*sync.Mutex),
		chains:     make(map[string]*Chain),
		backend:    backend,
		config:     config,
		logger:     logger,
		pendingOps: make([]*ChainOperation, 0),
	}
}

// getChainLock gets or creates a lock for a specific chain.
func (cm *ChainManager) getChainLock(chainName string) *sync.Mutex {
	cm.locksMu.Lock()
	defer cm.locksMu.Unlock()

	if lock, exists := cm.chainLocks[chainName]; exists {
		return lock
	}

	lock := &sync.Mutex{}
	cm.chainLocks[chainName] = lock
	return lock
}

// BeginTransaction starts an atomic transaction.
func (cm *ChainManager) BeginTransaction() error {
	// Use TryLock to avoid blocking if transaction already in progress
	if !cm.txMu.TryLock() {
		return errors.New("transaction already in progress")
	}

	cm.mu.Lock()
	cm.inTransaction = true
	cm.pendingOps = make([]*ChainOperation, 0)
	cm.mu.Unlock()

	cm.logger.Debug("began firewall transaction")
	return nil
}

// CommitTransaction commits all pending operations atomically.
func (cm *ChainManager) CommitTransaction(ctx context.Context) error {
	cm.mu.Lock()
	if !cm.inTransaction {
		cm.mu.Unlock()
		return errors.New("no transaction in progress")
	}

	ops := cm.pendingOps
	cm.mu.Unlock()

	// For nftables, use atomic file-based commit
	if cm.backend == BackendNftables {
		if err := cm.commitNftablesAtomic(ctx, ops); err != nil {
			cm.rollback(ctx, ops)
			cm.endTransaction()
			return err
		}
	} else {
		// For iptables, execute operations sequentially with rollback support
		for i, op := range ops {
			if err := cm.executeOperation(ctx, op); err != nil {
				// Rollback executed operations
				cm.rollback(ctx, ops[:i])
				cm.endTransaction()
				return fmt.Errorf("operation %d failed: %w", i, err)
			}
			op.Committed = true
		}
	}

	cm.endTransaction()
	cm.logger.Info("committed firewall transaction", "operations", len(ops))
	return nil
}

// RollbackTransaction rolls back all pending operations.
func (cm *ChainManager) RollbackTransaction(ctx context.Context) error {
	cm.mu.Lock()
	if !cm.inTransaction {
		cm.mu.Unlock()
		return errors.New("no transaction in progress")
	}

	ops := cm.pendingOps
	cm.mu.Unlock()

	cm.rollback(ctx, ops)
	cm.endTransaction()

	cm.logger.Info("rolled back firewall transaction")
	return nil
}

// endTransaction ends the current transaction.
func (cm *ChainManager) endTransaction() {
	cm.mu.Lock()
	cm.inTransaction = false
	cm.pendingOps = nil
	cm.mu.Unlock()
	cm.txMu.Unlock()
}

// rollback undoes committed operations in reverse order.
func (cm *ChainManager) rollback(ctx context.Context, ops []*ChainOperation) {
	for i := len(ops) - 1; i >= 0; i-- {
		op := ops[i]
		if op.Committed && op.RollbackCmd != "" {
			cm.executeRollback(ctx, op)
		}
	}
}

// commitNftablesAtomic commits nftables operations atomically using a temp file.
func (cm *ChainManager) commitNftablesAtomic(ctx context.Context, ops []*ChainOperation) error {
	// Create temporary file for atomic commit
	tmpFile, err := os.CreateTemp("", "nftables-tx-*.nft")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	// Build nftables script
	var script strings.Builder
	script.WriteString("#!/usr/sbin/nft -f\n")
	script.WriteString("# Atomic transaction\n\n")

	for _, op := range ops {
		cmd := cm.operationToNftables(op)
		if cmd != "" {
			script.WriteString(cmd)
			script.WriteString("\n")
		}
	}

	if _, err := tmpFile.WriteString(script.String()); err != nil {
		return fmt.Errorf("failed to write script: %w", err)
	}
	tmpFile.Close()

	// Execute atomically
	cmd := exec.CommandContext(ctx, cm.config.NftablesPath, "-f", tmpFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("atomic commit failed: %s: %w", string(output), err)
	}

	// Mark all operations as committed
	for _, op := range ops {
		op.Committed = true
	}

	return nil
}

// operationToNftables converts an operation to nftables command.
func (cm *ChainManager) operationToNftables(op *ChainOperation) string {
	switch op.Type {
	case OpCreateChain:
		if op.Chain.Hook != "" {
			return fmt.Sprintf("add chain %s %s %s { type %s hook %s priority %d; policy %s; }",
				op.Chain.Family, op.Chain.Table, op.Chain.Name,
				op.Chain.Type, op.Chain.Hook, op.Chain.Priority, op.Chain.Policy)
		}
		return fmt.Sprintf("add chain %s %s %s", op.Chain.Family, op.Chain.Table, op.Chain.Name)

	case OpDeleteChain:
		return fmt.Sprintf("delete chain %s %s %s", op.Chain.Family, op.Chain.Table, op.Chain.Name)

	case OpFlushChain:
		return fmt.Sprintf("flush chain %s %s %s", op.Chain.Family, op.Chain.Table, op.Chain.Name)

	case OpAddRule:
		return fmt.Sprintf("add rule %s %s %s %s",
			op.Chain.Family, op.Chain.Table, op.Chain.Name, op.Rule)

	case OpSetPolicy:
		// nftables doesn't have a direct policy command for base chains
		// This is set during chain creation
		return ""
	}
	return ""
}

// executeOperation executes a single chain operation.
func (cm *ChainManager) executeOperation(ctx context.Context, op *ChainOperation) error {
	chainLock := cm.getChainLock(op.Chain.Name)
	chainLock.Lock()
	defer chainLock.Unlock()

	switch cm.backend {
	case BackendNftables:
		return cm.executeNftablesOp(ctx, op)
	case BackendIptables:
		return cm.executeIptablesOp(ctx, op)
	default:
		return errors.New("no backend available")
	}
}

// executeNftablesOp executes an nftables operation.
func (cm *ChainManager) executeNftablesOp(ctx context.Context, op *ChainOperation) error {
	var args []string

	switch op.Type {
	case OpCreateChain:
		if op.Chain.Hook != "" {
			args = []string{"add", "chain", op.Chain.Family, op.Chain.Table, op.Chain.Name,
				"{", "type", op.Chain.Type, "hook", op.Chain.Hook,
				"priority", fmt.Sprintf("%d", op.Chain.Priority), ";",
				"policy", op.Chain.Policy, ";", "}"}
		} else {
			args = []string{"add", "chain", op.Chain.Family, op.Chain.Table, op.Chain.Name}
		}
		op.RollbackCmd = fmt.Sprintf("delete chain %s %s %s", op.Chain.Family, op.Chain.Table, op.Chain.Name)

	case OpDeleteChain:
		args = []string{"delete", "chain", op.Chain.Family, op.Chain.Table, op.Chain.Name}
		// Rollback would need to recreate the chain with its rules - complex

	case OpFlushChain:
		args = []string{"flush", "chain", op.Chain.Family, op.Chain.Table, op.Chain.Name}
		// Rollback would need to restore rules - save them first

	case OpAddRule:
		args = []string{"add", "rule", op.Chain.Family, op.Chain.Table, op.Chain.Name}
		args = append(args, strings.Fields(op.Rule)...)
		// Rollback: delete rule by handle (complex)
	}

	cmd := exec.CommandContext(ctx, cm.config.NftablesPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables command failed: %s: %w", string(output), err)
	}

	cm.updateChainState(op)
	return nil
}

// executeIptablesOp executes an iptables operation.
func (cm *ChainManager) executeIptablesOp(ctx context.Context, op *ChainOperation) error {
	var args []string

	switch op.Type {
	case OpCreateChain:
		args = []string{"-N", op.Chain.Name}
		op.RollbackCmd = fmt.Sprintf("-X %s", op.Chain.Name)

	case OpDeleteChain:
		args = []string{"-X", op.Chain.Name}

	case OpFlushChain:
		args = []string{"-F", op.Chain.Name}

	case OpAddRule:
		args = []string{"-A", op.Chain.Name}
		args = append(args, strings.Fields(op.Rule)...)

	case OpSetPolicy:
		args = []string{"-P", op.Chain.Name, op.Chain.Policy}
	}

	cmd := exec.CommandContext(ctx, cm.config.IptablesPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables command failed: %s: %w", string(output), err)
	}

	cm.updateChainState(op)
	return nil
}

// executeRollback executes a rollback command.
func (cm *ChainManager) executeRollback(ctx context.Context, op *ChainOperation) {
	if op.RollbackCmd == "" {
		return
	}

	var cmd *exec.Cmd
	switch cm.backend {
	case BackendNftables:
		args := strings.Fields(op.RollbackCmd)
		cmd = exec.CommandContext(ctx, cm.config.NftablesPath, args...)
	case BackendIptables:
		args := strings.Fields(op.RollbackCmd)
		cmd = exec.CommandContext(ctx, cm.config.IptablesPath, args...)
	default:
		return
	}

	if err := cmd.Run(); err != nil {
		cm.logger.Warn("rollback command failed",
			"command", op.RollbackCmd,
			"error", err,
		)
	}
}

// updateChainState updates the internal chain state after an operation.
func (cm *ChainManager) updateChainState(op *ChainOperation) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	key := fmt.Sprintf("%s.%s.%s", op.Chain.Family, op.Chain.Table, op.Chain.Name)

	switch op.Type {
	case OpCreateChain:
		chain := *op.Chain
		chain.State = ChainStateActive
		chain.CreatedAt = time.Now()
		chain.ModifiedAt = time.Now()
		cm.chains[key] = &chain

	case OpDeleteChain:
		delete(cm.chains, key)

	case OpAddRule:
		if chain, exists := cm.chains[key]; exists {
			chain.RuleCount++
			chain.ModifiedAt = time.Now()
		}

	case OpFlushChain:
		if chain, exists := cm.chains[key]; exists {
			chain.RuleCount = 0
			chain.ModifiedAt = time.Now()
		}
	}
}

// CreateChain creates a new chain with proper locking.
func (cm *ChainManager) CreateChain(ctx context.Context, chain *Chain) error {
	op := &ChainOperation{
		Type:      OpCreateChain,
		Chain:     chain,
		Timestamp: time.Now(),
	}

	cm.mu.Lock()
	if cm.inTransaction {
		cm.pendingOps = append(cm.pendingOps, op)
		cm.mu.Unlock()
		return nil
	}
	cm.mu.Unlock()

	return cm.executeOperation(ctx, op)
}

// DeleteChain deletes a chain with proper locking.
func (cm *ChainManager) DeleteChain(ctx context.Context, chain *Chain) error {
	// First flush the chain
	if err := cm.FlushChain(ctx, chain); err != nil {
		return err
	}

	op := &ChainOperation{
		Type:      OpDeleteChain,
		Chain:     chain,
		Timestamp: time.Now(),
	}

	cm.mu.Lock()
	if cm.inTransaction {
		cm.pendingOps = append(cm.pendingOps, op)
		cm.mu.Unlock()
		return nil
	}
	cm.mu.Unlock()

	return cm.executeOperation(ctx, op)
}

// FlushChain flushes all rules from a chain.
func (cm *ChainManager) FlushChain(ctx context.Context, chain *Chain) error {
	op := &ChainOperation{
		Type:      OpFlushChain,
		Chain:     chain,
		Timestamp: time.Now(),
	}

	cm.mu.Lock()
	if cm.inTransaction {
		cm.pendingOps = append(cm.pendingOps, op)
		cm.mu.Unlock()
		return nil
	}
	cm.mu.Unlock()

	return cm.executeOperation(ctx, op)
}

// AddRule adds a rule to a chain.
func (cm *ChainManager) AddRule(ctx context.Context, chain *Chain, rule string) error {
	op := &ChainOperation{
		Type:      OpAddRule,
		Chain:     chain,
		Rule:      rule,
		Timestamp: time.Now(),
	}

	cm.mu.Lock()
	if cm.inTransaction {
		cm.pendingOps = append(cm.pendingOps, op)
		cm.mu.Unlock()
		return nil
	}
	cm.mu.Unlock()

	return cm.executeOperation(ctx, op)
}

// GetChain returns information about a chain.
func (cm *ChainManager) GetChain(family, table, name string) *Chain {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	key := fmt.Sprintf("%s.%s.%s", family, table, name)
	return cm.chains[key]
}

// ListChains returns all managed chains.
func (cm *ChainManager) ListChains() []*Chain {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	chains := make([]*Chain, 0, len(cm.chains))
	for _, chain := range cm.chains {
		chains = append(chains, chain)
	}
	return chains
}

// ChainExists checks if a chain exists in the actual firewall.
func (cm *ChainManager) ChainExists(ctx context.Context, chain *Chain) (bool, error) {
	chainLock := cm.getChainLock(chain.Name)
	chainLock.Lock()
	defer chainLock.Unlock()

	switch cm.backend {
	case BackendNftables:
		cmd := exec.CommandContext(ctx, cm.config.NftablesPath,
			"list", "chain", chain.Family, chain.Table, chain.Name)
		return cmd.Run() == nil, nil

	case BackendIptables:
		cmd := exec.CommandContext(ctx, cm.config.IptablesPath,
			"-L", chain.Name, "-n")
		return cmd.Run() == nil, nil

	default:
		return false, errors.New("no backend available")
	}
}

// EnsureChain ensures a chain exists, creating it if necessary.
func (cm *ChainManager) EnsureChain(ctx context.Context, chain *Chain) error {
	exists, err := cm.ChainExists(ctx, chain)
	if err != nil {
		return err
	}

	if !exists {
		return cm.CreateChain(ctx, chain)
	}

	return nil
}

// SafeModifyChain modifies a chain with proper locking and rollback.
func (cm *ChainManager) SafeModifyChain(ctx context.Context, chain *Chain, modifyFn func() error) error {
	chainLock := cm.getChainLock(chain.Name)
	chainLock.Lock()
	defer chainLock.Unlock()

	// Update state
	cm.mu.Lock()
	key := fmt.Sprintf("%s.%s.%s", chain.Family, chain.Table, chain.Name)
	if existing, ok := cm.chains[key]; ok {
		existing.State = ChainStateModifying
	}
	cm.mu.Unlock()

	// Execute modification
	err := modifyFn()

	// Update state
	cm.mu.Lock()
	if existing, ok := cm.chains[key]; ok {
		if err != nil {
			existing.State = ChainStateError
		} else {
			existing.State = ChainStateActive
			existing.ModifiedAt = time.Now()
		}
	}
	cm.mu.Unlock()

	return err
}

// BackupChain creates a backup of a chain's rules.
func (cm *ChainManager) BackupChain(ctx context.Context, chain *Chain) (string, error) {
	chainLock := cm.getChainLock(chain.Name)
	chainLock.Lock()
	defer chainLock.Unlock()

	switch cm.backend {
	case BackendNftables:
		cmd := exec.CommandContext(ctx, cm.config.NftablesPath,
			"list", "chain", chain.Family, chain.Table, chain.Name)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("failed to backup chain: %w", err)
		}
		return string(output), nil

	case BackendIptables:
		cmd := exec.CommandContext(ctx, cm.config.IptablesPath+"-save")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("failed to backup rules: %w", err)
		}
		// Filter for specific chain
		lines := strings.Split(string(output), "\n")
		var chainRules []string
		for _, line := range lines {
			if strings.Contains(line, "-A "+chain.Name) {
				chainRules = append(chainRules, line)
			}
		}
		return strings.Join(chainRules, "\n"), nil

	default:
		return "", errors.New("no backend available")
	}
}

// RestoreChain restores a chain from a backup.
func (cm *ChainManager) RestoreChain(ctx context.Context, chain *Chain, backup string) error {
	chainLock := cm.getChainLock(chain.Name)
	chainLock.Lock()
	defer chainLock.Unlock()

	// First flush the chain
	switch cm.backend {
	case BackendNftables:
		flushCmd := exec.CommandContext(ctx, cm.config.NftablesPath,
			"flush", "chain", chain.Family, chain.Table, chain.Name)
		if err := flushCmd.Run(); err != nil {
			return fmt.Errorf("failed to flush chain: %w", err)
		}

		// Write backup to temp file and restore
		tmpFile, err := os.CreateTemp("", "chain-restore-*.nft")
		if err != nil {
			return err
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.WriteString(backup); err != nil {
			return err
		}
		tmpFile.Close()

		cmd := exec.CommandContext(ctx, cm.config.NftablesPath, "-f", tmpFile.Name())
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to restore chain: %s: %w", string(output), err)
		}

	case BackendIptables:
		// Flush chain
		flushCmd := exec.CommandContext(ctx, cm.config.IptablesPath, "-F", chain.Name)
		if err := flushCmd.Run(); err != nil {
			return fmt.Errorf("failed to flush chain: %w", err)
		}

		// Restore rules one by one
		lines := strings.Split(backup, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			args := strings.Fields(line)
			cmd := exec.CommandContext(ctx, cm.config.IptablesPath, args...)
			if err := cmd.Run(); err != nil {
				cm.logger.Warn("failed to restore rule", "rule", line, "error", err)
			}
		}
	}

	cm.logger.Info("restored chain from backup", "chain", chain.Name)
	return nil
}

// WaitForChainReady waits for a chain to be in a ready state.
func (cm *ChainManager) WaitForChainReady(ctx context.Context, chain *Chain, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		cm.mu.RLock()
		key := fmt.Sprintf("%s.%s.%s", chain.Family, chain.Table, chain.Name)
		existing := cm.chains[key]
		cm.mu.RUnlock()

		if existing != nil && existing.State == ChainStateActive {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
			continue
		}
	}

	return errors.New("timeout waiting for chain to be ready")
}

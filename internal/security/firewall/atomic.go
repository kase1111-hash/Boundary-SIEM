// Package firewall provides atomic nftables transaction support.
// This implementation uses nftables' native atomic file loading for all-or-nothing updates.
package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNoTransaction indicates no active transaction.
	ErrNoTransaction = errors.New("no transaction in progress")
	// ErrTransactionActive indicates a transaction is already active.
	ErrTransactionActive = errors.New("transaction already in progress")
	// ErrCommitFailed indicates the atomic commit failed.
	ErrCommitFailed = errors.New("atomic commit failed")
	// ErrRollbackFailed indicates rollback failed.
	ErrRollbackFailed = errors.New("rollback failed")
	// ErrSavepointNotFound indicates the savepoint doesn't exist.
	ErrSavepointNotFound = errors.New("savepoint not found")
	// ErrStateCaptureFailed indicates state capture failed.
	ErrStateCaptureFailed = errors.New("failed to capture current state")
)

// AtomicTransaction represents an atomic nftables transaction.
type AtomicTransaction struct {
	mu sync.Mutex

	// Transaction state
	active    bool
	commands  []string
	startTime time.Time

	// State management
	preState   string // nftables ruleset before transaction
	savepoints map[string]int // savepoint name -> command index

	// Configuration
	config *AtomicConfig
	logger *slog.Logger

	// Paths
	workDir     string
	batchFile   string
	backupFile  string
	rollbackFile string
}

// AtomicConfig configures the atomic transaction system.
type AtomicConfig struct {
	// WorkDir is the directory for temporary files.
	WorkDir string
	// Timeout is the maximum time for commit operations.
	Timeout time.Duration
	// MaxCommands is the maximum commands per transaction.
	MaxCommands int
	// AutoBackup enables automatic state backup before commit.
	AutoBackup bool
	// ValidateBeforeCommit validates syntax before applying.
	ValidateBeforeCommit bool
	// RetryCount is the number of retries for transient failures.
	RetryCount int
	// RetryDelay is the delay between retries.
	RetryDelay time.Duration
}

// DefaultAtomicConfig returns sensible defaults.
func DefaultAtomicConfig() *AtomicConfig {
	return &AtomicConfig{
		WorkDir:              "/tmp/boundary-siem-nft",
		Timeout:              30 * time.Second,
		MaxCommands:          1000,
		AutoBackup:           true,
		ValidateBeforeCommit: true,
		RetryCount:           3,
		RetryDelay:           100 * time.Millisecond,
	}
}

// NewAtomicTransaction creates a new atomic transaction manager.
func NewAtomicTransaction(config *AtomicConfig, logger *slog.Logger) (*AtomicTransaction, error) {
	if config == nil {
		config = DefaultAtomicConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Ensure work directory exists
	if err := os.MkdirAll(config.WorkDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	tx := &AtomicTransaction{
		config:     config,
		logger:     logger,
		workDir:    config.WorkDir,
		savepoints: make(map[string]int),
	}

	return tx, nil
}

// Begin starts a new atomic transaction.
func (tx *AtomicTransaction) Begin(ctx context.Context) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.active {
		return ErrTransactionActive
	}

	// Capture current state for rollback
	if tx.config.AutoBackup {
		state, err := tx.captureState(ctx)
		if err != nil {
			tx.logger.Warn("failed to capture pre-transaction state", "error", err)
			// Continue anyway - we just won't have rollback capability
		} else {
			tx.preState = state
		}
	}

	// Initialize transaction
	tx.active = true
	tx.commands = make([]string, 0, 100)
	tx.startTime = time.Now()
	tx.savepoints = make(map[string]int)

	// Generate unique file names
	timestamp := time.Now().UnixNano()
	tx.batchFile = filepath.Join(tx.workDir, fmt.Sprintf("batch-%d.nft", timestamp))
	tx.backupFile = filepath.Join(tx.workDir, fmt.Sprintf("backup-%d.nft", timestamp))
	tx.rollbackFile = filepath.Join(tx.workDir, fmt.Sprintf("rollback-%d.nft", timestamp))

	// Save backup state
	if tx.preState != "" {
		if err := os.WriteFile(tx.backupFile, []byte(tx.preState), 0600); err != nil {
			tx.logger.Warn("failed to write backup file", "error", err)
		}
	}

	tx.logger.Debug("began atomic transaction",
		"batch_file", tx.batchFile,
		"has_backup", tx.preState != "")

	return nil
}

// captureState captures the current nftables ruleset.
func (tx *AtomicTransaction) captureState(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "-s", "list", "ruleset")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("nft list ruleset failed: %w", err)
	}

	return string(output), nil
}

// Add adds a command to the transaction.
func (tx *AtomicTransaction) Add(command string) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if !tx.active {
		return ErrNoTransaction
	}

	if len(tx.commands) >= tx.config.MaxCommands {
		return fmt.Errorf("transaction exceeds maximum commands (%d)", tx.config.MaxCommands)
	}

	// Validate command doesn't contain dangerous characters
	if err := validateNftCommand(command); err != nil {
		return fmt.Errorf("invalid command: %w", err)
	}

	tx.commands = append(tx.commands, command)
	return nil
}

// AddMultiple adds multiple commands to the transaction.
func (tx *AtomicTransaction) AddMultiple(commands []string) error {
	for _, cmd := range commands {
		if err := tx.Add(cmd); err != nil {
			return err
		}
	}
	return nil
}

// validateNftCommand validates an nftables command for safety.
func validateNftCommand(cmd string) error {
	// nftables uses semicolons inside braces for chain/set definitions
	// Strip content inside braces before checking for dangerous chars
	stripped := stripBraceContent(cmd)

	// Reject shell metacharacters in the command outside braces
	dangerous := []string{"|", "&", "`", "$", "<", ">", "\n", "\r"}
	for _, char := range dangerous {
		if strings.Contains(stripped, char) {
			return fmt.Errorf("command contains dangerous character: %q", char)
		}
	}

	// Check for semicolon outside braces (shell command chaining)
	if strings.Contains(stripped, ";") {
		return fmt.Errorf("command contains dangerous character: %q", ";")
	}

	return nil
}

// stripBraceContent removes content inside braces for validation.
func stripBraceContent(cmd string) string {
	var result strings.Builder
	depth := 0
	for _, ch := range cmd {
		if ch == '{' {
			depth++
		} else if ch == '}' {
			depth--
		} else if depth == 0 {
			result.WriteRune(ch)
		}
	}
	return result.String()
}

// Savepoint creates a savepoint in the transaction.
func (tx *AtomicTransaction) Savepoint(name string) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if !tx.active {
		return ErrNoTransaction
	}

	tx.savepoints[name] = len(tx.commands)
	tx.logger.Debug("created savepoint", "name", name, "index", len(tx.commands))
	return nil
}

// RollbackToSavepoint rolls back to a savepoint.
func (tx *AtomicTransaction) RollbackToSavepoint(name string) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if !tx.active {
		return ErrNoTransaction
	}

	idx, ok := tx.savepoints[name]
	if !ok {
		return ErrSavepointNotFound
	}

	// Truncate commands to savepoint
	tx.commands = tx.commands[:idx]

	// Remove savepoints after this one
	for spName, spIdx := range tx.savepoints {
		if spIdx > idx {
			delete(tx.savepoints, spName)
		}
	}

	tx.logger.Debug("rolled back to savepoint", "name", name, "commands_remaining", len(tx.commands))
	return nil
}

// Commit atomically applies all transaction commands.
func (tx *AtomicTransaction) Commit(ctx context.Context) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if !tx.active {
		return ErrNoTransaction
	}

	if len(tx.commands) == 0 {
		tx.logger.Debug("empty transaction, nothing to commit")
		tx.cleanup()
		return nil
	}

	// Apply timeout
	if tx.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, tx.config.Timeout)
		defer cancel()
	}

	// Generate batch file content
	content := tx.generateBatchContent()
	checksum := tx.calculateChecksum(content)

	tx.logger.Debug("committing atomic transaction",
		"commands", len(tx.commands),
		"checksum", checksum)

	// Write batch file
	if err := os.WriteFile(tx.batchFile, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write batch file: %w", err)
	}

	// Validate syntax before commit
	if tx.config.ValidateBeforeCommit {
		if err := tx.validateBatch(ctx); err != nil {
			tx.logger.Error("batch validation failed", "error", err)
			return fmt.Errorf("validation failed: %w", err)
		}
	}

	// Atomic commit with retry
	var lastErr error
	for attempt := 0; attempt <= tx.config.RetryCount; attempt++ {
		if attempt > 0 {
			tx.logger.Debug("retrying commit", "attempt", attempt)
			time.Sleep(tx.config.RetryDelay)
		}

		if err := tx.applyBatch(ctx); err != nil {
			lastErr = err
			continue
		}

		// Success
		tx.logger.Info("atomic transaction committed",
			"commands", len(tx.commands),
			"duration", time.Since(tx.startTime),
			"checksum", checksum)

		tx.cleanup()
		return nil
	}

	// All retries failed - attempt rollback
	tx.logger.Error("commit failed after retries", "error", lastErr)
	if tx.preState != "" {
		if rbErr := tx.rollbackToPreState(ctx); rbErr != nil {
			tx.logger.Error("rollback also failed", "error", rbErr)
		}
	}

	tx.cleanup()
	return fmt.Errorf("%w: %v", ErrCommitFailed, lastErr)
}

// generateBatchContent generates the nftables batch file content.
func (tx *AtomicTransaction) generateBatchContent() string {
	var sb strings.Builder

	// Header comment
	sb.WriteString("#!/usr/sbin/nft -f\n")
	sb.WriteString("# Boundary SIEM atomic transaction\n")
	sb.WriteString(fmt.Sprintf("# Generated: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("# Commands: %d\n", len(tx.commands)))
	sb.WriteString("\n")

	// Write commands
	for _, cmd := range tx.commands {
		sb.WriteString(cmd)
		sb.WriteString("\n")
	}

	return sb.String()
}

// calculateChecksum calculates SHA256 checksum of content.
func (tx *AtomicTransaction) calculateChecksum(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:8]) // First 8 bytes for brevity
}

// validateBatch validates the batch file syntax.
func (tx *AtomicTransaction) validateBatch(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "nft", "-c", "-f", tx.batchFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("syntax error: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

// applyBatch atomically applies the batch file.
func (tx *AtomicTransaction) applyBatch(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", tx.batchFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

// rollbackToPreState restores the pre-transaction state.
func (tx *AtomicTransaction) rollbackToPreState(ctx context.Context) error {
	if tx.preState == "" {
		return errors.New("no pre-state available for rollback")
	}

	// Write rollback file
	rollbackContent := "#!/usr/sbin/nft -f\n"
	rollbackContent += "# Rollback transaction\n"
	rollbackContent += "flush ruleset\n"
	rollbackContent += tx.preState

	if err := os.WriteFile(tx.rollbackFile, []byte(rollbackContent), 0600); err != nil {
		return fmt.Errorf("failed to write rollback file: %w", err)
	}

	// Apply rollback
	cmd := exec.CommandContext(ctx, "nft", "-f", tx.rollbackFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rollback apply failed: %s", strings.TrimSpace(string(output)))
	}

	tx.logger.Info("rolled back to pre-transaction state")
	return nil
}

// Rollback aborts the transaction and optionally restores pre-state.
func (tx *AtomicTransaction) Rollback(ctx context.Context) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if !tx.active {
		return ErrNoTransaction
	}

	tx.logger.Info("rolling back transaction", "commands_discarded", len(tx.commands))
	tx.cleanup()
	return nil
}

// cleanup cleans up transaction resources.
func (tx *AtomicTransaction) cleanup() {
	tx.active = false
	tx.commands = nil
	tx.preState = ""
	tx.savepoints = nil

	// Remove temporary files
	for _, f := range []string{tx.batchFile, tx.backupFile, tx.rollbackFile} {
		if f != "" {
			os.Remove(f)
		}
	}

	tx.batchFile = ""
	tx.backupFile = ""
	tx.rollbackFile = ""
}

// IsActive returns whether a transaction is active.
func (tx *AtomicTransaction) IsActive() bool {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.active
}

// CommandCount returns the number of pending commands.
func (tx *AtomicTransaction) CommandCount() int {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return len(tx.commands)
}

// Duration returns how long the transaction has been active.
func (tx *AtomicTransaction) Duration() time.Duration {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if !tx.active {
		return 0
	}
	return time.Since(tx.startTime)
}

// AtomicBatch provides a simpler interface for one-shot atomic operations.
type AtomicBatch struct {
	commands []string
	config   *AtomicConfig
	logger   *slog.Logger
}

// NewAtomicBatch creates a new atomic batch.
func NewAtomicBatch(logger *slog.Logger) *AtomicBatch {
	return &AtomicBatch{
		commands: make([]string, 0, 50),
		config:   DefaultAtomicConfig(),
		logger:   logger,
	}
}

// Add adds a command to the batch.
func (b *AtomicBatch) Add(cmd string) *AtomicBatch {
	if err := validateNftCommand(cmd); err == nil {
		b.commands = append(b.commands, cmd)
	}
	return b
}

// AddTable adds a table creation command.
func (b *AtomicBatch) AddTable(family, name string) *AtomicBatch {
	return b.Add(fmt.Sprintf("add table %s %s", family, name))
}

// AddChain adds a chain creation command.
func (b *AtomicBatch) AddChain(family, table, name, chainType, hook string, priority int) *AtomicBatch {
	cmd := fmt.Sprintf("add chain %s %s %s { type %s hook %s priority %d ; }",
		family, table, name, chainType, hook, priority)
	return b.Add(cmd)
}

// AddRule adds a rule to a chain.
func (b *AtomicBatch) AddRule(family, table, chain, rule string) *AtomicBatch {
	return b.Add(fmt.Sprintf("add rule %s %s %s %s", family, table, chain, rule))
}

// AddSet adds a set creation command.
func (b *AtomicBatch) AddSet(family, table, name, setType string, flags ...string) *AtomicBatch {
	cmd := fmt.Sprintf("add set %s %s %s { type %s", family, table, name, setType)
	if len(flags) > 0 {
		cmd += " ; flags " + strings.Join(flags, ",")
	}
	cmd += " ; }"
	return b.Add(cmd)
}

// FlushChain adds a flush command for a chain.
func (b *AtomicBatch) FlushChain(family, table, chain string) *AtomicBatch {
	return b.Add(fmt.Sprintf("flush chain %s %s %s", family, table, chain))
}

// DeleteRule adds a delete rule command.
func (b *AtomicBatch) DeleteRule(family, table, chain string, handle int) *AtomicBatch {
	return b.Add(fmt.Sprintf("delete rule %s %s %s handle %d", family, table, chain, handle))
}

// Execute atomically applies the batch.
func (b *AtomicBatch) Execute(ctx context.Context) error {
	if len(b.commands) == 0 {
		return nil
	}

	tx, err := NewAtomicTransaction(b.config, b.logger)
	if err != nil {
		return err
	}

	if err := tx.Begin(ctx); err != nil {
		return err
	}

	if err := tx.AddMultiple(b.commands); err != nil {
		tx.Rollback(ctx)
		return err
	}

	return tx.Commit(ctx)
}

// Clear clears the batch.
func (b *AtomicBatch) Clear() {
	b.commands = b.commands[:0]
}

// TransactionLog records transaction history for audit.
type TransactionLog struct {
	mu      sync.Mutex
	entries []TransactionLogEntry
	maxSize int
	logger  *slog.Logger
}

// TransactionLogEntry is a single log entry.
type TransactionLogEntry struct {
	Timestamp   time.Time
	Action      string // "begin", "commit", "rollback"
	Commands    int
	Duration    time.Duration
	Checksum    string
	Success     bool
	Error       string
}

// NewTransactionLog creates a new transaction log.
func NewTransactionLog(maxSize int, logger *slog.Logger) *TransactionLog {
	if logger == nil {
		logger = slog.Default()
	}
	return &TransactionLog{
		entries: make([]TransactionLogEntry, 0, maxSize),
		maxSize: maxSize,
		logger:  logger,
	}
}

// Record records a transaction event.
func (tl *TransactionLog) Record(entry TransactionLogEntry) {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	// Evict oldest if at capacity
	if len(tl.entries) >= tl.maxSize {
		tl.entries = tl.entries[1:]
	}

	tl.entries = append(tl.entries, entry)

	tl.logger.Debug("transaction logged",
		"action", entry.Action,
		"commands", entry.Commands,
		"success", entry.Success)
}

// GetRecent returns the most recent entries.
func (tl *TransactionLog) GetRecent(count int) []TransactionLogEntry {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	if count > len(tl.entries) {
		count = len(tl.entries)
	}

	result := make([]TransactionLogEntry, count)
	copy(result, tl.entries[len(tl.entries)-count:])
	return result
}

// GetFailures returns recent failed transactions.
func (tl *TransactionLog) GetFailures() []TransactionLogEntry {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	var failures []TransactionLogEntry
	for _, e := range tl.entries {
		if !e.Success {
			failures = append(failures, e)
		}
	}
	return failures
}

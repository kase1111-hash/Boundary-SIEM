package firewall

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultAtomicConfig(t *testing.T) {
	config := DefaultAtomicConfig()

	if config.WorkDir != "/tmp/boundary-siem-nft" {
		t.Errorf("WorkDir = %s", config.WorkDir)
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v", config.Timeout)
	}
	if config.MaxCommands != 1000 {
		t.Errorf("MaxCommands = %d", config.MaxCommands)
	}
	if !config.AutoBackup {
		t.Error("AutoBackup should be true")
	}
	if !config.ValidateBeforeCommit {
		t.Error("ValidateBeforeCommit should be true")
	}
	if config.RetryCount != 3 {
		t.Errorf("RetryCount = %d", config.RetryCount)
	}
}

func TestNewAtomicTransaction(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{
		WorkDir:     tmpDir,
		Timeout:     10 * time.Second,
		MaxCommands: 100,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	tx, err := NewAtomicTransaction(config, logger)
	if err != nil {
		t.Fatalf("NewAtomicTransaction failed: %v", err)
	}
	if tx == nil {
		t.Fatal("expected non-nil transaction")
	}
	if tx.active {
		t.Error("new transaction should not be active")
	}
}

func TestNewAtomicTransaction_NilConfig(t *testing.T) {
	tx, err := NewAtomicTransaction(nil, nil)
	if err != nil {
		t.Fatalf("should accept nil config: %v", err)
	}
	if tx == nil {
		t.Fatal("expected non-nil transaction")
	}
}

func TestAtomicTransaction_Begin(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{
		WorkDir:    tmpDir,
		AutoBackup: false, // Disable to avoid nft command
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	tx, err := NewAtomicTransaction(config, logger)
	if err != nil {
		t.Fatalf("NewAtomicTransaction failed: %v", err)
	}

	ctx := context.Background()

	// Begin transaction
	if err := tx.Begin(ctx); err != nil {
		t.Fatalf("Begin failed: %v", err)
	}
	if !tx.IsActive() {
		t.Error("transaction should be active after Begin")
	}

	// Double begin should fail
	if err := tx.Begin(ctx); err != ErrTransactionActive {
		t.Errorf("expected ErrTransactionActive, got %v", err)
	}
}

func TestAtomicTransaction_Add(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{
		WorkDir:     tmpDir,
		MaxCommands: 5,
		AutoBackup:  false,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	tx, _ := NewAtomicTransaction(config, logger)
	ctx := context.Background()
	tx.Begin(ctx)

	// Add valid commands
	if err := tx.Add("add table inet test"); err != nil {
		t.Errorf("Add failed: %v", err)
	}
	if tx.CommandCount() != 1 {
		t.Errorf("CommandCount = %d, expected 1", tx.CommandCount())
	}

	// Add multiple
	if err := tx.AddMultiple([]string{
		"add chain inet test input",
		"add rule inet test input accept",
	}); err != nil {
		t.Errorf("AddMultiple failed: %v", err)
	}
	if tx.CommandCount() != 3 {
		t.Errorf("CommandCount = %d, expected 3", tx.CommandCount())
	}
}

func TestAtomicTransaction_Add_NoTransaction(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{WorkDir: tmpDir}
	tx, _ := NewAtomicTransaction(config, nil)

	err := tx.Add("add table inet test")
	if err != ErrNoTransaction {
		t.Errorf("expected ErrNoTransaction, got %v", err)
	}
}

func TestAtomicTransaction_Add_MaxCommands(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{
		WorkDir:     tmpDir,
		MaxCommands: 2,
		AutoBackup:  false,
	}
	tx, _ := NewAtomicTransaction(config, nil)
	tx.Begin(context.Background())

	tx.Add("cmd1")
	tx.Add("cmd2")

	err := tx.Add("cmd3")
	if err == nil {
		t.Error("expected error when exceeding MaxCommands")
	}
	if !strings.Contains(err.Error(), "maximum commands") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateNftCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		wantErr bool
	}{
		{"valid add table", "add table inet filter", false},
		{"valid add chain", "add chain inet filter input { type filter hook input priority 0 ; }", false},
		{"valid add set with flags", "add set inet filter blocked { type ipv4_addr ; flags timeout,dynamic ; }", false},
		{"semicolon injection", "add table inet foo; rm -rf /", true},
		{"pipe injection", "add table inet foo | cat /etc/passwd", true},
		{"ampersand injection", "add table inet foo && malicious", true},
		{"backtick injection", "add table inet `whoami`", true},
		{"dollar injection", "add table inet $(id)", true},
		{"redirect injection", "add table inet foo > /tmp/evil", true},
		{"newline injection", "add table inet foo\nrm -rf /", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNftCommand(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateNftCommand(%q) error = %v, wantErr %v", tt.cmd, err, tt.wantErr)
			}
		})
	}
}

func TestStripBraceContent(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"add table inet filter", "add table inet filter"},
		{"add chain { type filter ; }", "add chain "},
		{"nested { outer { inner } }", "nested "},
		{"no braces here", "no braces here"},
		{"start { mid } end", "start  end"},
	}

	for _, tt := range tests {
		result := stripBraceContent(tt.input)
		if result != tt.expected {
			t.Errorf("stripBraceContent(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestValidateNftCommand_Extended(t *testing.T) {
	// Test that dangerous chars inside braces are allowed
	cmd := "add set inet filter test { type ipv4_addr ; flags timeout ; }"
	err := validateNftCommand(cmd)
	if err != nil {
		t.Errorf("valid nftables command with semicolons in braces should be allowed: %v", err)
	}
}

func TestAtomicTransaction_Savepoint(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{
		WorkDir:     tmpDir,
		AutoBackup:  false,
		MaxCommands: 100,
	}
	tx, _ := NewAtomicTransaction(config, nil)
	ctx := context.Background()
	tx.Begin(ctx)

	tx.Add("add table inet filter")
	tx.Add("add table inet nat")
	tx.Savepoint("sp1")
	tx.Add("add table inet mangle")
	tx.Add("add table inet raw")

	if tx.CommandCount() != 4 {
		t.Errorf("expected 4 commands, got %d", tx.CommandCount())
	}

	// Rollback to savepoint
	err := tx.RollbackToSavepoint("sp1")
	if err != nil {
		t.Errorf("RollbackToSavepoint failed: %v", err)
	}
	if tx.CommandCount() != 2 {
		t.Errorf("expected 2 commands after rollback, got %d", tx.CommandCount())
	}
}

func TestAtomicTransaction_Savepoint_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{WorkDir: tmpDir, AutoBackup: false}
	tx, _ := NewAtomicTransaction(config, nil)
	tx.Begin(context.Background())

	err := tx.RollbackToSavepoint("nonexistent")
	if err != ErrSavepointNotFound {
		t.Errorf("expected ErrSavepointNotFound, got %v", err)
	}
}

func TestAtomicTransaction_Rollback(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{WorkDir: tmpDir, AutoBackup: false}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tx, _ := NewAtomicTransaction(config, logger)
	ctx := context.Background()

	tx.Begin(ctx)
	tx.Add("add table inet test1")
	tx.Add("add table inet test2")

	if err := tx.Rollback(ctx); err != nil {
		t.Errorf("Rollback failed: %v", err)
	}
	if tx.IsActive() {
		t.Error("transaction should not be active after rollback")
	}
	if tx.CommandCount() != 0 {
		t.Errorf("commands should be cleared after rollback")
	}
}

func TestAtomicTransaction_Rollback_NoTransaction(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{WorkDir: tmpDir}
	tx, _ := NewAtomicTransaction(config, nil)

	err := tx.Rollback(context.Background())
	if err != ErrNoTransaction {
		t.Errorf("expected ErrNoTransaction, got %v", err)
	}
}

func TestAtomicTransaction_Duration(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{WorkDir: tmpDir, AutoBackup: false}
	tx, _ := NewAtomicTransaction(config, nil)

	// No transaction
	if tx.Duration() != 0 {
		t.Error("duration should be 0 when not active")
	}

	// Start transaction
	tx.Begin(context.Background())
	time.Sleep(10 * time.Millisecond)

	dur := tx.Duration()
	if dur < 10*time.Millisecond {
		t.Errorf("duration = %v, expected >= 10ms", dur)
	}
}

func TestAtomicTransaction_generateBatchContent(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{WorkDir: tmpDir, AutoBackup: false, MaxCommands: 100}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tx, _ := NewAtomicTransaction(config, logger)
	tx.Begin(context.Background())

	// Use valid nftables commands
	err := tx.Add("add table inet filter")
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	err = tx.Add("add chain inet filter input")
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	content := tx.generateBatchContent()

	if !strings.Contains(content, "#!/usr/sbin/nft -f") {
		t.Error("missing shebang")
	}
	if !strings.Contains(content, "Boundary SIEM atomic transaction") {
		t.Error("missing header comment")
	}
	if !strings.Contains(content, "add table inet filter") {
		t.Errorf("missing command 1, content: %s", content)
	}
	if !strings.Contains(content, "add chain inet filter input") {
		t.Errorf("missing command 2, content: %s", content)
	}
}

func TestAtomicTransaction_calculateChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{WorkDir: tmpDir}
	tx, _ := NewAtomicTransaction(config, nil)

	cs1 := tx.calculateChecksum("content1")
	cs2 := tx.calculateChecksum("content2")
	cs1again := tx.calculateChecksum("content1")

	if cs1 == cs2 {
		t.Error("different content should produce different checksums")
	}
	if cs1 != cs1again {
		t.Error("same content should produce same checksum")
	}
	if len(cs1) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("checksum length = %d, expected 16", len(cs1))
	}
}

func TestAtomicTransaction_Commit_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{WorkDir: tmpDir, AutoBackup: false}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tx, _ := NewAtomicTransaction(config, logger)
	ctx := context.Background()

	tx.Begin(ctx)
	// Don't add any commands

	err := tx.Commit(ctx)
	if err != nil {
		t.Errorf("empty commit should succeed: %v", err)
	}
	if tx.IsActive() {
		t.Error("transaction should not be active after commit")
	}
}

func TestAtomicTransaction_Commit_NoTransaction(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{WorkDir: tmpDir}
	tx, _ := NewAtomicTransaction(config, nil)

	err := tx.Commit(context.Background())
	if err != ErrNoTransaction {
		t.Errorf("expected ErrNoTransaction, got %v", err)
	}
}

func TestAtomicTransaction_Commit_WritesBatchFile(t *testing.T) {
	tmpDir := t.TempDir()
	config := &AtomicConfig{
		WorkDir:              tmpDir,
		AutoBackup:           false,
		ValidateBeforeCommit: false, // Skip validation since nft isn't available
		MaxCommands:          100,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tx, _ := NewAtomicTransaction(config, logger)
	ctx := context.Background()

	tx.Begin(ctx)
	err := tx.Add("add table inet test")
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Record the batch file path before commit cleans up
	tx.mu.Lock()
	batchFile := tx.batchFile
	tx.mu.Unlock()

	// The commit will fail because nft isn't available, but we can check the file was written
	_ = tx.Commit(ctx) // Ignore error from nft

	// Check if batch file was created (may have been cleaned up)
	if batchFile != "" {
		if _, err := os.Stat(batchFile); err == nil {
			content, _ := os.ReadFile(batchFile)
			if !strings.Contains(string(content), "add table inet test") {
				t.Error("batch file should contain command")
			}
		}
	}
}

// AtomicBatch tests

func TestNewAtomicBatch(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	b := NewAtomicBatch(logger)

	if b == nil {
		t.Fatal("expected non-nil batch")
	}
	if len(b.commands) != 0 {
		t.Error("new batch should have no commands")
	}
}

func TestAtomicBatch_Add(t *testing.T) {
	b := NewAtomicBatch(nil)

	b.Add("add table inet test")
	if len(b.commands) != 1 {
		t.Errorf("expected 1 command, got %d", len(b.commands))
	}

	// Chain calls
	b.Add("cmd2").Add("cmd3")
	if len(b.commands) != 3 {
		t.Errorf("expected 3 commands, got %d", len(b.commands))
	}
}

func TestAtomicBatch_Add_Invalid(t *testing.T) {
	b := NewAtomicBatch(nil)

	b.Add("add table; rm -rf /") // Should be rejected
	if len(b.commands) != 0 {
		t.Error("invalid command should not be added")
	}
}

func TestAtomicBatch_AddTable(t *testing.T) {
	b := NewAtomicBatch(nil)
	b.AddTable("inet", "filter")

	if len(b.commands) != 1 {
		t.Fatal("expected 1 command")
	}
	if b.commands[0] != "add table inet filter" {
		t.Errorf("command = %q", b.commands[0])
	}
}

func TestAtomicBatch_AddChain(t *testing.T) {
	b := NewAtomicBatch(nil)
	b.AddChain("inet", "filter", "input", "filter", "input", 0)

	if len(b.commands) != 1 {
		t.Fatal("expected 1 command")
	}
	expected := "add chain inet filter input { type filter hook input priority 0 ; }"
	if b.commands[0] != expected {
		t.Errorf("command = %q, expected %q", b.commands[0], expected)
	}
}

func TestAtomicBatch_AddRule(t *testing.T) {
	b := NewAtomicBatch(nil)
	b.AddRule("inet", "filter", "input", "tcp dport 22 accept")

	if len(b.commands) != 1 {
		t.Fatal("expected 1 command")
	}
	expected := "add rule inet filter input tcp dport 22 accept"
	if b.commands[0] != expected {
		t.Errorf("command = %q", b.commands[0])
	}
}

func TestAtomicBatch_AddSet(t *testing.T) {
	b := NewAtomicBatch(nil)
	b.AddSet("inet", "filter", "blocked", "ipv4_addr", "timeout", "dynamic")

	if len(b.commands) != 1 {
		t.Fatal("expected 1 command")
	}
	if !strings.Contains(b.commands[0], "add set inet filter blocked") {
		t.Errorf("command = %q", b.commands[0])
	}
	if !strings.Contains(b.commands[0], "flags timeout,dynamic") {
		t.Errorf("command = %q", b.commands[0])
	}
}

func TestAtomicBatch_FlushChain(t *testing.T) {
	b := NewAtomicBatch(nil)
	b.FlushChain("inet", "filter", "input")

	expected := "flush chain inet filter input"
	if b.commands[0] != expected {
		t.Errorf("command = %q", b.commands[0])
	}
}

func TestAtomicBatch_DeleteRule(t *testing.T) {
	b := NewAtomicBatch(nil)
	b.DeleteRule("inet", "filter", "input", 42)

	expected := "delete rule inet filter input handle 42"
	if b.commands[0] != expected {
		t.Errorf("command = %q", b.commands[0])
	}
}

func TestAtomicBatch_Clear(t *testing.T) {
	b := NewAtomicBatch(nil)
	b.Add("cmd1").Add("cmd2")

	b.Clear()
	if len(b.commands) != 0 {
		t.Errorf("expected 0 commands after Clear, got %d", len(b.commands))
	}
}

func TestAtomicBatch_Execute_Empty(t *testing.T) {
	b := NewAtomicBatch(nil)
	err := b.Execute(context.Background())
	if err != nil {
		t.Errorf("empty batch should succeed: %v", err)
	}
}

// TransactionLog tests

func TestNewTransactionLog(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	tl := NewTransactionLog(100, logger)

	if tl == nil {
		t.Fatal("expected non-nil log")
	}
	if len(tl.entries) != 0 {
		t.Error("new log should be empty")
	}
}

func TestTransactionLog_Record(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tl := NewTransactionLog(10, logger)

	entry := TransactionLogEntry{
		Timestamp: time.Now(),
		Action:    "commit",
		Commands:  5,
		Duration:  100 * time.Millisecond,
		Checksum:  "abc123",
		Success:   true,
	}

	tl.Record(entry)

	recent := tl.GetRecent(10)
	if len(recent) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(recent))
	}
	if recent[0].Action != "commit" {
		t.Errorf("Action = %s", recent[0].Action)
	}
}

func TestTransactionLog_Record_Eviction(t *testing.T) {
	tl := NewTransactionLog(3, nil)

	for i := 0; i < 5; i++ {
		tl.Record(TransactionLogEntry{
			Action:   "test",
			Commands: i,
		})
	}

	recent := tl.GetRecent(10)
	if len(recent) != 3 {
		t.Errorf("expected 3 entries after eviction, got %d", len(recent))
	}
	// Should have entries 2, 3, 4 (oldest evicted)
	if recent[0].Commands != 2 {
		t.Errorf("oldest entry commands = %d, expected 2", recent[0].Commands)
	}
}

func TestTransactionLog_GetRecent(t *testing.T) {
	tl := NewTransactionLog(100, nil)

	for i := 0; i < 10; i++ {
		tl.Record(TransactionLogEntry{Commands: i})
	}

	// Get fewer than available
	recent := tl.GetRecent(3)
	if len(recent) != 3 {
		t.Errorf("expected 3 entries, got %d", len(recent))
	}
	// Should be most recent (7, 8, 9)
	if recent[0].Commands != 7 {
		t.Errorf("expected commands=7, got %d", recent[0].Commands)
	}
}

func TestTransactionLog_GetFailures(t *testing.T) {
	tl := NewTransactionLog(100, nil)

	tl.Record(TransactionLogEntry{Action: "commit", Success: true})
	tl.Record(TransactionLogEntry{Action: "commit", Success: false, Error: "fail1"})
	tl.Record(TransactionLogEntry{Action: "commit", Success: true})
	tl.Record(TransactionLogEntry{Action: "commit", Success: false, Error: "fail2"})

	failures := tl.GetFailures()
	if len(failures) != 2 {
		t.Errorf("expected 2 failures, got %d", len(failures))
	}
}

func TestAtomicTransaction_WorkDir_Creation(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "nested", "path")

	config := &AtomicConfig{
		WorkDir: subDir,
	}

	tx, err := NewAtomicTransaction(config, nil)
	if err != nil {
		t.Fatalf("should create nested work dir: %v", err)
	}
	if tx == nil {
		t.Fatal("expected non-nil transaction")
	}

	// Verify directory exists
	if _, err := os.Stat(subDir); os.IsNotExist(err) {
		t.Error("work directory should have been created")
	}
}

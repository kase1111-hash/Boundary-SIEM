package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mustLog logs an event and fails the test if it cannot be recorded.
func mustLog(t *testing.T, al *AuditLogger, eventType EventType, severity Severity, message string) {
	t.Helper()
	if err := al.Log(context.Background(), eventType, severity, message, nil); err != nil {
		t.Fatalf("Log(%s) error = %v", eventType, err)
	}
}

// mustFlushAndClose flushes and closes al, failing the test on error.
func mustFlushAndClose(t *testing.T, al *AuditLogger) {
	t.Helper()
	if err := al.ForceFlush(context.Background()); err != nil {
		t.Fatalf("ForceFlush() error = %v", err)
	}
	if err := al.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

// firstLogFile returns the first audit log file in dir.
func firstLogFile(t *testing.T, dir string) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "audit-*.log"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(files) == 0 {
		t.Fatal("No log files found")
	}
	return files[0]
}

// reopenLogger creates a new logger on config and closes it at test end.
func reopenLogger(t *testing.T, config *AuditLoggerConfig) *AuditLogger {
	t.Helper()
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() reopen error = %v", err)
	}
	t.Cleanup(func() { al.Close() })
	return al
}

func testConfig(t *testing.T) *AuditLoggerConfig {
	t.Helper()
	tmpDir := filepath.Join(os.TempDir(), "audit-test-"+t.Name())
	os.RemoveAll(tmpDir)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })
	return &AuditLoggerConfig{
		LogPath:        tmpDir,
		MaxFileSize:    1024 * 1024, // 1MB for testing
		MaxFiles:       5,
		FlushInterval:  100 * time.Millisecond,
		VerifyInterval: 0, // Disable auto-verify for tests
		BufferSize:     100,
		Hostname:       "test-host",
	}
}

func TestNewAuditLogger(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	defer al.Close()

	if al.sequence != 0 {
		t.Errorf("Initial sequence = %d, want 0", al.sequence)
	}

	// Check log directory was created
	if _, err := os.Stat(config.LogPath); os.IsNotExist(err) {
		t.Error("Log directory was not created")
	}
}

func TestAuditLogger_Log(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	defer al.Close()

	ctx := context.Background()

	// Log an event
	err = al.Log(ctx, EventSystemStart, SeverityInfo, "System started", map[string]interface{}{
		"version": "1.0.0",
	})
	if err != nil {
		t.Fatalf("Log() error = %v", err)
	}

	// Force flush
	err = al.ForceFlush(ctx)
	if err != nil {
		t.Fatalf("ForceFlush() error = %v", err)
	}

	// Check metrics
	metrics := al.Metrics()
	if metrics.Written == 0 {
		t.Error("Expected at least one written entry")
	}
}

func TestAuditEntry_SignAndVerify(t *testing.T) {
	key := []byte("test-key-32-bytes-long-here!!!!!")

	entry := &AuditEntry{
		ID:           "test-id",
		Sequence:     1,
		Timestamp:    time.Now(),
		Type:         EventSystemStart,
		Severity:     SeverityInfo,
		Message:      "Test message",
		PreviousHash: "previous-hash",
		Hostname:     "test-host",
		ProcessID:    1234,
		Success:      true,
	}

	// Sign
	entry.Sign(key)
	if entry.Signature == "" {
		t.Error("Signature should not be empty after signing")
	}
	if entry.EntryHash == "" {
		t.Error("EntryHash should not be empty after signing")
	}

	// Verify with correct key
	if !entry.Verify(key) {
		t.Error("Verify() should succeed with correct key")
	}

	// Verify with wrong key
	wrongKey := []byte("wrong-key-32-bytes-long-here!!!!")
	if entry.Verify(wrongKey) {
		t.Error("Verify() should fail with wrong key")
	}
}

func TestAuditEntry_TamperDetection(t *testing.T) {
	key := []byte("test-key-32-bytes-long-here!!!!!")

	entry := &AuditEntry{
		ID:           "test-id",
		Sequence:     1,
		Timestamp:    time.Now(),
		Type:         EventSystemStart,
		Severity:     SeverityInfo,
		Message:      "Test message",
		PreviousHash: "previous-hash",
		Success:      true,
	}

	entry.Sign(key)

	// Tamper with message
	entry.Message = "Tampered message"
	if entry.Verify(key) {
		t.Error("Verify() should detect tampering")
	}
}

func TestAuditLogger_ChainIntegrity(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}

	ctx := context.Background()

	// Log multiple events
	for i := 0; i < 10; i++ {
		err = al.Log(ctx, EventSystemStart, SeverityInfo, "Event", map[string]interface{}{
			"index": i,
		})
		if err != nil {
			t.Fatalf("Log() error = %v", err)
		}
	}

	// Flush and close
	mustFlushAndClose(t, al)

	// Reopen and verify
	al2 := reopenLogger(t, config)

	// Verify integrity
	err = al2.VerifyIntegrity(ctx)
	if err != nil {
		t.Errorf("VerifyIntegrity() error = %v", err)
	}
}

func TestAuditLogger_Query(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	defer al.Close()

	ctx := context.Background()

	// Log various events
	mustLog(t, al, EventSystemStart, SeverityInfo, "Start")
	mustLog(t, al, EventAuthSuccess, SeverityInfo, "Login")
	mustLog(t, al, EventAuthFailure, SeverityWarning, "Bad login")
	mustLog(t, al, EventFirewallBlock, SeverityCritical, "Blocked")
	if err := al.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush() error = %v", err)
	}

	// Query by type
	results, err := al.Query(ctx, QueryOptions{
		Types: []EventType{EventAuthSuccess, EventAuthFailure},
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Query by type returned %d results, want 2", len(results))
	}

	// Query by severity
	results, err = al.Query(ctx, QueryOptions{
		Severities: []Severity{SeverityCritical},
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Query by severity returned %d results, want 1", len(results))
	}

	// Query with limit
	results, err = al.Query(ctx, QueryOptions{
		Limit: 2,
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 2 {
		t.Errorf("Query with limit returned %d results, want 2", len(results))
	}
}

func TestAuditLogger_Metrics(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	defer al.Close()

	ctx := context.Background()

	// Initial metrics
	metrics := al.Metrics()
	if metrics.Written != 0 {
		t.Errorf("Initial Written = %d, want 0", metrics.Written)
	}

	// Log some events
	for i := 0; i < 5; i++ {
		mustLog(t, al, EventSystemStart, SeverityInfo, "Event")
	}
	if err := al.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush() error = %v", err)
	}

	// Check updated metrics
	metrics = al.Metrics()
	if metrics.Written != 5 {
		t.Errorf("Written = %d, want 5", metrics.Written)
	}
	if metrics.CurrentSequence != 5 {
		t.Errorf("CurrentSequence = %d, want 5", metrics.CurrentSequence)
	}
}

func TestAuditLogger_RecoverState(t *testing.T) {
	config := testConfig(t)

	// First logger
	al1, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}

	ctx := context.Background()

	// Log some events
	for i := 0; i < 5; i++ {
		mustLog(t, al1, EventSystemStart, SeverityInfo, "Event")
	}
	mustFlushAndClose(t, al1)

	// Second logger should recover state
	al2 := reopenLogger(t, config)

	// Sequence should continue
	if al2.sequence != 5 {
		t.Errorf("Recovered sequence = %d, want 5", al2.sequence)
	}

	// Log more events
	mustLog(t, al2, EventSystemShutdown, SeverityInfo, "Shutdown")
	if err := al2.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush() error = %v", err)
	}

	// Query all events
	results, err := al2.Query(ctx, QueryOptions{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 6 {
		t.Errorf("Total entries = %d, want 6", len(results))
	}
}

func TestAuditLogger_SequenceGapDetection(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}

	ctx := context.Background()

	// Log some events
	for i := 0; i < 5; i++ {
		mustLog(t, al, EventSystemStart, SeverityInfo, "Event")
	}
	mustFlushAndClose(t, al)

	// Manually tamper with the log file - remove an entry
	logFile := firstLogFile(t, config.LogPath)

	// Read entries
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	lines := []string{}
	for _, line := range splitLines(string(data)) {
		if line != "" {
			lines = append(lines, line)
		}
	}

	// Remove middle entry (create gap)
	if len(lines) >= 3 {
		tamperedLines := append(lines[:2], lines[3:]...)
		if err := os.WriteFile(logFile, []byte(joinLines(tamperedLines)), 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}

	// Reopen and verify - should detect gap
	al2 := reopenLogger(t, config)

	err = al2.VerifyIntegrity(ctx)
	if err == nil {
		t.Error("VerifyIntegrity() should detect sequence gap")
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func joinLines(lines []string) string {
	result := ""
	for _, l := range lines {
		result += l + "\n"
	}
	return result
}

func TestAuditLogger_SignatureTamperDetection(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}

	ctx := context.Background()

	mustLog(t, al, EventSystemStart, SeverityInfo, "Event")
	mustFlushAndClose(t, al)

	// Tamper with entry
	logFile := firstLogFile(t, config.LogPath)

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil { // Remove newline
		t.Fatalf("Unmarshal() error = %v", err)
	}

	// Modify message
	entry.Message = "TAMPERED"
	tamperedData, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(logFile, append(tamperedData, '\n'), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Verify should detect tampering
	al2 := reopenLogger(t, config)

	err = al2.VerifyIntegrity(ctx)
	if err == nil {
		t.Error("VerifyIntegrity() should detect signature tampering")
	}
}

func TestAuditLogger_ChainLinkTamperDetection(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}

	ctx := context.Background()

	// Log multiple events
	for i := 0; i < 3; i++ {
		mustLog(t, al, EventSystemStart, SeverityInfo, "Event")
	}
	mustFlushAndClose(t, al)

	// Tamper with chain - modify previous_hash of second entry
	logFile := firstLogFile(t, config.LogPath)

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	lines := splitLines(string(data))

	if len(lines) >= 2 {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(lines[1]), &entry); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		entry.PreviousHash = "tampered-hash"
		tamperedLine, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		lines[1] = string(tamperedLine)
		if err := os.WriteFile(logFile, []byte(joinLines(lines)), 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}

	// Verify should detect broken chain
	al2 := reopenLogger(t, config)

	err = al2.VerifyIntegrity(ctx)
	if err == nil {
		t.Error("VerifyIntegrity() should detect broken chain")
	}
}

func TestAuditLogger_GenesisTamperDetection(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}

	mustLog(t, al, EventSystemStart, SeverityInfo, "Event")
	mustFlushAndClose(t, al)

	al2 := reopenLogger(t, config)
	ctx := context.Background()
	if err := al2.VerifyIntegrity(ctx); err != nil {
		t.Fatalf("VerifyIntegrity() on untouched log error = %v", err)
	}

	// Re-link the first entry to a forged predecessor and re-sign it with the
	// real key, so only the genesis check can catch it.
	logFile := firstLogFile(t, config.LogPath)
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data[:len(data)-1], &entry); err != nil { // Remove newline
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if entry.Sequence != 1 {
		t.Fatalf("first entry sequence = %d, want 1", entry.Sequence)
	}
	entry.PreviousHash = "forged-predecessor-hash"
	entry.Sign(al2.hmacKey)
	tamperedData, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(logFile, append(tamperedData, '\n'), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	err = al2.VerifyIntegrity(ctx)
	if !errors.Is(err, ErrChainBroken) {
		t.Errorf("VerifyIntegrity() error = %v, want %v", err, ErrChainBroken)
	}
}

func TestEventTypes(t *testing.T) {
	types := []EventType{
		EventModeTransitionStart,
		EventModeTransitionComplete,
		EventAuthSuccess,
		EventAuthFailure,
		EventFirewallBlock,
		EventUSBConnect,
		EventConfigChange,
		EventSystemStart,
		EventAuditTamper,
	}

	for _, et := range types {
		if et == "" {
			t.Error("Event type should not be empty")
		}
	}
}

func TestSeverityLevels(t *testing.T) {
	severities := []Severity{
		SeverityInfo,
		SeverityWarning,
		SeverityError,
		SeverityCritical,
		SeverityAlert,
	}

	for _, s := range severities {
		if s == "" {
			t.Error("Severity should not be empty")
		}
	}
}

func TestDefaultAuditLoggerConfig(t *testing.T) {
	config := DefaultAuditLoggerConfig()

	if config.LogPath == "" {
		t.Error("LogPath should have default value")
	}
	if config.MaxFileSize <= 0 {
		t.Error("MaxFileSize should be positive")
	}
	if config.MaxFiles <= 0 {
		t.Error("MaxFiles should be positive")
	}
	if config.FlushInterval <= 0 {
		t.Error("FlushInterval should be positive")
	}
	if config.BufferSize <= 0 {
		t.Error("BufferSize should be positive")
	}
}

func TestAuditLogger_Close(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}

	ctx := context.Background()
	mustLog(t, al, EventSystemStart, SeverityInfo, "Event")

	// Close
	err = al.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Logging after close should fail
	err = al.Log(ctx, EventSystemStart, SeverityInfo, "After close", nil)
	if err != ErrLoggerClosed {
		t.Errorf("Log after close should return ErrLoggerClosed, got %v", err)
	}
}

func TestAuditLogger_ConcurrentLogging(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	defer al.Close()

	ctx := context.Background()
	done := make(chan bool, 100)

	// Concurrent writers
	for i := 0; i < 100; i++ {
		go func(idx int) {
			if err := al.Log(ctx, EventSystemStart, SeverityInfo, "Concurrent", map[string]interface{}{
				"index": idx,
			}); err != nil {
				t.Errorf("Log(%d) error = %v", idx, err)
			}
			done <- true
		}(i)
	}

	// Wait for all
	for i := 0; i < 100; i++ {
		<-done
	}

	if err := al.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush() error = %v", err)
	}

	// Verify integrity
	err = al.VerifyIntegrity(ctx)
	if err != nil {
		t.Errorf("VerifyIntegrity() after concurrent logging error = %v", err)
	}

	// Check metrics
	metrics := al.Metrics()
	if metrics.Written != 100 {
		t.Errorf("Written = %d, want 100", metrics.Written)
	}
}

func TestAuditEvent_LogEvent(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	defer al.Close()

	ctx := context.Background()

	event := &AuditEvent{
		Type:       EventAuthSuccess,
		Severity:   SeverityInfo,
		Message:    "User logged in",
		Actor:      "user@example.com",
		ActorIP:    "192.168.1.100",
		ActorType:  "user",
		Target:     "/admin",
		TargetType: "endpoint",
		Success:    true,
		Data: map[string]interface{}{
			"method": "password",
		},
	}

	err = al.LogEvent(ctx, event)
	if err != nil {
		t.Fatalf("LogEvent() error = %v", err)
	}

	if err := al.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush() error = %v", err)
	}

	// Query and verify
	results, err := al.Query(ctx, QueryOptions{
		Types: []EventType{EventAuthSuccess},
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
}

func TestAuditLogger_QueryTimeRange(t *testing.T) {
	config := testConfig(t)
	al, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	defer al.Close()

	ctx := context.Background()

	// Log some events
	now := time.Now()
	mustLog(t, al, EventSystemStart, SeverityInfo, "Event 1")
	if err := al.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush() error = %v", err)
	}

	// Query with time range
	results, err := al.Query(ctx, QueryOptions{
		StartTime: now.Add(-1 * time.Second),
		EndTime:   now.Add(1 * time.Second),
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Query time range returned %d results, want 1", len(results))
	}

	// Query outside time range
	results, err = al.Query(ctx, QueryOptions{
		StartTime: now.Add(-2 * time.Hour),
		EndTime:   now.Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Query outside range returned %d results, want 0", len(results))
	}
}

func TestComputeGenesisHash(t *testing.T) {
	hash1 := computeGenesisHash()
	hash2 := computeGenesisHash()

	if hash1 == "" {
		t.Error("Genesis hash should not be empty")
	}
	if hash1 != hash2 {
		t.Error("Genesis hash should be deterministic")
	}
}

func TestGenerateEntryID(t *testing.T) {
	id1 := generateEntryID()
	id2 := generateEntryID()

	if id1 == "" {
		t.Error("Entry ID should not be empty")
	}
	if id1 == id2 {
		t.Error("Entry IDs should be unique")
	}
}

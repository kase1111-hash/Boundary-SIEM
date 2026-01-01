package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
	al.ForceFlush(ctx)
	al.Close()

	// Reopen and verify
	al2, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() reopen error = %v", err)
	}
	defer al2.Close()

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
	al.Log(ctx, EventSystemStart, SeverityInfo, "Start", nil)
	al.Log(ctx, EventAuthSuccess, SeverityInfo, "Login", nil)
	al.Log(ctx, EventAuthFailure, SeverityWarning, "Bad login", nil)
	al.Log(ctx, EventFirewallBlock, SeverityCritical, "Blocked", nil)
	al.ForceFlush(ctx)

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
		al.Log(ctx, EventSystemStart, SeverityInfo, "Event", nil)
	}
	al.ForceFlush(ctx)

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
		al1.Log(ctx, EventSystemStart, SeverityInfo, "Event", nil)
	}
	al1.ForceFlush(ctx)
	al1.Close()

	// Second logger should recover state
	al2, err := NewAuditLogger(config, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() reopen error = %v", err)
	}
	defer al2.Close()

	// Sequence should continue
	if al2.sequence != 5 {
		t.Errorf("Recovered sequence = %d, want 5", al2.sequence)
	}

	// Log more events
	al2.Log(ctx, EventSystemShutdown, SeverityInfo, "Shutdown", nil)
	al2.ForceFlush(ctx)

	// Query all events
	results, _ := al2.Query(ctx, QueryOptions{})
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
		al.Log(ctx, EventSystemStart, SeverityInfo, "Event", nil)
	}
	al.ForceFlush(ctx)
	al.Close()

	// Manually tamper with the log file - remove an entry
	files, _ := filepath.Glob(filepath.Join(config.LogPath, "audit-*.log"))
	if len(files) == 0 {
		t.Fatal("No log files found")
	}

	// Read entries
	data, _ := os.ReadFile(files[0])
	lines := []string{}
	for _, line := range splitLines(string(data)) {
		if line != "" {
			lines = append(lines, line)
		}
	}

	// Remove middle entry (create gap)
	if len(lines) >= 3 {
		tamperedLines := append(lines[:2], lines[3:]...)
		os.WriteFile(files[0], []byte(joinLines(tamperedLines)), 0600)
	}

	// Reopen and verify - should detect gap
	al2, _ := NewAuditLogger(config, nil)
	defer al2.Close()

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

	al.Log(ctx, EventSystemStart, SeverityInfo, "Event", nil)
	al.ForceFlush(ctx)
	al.Close()

	// Tamper with entry
	files, _ := filepath.Glob(filepath.Join(config.LogPath, "audit-*.log"))
	if len(files) == 0 {
		t.Fatal("No log files found")
	}

	data, _ := os.ReadFile(files[0])
	var entry AuditEntry
	json.Unmarshal(data[:len(data)-1], &entry) // Remove newline

	// Modify message
	entry.Message = "TAMPERED"
	tamperedData, _ := json.Marshal(entry)
	os.WriteFile(files[0], append(tamperedData, '\n'), 0600)

	// Verify should detect tampering
	al2, _ := NewAuditLogger(config, nil)
	defer al2.Close()

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
		al.Log(ctx, EventSystemStart, SeverityInfo, "Event", nil)
	}
	al.ForceFlush(ctx)
	al.Close()

	// Tamper with chain - modify previous_hash of second entry
	files, _ := filepath.Glob(filepath.Join(config.LogPath, "audit-*.log"))
	if len(files) == 0 {
		t.Fatal("No log files found")
	}

	data, _ := os.ReadFile(files[0])
	lines := splitLines(string(data))

	if len(lines) >= 2 {
		var entry AuditEntry
		json.Unmarshal([]byte(lines[1]), &entry)
		entry.PreviousHash = "tampered-hash"
		tamperedLine, _ := json.Marshal(entry)
		lines[1] = string(tamperedLine)
		os.WriteFile(files[0], []byte(joinLines(lines)), 0600)
	}

	// Verify should detect broken chain
	al2, _ := NewAuditLogger(config, nil)
	defer al2.Close()

	err = al2.VerifyIntegrity(ctx)
	if err == nil {
		t.Error("VerifyIntegrity() should detect broken chain")
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
	al.Log(ctx, EventSystemStart, SeverityInfo, "Event", nil)

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
			al.Log(ctx, EventSystemStart, SeverityInfo, "Concurrent", map[string]interface{}{
				"index": idx,
			})
			done <- true
		}(i)
	}

	// Wait for all
	for i := 0; i < 100; i++ {
		<-done
	}

	al.ForceFlush(ctx)

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

	al.ForceFlush(ctx)

	// Query and verify
	results, _ := al.Query(ctx, QueryOptions{
		Types: []EventType{EventAuthSuccess},
	})
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
	al.Log(ctx, EventSystemStart, SeverityInfo, "Event 1", nil)
	al.ForceFlush(ctx)

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

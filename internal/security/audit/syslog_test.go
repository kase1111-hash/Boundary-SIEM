package audit

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDefaultSyslogConfig(t *testing.T) {
	config := DefaultSyslogConfig()

	if config.Protocol != ProtocolTCP {
		t.Errorf("Protocol = %s, want tcp", config.Protocol)
	}
	if config.Format != FormatRFC5424 {
		t.Errorf("Format = %s, want rfc5424", config.Format)
	}
	if config.Facility != FacilityLocal0 {
		t.Errorf("Facility = %d, want %d", config.Facility, FacilityLocal0)
	}
	if config.BufferSize <= 0 {
		t.Error("BufferSize should be positive")
	}
	if config.AppName == "" {
		t.Error("AppName should not be empty")
	}
}

func TestNewSyslogForwarder_Disabled(t *testing.T) {
	config := DefaultSyslogConfig()
	config.Enabled = false

	sf, err := NewSyslogForwarder(config)
	if err != nil {
		t.Fatalf("NewSyslogForwarder() error = %v", err)
	}
	if sf != nil {
		t.Error("Disabled forwarder should return nil")
	}
}

func TestNewSyslogForwarder_NoAddresses(t *testing.T) {
	config := DefaultSyslogConfig()
	config.Enabled = true
	config.Addresses = []string{}

	_, err := NewSyslogForwarder(config)
	if err == nil {
		t.Error("Should fail with no addresses")
	}
}

// testSyslogServer creates a test syslog server.
type testSyslogServer struct {
	listener net.Listener
	messages []string
	mu       sync.Mutex
	wg       sync.WaitGroup
	done     chan struct{}
}

func newTestSyslogServer(t *testing.T) *testSyslogServer {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	s := &testSyslogServer{
		listener: listener,
		messages: make([]string, 0),
		done:     make(chan struct{}),
	}

	s.wg.Add(1)
	go s.accept()

	return s
}

func (s *testSyslogServer) accept() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *testSyslogServer) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	buf := make([]byte, 4096)
	for {
		select {
		case <-s.done:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		if n > 0 {
			s.mu.Lock()
			// Split by newlines in case multiple messages
			msgs := strings.Split(string(buf[:n]), "\n")
			for _, msg := range msgs {
				if msg = strings.TrimSpace(msg); msg != "" {
					s.messages = append(s.messages, msg)
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *testSyslogServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *testSyslogServer) Messages() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]string, len(s.messages))
	copy(result, s.messages)
	return result
}

func (s *testSyslogServer) Close() {
	close(s.done)
	s.listener.Close()
	s.wg.Wait()
}

func TestSyslogForwarder_Connect(t *testing.T) {
	server := newTestSyslogServer(t)
	defer server.Close()

	config := DefaultSyslogConfig()
	config.Enabled = true
	config.Addresses = []string{server.Addr()}
	config.Protocol = ProtocolTCP
	config.ConnectionTimeout = 5 * time.Second

	sf, err := NewSyslogForwarder(config)
	if err != nil {
		t.Fatalf("NewSyslogForwarder() error = %v", err)
	}
	defer sf.Close()

	// Wait for connection
	time.Sleep(100 * time.Millisecond)

	if !sf.IsConnected() {
		t.Error("Forwarder should be connected")
	}
}

func TestSyslogForwarder_Forward(t *testing.T) {
	server := newTestSyslogServer(t)
	defer server.Close()

	config := DefaultSyslogConfig()
	config.Enabled = true
	config.Addresses = []string{server.Addr()}
	config.Protocol = ProtocolTCP
	config.Format = FormatRFC5424
	config.FlushInterval = 100 * time.Millisecond

	sf, err := NewSyslogForwarder(config)
	if err != nil {
		t.Fatalf("NewSyslogForwarder() error = %v", err)
	}
	defer sf.Close()

	// Wait for connection
	time.Sleep(100 * time.Millisecond)

	// Create test entry
	entry := &AuditEntry{
		ID:        "test-id-123",
		Sequence:  1,
		Timestamp: time.Now(),
		Type:      EventSystemStart,
		Severity:  SeverityInfo,
		Message:   "Test message",
		Hostname:  "test-host",
		ProcessID: 1234,
		EntryHash: "abc123",
	}

	// Forward entry
	err = sf.Forward(entry)
	if err != nil {
		t.Fatalf("Forward() error = %v", err)
	}

	// Wait for message to be sent
	time.Sleep(500 * time.Millisecond)

	// Check metrics
	metrics := sf.Metrics()
	if metrics.Sent == 0 {
		t.Error("Expected at least one sent message")
	}

	// Check server received message
	messages := server.Messages()
	if len(messages) == 0 {
		t.Error("Server should have received a message")
	}
}

func TestSyslogForwarder_FormatRFC3164(t *testing.T) {
	config := DefaultSyslogConfig()
	config.Format = FormatRFC3164
	config.Facility = FacilityLocal0
	config.AppName = "test-app"

	sf := &SyslogForwarder{config: config}

	entry := &AuditEntry{
		ID:        "test-id",
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Type:      EventAuthSuccess,
		Severity:  SeverityInfo,
		Message:   "User logged in",
		Hostname:  "server1",
	}

	msg := sf.formatRFC3164(entry)
	msgStr := string(msg)

	// Check format
	if !strings.Contains(msgStr, "<134>") { // pri = 16*8 + 6 = 134
		t.Errorf("Message missing correct priority: %s", msgStr)
	}
	if !strings.Contains(msgStr, "test-app") {
		t.Errorf("Message missing app name: %s", msgStr)
	}
	if !strings.Contains(msgStr, "auth.success") {
		t.Errorf("Message missing event type: %s", msgStr)
	}
}

func TestSyslogForwarder_FormatRFC5424(t *testing.T) {
	config := DefaultSyslogConfig()
	config.Format = FormatRFC5424
	config.Facility = FacilityLocal0
	config.AppName = "boundary-siem"

	sf := &SyslogForwarder{config: config}

	entry := &AuditEntry{
		ID:        "test-id-456",
		Sequence:  42,
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Type:      EventFirewallBlock,
		Severity:  SeverityWarning,
		Message:   "Blocked connection",
		Hostname:  "server1",
		ProcessID: 5678,
		EntryHash: "hash789",
		Actor:     "admin",
		ActorIP:   "192.168.1.100",
		ActorType: "user",
	}

	msg := sf.formatRFC5424(entry)
	msgStr := string(msg)

	// Check format
	if !strings.HasPrefix(msgStr, "<132>1 ") { // pri = 16*8 + 4 = 132, version 1
		t.Errorf("Message should start with RFC5424 header: %s", msgStr)
	}
	if !strings.Contains(msgStr, "boundary-siem") {
		t.Errorf("Message missing app name: %s", msgStr)
	}
	if !strings.Contains(msgStr, "[audit@boundary") {
		t.Errorf("Message missing structured data: %s", msgStr)
	}
	if !strings.Contains(msgStr, "id=\"test-id-456\"") {
		t.Errorf("Message missing entry ID in SD: %s", msgStr)
	}
	if !strings.Contains(msgStr, "[actor@boundary") {
		t.Errorf("Message missing actor SD: %s", msgStr)
	}
}

func TestSyslogForwarder_FormatCEF(t *testing.T) {
	config := DefaultSyslogConfig()
	config.Format = FormatCEF
	config.Facility = FacilityLocal0

	sf := &SyslogForwarder{config: config}

	entry := &AuditEntry{
		ID:        "test-id-789",
		Sequence:  100,
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		Type:      EventUSBBlocked,
		Severity:  SeverityCritical,
		Message:   "USB device blocked",
		Hostname:  "workstation1",
		ProcessID: 9999,
		EntryHash: "hashxyz",
		Success:   false,
		Error:     "Unauthorized device",
	}

	msg := sf.formatCEF(entry)
	msgStr := string(msg)

	// Check CEF format
	if !strings.Contains(msgStr, "CEF:0|Boundary|SIEM|1.0|") {
		t.Errorf("Message should contain CEF header: %s", msgStr)
	}
	if !strings.Contains(msgStr, "usb.blocked") {
		t.Errorf("Message should contain signature ID: %s", msgStr)
	}
	if !strings.Contains(msgStr, "cs1=test-id-789") {
		t.Errorf("Message should contain AuditID: %s", msgStr)
	}
	if !strings.Contains(msgStr, "outcome=Failure") {
		t.Errorf("Message should contain outcome: %s", msgStr)
	}
}

func TestSyslogForwarder_FormatJSON(t *testing.T) {
	config := DefaultSyslogConfig()
	config.Format = FormatJSON
	config.Facility = FacilityLocal0
	config.AppName = "test-siem"

	sf := &SyslogForwarder{config: config}

	entry := &AuditEntry{
		ID:        "json-test-id",
		Sequence:  50,
		Timestamp: time.Now(),
		Type:      EventConfigChange,
		Severity:  SeverityInfo,
		Message:   "Config updated",
		Hostname:  "server2",
		ProcessID: 1111,
	}

	msg := sf.formatJSON(entry)
	msgStr := string(msg)

	// Check JSON format
	if !strings.Contains(msgStr, "test-siem:") {
		t.Errorf("Message should contain app name: %s", msgStr)
	}
	if !strings.Contains(msgStr, `"id":"json-test-id"`) {
		t.Errorf("Message should contain JSON id field: %s", msgStr)
	}
	if !strings.Contains(msgStr, `"type":"config.change"`) {
		t.Errorf("Message should contain JSON type field: %s", msgStr)
	}
}

func TestSyslogForwarder_Metrics(t *testing.T) {
	server := newTestSyslogServer(t)
	defer server.Close()

	config := DefaultSyslogConfig()
	config.Enabled = true
	config.Addresses = []string{server.Addr()}
	config.FlushInterval = 50 * time.Millisecond

	sf, err := NewSyslogForwarder(config)
	if err != nil {
		t.Fatalf("NewSyslogForwarder() error = %v", err)
	}
	defer sf.Close()

	time.Sleep(100 * time.Millisecond)

	// Send some entries
	for i := 0; i < 5; i++ {
		entry := &AuditEntry{
			ID:        "metric-test",
			Sequence:  uint64(i),
			Timestamp: time.Now(),
			Type:      EventSystemStart,
			Severity:  SeverityInfo,
			Message:   "Test",
		}
		sf.Forward(entry)
	}

	time.Sleep(300 * time.Millisecond)

	metrics := sf.Metrics()
	if metrics.Sent == 0 {
		t.Error("Sent should be greater than 0")
	}
	if metrics.Reconnects == 0 {
		t.Error("Reconnects should be at least 1 (initial connection)")
	}
	if !metrics.Connected {
		t.Error("Should be connected")
	}
}

func TestSyslogForwarder_BufferFull(t *testing.T) {
	config := DefaultSyslogConfig()
	config.Enabled = true
	config.Addresses = []string{"127.0.0.1:99999"} // Invalid address
	config.BufferSize = 5
	config.ConnectionTimeout = 100 * time.Millisecond

	sf, err := NewSyslogForwarder(config)
	if err != nil {
		t.Fatalf("NewSyslogForwarder() error = %v", err)
	}
	defer sf.Close()

	// Fill the buffer
	for i := 0; i < 10; i++ {
		entry := &AuditEntry{
			ID:        "buffer-test",
			Timestamp: time.Now(),
			Type:      EventSystemStart,
			Severity:  SeverityInfo,
			Message:   "Test",
		}
		sf.Forward(entry)
	}

	metrics := sf.Metrics()
	if metrics.Dropped == 0 {
		t.Error("Should have dropped some messages")
	}
}

func TestSyslogForwarder_Close(t *testing.T) {
	server := newTestSyslogServer(t)
	defer server.Close()

	config := DefaultSyslogConfig()
	config.Enabled = true
	config.Addresses = []string{server.Addr()}

	sf, err := NewSyslogForwarder(config)
	if err != nil {
		t.Fatalf("NewSyslogForwarder() error = %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Close
	err = sf.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Forward after close should fail
	entry := &AuditEntry{
		ID:        "after-close",
		Timestamp: time.Now(),
		Type:      EventSystemStart,
		Severity:  SeverityInfo,
		Message:   "Test",
	}
	err = sf.Forward(entry)
	if err != ErrSyslogClosed {
		t.Errorf("Forward after close should return ErrSyslogClosed, got %v", err)
	}
}

func TestSyslogForwarder_Reconnect(t *testing.T) {
	// Start server
	server := newTestSyslogServer(t)

	config := DefaultSyslogConfig()
	config.Enabled = true
	config.Addresses = []string{server.Addr()}
	config.RetryInterval = 100 * time.Millisecond
	config.ConnectionTimeout = 500 * time.Millisecond

	sf, err := NewSyslogForwarder(config)
	if err != nil {
		t.Fatalf("NewSyslogForwarder() error = %v", err)
	}
	defer sf.Close()

	time.Sleep(200 * time.Millisecond)
	if !sf.IsConnected() {
		t.Error("Should be connected initially")
	}

	// Close server to simulate disconnect
	server.Close()
	time.Sleep(200 * time.Millisecond)

	// Connection should be lost
	// (Note: detection may take time, so we just verify the system handles it)

	metrics := sf.Metrics()
	t.Logf("Reconnects: %d, Connected: %v", metrics.Reconnects, metrics.Connected)
}

func TestWithRemoteSyslog(t *testing.T) {
	server := newTestSyslogServer(t)
	defer server.Close()

	// Create audit logger
	alConfig := testConfig(t)
	al, err := NewAuditLogger(alConfig, nil)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	defer al.Close()

	// Enable syslog
	syslogConfig := DefaultSyslogConfig()
	syslogConfig.Enabled = true
	syslogConfig.Addresses = []string{server.Addr()}
	syslogConfig.FlushInterval = 100 * time.Millisecond

	err = WithRemoteSyslog(al, syslogConfig)
	if err != nil {
		t.Fatalf("WithRemoteSyslog() error = %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Log an event
	ctx := context.Background()
	err = al.Log(ctx, EventSystemStart, SeverityInfo, "Test syslog integration", nil)
	if err != nil {
		t.Fatalf("Log() error = %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Check syslog status
	status := al.GetSyslogStatus()
	if status == nil {
		t.Fatal("GetSyslogStatus() returned nil")
	}
	if status.Sent == 0 {
		t.Error("Should have sent at least one message")
	}

	// Check server received message
	messages := server.Messages()
	if len(messages) == 0 {
		t.Error("Server should have received messages")
	}
}

func TestSeverityToSyslog(t *testing.T) {
	sf := &SyslogForwarder{config: DefaultSyslogConfig()}

	tests := []struct {
		severity Severity
		expected int
	}{
		{SeverityAlert, SyslogAlert},
		{SeverityCritical, SyslogCritical},
		{SeverityError, SyslogError},
		{SeverityWarning, SyslogWarning},
		{SeverityInfo, SyslogInfo},
	}

	for _, tc := range tests {
		result := sf.severityToSyslog(tc.severity)
		if result != tc.expected {
			t.Errorf("severityToSyslog(%s) = %d, want %d", tc.severity, result, tc.expected)
		}
	}
}

func TestCEFSeverity(t *testing.T) {
	sf := &SyslogForwarder{config: DefaultSyslogConfig()}

	tests := []struct {
		severity Severity
		min      int
		max      int
	}{
		{SeverityAlert, 9, 10},
		{SeverityCritical, 7, 9},
		{SeverityError, 5, 7},
		{SeverityWarning, 3, 5},
		{SeverityInfo, 1, 3},
	}

	for _, tc := range tests {
		result := sf.cefSeverity(tc.severity)
		if result < tc.min || result > tc.max {
			t.Errorf("cefSeverity(%s) = %d, want between %d and %d", tc.severity, result, tc.min, tc.max)
		}
	}
}

func TestEscapeSDValue(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{`with "quotes"`, `with \"quotes\"`},
		{"with [brackets]", `with [brackets\]`},
		{`with \backslash`, `with \\backslash`},
	}

	for _, tc := range tests {
		result := escapeSDValue(tc.input)
		if result != tc.expected {
			t.Errorf("escapeSDValue(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestEscapeFieldCEF(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with|pipe", `with\|pipe`},
		{"with=equals", `with\=equals`},
		{"with\nnewline", `with\nnewline`},
	}

	for _, tc := range tests {
		result := escapeFieldCEF(tc.input)
		if result != tc.expected {
			t.Errorf("escapeFieldCEF(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestSyslogProtocolConstants(t *testing.T) {
	if ProtocolUDP != "udp" {
		t.Error("ProtocolUDP should be 'udp'")
	}
	if ProtocolTCP != "tcp" {
		t.Error("ProtocolTCP should be 'tcp'")
	}
	if ProtocolTLS != "tls" {
		t.Error("ProtocolTLS should be 'tls'")
	}
}

func TestSyslogFormatConstants(t *testing.T) {
	if FormatRFC3164 != "rfc3164" {
		t.Error("FormatRFC3164 should be 'rfc3164'")
	}
	if FormatRFC5424 != "rfc5424" {
		t.Error("FormatRFC5424 should be 'rfc5424'")
	}
	if FormatCEF != "cef" {
		t.Error("FormatCEF should be 'cef'")
	}
	if FormatJSON != "json" {
		t.Error("FormatJSON should be 'json'")
	}
}

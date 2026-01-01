package alerting

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"boundary-siem/internal/correlation"

	"github.com/google/uuid"
)

func TestNewEmailChannel(t *testing.T) {
	tests := []struct {
		name         string
		config       *EmailConfig
		expectedPort int
	}{
		{
			name: "default port with TLS",
			config: &EmailConfig{
				SMTPHost: "smtp.example.com",
				UseTLS:   true,
			},
			expectedPort: 465,
		},
		{
			name: "default port without TLS",
			config: &EmailConfig{
				SMTPHost: "smtp.example.com",
				UseTLS:   false,
			},
			expectedPort: 587,
		},
		{
			name: "custom port",
			config: &EmailConfig{
				SMTPHost: "smtp.example.com",
				SMTPPort: 2525,
			},
			expectedPort: 2525,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := NewEmailChannel(tt.config)
			if ch.config.SMTPPort != tt.expectedPort {
				t.Errorf("expected port %d, got %d", tt.expectedPort, ch.config.SMTPPort)
			}
			if ch.Name() != "email" {
				t.Errorf("expected name 'email', got %s", ch.Name())
			}
		})
	}
}

func TestEmailChannelBuildTextBody(t *testing.T) {
	ch := NewEmailChannel(&EmailConfig{})

	alert := &Alert{
		ID:          uuid.New(),
		RuleID:      "test-rule-001",
		Title:       "Test Alert",
		Description: "This is a test alert description",
		Severity:    correlation.SeverityHigh,
		EventCount:  5,
		Tags:        []string{"blockchain", "ethereum"},
		GroupKey:    "test-group",
		CreatedAt:   time.Now(),
		MITRE: &correlation.MITREMapping{
			TacticID:    "TA0001",
			TacticName:  "Initial Access",
			TechniqueID: "T1190",
		},
	}

	body := ch.buildTextBody(alert)

	// Check required elements
	if !strings.Contains(body, "SECURITY ALERT: Test Alert") {
		t.Error("text body missing title")
	}
	if !strings.Contains(body, "Severity: HIGH") {
		t.Error("text body missing severity")
	}
	if !strings.Contains(body, "test-rule-001") {
		t.Error("text body missing rule ID")
	}
	if !strings.Contains(body, "Event Count: 5") {
		t.Error("text body missing event count")
	}
	if !strings.Contains(body, "blockchain") {
		t.Error("text body missing tags")
	}
	if !strings.Contains(body, "MITRE ATT&CK") {
		t.Error("text body missing MITRE section")
	}
	if !strings.Contains(body, "Initial Access") {
		t.Error("text body missing MITRE tactic")
	}
}

func TestEmailChannelBuildHTMLBody(t *testing.T) {
	ch := NewEmailChannel(&EmailConfig{})

	alert := &Alert{
		ID:          uuid.New(),
		RuleID:      "test-rule-002",
		Title:       "Critical Alert",
		Description: "This is a critical alert",
		Severity:    correlation.SeverityCritical,
		EventCount:  10,
		Tags:        []string{"defi", "flash-loan"},
		CreatedAt:   time.Now(),
		MITRE: &correlation.MITREMapping{
			TacticID:    "TA0040",
			TacticName:  "Impact",
			TechniqueID: "T1499",
		},
	}

	body := ch.buildHTMLBody(alert)

	// Check HTML structure
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("HTML body missing doctype")
	}
	if !strings.Contains(body, "Critical Alert") {
		t.Error("HTML body missing title")
	}
	if !strings.Contains(body, "#dc3545") {
		t.Error("HTML body missing critical severity color")
	}
	if !strings.Contains(body, "MITRE ATT&CK") {
		t.Error("HTML body missing MITRE section")
	}
	if !strings.Contains(body, "defi") {
		t.Error("HTML body missing tags")
	}
}

func TestEmailChannelBuildMIMEMessage(t *testing.T) {
	ch := NewEmailChannel(&EmailConfig{
		From: "alerts@example.com",
		To:   []string{"security@example.com", "ops@example.com"},
	})

	msg := ch.buildMIMEMessage("Test Subject", "Plain text body", "<html>HTML body</html>")

	msgStr := string(msg)

	// Check MIME headers
	if !strings.Contains(msgStr, "From: alerts@example.com") {
		t.Error("MIME message missing From header")
	}
	if !strings.Contains(msgStr, "To: security@example.com, ops@example.com") {
		t.Error("MIME message missing To header")
	}
	if !strings.Contains(msgStr, "MIME-Version: 1.0") {
		t.Error("MIME message missing MIME-Version header")
	}
	if !strings.Contains(msgStr, "multipart/alternative") {
		t.Error("MIME message missing multipart content type")
	}
	if !strings.Contains(msgStr, "text/plain") {
		t.Error("MIME message missing text/plain part")
	}
	if !strings.Contains(msgStr, "text/html") {
		t.Error("MIME message missing text/html part")
	}
	if !strings.Contains(msgStr, "Plain text body") {
		t.Error("MIME message missing plain text content")
	}
	if !strings.Contains(msgStr, "HTML body") {
		t.Error("MIME message missing HTML content")
	}
}

func TestEmailChannelSeverityColors(t *testing.T) {
	ch := NewEmailChannel(&EmailConfig{})

	tests := []struct {
		severity      correlation.Severity
		expectedColor string
		expectedBg    string
	}{
		{correlation.SeverityCritical, "#dc3545", "#fff5f5"},
		{correlation.SeverityHigh, "#fd7e14", "#fff8f0"},
		{correlation.SeverityMedium, "#ffc107", "#fffdf0"},
		{correlation.SeverityLow, "#28a745", "#f0fff4"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			color := ch.severityColor(tt.severity)
			if color != tt.expectedColor {
				t.Errorf("expected color %s, got %s", tt.expectedColor, color)
			}

			bgColor := ch.severityBgColor(tt.severity)
			if bgColor != tt.expectedBg {
				t.Errorf("expected bg color %s, got %s", tt.expectedBg, bgColor)
			}
		})
	}
}

func TestEmailChannelSendConnectionError(t *testing.T) {
	ch := NewEmailChannel(&EmailConfig{
		SMTPHost: "invalid.host.local",
		SMTPPort: 25,
		From:     "test@example.com",
		To:       []string{"dest@example.com"},
	})
	ch.timeout = 1 * time.Second

	alert := &Alert{
		ID:          uuid.New(),
		RuleID:      "test-rule",
		Title:       "Test",
		Description: "Test alert",
		Severity:    correlation.SeverityLow,
		CreatedAt:   time.Now(),
	}

	ctx := context.Background()
	err := ch.Send(ctx, alert)

	// Should fail to connect
	if err == nil {
		t.Error("expected connection error")
	}
	if !strings.Contains(err.Error(), "failed to connect") {
		t.Errorf("unexpected error: %v", err)
	}
}

// MockSMTPServer for integration testing
type MockSMTPServer struct {
	listener     net.Listener
	receivedMail [][]byte
	done         chan struct{}
}

func NewMockSMTPServer(t *testing.T) *MockSMTPServer {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create mock SMTP server: %v", err)
	}

	server := &MockSMTPServer{
		listener: listener,
		done:     make(chan struct{}),
	}

	go server.serve(t)
	return server
}

func (s *MockSMTPServer) serve(t *testing.T) {
	for {
		select {
		case <-s.done:
			return
		default:
		}

		s.listener.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		go s.handleConnection(t, conn)
	}
}

func (s *MockSMTPServer) handleConnection(t *testing.T, conn net.Conn) {
	defer conn.Close()

	// Send greeting
	conn.Write([]byte("220 mock.smtp.server ESMTP\r\n"))

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		cmd := strings.ToUpper(strings.TrimSpace(string(buf[:n])))

		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			conn.Write([]byte("250-mock.smtp.server\r\n250 OK\r\n"))
		case strings.HasPrefix(cmd, "MAIL FROM"):
			conn.Write([]byte("250 OK\r\n"))
		case strings.HasPrefix(cmd, "RCPT TO"):
			conn.Write([]byte("250 OK\r\n"))
		case strings.HasPrefix(cmd, "DATA"):
			conn.Write([]byte("354 Start mail input\r\n"))
			// Read until we get the terminating dot
			var data []byte
			for {
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				data = append(data, buf[:n]...)
				if strings.HasSuffix(string(data), "\r\n.\r\n") {
					break
				}
			}
			s.receivedMail = append(s.receivedMail, data)
			conn.Write([]byte("250 OK\r\n"))
		case strings.HasPrefix(cmd, "QUIT"):
			conn.Write([]byte("221 Bye\r\n"))
			return
		default:
			conn.Write([]byte("500 Unknown command\r\n"))
		}
	}
}

func (s *MockSMTPServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *MockSMTPServer) Close() {
	close(s.done)
	s.listener.Close()
}

func TestEmailChannelWithMockServer(t *testing.T) {
	server := NewMockSMTPServer(t)
	defer server.Close()

	addr := server.Addr()
	host, port, _ := net.SplitHostPort(addr)
	portInt := 0
	_, _ = strings.CutPrefix(port, "")
	for _, c := range port {
		portInt = portInt*10 + int(c-'0')
	}

	ch := NewEmailChannel(&EmailConfig{
		SMTPHost: host,
		SMTPPort: portInt,
		From:     "alerts@boundary-siem.io",
		To:       []string{"security-team@example.com"},
	})

	alert := &Alert{
		ID:          uuid.New(),
		RuleID:      "blockchain-001",
		Title:       "Flash Loan Attack Detected",
		Description: "Suspicious flash loan activity detected on Ethereum mainnet",
		Severity:    correlation.SeverityCritical,
		EventCount:  3,
		Tags:        []string{"defi", "flash-loan", "ethereum"},
		CreatedAt:   time.Now(),
		MITRE: &correlation.MITREMapping{
			TacticID:    "TA0040",
			TacticName:  "Impact",
			TechniqueID: "T1499",
		},
	}

	ctx := context.Background()
	err := ch.Send(ctx, alert)

	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	// Give the server time to receive
	time.Sleep(100 * time.Millisecond)

	if len(server.receivedMail) == 0 {
		t.Error("expected to receive mail")
	}

	// Check mail content
	mail := string(server.receivedMail[0])
	if !strings.Contains(mail, "Flash Loan Attack Detected") {
		t.Error("mail missing alert title")
	}
	if !strings.Contains(mail, "CRITICAL") {
		t.Error("mail missing severity")
	}
}

func TestLogChannel(t *testing.T) {
	var logged string
	logger := func(format string, args ...interface{}) {
		logged = format
	}

	ch := NewLogChannel(logger)

	if ch.Name() != "log" {
		t.Errorf("expected name 'log', got %s", ch.Name())
	}

	alert := &Alert{
		ID:          uuid.New(),
		RuleID:      "test-rule",
		Title:       "Test Alert",
		Description: "Test description",
		Severity:    correlation.SeverityMedium,
		EventCount:  1,
		Tags:        []string{"test"},
		CreatedAt:   time.Now(),
	}

	ctx := context.Background()
	err := ch.Send(ctx, alert)
	if err != nil {
		t.Errorf("Send() error = %v", err)
	}

	if logged == "" {
		t.Error("expected log output")
	}
}

func TestWebhookChannel(t *testing.T) {
	ch := NewWebhookChannel("test-webhook", "http://example.com/webhook", map[string]string{
		"Authorization": "Bearer token123",
	})

	if ch.Name() != "test-webhook" {
		t.Errorf("expected name 'test-webhook', got %s", ch.Name())
	}
}

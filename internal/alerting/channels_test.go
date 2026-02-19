package alerting

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
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
	ch, err := NewWebhookChannel("test-webhook", "http://example.com/webhook", map[string]string{
		"Authorization": "Bearer token123",
	})
	if err != nil {
		t.Fatalf("NewWebhookChannel failed: %v", err)
	}

	if ch.Name() != "test-webhook" {
		t.Errorf("expected name 'test-webhook', got %s", ch.Name())
	}
}

func TestSanitizeAlert(t *testing.T) {
	tests := []struct {
		name        string
		alert       *Alert
		wantMasked  bool
		checkField  string
		checkAbsent string // substring that should NOT appear after sanitization
	}{
		{
			name: "alert with API key in description",
			alert: &Alert{
				ID:          uuid.New(),
				Title:       "Credential Leak Detected",
				Description: "Found api_key='sk_live_abc123xyz789' in log entry",
				Severity:    correlation.SeverityHigh,
				CreatedAt:   time.Now(),
			},
			wantMasked:  true,
			checkField:  "Description",
			checkAbsent: "sk_live_abc123xyz789",
		},
		{
			name: "alert with Bearer token in title",
			alert: &Alert{
				ID:          uuid.New(),
				Title:       "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
				Description: "Normal description",
				Severity:    correlation.SeverityMedium,
				CreatedAt:   time.Now(),
			},
			wantMasked:  true,
			checkField:  "Title",
			checkAbsent: "eyJhbGciOiJIUzI1NiJ9",
		},
		{
			name: "alert with AWS key in tags",
			alert: &Alert{
				ID:          uuid.New(),
				Title:       "AWS Key Exposure",
				Description: "Found in config",
				Severity:    correlation.SeverityHigh,
				Tags:        []string{"aws", "AKIAIOSFODNN7EXAMPLE"},
				CreatedAt:   time.Now(),
			},
			wantMasked:  true,
			checkField:  "Tags",
			checkAbsent: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name: "clean alert is unchanged",
			alert: &Alert{
				ID:          uuid.New(),
				Title:       "Normal Alert",
				Description: "Nothing sensitive here",
				Severity:    correlation.SeverityLow,
				Tags:        []string{"normal"},
				CreatedAt:   time.Now(),
			},
			wantMasked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitized := sanitizeAlert(tt.alert)

			// Original alert must not be modified
			if sanitized == tt.alert {
				t.Error("sanitizeAlert should return a new alert, not the original")
			}

			if tt.wantMasked && tt.checkAbsent != "" {
				var fieldValue string
				switch tt.checkField {
				case "Title":
					fieldValue = sanitized.Title
				case "Description":
					fieldValue = sanitized.Description
				case "Tags":
					fieldValue = strings.Join(sanitized.Tags, " ")
				}
				if strings.Contains(fieldValue, tt.checkAbsent) {
					t.Errorf("%s still contains sensitive value %q after sanitization", tt.checkField, tt.checkAbsent)
				}
			}

			if !tt.wantMasked {
				if sanitized.Title != tt.alert.Title {
					t.Errorf("clean alert title was modified: got %q, want %q", sanitized.Title, tt.alert.Title)
				}
				if sanitized.Description != tt.alert.Description {
					t.Errorf("clean alert description was modified")
				}
			}
		})
	}
}

func TestEscapeSlackText(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal text", "normal text"},
		{"<script>alert('xss')</script>", "&lt;script&gt;alert('xss')&lt;/script&gt;"},
		{"A & B", "A &amp; B"},
		{"<@U12345> mentioned", "&lt;@U12345&gt; mentioned"},
		{"link: <http://evil.com|Click>", "link: &lt;http://evil.com|Click&gt;"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := escapeSlackText(tt.input)
			if result != tt.expected {
				t.Errorf("escapeSlackText(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeDiscordText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string // should NOT contain this after sanitization
	}{
		{
			name:     "strips @everyone",
			input:    "Alert: @everyone server is down",
			contains: "@everyone",
		},
		{
			name:     "strips @here",
			input:    "@here check this alert",
			contains: "@here",
		},
		{
			name:  "normal text unchanged",
			input: "Normal alert description",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeDiscordText(tt.input)
			if tt.contains != "" && strings.Contains(result, tt.contains) {
				t.Errorf("sanitizeDiscordText(%q) still contains %q", tt.input, tt.contains)
			}
			if tt.contains == "" && result != tt.input {
				t.Errorf("sanitizeDiscordText(%q) = %q, expected unchanged", tt.input, result)
			}
		})
	}
}

func TestWebhookSendSanitizesSecrets(t *testing.T) {
	// Verify the full pipeline: WebhookChannel.Send masks secrets in the JSON payload
	var receivedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		receivedBody = string(body)
		w.WriteHeader(200)
	}))
	defer server.Close()

	ch := NewWebhookChannelForTest("test", server.URL, nil)
	alert := &Alert{
		ID:          uuid.New(),
		Title:       "Leaked Key",
		Description: "Found token='sk_live_51234abcdef' in event",
		Severity:    correlation.SeverityHigh,
		EventCount:  1,
		CreatedAt:   time.Now(),
	}

	err := ch.Send(context.Background(), alert)
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if strings.Contains(receivedBody, "sk_live_51234abcdef") {
		t.Error("webhook payload still contains the secret after sanitization")
	}
}

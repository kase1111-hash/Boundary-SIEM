package alerting

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"boundary-siem/internal/correlation"
	"boundary-siem/internal/logging"
)

// validateWebhookURL validates that a URL is safe for server-side requests (SSRF protection).
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Only allow HTTP and HTTPS schemes
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q: only http and https are allowed", u.Scheme)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return fmt.Errorf("URL must have a hostname")
	}

	// Resolve hostname to check for private IPs.
	// If DNS resolution fails, allow the URL — it will fail at send time.
	// This prevents blocking valid URLs in environments with restricted DNS.
	ips, err := net.LookupIP(hostname)
	if err == nil {
		for _, ip := range ips {
			if isPrivateIP(ip) {
				return fmt.Errorf("webhook URL resolves to private/reserved IP %s", ip)
			}
		}
	}

	return nil
}

// isPrivateIP checks if an IP address is in a private or reserved range.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []struct {
		network *net.IPNet
	}{
		{parseCIDR("127.0.0.0/8")},
		{parseCIDR("10.0.0.0/8")},
		{parseCIDR("172.16.0.0/12")},
		{parseCIDR("192.168.0.0/16")},
		{parseCIDR("169.254.0.0/16")},
		{parseCIDR("0.0.0.0/8")},
		{parseCIDR("::1/128")},
		{parseCIDR("fd00::/8")},
		{parseCIDR("fe80::/10")},
	}

	for _, r := range privateRanges {
		if r.network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDR(cidr string) *net.IPNet {
	_, network, _ := net.ParseCIDR(cidr)
	return network
}

// sanitizeAlert returns a shallow copy of the alert with sensitive patterns
// masked in all free-text fields. This prevents secrets embedded in event data
// (e.g., leaked API keys in syslog messages) from being forwarded to external
// notification channels.
func sanitizeAlert(alert *Alert) *Alert {
	sanitized := *alert

	original := alert.Title + alert.Description + alert.GroupKey + strings.Join(alert.Tags, "")

	sanitized.Title = logging.MaskSensitivePatterns(sanitized.Title)
	sanitized.Description = logging.MaskSensitivePatterns(sanitized.Description)
	sanitized.GroupKey = logging.MaskSensitivePatterns(sanitized.GroupKey)

	if len(sanitized.Tags) > 0 {
		tags := make([]string, len(sanitized.Tags))
		for i, tag := range sanitized.Tags {
			tags[i] = logging.MaskSensitivePatterns(tag)
		}
		sanitized.Tags = tags
	}

	masked := sanitized.Title + sanitized.Description + sanitized.GroupKey + strings.Join(sanitized.Tags, "")
	if masked != original {
		slog.Warn("sensitive data masked in outbound alert",
			"alert_id", alert.ID.String(),
		)
	}

	return &sanitized
}

// WebhookChannel sends alerts via HTTP webhook.
type WebhookChannel struct {
	name    string
	url     string
	headers map[string]string
	client  *http.Client
}

// NewWebhookChannel creates a new webhook channel.
// Returns an error if the URL targets a private/reserved IP range (SSRF protection).
func NewWebhookChannel(name, rawURL string, headers map[string]string) (*WebhookChannel, error) {
	if err := validateWebhookURL(rawURL); err != nil {
		return nil, fmt.Errorf("invalid webhook URL: %w", err)
	}

	return &WebhookChannel{
		name:    name,
		url:     rawURL,
		headers: headers,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// NewWebhookChannelForTest creates a webhook channel without SSRF validation.
// Only for use in tests with httptest servers on localhost.
func NewWebhookChannelForTest(name, rawURL string, headers map[string]string) *WebhookChannel {
	return &WebhookChannel{
		name:    name,
		url:     rawURL,
		headers: headers,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (w *WebhookChannel) Name() string {
	return w.name
}

func (w *WebhookChannel) Send(ctx context.Context, alert *Alert) error {
	alert = sanitizeAlert(alert)
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", w.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// SlackChannel sends alerts to Slack.
type SlackChannel struct {
	webhookURL string
	channel    string
	username   string
	client     *http.Client
}

// NewSlackChannel creates a new Slack channel.
func NewSlackChannel(webhookURL, channel, username string) *SlackChannel {
	return &SlackChannel{
		webhookURL: webhookURL,
		channel:    channel,
		username:   username,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (s *SlackChannel) Name() string {
	return "slack"
}

func (s *SlackChannel) Send(ctx context.Context, alert *Alert) error {
	alert = sanitizeAlert(alert)
	color := s.severityColor(alert.Severity)

	payload := map[string]interface{}{
		"channel":  s.channel,
		"username": s.username,
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  fmt.Sprintf("[%s] %s", strings.ToUpper(string(alert.Severity)), escapeSlackText(alert.Title)),
				"text":   escapeSlackText(alert.Description),
				"fields": s.buildFields(alert),
				"footer": fmt.Sprintf("Alert ID: %s | Rule: %s", alert.ID.String()[:8], escapeSlackText(alert.RuleID)),
				"ts":     alert.CreatedAt.Unix(),
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.webhookURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("slack returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (s *SlackChannel) severityColor(sev correlation.Severity) string {
	switch sev {
	case correlation.SeverityCritical:
		return "#FF0000"
	case correlation.SeverityHigh:
		return "#FFA500"
	case correlation.SeverityMedium:
		return "#FFFF00"
	case correlation.SeverityLow:
		return "#00FF00"
	default:
		return "#808080"
	}
}

func (s *SlackChannel) buildFields(alert *Alert) []map[string]interface{} {
	fields := []map[string]interface{}{
		{"title": "Severity", "value": string(alert.Severity), "short": true},
		{"title": "Events", "value": fmt.Sprintf("%d", alert.EventCount), "short": true},
	}

	if alert.GroupKey != "" {
		fields = append(fields, map[string]interface{}{
			"title": "Group", "value": escapeSlackText(alert.GroupKey), "short": true,
		})
	}

	if len(alert.Tags) > 0 {
		escapedTags := make([]string, len(alert.Tags))
		for i, tag := range alert.Tags {
			escapedTags[i] = escapeSlackText(tag)
		}
		fields = append(fields, map[string]interface{}{
			"title": "Tags", "value": strings.Join(escapedTags, ", "), "short": false,
		})
	}

	if alert.MITRE != nil {
		fields = append(fields, map[string]interface{}{
			"title": "MITRE ATT&CK",
			"value": fmt.Sprintf("%s (%s)", escapeSlackText(alert.MITRE.TacticName), escapeSlackText(alert.MITRE.TechniqueID)),
			"short": false,
		})
	}

	return fields
}

// DiscordChannel sends alerts to Discord.
type DiscordChannel struct {
	webhookURL string
	username   string
	client     *http.Client
}

// NewDiscordChannel creates a new Discord channel.
func NewDiscordChannel(webhookURL, username string) *DiscordChannel {
	return &DiscordChannel{
		webhookURL: webhookURL,
		username:   username,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (d *DiscordChannel) Name() string {
	return "discord"
}

func (d *DiscordChannel) Send(ctx context.Context, alert *Alert) error {
	alert = sanitizeAlert(alert)
	color := d.severityColor(alert.Severity)

	payload := map[string]interface{}{
		"username": d.username,
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("[%s] %s", strings.ToUpper(string(alert.Severity)), sanitizeDiscordText(alert.Title)),
				"description": sanitizeDiscordText(alert.Description),
				"color":       color,
				"fields":      d.buildFields(alert),
				"footer": map[string]interface{}{
					"text": fmt.Sprintf("Alert ID: %s | Rule: %s", alert.ID.String()[:8], sanitizeDiscordText(alert.RuleID)),
				},
				"timestamp": alert.CreatedAt.Format(time.RFC3339),
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", d.webhookURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("discord returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (d *DiscordChannel) severityColor(sev correlation.Severity) int {
	switch sev {
	case correlation.SeverityCritical:
		return 0xFF0000
	case correlation.SeverityHigh:
		return 0xFFA500
	case correlation.SeverityMedium:
		return 0xFFFF00
	case correlation.SeverityLow:
		return 0x00FF00
	default:
		return 0x808080
	}
}

func (d *DiscordChannel) buildFields(alert *Alert) []map[string]interface{} {
	fields := []map[string]interface{}{
		{"name": "Severity", "value": string(alert.Severity), "inline": true},
		{"name": "Events", "value": fmt.Sprintf("%d", alert.EventCount), "inline": true},
	}

	if len(alert.Tags) > 0 {
		escapedTags := make([]string, len(alert.Tags))
		for i, tag := range alert.Tags {
			escapedTags[i] = sanitizeDiscordText(tag)
		}
		fields = append(fields, map[string]interface{}{
			"name": "Tags", "value": strings.Join(escapedTags, ", "), "inline": false,
		})
	}

	return fields
}

// PagerDutyChannel sends alerts to PagerDuty.
type PagerDutyChannel struct {
	routingKey string
	client     *http.Client
}

// NewPagerDutyChannel creates a new PagerDuty channel.
func NewPagerDutyChannel(routingKey string) *PagerDutyChannel {
	return &PagerDutyChannel{
		routingKey: routingKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (p *PagerDutyChannel) Name() string {
	return "pagerduty"
}

func (p *PagerDutyChannel) Send(ctx context.Context, alert *Alert) error {
	alert = sanitizeAlert(alert)
	severity := p.mapSeverity(alert.Severity)

	payload := map[string]interface{}{
		"routing_key":  p.routingKey,
		"event_action": "trigger",
		"dedup_key":    fmt.Sprintf("%s-%s", alert.RuleID, alert.GroupKey),
		"payload": map[string]interface{}{
			"summary":   alert.Title,
			"source":    "boundary-siem",
			"severity":  severity,
			"timestamp": alert.CreatedAt.Format(time.RFC3339),
			"custom_details": map[string]interface{}{
				"description": alert.Description,
				"rule_id":     alert.RuleID,
				"event_count": alert.EventCount,
				"tags":        alert.Tags,
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://events.pagerduty.com/v2/enqueue", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 202 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pagerduty returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (p *PagerDutyChannel) mapSeverity(sev correlation.Severity) string {
	switch sev {
	case correlation.SeverityCritical:
		return "critical"
	case correlation.SeverityHigh:
		return "error"
	case correlation.SeverityMedium:
		return "warning"
	case correlation.SeverityLow:
		return "info"
	default:
		return "info"
	}
}

// LogChannel logs alerts (for debugging/development).
type LogChannel struct {
	logger func(format string, args ...interface{})
}

// NewLogChannel creates a new log channel.
func NewLogChannel(logger func(format string, args ...interface{})) *LogChannel {
	return &LogChannel{logger: logger}
}

func (l *LogChannel) Name() string {
	return "log"
}

func (l *LogChannel) Send(ctx context.Context, alert *Alert) error {
	alert = sanitizeAlert(alert)
	// Use structured logging to prevent log injection via alert fields
	slog.Warn("ALERT",
		"severity", string(alert.Severity),
		"title", alert.Title,
		"description", alert.Description,
		"rule_id", alert.RuleID,
		"event_count", alert.EventCount,
		"tags", alert.Tags,
	)
	// Also call the configured logger for backward compatibility
	if l.logger != nil {
		l.logger("ALERT [%s] %s - %s (rule=%s, events=%d)",
			alert.Severity, alert.Title, alert.Description,
			alert.RuleID, alert.EventCount)
	}
	return nil
}

// EmailConfig configures email notifications.
type EmailConfig struct {
	SMTPHost    string
	SMTPPort    int
	Username    string
	Password    string
	From        string
	To          []string
	UseTLS      bool
	UseSTARTTLS bool
}

// EmailChannel sends alerts via SMTP email.
type EmailChannel struct {
	config  *EmailConfig
	timeout time.Duration
}

// NewEmailChannel creates a new email channel.
func NewEmailChannel(config *EmailConfig) *EmailChannel {
	if config.SMTPPort == 0 {
		if config.UseTLS {
			config.SMTPPort = 465 // SMTPS
		} else {
			config.SMTPPort = 587 // Submission with STARTTLS
		}
	}
	return &EmailChannel{
		config:  config,
		timeout: 30 * time.Second,
	}
}

func (e *EmailChannel) Name() string {
	return "email"
}

func (e *EmailChannel) Send(ctx context.Context, alert *Alert) error {
	alert = sanitizeAlert(alert)
	// Build email content
	subject := fmt.Sprintf("[%s] %s", strings.ToUpper(string(alert.Severity)), alert.Title)
	htmlBody := e.buildHTMLBody(alert)
	textBody := e.buildTextBody(alert)

	// Build MIME message
	msg := e.buildMIMEMessage(subject, textBody, htmlBody)

	// Send via SMTP
	return e.sendMail(ctx, msg)
}

func (e *EmailChannel) sendMail(ctx context.Context, msg []byte) error {
	addr := fmt.Sprintf("%s:%d", e.config.SMTPHost, e.config.SMTPPort)

	// Create connection with timeout
	dialer := &net.Dialer{Timeout: e.timeout}

	var conn net.Conn
	var err error

	if e.config.UseTLS {
		// Direct TLS connection (SMTPS on port 465)
		tlsConfig := &tls.Config{
			ServerName: e.config.SMTPHost,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, e.config.SMTPHost)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	// STARTTLS if requested and not already using TLS
	if e.config.UseSTARTTLS && !e.config.UseTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{
				ServerName: e.config.SMTPHost,
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("STARTTLS failed: %w", err)
			}
		}
	}

	// Authenticate if credentials provided
	if e.config.Username != "" && e.config.Password != "" {
		auth := smtp.PlainAuth("", e.config.Username, e.config.Password, e.config.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	// Set sender
	if err := client.Mail(e.config.From); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	// Set recipients
	for _, to := range e.config.To {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("RCPT TO failed for %s: %w", to, err)
		}
	}

	// Send message body
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}

	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close message: %w", err)
	}

	return client.Quit()
}

func (e *EmailChannel) buildMIMEMessage(subject, textBody, htmlBody string) []byte {
	var buf bytes.Buffer
	boundary := "boundary-siem-alert-" + fmt.Sprintf("%d", time.Now().UnixNano())

	// Headers
	buf.WriteString(fmt.Sprintf("From: %s\r\n", e.config.From))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(e.config.To, ", ")))
	buf.WriteString(fmt.Sprintf("Subject: =?UTF-8?B?%s?=\r\n", base64.StdEncoding.EncodeToString([]byte(subject))))
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
	buf.WriteString("\r\n")

	// Plain text part
	buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	buf.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(textBody)
	buf.WriteString("\r\n")

	// HTML part
	buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	buf.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	buf.WriteString("\r\n")
	buf.WriteString(htmlBody)
	buf.WriteString("\r\n")

	// End boundary
	buf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	return buf.Bytes()
}

func (e *EmailChannel) buildTextBody(alert *Alert) string {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("SECURITY ALERT: %s\n", alert.Title))
	buf.WriteString(fmt.Sprintf("Severity: %s\n", strings.ToUpper(string(alert.Severity))))
	buf.WriteString(fmt.Sprintf("Time: %s\n", alert.CreatedAt.Format("2006-01-02 15:04:05 UTC")))
	buf.WriteString("\n")
	buf.WriteString(fmt.Sprintf("Description:\n%s\n", alert.Description))
	buf.WriteString("\n")
	buf.WriteString("Details:\n")
	buf.WriteString(fmt.Sprintf("  - Alert ID: %s\n", alert.ID.String()))
	buf.WriteString(fmt.Sprintf("  - Rule ID: %s\n", alert.RuleID))
	buf.WriteString(fmt.Sprintf("  - Event Count: %d\n", alert.EventCount))

	if alert.GroupKey != "" {
		buf.WriteString(fmt.Sprintf("  - Group Key: %s\n", alert.GroupKey))
	}

	if len(alert.Tags) > 0 {
		buf.WriteString(fmt.Sprintf("  - Tags: %s\n", strings.Join(alert.Tags, ", ")))
	}

	if alert.MITRE != nil {
		buf.WriteString("\n")
		buf.WriteString("MITRE ATT&CK:\n")
		buf.WriteString(fmt.Sprintf("  - Tactic: %s (%s)\n", alert.MITRE.TacticName, alert.MITRE.TacticID))
		buf.WriteString(fmt.Sprintf("  - Technique: %s\n", alert.MITRE.TechniqueID))
		if len(alert.MITRE.Techniques) > 0 {
			buf.WriteString(fmt.Sprintf("  - Related Techniques: %s\n", strings.Join(alert.MITRE.Techniques, ", ")))
		}
	}

	buf.WriteString("\n---\n")
	buf.WriteString("This alert was generated by Boundary SIEM.\n")

	return buf.String()
}

func (e *EmailChannel) buildHTMLBody(alert *Alert) string {
	severityColor := e.severityColor(alert.Severity)
	severityBgColor := e.severityBgColor(alert.Severity)

	// HTML-escape all user-controlled alert fields to prevent HTML injection
	safeTitle := html.EscapeString(alert.Title)
	safeDescription := html.EscapeString(alert.Description)
	safeRuleID := html.EscapeString(alert.RuleID)

	var mitreSection string
	if alert.MITRE != nil {
		techniquesRow := ""
		if len(alert.MITRE.Techniques) > 0 {
			safeTechniques := make([]string, len(alert.MITRE.Techniques))
			for i, t := range alert.MITRE.Techniques {
				safeTechniques[i] = html.EscapeString(t)
			}
			techniquesRow = fmt.Sprintf(`
					<tr>
						<td style="padding: 5px 0; color: #6c757d;">Related:</td>
						<td style="padding: 5px 0; color: #212529;">%s</td>
					</tr>`, strings.Join(safeTechniques, ", "))
		}
		mitreSection = fmt.Sprintf(`
		<tr>
			<td colspan="2" style="padding: 15px; background-color: #f8f9fa; border-bottom: 1px solid #e9ecef;">
				<h3 style="margin: 0 0 10px 0; color: #495057; font-size: 14px;">MITRE ATT&CK</h3>
				<table style="width: 100%%; border-collapse: collapse;">
					<tr>
						<td style="padding: 5px 0; color: #6c757d;">Tactic:</td>
						<td style="padding: 5px 0; color: #212529;">%s (%s)</td>
					</tr>
					<tr>
						<td style="padding: 5px 0; color: #6c757d;">Technique:</td>
						<td style="padding: 5px 0; color: #212529;">%s</td>
					</tr>
					%s
				</table>
			</td>
		</tr>`, html.EscapeString(alert.MITRE.TacticName), html.EscapeString(alert.MITRE.TacticID),
			html.EscapeString(alert.MITRE.TechniqueID), techniquesRow)
	}

	var tagsSection string
	if len(alert.Tags) > 0 {
		var tagBadges []string
		for _, tag := range alert.Tags {
			tagBadges = append(tagBadges, fmt.Sprintf(
				`<span style="display: inline-block; padding: 2px 8px; margin: 2px; background-color: #e9ecef; border-radius: 3px; font-size: 12px;">%s</span>`,
				html.EscapeString(tag)))
		}
		tagsSection = fmt.Sprintf(`
		<tr>
			<td style="padding: 8px 15px; color: #6c757d; width: 120px;">Tags:</td>
			<td style="padding: 8px 15px;">%s</td>
		</tr>`, strings.Join(tagBadges, ""))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
	<table width="100%%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: 20px auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
		<!-- Header -->
		<tr>
			<td style="background-color: %s; padding: 20px; border-radius: 8px 8px 0 0;">
				<table width="100%%" cellpadding="0" cellspacing="0">
					<tr>
						<td>
							<span style="display: inline-block; padding: 4px 12px; background-color: %s; color: %s; border-radius: 4px; font-weight: bold; font-size: 12px; text-transform: uppercase;">%s</span>
						</td>
					</tr>
					<tr>
						<td style="padding-top: 10px;">
							<h1 style="margin: 0; color: #ffffff; font-size: 20px; font-weight: 600;">%s</h1>
						</td>
					</tr>
				</table>
			</td>
		</tr>

		<!-- Description -->
		<tr>
			<td style="padding: 20px; border-bottom: 1px solid #e9ecef;">
				<p style="margin: 0; color: #495057; font-size: 14px; line-height: 1.6;">%s</p>
			</td>
		</tr>

		<!-- Details -->
		<tr>
			<td style="padding: 0;">
				<table width="100%%" cellpadding="0" cellspacing="0" style="border-collapse: collapse;">
					<tr>
						<td style="padding: 8px 15px; color: #6c757d; width: 120px; border-bottom: 1px solid #e9ecef;">Alert ID:</td>
						<td style="padding: 8px 15px; color: #212529; border-bottom: 1px solid #e9ecef; font-family: monospace; font-size: 12px;">%s</td>
					</tr>
					<tr>
						<td style="padding: 8px 15px; color: #6c757d; border-bottom: 1px solid #e9ecef;">Rule ID:</td>
						<td style="padding: 8px 15px; color: #212529; border-bottom: 1px solid #e9ecef;">%s</td>
					</tr>
					<tr>
						<td style="padding: 8px 15px; color: #6c757d; border-bottom: 1px solid #e9ecef;">Time:</td>
						<td style="padding: 8px 15px; color: #212529; border-bottom: 1px solid #e9ecef;">%s</td>
					</tr>
					<tr>
						<td style="padding: 8px 15px; color: #6c757d; border-bottom: 1px solid #e9ecef;">Event Count:</td>
						<td style="padding: 8px 15px; color: #212529; border-bottom: 1px solid #e9ecef;">%d</td>
					</tr>
					%s
				</table>
			</td>
		</tr>

		%s

		<!-- Footer -->
		<tr>
			<td style="padding: 15px; background-color: #f8f9fa; border-radius: 0 0 8px 8px; text-align: center;">
				<p style="margin: 0; color: #6c757d; font-size: 12px;">This alert was generated by Boundary SIEM</p>
			</td>
		</tr>
	</table>
</body>
</html>`,
		severityColor,
		severityBgColor, severityColor, html.EscapeString(string(alert.Severity)),
		safeTitle,
		safeDescription,
		alert.ID.String(),
		safeRuleID,
		alert.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
		alert.EventCount,
		tagsSection,
		mitreSection,
	)
}

func (e *EmailChannel) severityColor(sev correlation.Severity) string {
	switch sev {
	case correlation.SeverityCritical:
		return "#dc3545" // Red
	case correlation.SeverityHigh:
		return "#fd7e14" // Orange
	case correlation.SeverityMedium:
		return "#ffc107" // Yellow
	case correlation.SeverityLow:
		return "#28a745" // Green
	default:
		return "#6c757d" // Gray
	}
}

func (e *EmailChannel) severityBgColor(sev correlation.Severity) string {
	switch sev {
	case correlation.SeverityCritical:
		return "#fff5f5"
	case correlation.SeverityHigh:
		return "#fff8f0"
	case correlation.SeverityMedium:
		return "#fffdf0"
	case correlation.SeverityLow:
		return "#f0fff4"
	default:
		return "#f8f9fa"
	}
}

// TelegramChannel sends alerts to Telegram.
type TelegramChannel struct {
	botToken string
	chatID   string
	client   *http.Client
}

// NewTelegramChannel creates a new Telegram channel.
func NewTelegramChannel(botToken, chatID string) *TelegramChannel {
	return &TelegramChannel{
		botToken: botToken,
		chatID:   chatID,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (t *TelegramChannel) Name() string {
	return "telegram"
}

func (t *TelegramChannel) Send(ctx context.Context, alert *Alert) error {
	alert = sanitizeAlert(alert)
	emoji := t.severityEmoji(alert.Severity)
	text := fmt.Sprintf(`%s *[%s] %s*

%s

*Rule:* %s
*Events:* %d
*Time:* %s`,
		emoji,
		strings.ToUpper(string(alert.Severity)),
		escapeMarkdown(alert.Title),
		escapeMarkdown(alert.Description),
		escapeMarkdown(alert.RuleID),
		alert.EventCount,
		alert.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
	)

	if len(alert.Tags) > 0 {
		escapedTags := make([]string, len(alert.Tags))
		for i, tag := range alert.Tags {
			escapedTags[i] = escapeMarkdown(tag)
		}
		text += fmt.Sprintf("\n*Tags:* %s", strings.Join(escapedTags, ", "))
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)
	payload := map[string]interface{}{
		"chat_id":    t.chatID,
		"text":       text,
		"parse_mode": "MarkdownV2",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("telegram returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (t *TelegramChannel) severityEmoji(sev correlation.Severity) string {
	switch sev {
	case correlation.SeverityCritical:
		return "🔴"
	case correlation.SeverityHigh:
		return "🟠"
	case correlation.SeverityMedium:
		return "🟡"
	case correlation.SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"(", "\\(",
		")", "\\)",
		"~", "\\~",
		"`", "\\`",
		">", "\\>",
		"#", "\\#",
		"+", "\\+",
		"-", "\\-",
		"=", "\\=",
		"|", "\\|",
		"{", "\\{",
		"}", "\\}",
		".", "\\.",
		"!", "\\!",
	)
	return replacer.Replace(s)
}

// escapeSlackText neutralizes Slack mrkdwn injection by escaping angle brackets
// (which Slack interprets as links/mentions) and ampersands.
func escapeSlackText(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// sanitizeDiscordText strips Discord-specific injection patterns like
// @everyone/@here pings that could be abused via attacker-crafted event data.
func sanitizeDiscordText(s string) string {
	s = strings.ReplaceAll(s, "@everyone", "@\u200beveryone")
	s = strings.ReplaceAll(s, "@here", "@\u200bhere")
	return s
}

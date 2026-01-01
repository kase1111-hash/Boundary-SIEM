package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"boundary-siem/internal/correlation"
)

// WebhookChannel sends alerts via HTTP webhook.
type WebhookChannel struct {
	name    string
	url     string
	headers map[string]string
	client  *http.Client
}

// NewWebhookChannel creates a new webhook channel.
func NewWebhookChannel(name, url string, headers map[string]string) *WebhookChannel {
	return &WebhookChannel{
		name:    name,
		url:     url,
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
	color := s.severityColor(alert.Severity)

	payload := map[string]interface{}{
		"channel":  s.channel,
		"username": s.username,
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  fmt.Sprintf("[%s] %s", strings.ToUpper(string(alert.Severity)), alert.Title),
				"text":   alert.Description,
				"fields": s.buildFields(alert),
				"footer": fmt.Sprintf("Alert ID: %s | Rule: %s", alert.ID.String()[:8], alert.RuleID),
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
			"title": "Group", "value": alert.GroupKey, "short": true,
		})
	}

	if len(alert.Tags) > 0 {
		fields = append(fields, map[string]interface{}{
			"title": "Tags", "value": strings.Join(alert.Tags, ", "), "short": false,
		})
	}

	if alert.MITRE != nil {
		fields = append(fields, map[string]interface{}{
			"title": "MITRE ATT&CK",
			"value": fmt.Sprintf("%s (%s)", alert.MITRE.TacticName, alert.MITRE.TechniqueID),
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
	color := d.severityColor(alert.Severity)

	payload := map[string]interface{}{
		"username": d.username,
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("[%s] %s", strings.ToUpper(string(alert.Severity)), alert.Title),
				"description": alert.Description,
				"color":       color,
				"fields":      d.buildFields(alert),
				"footer": map[string]interface{}{
					"text": fmt.Sprintf("Alert ID: %s | Rule: %s", alert.ID.String()[:8], alert.RuleID),
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
		fields = append(fields, map[string]interface{}{
			"name": "Tags", "value": strings.Join(alert.Tags, ", "), "inline": false,
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
	l.logger("ALERT [%s] %s - %s (rule=%s, events=%d, tags=%v)",
		alert.Severity, alert.Title, alert.Description,
		alert.RuleID, alert.EventCount, alert.Tags)
	return nil
}

// EmailConfig configures email notifications.
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	Username     string
	Password     string
	From         string
	To           []string
	UseTLS       bool
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
		text += fmt.Sprintf("\n*Tags:* %s", strings.Join(alert.Tags, ", "))
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.botToken)
	payload := map[string]interface{}{
		"chat_id":    t.chatID,
		"text":       text,
		"parse_mode": "Markdown",
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

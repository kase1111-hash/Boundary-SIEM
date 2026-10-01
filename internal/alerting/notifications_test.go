package alerting

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func boolPtr(b bool) *bool { return &b }

// TestSetupNotifications is a regression test for siem-ingest running with no
// notification channels at all: nothing could build channels from config, so
// the manager had zero channels and every built-in escalation (which targets
// the "default" channel) logged "escalation channel not found".
func TestSetupNotifications(t *testing.T) {
	const publicURL = "https://203.0.113.10/hook" // TEST-NET-3: public, no DNS lookup

	tests := []struct {
		name           string
		cfg            NotificationsConfig
		wantManager    []string // channel names that receive every alert
		wantEscalation []string // channel names escalation policies can target
		wantTypes      map[string]string
		wantErr        string
	}{
		{
			name:           "empty config falls back to a default log channel",
			cfg:            NotificationsConfig{},
			wantManager:    []string{"default"},
			wantEscalation: []string{"default"},
			wantTypes:      map[string]string{"default": "log"},
		},
		{
			name: "named channels, escalation-only and fallback default",
			cfg: NotificationsConfig{Channels: []ChannelConfig{
				{Name: "audit", Type: "log"},
				{Name: "oncall", Type: "pagerduty", RoutingKey: "rk", EscalationOnly: true},
				{Type: "telegram", BotToken: "t", ChatID: "c"},
			}},
			wantManager:    []string{"audit", "default", "telegram"},
			wantEscalation: []string{"audit", "default", "oncall", "telegram"},
			wantTypes:      map[string]string{"audit": "log", "oncall": "pagerduty", "telegram": "telegram", "default": "log"},
		},
		{
			name: "configured default channel is used instead of the fallback",
			cfg: NotificationsConfig{Channels: []ChannelConfig{
				{Name: "default", Type: "slack", URL: publicURL, Channel: "#soc"},
				{Name: "chat", Type: "discord", URL: publicURL},
				{Name: "mail", Type: "email", Email: &EmailConfig{SMTPHost: "smtp.example.com", From: "siem@example.com", To: []string{"soc@example.com"}}},
				{Name: "hook", Type: "webhook", URL: publicURL, Headers: map[string]string{"X-Token": "x"}},
			}},
			wantManager:    []string{"chat", "default", "hook", "mail"},
			wantEscalation: []string{"chat", "default", "hook", "mail"},
			wantTypes:      map[string]string{"default": "slack", "chat": "discord", "mail": "email", "hook": "webhook"},
		},
		{
			name: "disabled channels are skipped",
			cfg: NotificationsConfig{Channels: []ChannelConfig{
				{Name: "default", Type: "log", Enabled: boolPtr(false)},
				{Name: "on", Type: "log", Enabled: boolPtr(true)},
			}},
			wantManager:    []string{"default", "on"},
			wantEscalation: []string{"default", "on"},
			wantTypes:      map[string]string{"on": "log", "default": "log"},
		},
		{name: "unknown type", cfg: NotificationsConfig{Channels: []ChannelConfig{{Name: "x", Type: "carrier-pigeon"}}}, wantErr: "unknown type"},
		{name: "missing type", cfg: NotificationsConfig{Channels: []ChannelConfig{{Name: "x"}}}, wantErr: "type is required"},
		{name: "duplicate names", cfg: NotificationsConfig{Channels: []ChannelConfig{{Name: "a", Type: "log"}, {Name: "a", Type: "log"}}}, wantErr: "duplicate"},
		{name: "slack without url", cfg: NotificationsConfig{Channels: []ChannelConfig{{Type: "slack"}}}, wantErr: "url is required"},
		{name: "discord bad scheme", cfg: NotificationsConfig{Channels: []ChannelConfig{{Type: "discord", URL: "ftp://203.0.113.10/x"}}}, wantErr: "unsupported scheme"},
		{name: "webhook to private address", cfg: NotificationsConfig{Channels: []ChannelConfig{{Type: "webhook", URL: "http://127.0.0.1:8080/x"}}}, wantErr: "private"},
		{name: "pagerduty without routing key", cfg: NotificationsConfig{Channels: []ChannelConfig{{Type: "pagerduty"}}}, wantErr: "routing_key is required"},
		{name: "telegram without chat id", cfg: NotificationsConfig{Channels: []ChannelConfig{{Type: "telegram", BotToken: "t"}}}, wantErr: "chat_id are required"},
		{name: "email without recipients", cfg: NotificationsConfig{Channels: []ChannelConfig{{Type: "email", Email: &EmailConfig{SMTPHost: "h", From: "f@example.com"}}}}, wantErr: "email.to"},
		{name: "email without section", cfg: NotificationsConfig{Channels: []ChannelConfig{{Type: "email"}}}, wantErr: "email.smtp_host"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := NewManager(DefaultManagerConfig(), nil)
			esc := NewEscalationEngine(mgr)

			names, err := SetupNotifications(tt.cfg, mgr, esc)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				if n := mgr.Stats()["channels"].(int); n != 0 {
					t.Errorf("a failed setup registered %d manager channels", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("SetupNotifications: %v", err)
			}

			var mgrNames []string
			for _, ch := range mgr.channels {
				mgrNames = append(mgrNames, ch.Name())
			}
			sort.Strings(mgrNames)
			if !slices.Equal(mgrNames, tt.wantManager) {
				t.Errorf("manager channels = %v, want %v", mgrNames, tt.wantManager)
			}

			var escNames []string
			for name, ch := range esc.channels {
				if ch.Name() != name {
					t.Errorf("escalation channel registered as %q reports Name() %q", name, ch.Name())
				}
				escNames = append(escNames, name)
			}
			sort.Strings(escNames)
			if !slices.Equal(escNames, tt.wantEscalation) {
				t.Errorf("escalation channels = %v, want %v", escNames, tt.wantEscalation)
			}
			sort.Strings(names)
			if !slices.Equal(names, tt.wantEscalation) {
				t.Errorf("returned names = %v, want %v", names, tt.wantEscalation)
			}

			for name, wantType := range tt.wantTypes {
				ch, ok := esc.channels[name]
				if !ok {
					t.Errorf("channel %q not registered", name)
					continue
				}
				if got := channelType(ch); got != wantType {
					t.Errorf("channel %q has type %q, want %q", name, got, wantType)
				}
			}

			// Every built-in escalation policy must find its target channels.
			for _, p := range BuiltinEscalationPolicies() {
				for _, r := range p.Rules {
					for _, target := range r.Channels {
						if _, ok := esc.channels[target]; !ok {
							t.Errorf("built-in policy %s targets unregistered channel %q", p.ID, target)
						}
					}
				}
			}
		})
	}
}

// channelType reports the underlying channel type of a configured channel.
func channelType(ch NotificationChannel) string {
	if n, ok := ch.(*namedChannel); ok {
		ch = n.NotificationChannel
	}
	switch ch.(type) {
	case *LogChannel:
		return "log"
	case *WebhookChannel:
		return "webhook"
	case *SlackChannel:
		return "slack"
	case *DiscordChannel:
		return "discord"
	case *PagerDutyChannel:
		return "pagerduty"
	case *EmailChannel:
		return "email"
	case *TelegramChannel:
		return "telegram"
	}
	return "unknown"
}

func TestNotificationsConfigYAML(t *testing.T) {
	const doc = `
channels:
  - name: default
    type: slack
    url: https://203.0.113.10/hook
    channel: "#soc"
    username: boundary-siem
  - name: oncall
    type: pagerduty
    routing_key: abc123
    escalation_only: true
  - name: mail
    type: email
    enabled: false
    email:
      smtp_host: smtp.example.com
      smtp_port: 587
      username: siem
      password: secret
      from: siem@example.com
      to: [soc@example.com]
      use_starttls: true
`
	var cfg NotificationsConfig
	if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.Channels) != 3 {
		t.Fatalf("expected 3 channels, got %d", len(cfg.Channels))
	}
	slack, pd, mail := cfg.Channels[0], cfg.Channels[1], cfg.Channels[2]
	if slack.Name != "default" || slack.Type != "slack" || slack.URL == "" || slack.Channel != "#soc" || slack.Username != "boundary-siem" {
		t.Errorf("slack channel parsed wrong: %+v", slack)
	}
	if pd.RoutingKey != "abc123" || !pd.EscalationOnly {
		t.Errorf("pagerduty channel parsed wrong: %+v", pd)
	}
	if mail.Enabled == nil || *mail.Enabled || mail.Email == nil {
		t.Fatalf("email channel parsed wrong: %+v", mail)
	}
	e := mail.Email
	if e.SMTPHost != "smtp.example.com" || e.SMTPPort != 587 || e.Username != "siem" || e.Password != "secret" ||
		e.From != "siem@example.com" || !slices.Equal(e.To, []string{"soc@example.com"}) || !e.UseSTARTTLS || e.UseTLS {
		t.Errorf("email settings parsed wrong: %+v", e)
	}
}

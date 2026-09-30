package alerting

import (
	"errors"
	"fmt"
	"strings"
)

// Notification channel types accepted in ChannelConfig.Type.
const (
	ChannelTypeLog       = "log"
	ChannelTypeWebhook   = "webhook"
	ChannelTypeSlack     = "slack"
	ChannelTypeDiscord   = "discord"
	ChannelTypePagerDuty = "pagerduty"
	ChannelTypeEmail     = "email"
	ChannelTypeTelegram  = "telegram"
)

// DefaultChannelName is the channel the built-in escalation policies notify.
const DefaultChannelName = "default"

// NotificationsConfig configures alert notification channels. It is meant to
// be loaded from the service configuration, for example:
//
//	notifications:
//	  channels:
//	    - name: default            # escalation policies address channels by name
//	      type: slack
//	      url: https://hooks.slack.com/services/...
//	      channel: "#soc"
//	    - name: oncall
//	      type: pagerduty
//	      routing_key: <routing key>
//	      escalation_only: true    # only notified by escalation policies
type NotificationsConfig struct {
	Channels []ChannelConfig `yaml:"channels"`
}

// ChannelConfig configures one notification channel. Which fields are used
// depends on Type.
type ChannelConfig struct {
	// Name identifies the channel; escalation policies refer to it. Defaults
	// to Type. Names must be unique.
	Name string `yaml:"name"`
	// Type is one of the ChannelType* constants.
	Type string `yaml:"type"`
	// Enabled defaults to true.
	Enabled *bool `yaml:"enabled,omitempty"`
	// EscalationOnly channels are only notified by escalation policies, not
	// for every new alert.
	EscalationOnly bool `yaml:"escalation_only,omitempty"`

	URL        string            `yaml:"url,omitempty"`         // webhook, slack, discord
	Headers    map[string]string `yaml:"headers,omitempty"`     // webhook
	Channel    string            `yaml:"channel,omitempty"`     // slack
	Username   string            `yaml:"username,omitempty"`    // slack, discord
	RoutingKey string            `yaml:"routing_key,omitempty"` // pagerduty
	BotToken   string            `yaml:"bot_token,omitempty"`   // telegram
	ChatID     string            `yaml:"chat_id,omitempty"`     // telegram
	Email      *EmailConfig      `yaml:"email,omitempty"`       // email
}

func (c ChannelConfig) enabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// namedChannel gives a channel the name it was configured with. The
// built-in channel types report fixed names ("slack", "log", ...), but
// escalation policies address channels by their configured name.
type namedChannel struct {
	NotificationChannel
	name string
}

func (c *namedChannel) Name() string { return c.name }

type builtChannel struct {
	channel        NotificationChannel
	escalationOnly bool
}

// buildChannel constructs one channel from its configuration.
func buildChannel(cfg ChannelConfig) (NotificationChannel, error) {
	switch strings.ToLower(cfg.Type) {
	case ChannelTypeLog:
		return NewLogChannel(nil), nil
	case ChannelTypeWebhook:
		if cfg.URL == "" {
			return nil, errors.New("url is required")
		}
		return NewWebhookChannel(cfg.Name, cfg.URL, cfg.Headers)
	case ChannelTypeSlack, ChannelTypeDiscord:
		if cfg.URL == "" {
			return nil, errors.New("url is required")
		}
		if err := validateWebhookURL(cfg.URL); err != nil {
			return nil, fmt.Errorf("invalid url: %w", err)
		}
		if strings.EqualFold(cfg.Type, ChannelTypeSlack) {
			return NewSlackChannel(cfg.URL, cfg.Channel, cfg.Username), nil
		}
		return NewDiscordChannel(cfg.URL, cfg.Username), nil
	case ChannelTypePagerDuty:
		if cfg.RoutingKey == "" {
			return nil, errors.New("routing_key is required")
		}
		return NewPagerDutyChannel(cfg.RoutingKey), nil
	case ChannelTypeEmail:
		if cfg.Email == nil || cfg.Email.SMTPHost == "" || cfg.Email.From == "" {
			return nil, errors.New("email.smtp_host and email.from are required")
		}
		if len(cfg.Email.To) == 0 {
			return nil, errors.New("email.to must list at least one recipient")
		}
		emailCfg := *cfg.Email
		emailCfg.To = append([]string(nil), cfg.Email.To...)
		return NewEmailChannel(&emailCfg), nil
	case ChannelTypeTelegram:
		if cfg.BotToken == "" || cfg.ChatID == "" {
			return nil, errors.New("bot_token and chat_id are required")
		}
		return NewTelegramChannel(cfg.BotToken, cfg.ChatID), nil
	case "":
		return nil, errors.New("type is required")
	default:
		return nil, fmt.Errorf("unknown type %q", cfg.Type)
	}
}

// buildChannels constructs every enabled channel in cfg, in order. If no
// enabled channel is named DefaultChannelName, a log channel with that name
// is appended so the built-in escalation policies always have a target and
// every alert is at least logged.
func buildChannels(cfg NotificationsConfig) ([]builtChannel, error) {
	seen := make(map[string]bool)
	var built []builtChannel
	for i, cc := range cfg.Channels {
		if cc.Name == "" {
			cc.Name = strings.ToLower(cc.Type)
		}
		if !cc.enabled() {
			continue
		}
		if seen[cc.Name] {
			return nil, fmt.Errorf("notification channel %d: duplicate name %q", i, cc.Name)
		}
		seen[cc.Name] = true

		ch, err := buildChannel(cc)
		if err != nil {
			return nil, fmt.Errorf("notification channel %d (%q): %w", i, cc.Name, err)
		}
		built = append(built, builtChannel{
			channel:        &namedChannel{NotificationChannel: ch, name: cc.Name},
			escalationOnly: cc.EscalationOnly,
		})
	}
	if !seen[DefaultChannelName] {
		built = append(built, builtChannel{
			channel: &namedChannel{NotificationChannel: NewLogChannel(nil), name: DefaultChannelName},
		})
	}
	return built, nil
}

// SetupNotifications builds the channels described by cfg and registers
// them: every channel with the escalation engine (when esc is non-nil) under
// its configured name, and every channel not marked escalation_only with the
// manager, so it is notified of each new alert. See buildChannels for the
// fallback "default" channel. Nothing is registered if the configuration is
// invalid. It returns the names of the registered channels.
func SetupNotifications(cfg NotificationsConfig, mgr *Manager, esc *EscalationEngine) ([]string, error) {
	built, err := buildChannels(cfg)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(built))
	for _, b := range built {
		if !b.escalationOnly && mgr != nil {
			mgr.AddChannel(b.channel)
		}
		if esc != nil {
			esc.RegisterChannel(b.channel)
		}
		names = append(names, b.channel.Name())
	}
	return names, nil
}

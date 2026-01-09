// Package scenes provides TUI scenes for Boundary-SIEM
package scenes

import (
	"fmt"
	"strings"
	"time"

	"boundary-siem/internal/tui/api"
	"boundary-siem/internal/tui/styles"

	tea "github.com/charmbracelet/bubbletea"
)

// SystemScene displays system configuration and status
type SystemScene struct {
	client     *api.Client
	stats      *api.Stats
	err        error
	width      int
	height     int
	lastUpdate time.Time
	loading    bool
}

// NewSystemScene creates a new system info scene
func NewSystemScene(client *api.Client) *SystemScene {
	return &SystemScene{
		client:  client,
		loading: true,
		stats: &api.Stats{
			Healthy: false,
		},
	}
}

// Init initializes the system scene
func (s *SystemScene) Init() tea.Cmd {
	return s.fetchStats()
}

// fetchStats fetches stats from the API
func (s *SystemScene) fetchStats() tea.Cmd {
	return func() tea.Msg {
		stats, err := s.client.GetStats()
		return systemMsg{stats: stats, err: err}
	}
}

// systemMsg carries updated system stats
type systemMsg struct {
	stats *api.Stats
	err   error
}

// TickCmd returns a command that ticks every interval
func (s *SystemScene) TickCmd() tea.Cmd {
	return tea.Tick(10*time.Second, func(t time.Time) tea.Msg {
		return TickMsg{Scene: "system", Time: t}
	})
}

// Update handles messages for the system scene
func (s *SystemScene) Update(msg tea.Msg) (*SystemScene, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		s.width = msg.Width
		s.height = msg.Height
		return s, nil

	case systemMsg:
		s.loading = false
		s.stats = msg.stats
		s.err = msg.err
		s.lastUpdate = time.Now()
		return s, nil

	case TickMsg:
		if msg.Scene == "system" {
			return s, s.fetchStats()
		}
		return s, nil
	}

	return s, nil
}

// View renders the system info scene
func (s *SystemScene) View() string {
	var b strings.Builder

	// Title
	title := styles.Title.Render("  System Information")
	b.WriteString(title)
	b.WriteString("\n\n")

	if s.loading {
		b.WriteString(styles.Muted.Render("Loading system information..."))
		return b.String()
	}

	if s.err != nil {
		b.WriteString(styles.StatusError.Render(fmt.Sprintf("Error: %v", s.err)))
		b.WriteString("\n\n")
	}

	// Connection Status
	b.WriteString(styles.Subtitle.Render("  Backend Connection"))
	b.WriteString("\n")
	if s.stats.Healthy {
		b.WriteString(fmt.Sprintf("  %s Connected to backend\n", styles.StatusOK.Render("●")))
		b.WriteString(fmt.Sprintf("  %s Status: %s\n", styles.Muted.Render("├"), s.stats.HealthStatus))
		b.WriteString(fmt.Sprintf("  %s Uptime: %s\n", styles.Muted.Render("└"), s.stats.Uptime))
	} else {
		b.WriteString(fmt.Sprintf("  %s Not connected\n", styles.StatusError.Render("●")))
		b.WriteString(fmt.Sprintf("  %s Reason: %s\n", styles.Muted.Render("└"), s.stats.StatusReason))
	}
	b.WriteString("\n")

	// Server Endpoints
	b.WriteString(styles.Subtitle.Render("  Server Endpoints"))
	b.WriteString("\n")
	endpoints := []struct {
		name    string
		port    string
		enabled bool
		note    string
	}{
		{"HTTP API", "8080", true, "REST API & Health checks"},
		{"CEF TCP", "5515", true, "Secure CEF ingestion"},
		{"CEF UDP", "5514", false, "Disabled (insecure)"},
		{"CEF DTLS", "5516", false, "Encrypted UDP (configure certs)"},
	}
	for _, ep := range endpoints {
		var status string
		if ep.enabled {
			status = styles.StatusOK.Render("●")
		} else {
			status = styles.Muted.Render("○")
		}
		note := ""
		if ep.note != "" {
			note = styles.Muted.Render(" - " + ep.note)
		}
		b.WriteString(fmt.Sprintf("  %s %-12s Port %-6s%s\n", status, ep.name, ep.port, note))
	}
	b.WriteString("\n")

	// Queue Configuration
	b.WriteString(styles.Subtitle.Render("  Queue Configuration"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  Capacity:       %s\n", styles.MetricValue.Render(fmt.Sprintf("%d", s.stats.QueueCapacity))))
	b.WriteString(fmt.Sprintf("  Current Depth:  %s\n", styles.MetricValue.Render(fmt.Sprintf("%d", s.stats.QueueSize))))
	usageColor := styles.StatusOK
	if s.stats.QueueUsage >= 90 {
		usageColor = styles.StatusError
	} else if s.stats.QueueUsage >= 70 {
		usageColor = styles.StatusWarning
	}
	b.WriteString(fmt.Sprintf("  Usage:          %s\n", usageColor.Render(fmt.Sprintf("%.1f%%", s.stats.QueueUsage))))
	b.WriteString(fmt.Sprintf("  Pushed Total:   %s\n", formatNumber(s.stats.QueuePushed)))
	b.WriteString(fmt.Sprintf("  Popped Total:   %s\n", formatNumber(s.stats.QueuePopped)))
	if s.stats.QueueDropped > 0 {
		b.WriteString(fmt.Sprintf("  Dropped:        %s\n", styles.StatusError.Render(formatNumber(s.stats.QueueDropped))))
	} else {
		b.WriteString(fmt.Sprintf("  Dropped:        %s\n", styles.StatusOK.Render("0")))
	}
	b.WriteString("\n")

	// Module Integrations (from config)
	b.WriteString(styles.Subtitle.Render("  Available Integrations"))
	b.WriteString("\n")
	integrations := []struct {
		name        string
		description string
	}{
		{"NatLangChain", "Blockchain event ingestion"},
		{"Value Ledger", "Value tracking & vector scores"},
		{"ILR-Module", "Immutable License Registry"},
		{"Learning Contracts", "Consent management"},
		{"Mediator Node", "Intent-aligned mediation"},
		{"Memory Vault", "Secure memory storage"},
		{"Synth Mind", "Agent-OS psychological modules"},
		{"IntentLog", "Prose-based version control"},
		{"RRA-Module", "Revenant Repo Agent"},
	}
	b.WriteString(styles.Muted.Render("  Configure in config.yaml to enable:\n"))
	for _, intg := range integrations {
		b.WriteString(fmt.Sprintf("  %s %-20s %s\n",
			styles.Muted.Render("○"),
			intg.name,
			styles.Muted.Render(intg.description)))
	}
	b.WriteString("\n")

	// Activity Status
	if s.stats.Activity != "" && s.stats.Activity != "unknown" {
		b.WriteString(styles.Subtitle.Render("  Current Activity"))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", s.stats.ActivityDesc))
		b.WriteString("\n")
	}

	// Last update
	if !s.lastUpdate.IsZero() {
		b.WriteString(styles.Muted.Render(fmt.Sprintf("  Last updated: %s", s.lastUpdate.Format("15:04:05"))))
	}

	return b.String()
}

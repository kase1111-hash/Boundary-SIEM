// Package scenes provides TUI scenes for Boundary-SIEM
package scenes

import (
	"fmt"
	"strings"
	"time"

	"boundary-siem/internal/tui/api"
	"boundary-siem/internal/tui/styles"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// DashboardScene displays system overview and metrics
type DashboardScene struct {
	client     *api.Client
	stats      *api.Stats
	err        error
	width      int
	height     int
	lastUpdate time.Time
	loading    bool
}

// statsMsg carries updated stats
type statsMsg struct {
	stats *api.Stats
	err   error
}

// NewDashboardScene creates a new dashboard scene
func NewDashboardScene(client *api.Client) *DashboardScene {
	return &DashboardScene{
		client:  client,
		loading: true,
		stats: &api.Stats{
			Healthy: false,
		},
	}
}

// Init initializes the dashboard scene - fetches initial data
func (d *DashboardScene) Init() tea.Cmd {
	return d.fetchStats()
}

// fetchStats fetches stats from the API
func (d *DashboardScene) fetchStats() tea.Cmd {
	return func() tea.Msg {
		stats, err := d.client.GetStats()
		return statsMsg{stats: stats, err: err}
	}
}

// TickCmd returns a command that ticks every interval
// IMPORTANT: This is returned by the parent model only when this scene is active
func (d *DashboardScene) TickCmd() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		return TickMsg{Scene: "dashboard", Time: t}
	})
}

// TickMsg is sent on each tick - exported for use by parent model
type TickMsg struct {
	Scene string
	Time  time.Time
}

// Update handles messages for the dashboard
func (d *DashboardScene) Update(msg tea.Msg) (*DashboardScene, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		d.width = msg.Width
		d.height = msg.Height
		return d, nil

	case statsMsg:
		d.loading = false
		d.stats = msg.stats
		d.err = msg.err
		d.lastUpdate = time.Now()
		return d, nil

	case TickMsg:
		// Only respond to our own ticks
		if msg.Scene == "dashboard" {
			return d, d.fetchStats()
		}
		return d, nil
	}

	return d, nil
}

// View renders the dashboard
func (d *DashboardScene) View() string {
	var b strings.Builder

	// Title
	title := styles.Title.Render("  Boundary-SIEM Dashboard")
	b.WriteString(title)
	b.WriteString("\n\n")

	if d.loading {
		b.WriteString(styles.Muted.Render("Loading..."))
		return b.String()
	}

	if d.err != nil {
		b.WriteString(styles.StatusError.Render(fmt.Sprintf("Error: %v", d.err)))
		b.WriteString("\n")
	}

	// Status indicator
	var statusText string
	if d.stats.Healthy {
		statusText = styles.StatusOK.Render("● HEALTHY")
	} else {
		statusText = styles.StatusError.Render("● UNHEALTHY")
	}
	b.WriteString(fmt.Sprintf("  Status: %s\n\n", statusText))

	// Metrics cards in a row
	cards := []string{
		d.renderMetricCard("Events Total", formatNumber(d.stats.EventsTotal)),
		d.renderMetricCard("Events/sec", fmt.Sprintf("%.1f", d.stats.EventsPerSecond)),
		d.renderMetricCard("Queue", fmt.Sprintf("%d/%d", d.stats.QueueSize, d.stats.QueueCapacity)),
		d.renderMetricCard("Uptime", d.stats.Uptime),
	}

	cardRow := lipgloss.JoinHorizontal(lipgloss.Top, cards...)
	b.WriteString(cardRow)
	b.WriteString("\n\n")

	// Service status section
	b.WriteString(styles.Subtitle.Render("  Active Services"))
	b.WriteString("\n")
	b.WriteString(d.renderServiceStatus())
	b.WriteString("\n")

	// Last update
	if !d.lastUpdate.IsZero() {
		b.WriteString(styles.Muted.Render(fmt.Sprintf("  Last updated: %s", d.lastUpdate.Format("15:04:05"))))
	}

	return b.String()
}

func (d *DashboardScene) renderMetricCard(label, value string) string {
	card := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(styles.MutedColor).
		Padding(0, 2).
		Width(18).
		Align(lipgloss.Center)

	content := fmt.Sprintf("%s\n%s",
		styles.MetricValue.Render(value),
		styles.MetricLabel.Render(label),
	)

	return card.Render(content)
}

func (d *DashboardScene) renderServiceStatus() string {
	services := []struct {
		name   string
		status string
		port   string
	}{
		{"HTTP API", "running", "8080"},
		{"CEF UDP", "running", "5514"},
		{"CEF TCP", "running", "5515"},
		{"Queue Consumer", "running", "-"},
	}

	var rows []string
	for _, svc := range services {
		status := styles.StatusOK.Render("●")
		row := fmt.Sprintf("  %s %-16s Port: %s", status, svc.name, svc.port)
		rows = append(rows, row)
	}

	return strings.Join(rows, "\n")
}

func formatNumber(n int64) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

// Package tui provides a terminal user interface for Boundary-SIEM
package tui

import (
	"fmt"
	"strings"

	"boundary-siem/internal/tui/api"
	"boundary-siem/internal/tui/scenes"
	"boundary-siem/internal/tui/styles"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Scene represents the current view
type Scene int

const (
	SceneDashboard Scene = iota
	SceneEvents
	SceneSystem
)

// Model is the main TUI model
type Model struct {
	client *api.Client

	// Current scene
	scene Scene

	// Scene models - only the active one receives updates
	dashboard *scenes.DashboardScene
	events    *scenes.EventsScene
	system    *scenes.SystemScene

	// Window dimensions
	width  int
	height int

	// Whether we're quitting
	quitting bool
}

// New creates a new TUI model
func New(baseURL string) *Model {
	client := api.NewClient(baseURL)

	return &Model{
		client:    client,
		scene:     SceneDashboard,
		dashboard: scenes.NewDashboardScene(client),
		events:    scenes.NewEventsScene(client),
		system:    scenes.NewSystemScene(client),
	}
}

// Init initializes the TUI
func (m *Model) Init() tea.Cmd {
	// Only initialize the current scene's data fetch
	// This prevents multiple tickers from running at startup
	return tea.Batch(
		m.dashboard.Init(),
		m.getActiveSceneTickCmd(),
	)
}

// getActiveSceneTickCmd returns the tick command for the active scene only
// This is critical for performance - we don't want inactive scenes ticking
func (m *Model) getActiveSceneTickCmd() tea.Cmd {
	switch m.scene {
	case SceneDashboard:
		return m.dashboard.TickCmd()
	case SceneEvents:
		return m.events.TickCmd()
	case SceneSystem:
		return m.system.TickCmd()
	default:
		return nil
	}
}

// Update handles all messages
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		// Tab switching - number keys
		case "1":
			if m.scene != SceneDashboard {
				m.scene = SceneDashboard
				// Re-init dashboard and start its ticker
				cmds = append(cmds, m.dashboard.Init(), m.dashboard.TickCmd())
			}
			return m, tea.Batch(cmds...)

		case "2":
			if m.scene != SceneEvents {
				m.scene = SceneEvents
				// Re-init events and start its ticker
				cmds = append(cmds, m.events.Init(), m.events.TickCmd())
			}
			return m, tea.Batch(cmds...)

		case "3":
			if m.scene != SceneSystem {
				m.scene = SceneSystem
				// Re-init system and start its ticker
				cmds = append(cmds, m.system.Init(), m.system.TickCmd())
			}
			return m, tea.Batch(cmds...)

		// Tab key cycles through scenes
		case "tab":
			m.scene = (m.scene + 1) % 3 // 3 scenes
			// Start the new scene's ticker
			cmds = append(cmds, m.getActiveSceneTickCmd())
			return m, tea.Batch(cmds...)
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Pass to all scenes so they can adjust
		m.dashboard, _ = m.dashboard.Update(msg)
		m.events, _ = m.events.Update(msg)
		m.system, _ = m.system.Update(msg)
		return m, nil

	case scenes.TickMsg:
		// Only forward tick to the active scene
		// This prevents inactive scenes from doing work
		var cmd tea.Cmd
		switch m.scene {
		case SceneDashboard:
			m.dashboard, cmd = m.dashboard.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
			// Schedule next tick for dashboard only
			cmds = append(cmds, m.dashboard.TickCmd())
		case SceneEvents:
			m.events, cmd = m.events.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
			// Schedule next tick for events only
			cmds = append(cmds, m.events.TickCmd())
		case SceneSystem:
			m.system, cmd = m.system.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
			// Schedule next tick for system only
			cmds = append(cmds, m.system.TickCmd())
		}
		return m, tea.Batch(cmds...)
	}

	// Forward other messages to active scene only
	var cmd tea.Cmd
	switch m.scene {
	case SceneDashboard:
		m.dashboard, cmd = m.dashboard.Update(msg)
	case SceneEvents:
		m.events, cmd = m.events.Update(msg)
	case SceneSystem:
		m.system, cmd = m.system.Update(msg)
	}

	if cmd != nil {
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

// View renders the current view
func (m *Model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder

	// Header with tabs
	b.WriteString(m.renderHeader())
	b.WriteString("\n")

	// Scene content
	switch m.scene {
	case SceneDashboard:
		b.WriteString(m.dashboard.View())
	case SceneEvents:
		b.WriteString(m.events.View())
	case SceneSystem:
		b.WriteString(m.system.View())
	}

	// Footer with help
	b.WriteString("\n")
	b.WriteString(m.renderFooter())

	return b.String()
}

func (m *Model) renderHeader() string {
	tabs := []struct {
		name  string
		key   string
		scene Scene
	}{
		{"Dashboard", "1", SceneDashboard},
		{"Events", "2", SceneEvents},
		{"System", "3", SceneSystem},
	}

	var tabViews []string
	for _, tab := range tabs {
		label := fmt.Sprintf(" %s %s ", tab.key, tab.name)
		if tab.scene == m.scene {
			tabViews = append(tabViews, styles.TabActive.Render(label))
		} else {
			tabViews = append(tabViews, styles.TabInactive.Render(label))
		}
	}

	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, tabViews...)

	header := lipgloss.NewStyle().
		BorderBottom(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(styles.MutedColor).
		Width(m.width).
		Render(tabBar)

	return header
}

func (m *Model) renderFooter() string {
	help := " [1-3] Switch tabs  [Tab] Next tab  [↑↓/jk] Navigate  [q] Quit "
	return styles.Help.Render(help)
}

// Run starts the TUI application
func Run(baseURL string) error {
	m := New(baseURL)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

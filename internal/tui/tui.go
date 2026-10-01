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

	// scroll is the first visible line of the Dashboard and System scenes
	// when they are taller than the window (↑↓/jk scroll them; the Events
	// scene uses those keys to move its selection).
	scroll map[Scene]int

	// Whether we're quitting
	quitting bool
}

// New creates a new TUI model. opts configure the API client, e.g.
// api.WithAPIKey for servers with auth.enabled.
func New(baseURL string, opts ...api.Option) *Model {
	client := api.NewClient(baseURL, opts...)

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

		// Scroll scenes that do not use the arrow keys themselves.
		case "up", "k", "down", "j", "pgup", "pgdown", "home":
			if m.scene != SceneEvents {
				if m.scroll == nil {
					m.scroll = make(map[Scene]int)
				}
				switch msg.String() {
				case "up", "k":
					m.scroll[m.scene]--
				case "down", "j":
					m.scroll[m.scene]++
				case "pgup":
					m.scroll[m.scene] -= max(m.height/2, 1)
				case "pgdown":
					m.scroll[m.scene] += max(m.height/2, 1)
				case "home":
					m.scroll[m.scene] = 0
				}
				// View clamps the offset to the content.
				m.scroll[m.scene] = max(m.scroll[m.scene], 0)
				return m, nil
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Pass to all scenes so they can adjust. The events table sizes itself
		// to the content area (the window minus the tab bar and footer, as in
		// View), so it is not clipped; the other scenes scroll.
		m.dashboard, _ = m.dashboard.Update(msg)
		content := max(1, msg.Height-lipgloss.Height(m.renderHeader())-lipgloss.Height(m.renderFooter()))
		m.events, _ = m.events.Update(tea.WindowSizeMsg{Width: msg.Width, Height: content})
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

	header := m.renderHeader()
	footer := m.renderFooter()

	// Scene content
	var content string
	switch m.scene {
	case SceneDashboard:
		content = m.dashboard.View()
	case SceneEvents:
		content = m.events.View()
	case SceneSystem:
		content = m.system.View()
	}
	// Keep the tab bar and the footer on screen: a scene taller than the
	// window is clipped (and scrollable) instead of pushing the header off
	// the top, as the System tab did in a 45-row terminal.
	if m.height > 0 {
		avail := m.height - lipgloss.Height(header) - lipgloss.Height(footer)
		var offset int
		content, offset = clipLines(content, avail, m.scroll[m.scene])
		if m.scroll != nil {
			m.scroll[m.scene] = offset
		}
	}

	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(content)
	b.WriteString("\n")
	b.WriteString(footer)

	return b.String()
}

// clipLines returns at most height lines of content starting at line offset
// (clamped to the content), and the offset used. When lines are hidden, the
// first and last visible lines say so.
func clipLines(content string, height, offset int) (string, int) {
	lines := strings.Split(content, "\n")
	if height < 1 {
		height = 1
	}
	if len(lines) <= height {
		return content, 0
	}
	offset = min(max(offset, 0), len(lines)-height)
	visible := append([]string(nil), lines[offset:offset+height]...)
	if offset > 0 {
		visible[0] = styles.Muted.Render(fmt.Sprintf("  ↑ %d more line(s) (↑/k to scroll)", offset))
	}
	if below := len(lines) - offset - height; below > 0 {
		visible[len(visible)-1] = styles.Muted.Render(fmt.Sprintf("  ↓ %d more line(s) (↓/j to scroll)", below))
	}
	return strings.Join(visible, "\n"), offset
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

// Run starts the TUI application. opts configure the API client.
func Run(baseURL string, opts ...api.Option) error {
	m := New(baseURL, opts...)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

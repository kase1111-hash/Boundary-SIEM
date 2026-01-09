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

// EventsScene displays recent security events
type EventsScene struct {
	client     *api.Client
	events     []api.Event
	totalCount int64
	err        string
	width      int
	height     int
	cursor     int
	offset     int
	loading    bool
	maxRows    int
	lastUpdate time.Time
}

// eventsMsg carries updated events
type eventsMsg struct {
	events     []api.Event
	totalCount int64
	err        string
}

// NewEventsScene creates a new events scene
func NewEventsScene(client *api.Client) *EventsScene {
	return &EventsScene{
		client:  client,
		loading: true,
		maxRows: 10,
	}
}

// Init initializes the events scene
func (e *EventsScene) Init() tea.Cmd {
	return e.fetchEvents()
}

// fetchEvents fetches events from the API
func (e *EventsScene) fetchEvents() tea.Cmd {
	return func() tea.Msg {
		resp, err := e.client.GetEvents(100)
		if err != nil {
			return eventsMsg{err: err.Error()}
		}
		if resp.Error != "" {
			return eventsMsg{err: resp.Error}
		}
		return eventsMsg{
			events:     resp.Events,
			totalCount: resp.TotalCount,
		}
	}
}

// TickCmd returns a command that ticks every interval
func (e *EventsScene) TickCmd() tea.Cmd {
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
		return TickMsg{Scene: "events", Time: t}
	})
}

// Update handles messages for the events scene
func (e *EventsScene) Update(msg tea.Msg) (*EventsScene, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		e.width = msg.Width
		e.height = msg.Height
		e.maxRows = max(5, e.height-12)
		return e, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if e.cursor > 0 {
				e.cursor--
				if e.cursor < e.offset {
					e.offset = e.cursor
				}
			}
		case "down", "j":
			if e.cursor < len(e.events)-1 {
				e.cursor++
				if e.cursor >= e.offset+e.maxRows {
					e.offset = e.cursor - e.maxRows + 1
				}
			}
		case "pgup":
			e.cursor = max(0, e.cursor-e.maxRows)
			e.offset = max(0, e.offset-e.maxRows)
		case "pgdown":
			e.cursor = min(len(e.events)-1, e.cursor+e.maxRows)
			e.offset = min(max(0, len(e.events)-e.maxRows), e.offset+e.maxRows)
		case "r":
			// Manual refresh
			e.loading = true
			return e, e.fetchEvents()
		}
		return e, nil

	case eventsMsg:
		e.loading = false
		e.events = msg.events
		e.totalCount = msg.totalCount
		e.err = msg.err
		e.lastUpdate = time.Now()
		// Reset cursor if out of bounds
		if e.cursor >= len(e.events) {
			e.cursor = max(0, len(e.events)-1)
		}
		return e, nil

	case TickMsg:
		if msg.Scene == "events" {
			// Auto-refresh events
			return e, e.fetchEvents()
		}
		return e, nil
	}

	return e, nil
}

// View renders the events list
func (e *EventsScene) View() string {
	var b strings.Builder

	// Title
	title := styles.Title.Render("  Security Events")
	b.WriteString(title)
	b.WriteString("\n\n")

	if e.loading && len(e.events) == 0 {
		b.WriteString(styles.Muted.Render("  Loading events..."))
		return b.String()
	}

	// Error display
	if e.err != "" {
		b.WriteString(styles.StatusError.Render(fmt.Sprintf("  Error: %s", e.err)))
		b.WriteString("\n\n")
		b.WriteString(styles.Muted.Render("  Make sure storage is enabled in config.yaml to persist and query events."))
		b.WriteString("\n")
		b.WriteString(styles.Muted.Render("  Press [r] to retry."))
		return b.String()
	}

	// No events
	if len(e.events) == 0 {
		b.WriteString(styles.Muted.Render("  No events found."))
		b.WriteString("\n\n")
		b.WriteString(styles.Muted.Render("  Events will appear here once they are ingested and storage is configured."))
		b.WriteString("\n")
		b.WriteString(styles.Muted.Render("  Send events via the HTTP API (POST /v1/events) or CEF endpoints."))
		return b.String()
	}

	// Event count and status
	countText := fmt.Sprintf("  Showing %d of %d events", len(e.events), e.totalCount)
	b.WriteString(styles.Subtitle.Render(countText))
	if e.loading {
		b.WriteString(styles.Muted.Render("  (refreshing...)"))
	}
	b.WriteString("\n\n")

	// Table header
	header := fmt.Sprintf("  %-20s %-10s %-15s %s",
		"Timestamp", "Severity", "Source", "Action")
	b.WriteString(styles.TableHeader.Render(header))
	b.WriteString("\n")

	// Table rows
	endIdx := min(e.offset+e.maxRows, len(e.events))
	visibleEvents := e.events[e.offset:endIdx]
	for i, event := range visibleEvents {
		idx := e.offset + i
		row := e.renderEventRow(event, idx == e.cursor)
		b.WriteString(row)
		b.WriteString("\n")
	}

	// Scroll indicator
	if len(e.events) > e.maxRows {
		scrollInfo := fmt.Sprintf("\n  %d-%d of %d (↑↓ to scroll, [r] refresh)",
			e.offset+1, endIdx, len(e.events))
		b.WriteString(styles.Muted.Render(scrollInfo))
	} else {
		b.WriteString(styles.Muted.Render("\n  [r] Refresh"))
	}

	// Last update time
	if !e.lastUpdate.IsZero() {
		b.WriteString(styles.Muted.Render(fmt.Sprintf("  |  Updated: %s", e.lastUpdate.Format("15:04:05"))))
	}

	return b.String()
}

func (e *EventsScene) renderEventRow(event api.Event, selected bool) string {
	timestamp := event.Timestamp.Format("15:04:05")
	severity := e.formatSeverity(event.Severity)
	source := truncate(event.Source, 15)
	action := truncate(event.Message, 50)

	row := fmt.Sprintf("  %-20s %s %-15s %s", timestamp, severity, source, action)

	if selected {
		return lipgloss.NewStyle().
			Background(styles.Primary).
			Foreground(styles.White).
			Render(row)
	}

	return row
}

func (e *EventsScene) formatSeverity(sev int) string {
	width := 10
	var label string
	var style lipgloss.Style

	switch {
	case sev >= 8:
		label = "CRITICAL"
		style = styles.StatusError
	case sev >= 6:
		label = "HIGH"
		style = styles.StatusError
	case sev >= 4:
		label = "MEDIUM"
		style = styles.StatusWarning
	case sev >= 2:
		label = "LOW"
		style = styles.StatusOK
	default:
		label = "INFO"
		style = styles.Muted
	}

	padded := fmt.Sprintf("%-*s", width, label)
	return style.Render(padded)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

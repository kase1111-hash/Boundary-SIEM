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
	client   *api.Client
	events   []api.Event
	err      error
	width    int
	height   int
	cursor   int
	offset   int
	loading  bool
	maxRows  int
}

// eventsMsg carries updated events
type eventsMsg struct {
	events []api.Event
	err    error
}

// NewEventsScene creates a new events scene
func NewEventsScene(client *api.Client) *EventsScene {
	return &EventsScene{
		client:  client,
		loading: true,
		events:  generateSampleEvents(), // Use sample events until backend implements events API
		maxRows: 10,
	}
}

// Init initializes the events scene
func (e *EventsScene) Init() tea.Cmd {
	e.loading = false // We have sample events ready
	return nil
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
		e.maxRows = max(5, e.height-10)
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
		}
		return e, nil

	case eventsMsg:
		e.loading = false
		e.events = msg.events
		e.err = msg.err
		return e, nil

	case TickMsg:
		if msg.Scene == "events" {
			// Add a new sample event to simulate real-time updates
			e.events = append([]api.Event{generateRandomEvent()}, e.events...)
			if len(e.events) > 100 {
				e.events = e.events[:100]
			}
			return e, nil
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

	if e.loading {
		b.WriteString(styles.Muted.Render("Loading events..."))
		return b.String()
	}

	if e.err != nil {
		b.WriteString(styles.StatusError.Render(fmt.Sprintf("Error: %v", e.err)))
		b.WriteString("\n\n")
	}

	// Event count
	b.WriteString(styles.Subtitle.Render(fmt.Sprintf("  Showing %d events", len(e.events))))
	b.WriteString("\n\n")

	// Table header
	header := fmt.Sprintf("  %-20s %-10s %-15s %s",
		"Timestamp", "Severity", "Source", "Message")
	b.WriteString(styles.TableHeader.Render(header))
	b.WriteString("\n")

	// Table rows
	visibleEvents := e.events[e.offset:min(e.offset+e.maxRows, len(e.events))]
	for i, event := range visibleEvents {
		idx := e.offset + i
		row := e.renderEventRow(event, idx == e.cursor)
		b.WriteString(row)
		b.WriteString("\n")
	}

	// Scroll indicator
	if len(e.events) > e.maxRows {
		scrollInfo := fmt.Sprintf("\n  %d-%d of %d (↑↓ to scroll)",
			e.offset+1, min(e.offset+e.maxRows, len(e.events)), len(e.events))
		b.WriteString(styles.Muted.Render(scrollInfo))
	}

	return b.String()
}

func (e *EventsScene) renderEventRow(event api.Event, selected bool) string {
	timestamp := event.Timestamp.Format("15:04:05")
	severity := e.formatSeverity(event.Severity)
	source := truncate(event.Source, 15)
	message := truncate(event.Message, 50)

	row := fmt.Sprintf("  %-20s %s %-15s %s", timestamp, severity, source, message)

	if selected {
		return lipgloss.NewStyle().
			Background(styles.Primary).
			Foreground(styles.White).
			Render(row)
	}

	return row
}

func (e *EventsScene) formatSeverity(sev string) string {
	width := 10
	padded := fmt.Sprintf("%-*s", width, sev)

	switch strings.ToLower(sev) {
	case "critical", "high":
		return styles.StatusError.Render(padded)
	case "medium", "warning":
		return styles.StatusWarning.Render(padded)
	case "low", "info":
		return styles.StatusOK.Render(padded)
	default:
		return styles.Muted.Render(padded)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func generateSampleEvents() []api.Event {
	now := time.Now()
	events := []api.Event{
		{ID: "1", Timestamp: now.Add(-1 * time.Minute), Source: "firewall", Severity: "high", Message: "Blocked connection from suspicious IP"},
		{ID: "2", Timestamp: now.Add(-2 * time.Minute), Source: "auth-svc", Severity: "medium", Message: "Multiple failed login attempts"},
		{ID: "3", Timestamp: now.Add(-3 * time.Minute), Source: "api-gateway", Severity: "low", Message: "Rate limit threshold reached"},
		{ID: "4", Timestamp: now.Add(-4 * time.Minute), Source: "storage", Severity: "info", Message: "Batch write completed"},
		{ID: "5", Timestamp: now.Add(-5 * time.Minute), Source: "cef-udp", Severity: "low", Message: "Received 1000 events"},
		{ID: "6", Timestamp: now.Add(-6 * time.Minute), Source: "queue", Severity: "warning", Message: "Queue depth above 80%"},
		{ID: "7", Timestamp: now.Add(-7 * time.Minute), Source: "blockchain", Severity: "high", Message: "Suspicious transaction pattern detected"},
		{ID: "8", Timestamp: now.Add(-8 * time.Minute), Source: "network", Severity: "medium", Message: "Unusual outbound traffic volume"},
		{ID: "9", Timestamp: now.Add(-9 * time.Minute), Source: "endpoint", Severity: "critical", Message: "Malware signature detected"},
		{ID: "10", Timestamp: now.Add(-10 * time.Minute), Source: "cloud-aws", Severity: "info", Message: "IAM policy change detected"},
	}
	return events
}

var eventCounter = 10

func generateRandomEvent() api.Event {
	eventCounter++
	sources := []string{"firewall", "auth-svc", "api-gateway", "blockchain", "network", "endpoint"}
	severities := []string{"info", "low", "medium", "high", "critical"}
	messages := []string{
		"Connection attempt blocked",
		"Authentication event",
		"Rate limit triggered",
		"Anomaly detected",
		"Policy violation",
		"Configuration change",
	}

	return api.Event{
		ID:        fmt.Sprintf("%d", eventCounter),
		Timestamp: time.Now(),
		Source:    sources[eventCounter%len(sources)],
		Severity:  severities[eventCounter%len(severities)],
		Message:   messages[eventCounter%len(messages)],
	}
}

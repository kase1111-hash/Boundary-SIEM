// Package styles provides consistent styling for the TUI
package styles

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	Primary    = lipgloss.Color("#7C3AED")
	Secondary  = lipgloss.Color("#10B981")
	Warning    = lipgloss.Color("#F59E0B")
	Error      = lipgloss.Color("#EF4444")
	MutedColor = lipgloss.Color("#6B7280")
	White      = lipgloss.Color("#FFFFFF")
	Dark       = lipgloss.Color("#1F2937")

	// Muted text style
	Muted = lipgloss.NewStyle().Foreground(MutedColor)

	// Base styles
	Title = lipgloss.NewStyle().
		Bold(true).
		Foreground(Primary).
		MarginBottom(1)

	Subtitle = lipgloss.NewStyle().
			Foreground(MutedColor).
			Italic(true)

	// Box styles
	Box = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(Primary).
		Padding(1, 2)

	// Status styles
	StatusOK = lipgloss.NewStyle().
			Foreground(Secondary).
			Bold(true)

	StatusWarning = lipgloss.NewStyle().
			Foreground(Warning).
			Bold(true)

	StatusError = lipgloss.NewStyle().
			Foreground(Error).
			Bold(true)

	// Tab styles
	TabActive = lipgloss.NewStyle().
			Foreground(White).
			Background(Primary).
			Padding(0, 2).
			Bold(true)

	TabInactive = lipgloss.NewStyle().
			Foreground(MutedColor).
			Padding(0, 2)

	// Help text
	Help = lipgloss.NewStyle().
		Foreground(MutedColor).
		MarginTop(1)

	// Table styles
	TableHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(Primary).
			BorderBottom(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(MutedColor)

	TableRow = lipgloss.NewStyle().
			Foreground(White)

	TableRowSelected = lipgloss.NewStyle().
				Foreground(White).
				Background(Primary)

	// Metric card
	MetricCard = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(MutedColor).
			Padding(1, 2).
			Width(20)

	MetricValue = lipgloss.NewStyle().
			Bold(true).
			Foreground(Secondary)

	MetricLabel = lipgloss.NewStyle().
			Foreground(MutedColor)
)

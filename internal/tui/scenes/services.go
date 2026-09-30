// Package scenes provides TUI scenes for Boundary-SIEM
package scenes

import (
	"fmt"
	"sort"
	"strings"

	"boundary-siem/internal/tui/api"
	"boundary-siem/internal/tui/styles"
)

// knownComponents lists the siem-ingest modules shown even when the server
// does not report them, in display order. Their status is then "unknown":
// the TUI must not guess what the server's config enables.
var knownComponents = []struct {
	key  string
	name string
}{
	{"storage", "Storage"},
	{"cef_udp", "CEF UDP"},
	{"cef_tcp", "CEF TCP"},
	{"cef_dtls", "CEF DTLS"},
}

// componentNames maps additional component keys to display names.
var componentNames = map[string]string{
	"correlation": "Correlation",
	"consumer":    "Queue Consumer",
	"evm":         "EVM Poller",
	"websocket":   "WebSocket",
}

func componentName(key string) string {
	for _, kc := range knownComponents {
		if kc.key == key {
			return kc.name
		}
	}
	if name, ok := componentNames[key]; ok {
		return name
	}
	return key
}

// statusIcon renders the indicator for a component status string.
func statusIcon(status string) string {
	switch strings.ToLower(status) {
	case "up", "ok", "running", "healthy", "enabled", "connected", "reachable", "accepted":
		return styles.StatusOK.Render("●")
	case "degraded", "warning":
		return styles.StatusWarning.Render("●")
	case "down", "error", "failed", "unhealthy", "unreachable", "rejected":
		return styles.StatusError.Render("●")
	case "disabled", "not required":
		return styles.Muted.Render("○")
	default:
		return styles.Muted.Render("?")
	}
}

// serviceLine formats one row of the service table.
func serviceLine(status, name, detail string) string {
	line := fmt.Sprintf("  %s %-16s %s", statusIcon(status), name, status)
	if detail != "" {
		line += styles.Muted.Render("  " + detail)
	}
	return line
}

// renderServices renders backend status using only what the API reports:
// reachability of /health, the auth check, queue metrics and the optional
// "components" object of /health. Anything not reported is "unknown".
func renderServices(client *api.Client, stats *api.Stats) string {
	var rows []string

	baseURL := ""
	if client != nil {
		baseURL = client.BaseURL()
	}

	if stats.Connected {
		rows = append(rows, serviceLine("reachable", "HTTP API", baseURL))
	} else {
		rows = append(rows, serviceLine("unreachable", "HTTP API", baseURL))
	}

	authStatus := stats.AuthStatus
	if authStatus == "" {
		authStatus = api.AuthUnknown
	}
	authDetail := stats.AuthDetail
	if authStatus == api.AuthRejected {
		authDetail = strings.TrimSpace(authDetail + " (set -api-key or SIEM_API_KEY)")
	}
	rows = append(rows, serviceLine(authStatus, "Authentication", authDetail))

	if stats.Connected {
		queue := fmt.Sprintf("%d/%d (%.1f%%)", stats.QueueSize, stats.QueueCapacity, stats.QueueUsage)
		rows = append(rows, serviceLine(queueStatus(stats), "Ingest Queue", queue))
	} else {
		rows = append(rows, serviceLine("unknown", "Ingest Queue", ""))
	}

	// Modules: reported ones in known order, then any extra ones sorted.
	// Components is only populated when /health answered.
	seen := make(map[string]bool)
	for _, kc := range knownComponents {
		seen[kc.key] = true
		cs, ok := stats.Components[kc.key]
		if !ok || cs.Status == "" {
			rows = append(rows, serviceLine("unknown", kc.name, "not reported by server"))
			continue
		}
		rows = append(rows, componentLine(kc.name, cs))
	}
	var extra []string
	for key := range stats.Components {
		if !seen[key] {
			extra = append(extra, key)
		}
	}
	sort.Strings(extra)
	for _, key := range extra {
		rows = append(rows, componentLine(componentName(key), stats.Components[key]))
	}

	return strings.Join(rows, "\n")
}

func componentLine(name string, cs api.ComponentStatus) string {
	status := cs.Status
	if status == "" {
		status = "unknown"
	}
	var details []string
	if cs.Address != "" {
		details = append(details, cs.Address)
	}
	if cs.Message != "" {
		details = append(details, cs.Message)
	}
	return serviceLine(status, name, strings.Join(details, " - "))
}

func queueStatus(stats *api.Stats) string {
	switch {
	case stats.QueueUsage >= 90:
		return "degraded"
	case stats.QueueCapacity > 0:
		return "up"
	default:
		return "unknown"
	}
}

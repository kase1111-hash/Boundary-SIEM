// Package startup provides verbose startup diagnostics and initialization
package startup

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"boundary-siem/internal/config"
)

// DiagnosticResult represents the result of a diagnostic check
type DiagnosticResult struct {
	Name    string
	Status  Status
	Message string
	Details map[string]string
}

// Status represents the status of a diagnostic check
type Status int

const (
	StatusOK Status = iota
	StatusWarning
	StatusError
	StatusSkipped
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusWarning:
		return "WARNING"
	case StatusError:
		return "ERROR"
	case StatusSkipped:
		return "SKIPPED"
	default:
		return "UNKNOWN"
	}
}

// Diagnostics runs all startup diagnostics
type Diagnostics struct {
	cfg     *config.Config
	results []DiagnosticResult
	logger  *slog.Logger
}

// NewDiagnostics creates a new diagnostics runner
func NewDiagnostics(cfg *config.Config, logger *slog.Logger) *Diagnostics {
	return &Diagnostics{
		cfg:    cfg,
		logger: logger,
	}
}

// RunAll runs all diagnostic checks
func (d *Diagnostics) RunAll(ctx context.Context) []DiagnosticResult {
	d.logger.Info("=== Boundary-SIEM Startup Diagnostics ===")
	d.logger.Info("running startup diagnostics")

	// System checks
	d.checkSystem()
	d.checkDirectories()
	d.checkConfiguration()

	// Network checks
	d.checkPorts()

	// Security checks
	d.checkSecurityConfiguration()

	// Module checks
	d.checkModules()

	// Storage checks
	d.checkStorage(ctx)

	// Summary
	d.printSummary()

	return d.results
}

func (d *Diagnostics) addResult(result DiagnosticResult) {
	d.results = append(d.results, result)

	// Log the result
	attrs := []any{
		"check", result.Name,
		"status", result.Status.String(),
	}
	if result.Message != "" {
		attrs = append(attrs, "message", result.Message)
	}
	for k, v := range result.Details {
		attrs = append(attrs, k, v)
	}

	switch result.Status {
	case StatusOK:
		d.logger.Info("diagnostic check passed", attrs...)
	case StatusWarning:
		d.logger.Warn("diagnostic check warning", attrs...)
	case StatusError:
		d.logger.Error("diagnostic check failed", attrs...)
	case StatusSkipped:
		d.logger.Debug("diagnostic check skipped", attrs...)
	}
}

func (d *Diagnostics) checkSystem() {
	d.logger.Info("checking system requirements")

	// Check Go version and runtime
	d.addResult(DiagnosticResult{
		Name:    "runtime",
		Status:  StatusOK,
		Message: "Go runtime detected",
		Details: map[string]string{
			"go_version": runtime.Version(),
			"os":         runtime.GOOS,
			"arch":       runtime.GOARCH,
			"cpus":       fmt.Sprintf("%d", runtime.NumCPU()),
		},
	})

	// Check available memory (basic check)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	d.addResult(DiagnosticResult{
		Name:    "memory",
		Status:  StatusOK,
		Message: "Memory statistics",
		Details: map[string]string{
			"alloc_mb":       fmt.Sprintf("%.2f", float64(m.Alloc)/1024/1024),
			"sys_mb":         fmt.Sprintf("%.2f", float64(m.Sys)/1024/1024),
			"num_goroutines": fmt.Sprintf("%d", runtime.NumGoroutine()),
		},
	})
}

func (d *Diagnostics) checkDirectories() {
	d.logger.Info("checking required directories")

	dirs := []struct {
		path     string
		required bool
		create   bool
	}{
		{"data", false, true},
		{"data/events", false, true},
		{"logs", false, true},
		{"certs", false, true},
		{"configs", true, false},
	}

	for _, dir := range dirs {
		info, err := os.Stat(dir.path)
		if os.IsNotExist(err) {
			if dir.create {
				if err := os.MkdirAll(dir.path, 0750); err != nil {
					d.addResult(DiagnosticResult{
						Name:    fmt.Sprintf("directory_%s", dir.path),
						Status:  StatusError,
						Message: fmt.Sprintf("Failed to create directory: %s", err),
					})
				} else {
					d.addResult(DiagnosticResult{
						Name:    fmt.Sprintf("directory_%s", dir.path),
						Status:  StatusOK,
						Message: "Directory created",
						Details: map[string]string{"path": dir.path},
					})
				}
			} else if dir.required {
				d.addResult(DiagnosticResult{
					Name:    fmt.Sprintf("directory_%s", dir.path),
					Status:  StatusError,
					Message: "Required directory missing",
					Details: map[string]string{"path": dir.path},
				})
			} else {
				d.addResult(DiagnosticResult{
					Name:    fmt.Sprintf("directory_%s", dir.path),
					Status:  StatusWarning,
					Message: "Optional directory missing",
					Details: map[string]string{"path": dir.path},
				})
			}
		} else if err != nil {
			d.addResult(DiagnosticResult{
				Name:    fmt.Sprintf("directory_%s", dir.path),
				Status:  StatusError,
				Message: fmt.Sprintf("Error checking directory: %s", err),
			})
		} else if !info.IsDir() {
			d.addResult(DiagnosticResult{
				Name:    fmt.Sprintf("directory_%s", dir.path),
				Status:  StatusError,
				Message: "Path exists but is not a directory",
				Details: map[string]string{"path": dir.path},
			})
		} else {
			d.addResult(DiagnosticResult{
				Name:    fmt.Sprintf("directory_%s", dir.path),
				Status:  StatusOK,
				Message: "Directory exists",
				Details: map[string]string{"path": dir.path},
			})
		}
	}
}

func (d *Diagnostics) checkConfiguration() {
	d.logger.Info("validating configuration")

	// Check config file
	configPath := os.Getenv("SIEM_CONFIG_PATH")
	if configPath == "" {
		configPath = "configs/config.yaml"
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) { // #nosec G703 -- SIEM_CONFIG_PATH is set by the operator launching the process and may legitimately point anywhere; it is only stat'ed to report existence
		d.addResult(DiagnosticResult{
			Name:    "config_file",
			Status:  StatusWarning,
			Message: "Config file not found, using defaults",
			Details: map[string]string{"path": configPath},
		})
	} else {
		d.addResult(DiagnosticResult{
			Name:    "config_file",
			Status:  StatusOK,
			Message: "Config file found",
			Details: map[string]string{"path": configPath},
		})
	}

	// Validate config
	if err := d.cfg.Validate(); err != nil {
		d.addResult(DiagnosticResult{
			Name:    "config_validation",
			Status:  StatusError,
			Message: fmt.Sprintf("Configuration validation failed: %s", err),
		})
	} else {
		d.addResult(DiagnosticResult{
			Name:    "config_validation",
			Status:  StatusOK,
			Message: "Configuration is valid",
		})
	}
}

// portCheck is one listener whose address is probed before startup.
type portCheck struct {
	name    string
	network string // "tcp" or "udp", the protocol the listener uses
	address string // the address the listener binds, e.g. ":5515" or "10.0.0.1:5515"
	port    int
}

func (d *Diagnostics) checkPorts() {
	d.logger.Info("checking network ports")

	// The HTTP server binds ":<http_port>" (see internal/app).
	checks := []portCheck{{
		name:    "HTTP API",
		network: "tcp",
		address: fmt.Sprintf(":%d", d.cfg.Server.HTTPPort),
		port:    d.cfg.Server.HTTPPort,
	}}

	// CEF listeners bind their configured address with their own protocol:
	// plain UDP and DTLS are UDP, CEF TCP is TCP. Probing a UDP port with a
	// TCP bind would miss a UDP port that is taken and fail on an unrelated
	// TCP listener with the same number.
	cef := d.cfg.Ingest.CEF
	listeners := []struct {
		name    string
		network string
		enabled bool
		address string
	}{
		{"CEF UDP", "udp", cef.UDP.Enabled, cef.UDP.Address},
		{"CEF TCP", "tcp", cef.TCP.Enabled, cef.TCP.Address},
		{"CEF DTLS", "udp", cef.DTLS.Enabled, cef.DTLS.Address},
	}
	for _, l := range listeners {
		if !l.enabled {
			continue
		}
		if port, ok := d.parseListenPort(l.name, l.address); ok {
			checks = append(checks, portCheck{name: l.name, network: l.network, address: l.address, port: port})
		}
	}

	for _, c := range checks {
		d.addResult(probePort(c))
	}
}

// probePort binds c.address with c.network briefly and reports whether the
// listener will be able to bind it.
func probePort(c portCheck) DiagnosticResult {
	details := map[string]string{
		"port":     strconv.Itoa(c.port),
		"protocol": c.network,
		"address":  c.address,
	}

	var err error
	if c.network == "udp" {
		var pc net.PacketConn
		if pc, err = net.ListenPacket("udp", c.address); err == nil {
			_ = pc.Close()
		}
	} else {
		var ln net.Listener
		if ln, err = net.Listen("tcp", c.address); err == nil {
			_ = ln.Close()
		}
	}

	if err != nil {
		return DiagnosticResult{
			Name:    fmt.Sprintf("port_%s", c.name),
			Status:  StatusError,
			Message: fmt.Sprintf("Port %d/%s is not available: %s", c.port, c.network, err),
			Details: details,
		}
	}
	return DiagnosticResult{
		Name:    fmt.Sprintf("port_%s", c.name),
		Status:  StatusOK,
		Message: fmt.Sprintf("Port %d/%s is available", c.port, c.network),
		Details: details,
	}
}

// parseListenPort extracts a positive port number from a listen address such
// as ":514" or "0.0.0.0:514". Unparseable addresses are logged and reported
// as not ok so the port check is skipped for that listener.
func (d *Diagnostics) parseListenPort(name, address string) (int, bool) {
	_, portStr, err := net.SplitHostPort(address)
	if err != nil {
		d.logger.Warn("cannot parse listen address, skipping port check",
			"listener", name, "address", address, "error", err)
		return 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		d.logger.Warn("cannot parse listen port, skipping port check",
			"listener", name, "address", address, "error", err)
		return 0, false
	}
	return port, port > 0
}

func (d *Diagnostics) checkSecurityConfiguration() {
	d.logger.Info("checking security configuration")

	// Check authentication
	if !d.cfg.Auth.Enabled {
		d.addResult(DiagnosticResult{
			Name:    "auth",
			Status:  StatusWarning,
			Message: "Authentication is DISABLED - enable for production",
			Details: map[string]string{"recommendation": "Set auth.enabled=true"},
		})
	} else {
		d.addResult(DiagnosticResult{
			Name:    "auth",
			Status:  StatusOK,
			Message: "Authentication is enabled",
		})
	}

	// Check UDP security (plain UDP is insecure)
	if d.cfg.Ingest.CEF.UDP.Enabled {
		d.addResult(DiagnosticResult{
			Name:    "cef_udp_security",
			Status:  StatusWarning,
			Message: "Plain UDP is INSECURE - no encryption",
			Details: map[string]string{
				"recommendation": "Use DTLS (dtls.enabled=true) or disable UDP (udp.enabled=false)",
				"risk":           "Events may be intercepted or spoofed",
			},
		})
	} else {
		d.addResult(DiagnosticResult{
			Name:    "cef_udp_security",
			Status:  StatusOK,
			Message: "Insecure UDP is disabled",
		})
	}

	// Check TCP TLS
	if d.cfg.Ingest.CEF.TCP.Enabled {
		if !d.cfg.Ingest.CEF.TCP.TLSEnabled {
			d.addResult(DiagnosticResult{
				Name:    "cef_tcp_security",
				Status:  StatusWarning,
				Message: "TCP is running WITHOUT TLS encryption",
				Details: map[string]string{
					"recommendation": "Enable TLS with tcp.tls_enabled=true and configure certificates",
					"risk":           "Events may be intercepted",
				},
			})
		} else {
			// Check if cert files exist
			certExists := fileExists(d.cfg.Ingest.CEF.TCP.TLSCertFile)
			keyExists := fileExists(d.cfg.Ingest.CEF.TCP.TLSKeyFile)

			if !certExists || !keyExists {
				d.addResult(DiagnosticResult{
					Name:    "cef_tcp_security",
					Status:  StatusError,
					Message: "TLS enabled but certificate files missing",
					Details: map[string]string{
						"cert_file": d.cfg.Ingest.CEF.TCP.TLSCertFile,
						"key_file":  d.cfg.Ingest.CEF.TCP.TLSKeyFile,
					},
				})
			} else {
				d.addResult(DiagnosticResult{
					Name:    "cef_tcp_security",
					Status:  StatusOK,
					Message: "TCP TLS is properly configured",
				})
			}
		}
	}

	// Check rate limiting
	if !d.cfg.RateLimit.Enabled {
		d.addResult(DiagnosticResult{
			Name:    "rate_limiting",
			Status:  StatusWarning,
			Message: "Rate limiting is DISABLED",
			Details: map[string]string{"recommendation": "Enable rate limiting for production"},
		})
	} else {
		d.addResult(DiagnosticResult{
			Name:    "rate_limiting",
			Status:  StatusOK,
			Message: "Rate limiting is enabled",
			Details: map[string]string{
				"requests_per_ip": fmt.Sprintf("%d", d.cfg.RateLimit.RequestsPerIP),
				"window":          d.cfg.RateLimit.WindowSize.String(),
			},
		})
	}

	// Check security headers
	if !d.cfg.SecurityHeaders.Enabled {
		d.addResult(DiagnosticResult{
			Name:    "security_headers",
			Status:  StatusWarning,
			Message: "Security headers are DISABLED",
		})
	} else {
		d.addResult(DiagnosticResult{
			Name:    "security_headers",
			Status:  StatusOK,
			Message: "Security headers are enabled",
		})
	}

	// Check encryption at rest
	if !d.cfg.Encryption.Enabled {
		d.addResult(DiagnosticResult{
			Name:    "encryption_at_rest",
			Status:  StatusWarning,
			Message: "Encryption at rest is DISABLED",
			Details: map[string]string{"recommendation": "Enable for sensitive data protection"},
		})
	} else {
		d.addResult(DiagnosticResult{
			Name:    "encryption_at_rest",
			Status:  StatusOK,
			Message: "Encryption at rest is enabled",
		})
	}
}

func (d *Diagnostics) checkModules() {
	d.logger.Info("checking enabled modules")

	modules := []struct {
		name    string
		enabled bool
	}{
		{"HTTP API", true},
		{"CEF UDP Ingest", d.cfg.Ingest.CEF.UDP.Enabled},
		{"CEF TCP Ingest", d.cfg.Ingest.CEF.TCP.Enabled},
		{"CEF DTLS Ingest", d.cfg.Ingest.CEF.DTLS.Enabled},
		{"ClickHouse Storage", d.cfg.Storage.Enabled},
		{"Authentication", d.cfg.Auth.Enabled},
		{"Rate Limiting", d.cfg.RateLimit.Enabled},
		{"CORS", d.cfg.CORS.Enabled},
		{"Security Headers", d.cfg.SecurityHeaders.Enabled},
	}

	enabledCount := 0
	for _, m := range modules {
		status := StatusSkipped
		message := "Disabled"
		if m.enabled {
			status = StatusOK
			message = "Enabled"
			enabledCount++
		}
		d.addResult(DiagnosticResult{
			Name:    fmt.Sprintf("module_%s", m.name),
			Status:  status,
			Message: message,
		})
	}

	d.logger.Info("modules summary", "enabled", enabledCount, "total", len(modules))
}

func (d *Diagnostics) checkStorage(ctx context.Context) {
	d.logger.Info("checking storage configuration")

	if !d.cfg.Storage.Enabled {
		d.addResult(DiagnosticResult{
			Name:    "storage",
			Status:  StatusWarning,
			Message: "Storage is DISABLED - events will not be persisted",
			Details: map[string]string{
				"mode":           "placeholder",
				"recommendation": "Enable storage for production use",
			},
		})
		return
	}

	// Check ClickHouse connectivity (with timeout)
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	host := "localhost:9000"
	if len(d.cfg.Storage.ClickHouse.Hosts) > 0 {
		host = d.cfg.Storage.ClickHouse.Hosts[0]
	}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(checkCtx, "tcp", host)
	if err != nil {
		d.addResult(DiagnosticResult{
			Name:    "clickhouse_connectivity",
			Status:  StatusError,
			Message: fmt.Sprintf("Cannot connect to ClickHouse: %s", err),
			Details: map[string]string{"host": host},
		})
	} else {
		_ = conn.Close()
		d.addResult(DiagnosticResult{
			Name:    "clickhouse_connectivity",
			Status:  StatusOK,
			Message: "ClickHouse is reachable",
			Details: map[string]string{"host": host},
		})
	}
}

func (d *Diagnostics) printSummary() {
	var ok, warnings, errors, skipped int
	for _, r := range d.results {
		switch r.Status {
		case StatusOK:
			ok++
		case StatusWarning:
			warnings++
		case StatusError:
			errors++
		case StatusSkipped:
			skipped++
		}
	}

	d.logger.Info("=== Diagnostics Summary ===",
		"passed", ok,
		"warnings", warnings,
		"errors", errors,
		"skipped", skipped,
	)

	if errors > 0 {
		d.logger.Error("startup diagnostics found critical errors - service may not function correctly")
	} else if warnings > 0 {
		d.logger.Warn("startup diagnostics found warnings - review for production readiness")
	} else {
		d.logger.Info("all startup diagnostics passed")
	}
}

// HasErrors returns true if any diagnostic check failed
func (d *Diagnostics) HasErrors() bool {
	for _, r := range d.results {
		if r.Status == StatusError {
			return true
		}
	}
	return false
}

// HasWarnings returns true if any diagnostic check has warnings
func (d *Diagnostics) HasWarnings() bool {
	for _, r := range d.results {
		if r.Status == StatusWarning {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// EnsureDirectories creates all required directories
func EnsureDirectories() error {
	dirs := []string{
		"data",
		"data/events",
		"logs",
		"certs",
		filepath.Join("configs"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// PrintBanner prints the startup banner
func PrintBanner(version string) {
	banner := `
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗  ██████╗ ██╗   ██╗███╗   ██╗██████╗  █████╗ ██████╗ ██╗   ██╗ ║
║   ██╔══██╗██╔═══██╗██║   ██║████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝ ║
║   ██████╔╝██║   ██║██║   ██║██╔██╗ ██║██║  ██║███████║██████╔╝ ╚████╔╝  ║
║   ██╔══██╗██║   ██║██║   ██║██║╚██╗██║██║  ██║██╔══██║██╔══██╗  ╚██╔╝   ║
║   ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║██║  ██║   ██║    ║
║   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ║
║                        SIEM                                   ║
║                                                              ║
║   Agent-Native Security Intelligence Platform                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
	fmt.Printf("  Version: %s\n\n", version)
}

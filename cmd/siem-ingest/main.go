// Package main is the entry point for the SIEM ingest service.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"boundary-siem/internal/app"
	"boundary-siem/internal/config"
	siemErrors "boundary-siem/internal/errors"
	"boundary-siem/internal/startup"
)

var version = "dev"

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
}

// command is what the command line asks for.
type command struct {
	configPath string // -config; "" = $SIEM_CONFIG_PATH or configs/config.yaml
	version    bool
	health     bool // the health subcommand
}

// parseArgs parses the command line:
//
//	siem-ingest [-config file] [-version]
//	siem-ingest [-config file] health
//
// Unknown arguments are an error (they used to be ignored).
func parseArgs(args []string, stderr io.Writer) (*command, error) {
	c := &command{}
	fs := flag.NewFlagSet("siem-ingest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.configPath, "config", "", "configuration file (default: $SIEM_CONFIG_PATH, else configs/config.yaml)")
	fs.BoolVar(&c.version, "version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  siem-ingest [flags]          run the SIEM service\n  siem-ingest [flags] health   check a running service (exit 0 when /health answers 200)\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	switch fs.Arg(0) {
	case "":
		return c, nil
	case "health":
		c.health = true
		hfs := flag.NewFlagSet("siem-ingest health", flag.ContinueOnError)
		hfs.SetOutput(stderr)
		hfs.StringVar(&c.configPath, "config", c.configPath, "configuration file, for server.http_port (checked on 127.0.0.1)")
		if err := hfs.Parse(fs.Args()[1:]); err != nil {
			return nil, err
		}
		if hfs.NArg() > 0 {
			return nil, fmt.Errorf("unexpected argument %q after health", hfs.Arg(0))
		}
		return c, nil
	default:
		return nil, fmt.Errorf("unknown command %q (siem-ingest runs the service; its only command is health)", fs.Arg(0))
	}
}

// dispatch runs the command line args and returns the exit code.
func dispatch(args []string, stdout, stderr io.Writer) int {
	c, err := parseArgs(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "siem-ingest: %v\n", err)
		return 2
	}
	switch {
	case c.version:
		fmt.Fprintf(stdout, "siem-ingest %s\n", version)
		return 0
	case c.health:
		return runHealth(c, stdout, stderr)
	}
	return run(c.configPath)
}

// healthTimeout bounds the health subcommand's request.
const healthTimeout = 5 * time.Second

// runHealth checks a running service: exit 0 when its /health answers 200
// (it does while the process serves; "status" says whether a subsystem is
// degraded), 1 otherwise. A container image without curl (FROM scratch) can
// use it as its HEALTHCHECK.
func runHealth(c *command, stdout, stderr io.Writer) int {
	cfg, err := config.LoadFrom(c.configPath)
	if err != nil {
		fmt.Fprintf(stderr, "siem-ingest health: %v\n", err)
		return 1
	}
	// Always the local instance: the command is a container health check,
	// not a client for arbitrary URLs.
	target := (&url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Server.HTTPPort)),
		Path:   "/health",
	}).String()
	ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		fmt.Fprintf(stderr, "siem-ingest health: %v\n", err)
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "siem-ingest health: %v\n", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "siem-ingest health: %s answered %s\n", target, resp.Status)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n", cmp.Or(body.Status, "ok"))
	return 0
}

func run(configPath string) int {
	// Setup structured logging
	logLevel := slog.LevelInfo
	if os.Getenv("SIEM_LOG_LEVEL") == "debug" {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Print startup banner
	startup.PrintBanner(version)

	// Ensure required directories exist
	if err := startup.EnsureDirectories(); err != nil {
		slog.Error("failed to create required directories", "error", err)
		return 1
	}

	// Load configuration (file, then environment overrides)
	cfg, err := config.LoadFrom(configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		return 1
	}

	// Enable production mode by default; only disable in dev mode
	devMode := os.Getenv("SIEM_DEV_MODE") == "true"
	siemErrors.SetProductionMode(!devMode)
	if devMode {
		slog.Warn("running in DEVELOPMENT mode — error sanitization is disabled")
	}

	// Run startup diagnostics
	diagnostics := startup.NewDiagnostics(cfg, logger)
	diagnostics.RunAll(context.Background())

	// Check for critical errors
	if diagnostics.HasErrors() {
		if os.Getenv("SIEM_IGNORE_ERRORS") == "true" && devMode {
			slog.Warn("ignoring startup errors due to SIEM_IGNORE_ERRORS=true (dev mode only)")
		} else {
			slog.Error("startup diagnostics failed — resolve errors before starting (SIEM_IGNORE_ERRORS only works with SIEM_DEV_MODE=true)")
			return 1
		}
	}

	warnInsecureConfig(cfg)

	slog.Info("configuration loaded",
		"http_port", cfg.Server.HTTPPort,
		"queue_size", cfg.Queue.Size,
		"auth_enabled", cfg.Auth.Enabled,
		"storage_enabled", cfg.Storage.Enabled,
		"cef_udp_enabled", cfg.Ingest.CEF.UDP.Enabled,
		"cef_tcp_enabled", cfg.Ingest.CEF.TCP.Enabled,
		"cef_dtls_enabled", cfg.Ingest.CEF.DTLS.Enabled,
		"websocket_enabled", cfg.WebSocket.Enabled,
		"rules_dir", cfg.Correlation.RulesDir,
		"shutdown_timeout", cfg.Server.ShutdownTimeout,
	)

	a, err := app.New(cfg, app.Options{})
	if err != nil {
		slog.Error("failed to initialize", "error", err)
		return 1
	}

	// Register for signals before starting, so an early SIGTERM is not lost.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)

	exitCode := 0
	if err := a.Start(); err != nil {
		slog.Error("failed to start", "error", err)
		a.Shutdown(cfg.Server.ShutdownTimeout)
		return 1
	}

	select {
	case sig := <-quit:
		slog.Info("shutdown signal received", "signal", sig.String())
	case err := <-a.Err():
		slog.Error("server error", "error", err)
		exitCode = 1
	}

	a.Shutdown(cfg.Server.ShutdownTimeout)
	return exitCode
}

// warnInsecureConfig logs warnings for insecure configurations.
func warnInsecureConfig(cfg *config.Config) {
	if !cfg.Auth.Enabled {
		slog.Warn("API authentication is DISABLED — not recommended for production")
	} else if !hasAPIKey(cfg.Auth.APIKeys) {
		slog.Warn("API authentication is enabled but no API key is configured — every API request will be rejected; set SIEM_API_KEY or auth.api_keys")
	}
	if cfg.Storage.Enabled {
		if cfg.Storage.ClickHouse.Password == "" {
			slog.Warn("ClickHouse password is empty — configure a strong password for production")
		}
		if !cfg.Storage.ClickHouse.TLSEnabled {
			slog.Warn("ClickHouse TLS is disabled — enable tls_enabled for production")
		}
	} else {
		slog.Warn("storage is DISABLED — events are correlated but not persisted, and search is unavailable")
	}
	if cfg.Ingest.CEF.TCP.Enabled && !cfg.Ingest.CEF.TCP.TLSEnabled {
		slog.Warn("CEF TCP ingestion is running without TLS — enable tls_enabled for production")
	}
}

func hasAPIKey(keys []string) bool {
	for _, k := range keys {
		if k != "" {
			return true
		}
	}
	return false
}

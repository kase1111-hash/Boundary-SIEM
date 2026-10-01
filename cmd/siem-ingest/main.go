// Package main is the entry point for the SIEM ingest service.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"boundary-siem/internal/app"
	"boundary-siem/internal/config"
	siemErrors "boundary-siem/internal/errors"
	"boundary-siem/internal/startup"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
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
	cfg, err := config.Load()
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

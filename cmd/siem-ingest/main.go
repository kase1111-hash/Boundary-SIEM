// Package main is the entry point for the SIEM ingest service.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"boundary-siem/internal/alerting"
	"boundary-siem/internal/config"
	siemErrors "boundary-siem/internal/errors"
	"boundary-siem/internal/consumer"
	"boundary-siem/internal/correlation"
	detectionrules "boundary-siem/internal/detection/rules"
	"boundary-siem/internal/ingest"
	"boundary-siem/internal/ingest/cef"
	"boundary-siem/internal/ingest/evm"
	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
	"boundary-siem/internal/search"
	"boundary-siem/internal/startup"
	"boundary-siem/internal/storage"
)

var version = "dev"

func main() {
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
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Enable production mode by default; only disable in dev mode
	devMode := os.Getenv("SIEM_DEV_MODE") == "true"
	siemErrors.SetProductionMode(!devMode)
	if devMode {
		slog.Warn("running in DEVELOPMENT mode — error sanitization is disabled")
	}

	// Run startup diagnostics
	ctx := context.Background()
	diagnostics := startup.NewDiagnostics(cfg, logger)
	diagnostics.RunAll(ctx)

	// Check for critical errors
	if diagnostics.HasErrors() {
		if os.Getenv("SIEM_IGNORE_ERRORS") == "true" && devMode {
			slog.Warn("ignoring startup errors due to SIEM_IGNORE_ERRORS=true (dev mode only)")
		} else {
			slog.Error("startup diagnostics failed — resolve errors before starting (SIEM_IGNORE_ERRORS only works with SIEM_DEV_MODE=true)")
			os.Exit(1)
		}
	}

	// Security warnings for insecure default configurations
	if !cfg.Auth.Enabled {
		slog.Warn("API authentication is DISABLED — not recommended for production")
	}
	if cfg.Storage.Enabled {
		if cfg.Storage.ClickHouse.Password == "" {
			slog.Warn("ClickHouse password is empty — configure a strong password for production")
		}
		if !cfg.Storage.ClickHouse.TLSEnabled {
			slog.Warn("ClickHouse TLS is disabled — enable tls_enabled for production")
		}
	}
	if cfg.Ingest.CEF.TCP.Enabled && !cfg.Ingest.CEF.TCP.TLSEnabled {
		slog.Warn("CEF TCP ingestion is running without TLS — enable tls_enabled for production")
	}

	slog.Info("configuration loaded",
		"http_port", cfg.Server.HTTPPort,
		"queue_size", cfg.Queue.Size,
		"auth_enabled", cfg.Auth.Enabled,
		"storage_enabled", cfg.Storage.Enabled,
		"cef_udp_enabled", cfg.Ingest.CEF.UDP.Enabled,
		"cef_tcp_enabled", cfg.Ingest.CEF.TCP.Enabled,
	)

	// Initialize components
	validatorCfg := schema.ValidatorConfig{
		MaxAge:    cfg.Validation.MaxEventAge,
		MaxFuture: cfg.Validation.MaxFuture,
	}
	validator := schema.NewValidatorWithConfig(validatorCfg)

	eventQueue := queue.NewRingBuffer(cfg.Queue.Size)

	handler := ingest.NewHandler(validator, eventQueue).
		WithMaxPayload(cfg.Ingest.MaxPayloadSize).
		WithMaxBatch(cfg.Ingest.MaxBatchSize)

	// Setup HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/events", handler.HandleEvents)
	mux.HandleFunc("GET /health", handler.HealthCheck)
	mux.HandleFunc("GET /metrics", handler.Metrics)
	mux.HandleFunc("GET /api/system/dreaming", handler.Dreaming)

	// Apply middleware
	wrappedHandler := ingest.WithMiddleware(mux, cfg)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler:      wrappedHandler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize storage if enabled
	var chClient *storage.ClickHouseClient
	var batchWriter *storage.BatchWriter
	var queueConsumer *consumer.Consumer

	if cfg.Storage.Enabled {
		slog.Info("initializing ClickHouse storage",
			"hosts", cfg.Storage.ClickHouse.Hosts,
			"database", cfg.Storage.ClickHouse.Database,
		)

		// Create ClickHouse client
		chConfig := storage.ClickHouseConfig{
			Hosts:           cfg.Storage.ClickHouse.Hosts,
			Database:        cfg.Storage.ClickHouse.Database,
			Username:        cfg.Storage.ClickHouse.Username,
			Password:        cfg.Storage.ClickHouse.Password,
			MaxOpenConns:    cfg.Storage.ClickHouse.MaxOpenConns,
			MaxIdleConns:    cfg.Storage.ClickHouse.MaxIdleConns,
			ConnMaxLifetime: cfg.Storage.ClickHouse.ConnMaxLifetime,
			TLSEnabled:      cfg.Storage.ClickHouse.TLSEnabled,
			DialTimeout:     cfg.Storage.ClickHouse.DialTimeout,
		}

		chClient, err = storage.NewClickHouseClient(chConfig)
		if err != nil {
			slog.Error("failed to connect to ClickHouse", "error", err)
			os.Exit(1)
		}

		// Run migrations
		slog.Info("running database migrations")
		migrator := storage.NewMigrator(chClient)
		if err := migrator.Run(ctx); err != nil {
			slog.Error("failed to run migrations", "error", err)
			os.Exit(1)
		}

		// Create batch writer
		bwConfig := storage.BatchWriterConfig{
			BatchSize:     cfg.Storage.BatchWriter.BatchSize,
			FlushInterval: cfg.Storage.BatchWriter.FlushInterval,
			MaxRetries:    cfg.Storage.BatchWriter.MaxRetries,
			RetryDelay:    cfg.Storage.BatchWriter.RetryDelay,
		}
		batchWriter = storage.NewBatchWriter(chClient, bwConfig)

		// Create and start queue consumer
		consumerCfg := consumer.Config{
			Workers:      cfg.Consumer.Workers,
			PollInterval: cfg.Consumer.PollInterval,
			ShutdownWait: cfg.Consumer.ShutdownWait,
		}
		queueConsumer = consumer.New(eventQueue, batchWriter, consumerCfg)
		queueConsumer.Start(ctx)

		// Apply retention policies
		retentionCfg := storage.RetentionConfig{
			EventsTTL:     cfg.Storage.Retention.EventsTTL,
			CriticalTTL:   cfg.Storage.Retention.CriticalTTL,
			QuarantineTTL: cfg.Storage.Retention.QuarantineTTL,
			AlertsTTL:     cfg.Storage.Retention.AlertsTTL,
		}
		retentionMgr := storage.NewRetentionManager(chClient, retentionCfg)
		if err := retentionMgr.ApplyTTLs(ctx); err != nil {
			slog.Warn("failed to apply retention policies", "error", err)
		}

		// Register search routes when storage is enabled
		searchExecutor := search.NewExecutor(chClient.DB())
		searchHandler := search.NewHandler(searchExecutor)
		searchHandler.RegisterRoutes(mux)
		slog.Info("search API registered", "endpoints", []string{
			"/v1/search", "/v1/aggregations", "/v1/events/{id}", "/v1/stats", "/v1/search/explain",
		})

		slog.Info("storage initialized successfully")
	} else {
		// Start placeholder consumer for development without storage
		go consumeQueuePlaceholder(ctx, eventQueue)
	}

	// Initialize correlation engine with detection rules
	corrEngine := correlation.NewEngine(correlation.DefaultEngineConfig())
	for _, rule := range detectionrules.GetAllRules() {
		if err := corrEngine.AddRule(rule); err != nil {
			slog.Warn("failed to add detection rule", "rule_id", rule.ID, "error", err)
		}
	}

	// Initialize baseline engine for adaptive thresholds
	baselineEngine := correlation.NewBaselineEngine()
	slog.Info("baseline engine initialized")

	// Initialize alert manager
	alertMgr := alerting.NewManager(alerting.DefaultManagerConfig(), nil)
	corrEngine.AddHandler(func(ctx context.Context, alert *correlation.Alert) error {
		return alertMgr.HandleCorrelationAlert(ctx, alert)
	})

	// Initialize alert reinjector for rule chaining
	reinjector := correlation.NewAlertReinjector(corrEngine)
	corrEngine.AddHandler(func(ctx context.Context, alert *correlation.Alert) error {
		reinjector.Reinject(alert)
		return nil
	})

	// Register built-in kill chain rules
	for _, chain := range correlation.BuiltinChains() {
		chainRule := correlation.ChainToRule(chain)
		if err := corrEngine.AddRule(chainRule); err != nil {
			slog.Warn("failed to add kill chain rule", "chain_id", chain.ID, "error", err)
		}
	}
	slog.Info("kill chain rules registered", "count", len(correlation.BuiltinChains()))

	// Start correlation engine
	corrEngine.Start(ctx)

	// Suppress unused variable warning for baseline engine (used by rules at runtime)
	_ = baselineEngine

	// Initialize escalation engine
	escalationEngine := alerting.NewEscalationEngine(alertMgr)
	for _, policy := range alerting.BuiltinEscalationPolicies() {
		escalationEngine.AddPolicy(policy)
	}
	escalationEngine.Start(ctx, 1*time.Minute)
	slog.Info("escalation engine started", "policies", len(alerting.BuiltinEscalationPolicies()))

	// Register alert management API
	alertHandler := alerting.NewHandler(alertMgr)
	alertHandler.RegisterRoutes(mux)
	slog.Info("alert API registered", "endpoints", []string{
		"/v1/alerts", "/v1/alerts/{id}", "/v1/alerts/{id}/acknowledge",
		"/v1/alerts/{id}/resolve", "/v1/alerts/{id}/notes", "/v1/alerts/{id}/assign",
	})

	// Register rule management API
	rulesDir := os.Getenv("SIEM_RULES_DIR")
	if rulesDir == "" {
		rulesDir = "data/rules"
	}
	ruleHandler := correlation.NewRuleHandler(corrEngine, rulesDir)
	if err := ruleHandler.LoadCustomRules(); err != nil {
		slog.Warn("failed to load custom rules", "error", err)
	}
	ruleHandler.RegisterRoutes(mux)
	slog.Info("rule API registered", "endpoints", []string{
		"/v1/rules", "/v1/rules/{id}", "/v1/rules/{id}/test",
	})

	// Initialize CEF parser and normalizer
	cefParser := cef.NewParser(cef.ParserConfig{
		StrictMode:    cfg.Ingest.CEF.Parser.StrictMode,
		MaxExtensions: cfg.Ingest.CEF.Parser.MaxExtensions,
	})

	cefNormalizer := cef.NewNormalizer(cef.NormalizerConfig{
		DefaultTenantID: cfg.Ingest.CEF.Normalizer.DefaultTenantID,
	})

	// Start CEF UDP server if enabled
	var udpServer *ingest.UDPServer
	if cfg.Ingest.CEF.UDP.Enabled {
		udpCfg := ingest.UDPServerConfig{
			Address:        cfg.Ingest.CEF.UDP.Address,
			BufferSize:     cfg.Ingest.CEF.UDP.BufferSize,
			Workers:        cfg.Ingest.CEF.UDP.Workers,
			MaxMessageSize: cfg.Ingest.CEF.UDP.MaxMessageSize,
		}
		udpServer = ingest.NewUDPServer(udpCfg, cefParser, cefNormalizer, validator, eventQueue)
		if err := udpServer.Start(ctx); err != nil {
			slog.Error("failed to start UDP server", "error", err)
			os.Exit(1)
		}
	}

	// Start CEF TCP server if enabled
	var tcpServer *ingest.TCPServer
	if cfg.Ingest.CEF.TCP.Enabled {
		tcpCfg := ingest.TCPServerConfig{
			Address:        cfg.Ingest.CEF.TCP.Address,
			TLSEnabled:     cfg.Ingest.CEF.TCP.TLSEnabled,
			TLSCertFile:    cfg.Ingest.CEF.TCP.TLSCertFile,
			TLSKeyFile:     cfg.Ingest.CEF.TCP.TLSKeyFile,
			MaxConnections: cfg.Ingest.CEF.TCP.MaxConnections,
			IdleTimeout:    cfg.Ingest.CEF.TCP.IdleTimeout,
			MaxLineLength:  cfg.Ingest.CEF.TCP.MaxLineLength,
		}
		tcpServer = ingest.NewTCPServer(tcpCfg, cefParser, cefNormalizer, validator, eventQueue)
		if err := tcpServer.Start(ctx); err != nil {
			slog.Error("failed to start TCP server", "error", err)
			os.Exit(1)
		}
	}

	// Start EVM poller if enabled
	var evmPoller *evm.Poller
	if cfg.Ingest.EVM.Enabled {
		evmCfg := evm.Config{
			Enabled:      true,
			PollInterval: cfg.Ingest.EVM.PollInterval,
			BatchSize:    cfg.Ingest.EVM.BatchSize,
			StartBlock:   cfg.Ingest.EVM.StartBlock,
		}
		for _, chain := range cfg.Ingest.EVM.Chains {
			evmCfg.Chains = append(evmCfg.Chains, evm.ChainConfig{
				Name:    chain.Name,
				ChainID: chain.ChainID,
				RPCURL:  chain.RPCURL,
				Enabled: chain.Enabled,
			})
		}
		evmPoller = evm.NewPoller(evmCfg, eventQueue)
		evmPoller.Start(ctx)
		slog.Info("EVM poller started",
			"chains", len(cfg.Ingest.EVM.Chains),
			"poll_interval", cfg.Ingest.EVM.PollInterval,
		)
	}

	// Start HTTP server
	go func() {
		slog.Info("starting ingest server", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	slog.Info("shutdown signal received", "signal", sig.String())

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Stop accepting new requests
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server shutdown error", "error", err)
	}

	// Stop EVM poller
	if evmPoller != nil {
		evmPoller.Stop()
	}

	// Stop CEF servers
	if udpServer != nil {
		udpServer.Stop()
	}
	if tcpServer != nil {
		tcpServer.Stop()
	}

	// Stop escalation engine
	escalationEngine.Stop()

	// Stop correlation engine
	corrEngine.Stop()

	// Stop queue consumer
	cancel()

	if cfg.Storage.Enabled {
		// Stop queue consumer
		if queueConsumer != nil {
			queueConsumer.Stop()
		}

		// Close batch writer
		if batchWriter != nil {
			if err := batchWriter.Close(); err != nil {
				slog.Error("batch writer close error", "error", err)
			}
		}

		// Close ClickHouse connection
		if chClient != nil {
			if err := chClient.Close(); err != nil {
				slog.Error("clickhouse close error", "error", err)
			}
		}
	}

	// Close queue
	eventQueue.Close()

	// Log final metrics
	queueMetrics := eventQueue.Metrics()
	slog.Info("shutdown complete",
		"events_pushed", queueMetrics.Pushed,
		"events_popped", queueMetrics.Popped,
		"events_dropped", queueMetrics.Dropped,
	)

	if batchWriter != nil {
		bwMetrics := batchWriter.Metrics()
		slog.Info("storage metrics",
			"events_written", bwMetrics.Written,
			"events_failed", bwMetrics.Failed,
			"batches", bwMetrics.Batches,
		)
	}

	// Log CEF server metrics
	if udpServer != nil {
		udpMetrics := udpServer.Metrics()
		slog.Info("CEF UDP metrics",
			"received", udpMetrics.Received,
			"parsed", udpMetrics.Parsed,
			"queued", udpMetrics.Queued,
			"errors", udpMetrics.Errors,
		)
	}
	if tcpServer != nil {
		tcpMetrics := tcpServer.Metrics()
		slog.Info("CEF TCP metrics",
			"connections", tcpMetrics.Connections,
			"received", tcpMetrics.Received,
			"queued", tcpMetrics.Queued,
			"errors", tcpMetrics.Errors,
		)
	}
}

// consumeQueuePlaceholder processes events when storage is disabled.
// Used for development/testing without ClickHouse.
func consumeQueuePlaceholder(ctx context.Context, q *queue.RingBuffer) {
	slog.Info("queue consumer started (placeholder mode - no storage)")

	for {
		select {
		case <-ctx.Done():
			slog.Info("queue consumer stopping")
			return
		default:
		}

		event, err := q.PopWithTimeout(100 * time.Millisecond)
		if err != nil {
			if err == queue.ErrQueueEmpty {
				continue
			}
			if err == queue.ErrQueueClosed {
				return
			}
			continue
		}

		// Log event (placeholder for storage)
		slog.Debug("event processed (placeholder)",
			"event_id", event.EventID,
			"action", event.Action,
			"source", event.Source.Product,
			"severity", event.Severity,
		)
	}
}

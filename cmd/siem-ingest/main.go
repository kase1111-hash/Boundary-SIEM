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

	"boundary-siem/internal/config"
	"boundary-siem/internal/consumer"
	"boundary-siem/internal/ingest"
	"boundary-siem/internal/ingest/cef"
	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
	"boundary-siem/internal/storage"
)

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

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		slog.Error("invalid config", "error", err)
		os.Exit(1)
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

		slog.Info("storage initialized successfully")
	} else {
		// Start placeholder consumer for development without storage
		go consumeQueuePlaceholder(ctx, eventQueue)
	}

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

	// Stop CEF servers
	if udpServer != nil {
		udpServer.Stop()
	}
	if tcpServer != nil {
		tcpServer.Stop()
	}

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

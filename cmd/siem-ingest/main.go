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
	"boundary-siem/internal/ingest"
	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
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

	// Start queue consumer in background
	ctx, cancel := context.WithCancel(context.Background())
	go consumeQueue(ctx, eventQueue)

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

	// Stop queue consumer
	cancel()

	// Close queue
	eventQueue.Close()

	// Log final metrics
	metrics := eventQueue.Metrics()
	slog.Info("shutdown complete",
		"events_pushed", metrics.Pushed,
		"events_popped", metrics.Popped,
		"events_dropped", metrics.Dropped,
	)
}

// consumeQueue processes events from the queue.
// In Step 2, this will write to ClickHouse.
func consumeQueue(ctx context.Context, q *queue.RingBuffer) {
	slog.Info("queue consumer started")

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

		// Log event (placeholder for storage in Step 2)
		slog.Debug("event processed",
			"event_id", event.EventID,
			"action", event.Action,
			"source", event.Source.Product,
			"severity", event.Severity,
		)
	}
}

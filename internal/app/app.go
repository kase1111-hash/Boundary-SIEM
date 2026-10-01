// Package app assembles the ingest service (cmd/siem-ingest): storage, the
// event pipeline, correlation, alerting, the HTTP API, the WebSocket stream
// and the CEF/EVM transports, and runs and stops them in the right order.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"boundary-siem/internal/alerting"
	"boundary-siem/internal/config"
	"boundary-siem/internal/consumer"
	"boundary-siem/internal/correlation"
	detectionrules "boundary-siem/internal/detection/rules"
	"boundary-siem/internal/ingest"
	"boundary-siem/internal/ingest/cef"
	"boundary-siem/internal/ingest/evm"
	"boundary-siem/internal/queue"
	"boundary-siem/internal/schema"
	"boundary-siem/internal/search"
	"boundary-siem/internal/storage"
	"boundary-siem/internal/ws"
)

// EventStore is the storage destination of ingested events.
// *storage.BatchWriter implements it; tests substitute an in-memory store.
type EventStore interface {
	consumer.EventWriter
	Close() error
	Metrics() storage.BatchWriterMetrics
}

// Options holds dependencies that can be replaced, mainly for tests.
type Options struct {
	// Store replaces the ClickHouse batch writer. When set, no ClickHouse
	// connection is made and the search API is not registered.
	Store EventStore
	// Listener is the HTTP listener; by default :server.http_port.
	Listener net.Listener
	// Quarantine replaces the ClickHouse events_quarantine writer for
	// rejected events when Store is set.
	Quarantine ingest.QuarantineStore
}

// App is the assembled ingest service. Every accepted event flows
// HTTP/CEF/EVM -> ring buffer -> consumer -> {correlation engine (bounded,
// non-blocking), storage (blocking, with backpressure)}.
type App struct {
	cfg    *config.Config
	logger *slog.Logger

	validator *schema.Validator
	queue     *queue.RingBuffer

	// Storage. chClient is nil when ClickHouse is not used; store is nil
	// when storage is disabled.
	chClient   *storage.ClickHouseClient
	store      EventStore
	quarantine *ingest.Quarantiner
	storage    *storageHealth

	consumer *consumer.Consumer
	corrSink *consumer.AsyncSink

	engine      *correlation.Engine
	rules       *correlation.RuleHandler
	alertMgr    *alerting.Manager
	escalation  *alerting.EscalationEngine
	searchStats func(context.Context) ([]byte, error) // nil without search

	handler         *ingest.Handler
	hub             *ws.Hub
	server          *http.Server
	listener        net.Listener
	stopRateLimiter func()

	udp  *ingest.UDPServer
	tcp  *ingest.TCPServer
	dtls *ingest.DTLSServer
	evm  *evm.Poller

	runCtx    context.Context
	cancelRun context.CancelFunc
	bg        sync.WaitGroup

	serveErr     chan error
	started      atomic.Bool
	shutdownOnce sync.Once
	report       ShutdownReport
}

// New builds the service from cfg without starting anything that
// listens or runs in the background (except the storage connection and the
// correlation sink's forwarder).
func New(cfg *config.Config, opts Options) (*App, error) {
	a := &App{
		cfg:             cfg,
		logger:          slog.Default(),
		serveErr:        make(chan error, 1),
		stopRateLimiter: func() {},
		listener:        opts.Listener,
	}
	a.runCtx, a.cancelRun = context.WithCancel(context.Background())

	cfg.Auth.APIKeys = nonEmpty(cfg.Auth.APIKeys)

	a.validator = schema.NewValidatorWithConfig(schema.ValidatorConfig{
		MaxAge:    cfg.Validation.MaxEventAge,
		MaxFuture: cfg.Validation.MaxFuture,
	})
	a.queue = queue.NewRingBuffer(cfg.Queue.Size)

	if err := a.initStorage(opts.Store, opts.Quarantine); err != nil {
		a.closeStorage()
		return nil, err
	}
	if err := a.initCorrelation(); err != nil {
		a.closeStorage()
		return nil, err
	}

	consumerOpts := []consumer.Option{consumer.WithSink(a.corrSink)}
	if a.store != nil {
		consumerOpts = append(consumerOpts, consumer.WithWriter(a.store))
	}
	a.consumer = consumer.NewConsumer(a.queue, consumer.Config{
		Workers:      cfg.Consumer.Workers,
		PollInterval: cfg.Consumer.PollInterval,
		ShutdownWait: cfg.Consumer.ShutdownWait,
	}, consumerOpts...)

	if err := a.initTransports(); err != nil {
		a.closeStorage()
		return nil, err
	}
	if err := a.initHTTP(); err != nil {
		a.closeStorage()
		return nil, err
	}
	return a, nil
}

func nonEmpty(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}

// quarantineBuffer is the number of rejected events waiting to be written
// to events_quarantine; beyond it they are dropped (and counted).
const quarantineBuffer = 1000

// initStorage connects to ClickHouse (creating the database if needed),
// runs the migrations and builds the batch writer and quarantine writer.
func (a *App) initStorage(store EventStore, quarantine ingest.QuarantineStore) error {
	cfg := a.cfg
	if store != nil {
		a.store = store
		a.storage = newStorageHealth(nil)
		if quarantine != nil {
			a.quarantine = ingest.NewQuarantiner(quarantine, quarantineBuffer)
		}
		return nil
	}
	if !cfg.Storage.Enabled {
		a.storage = newStorageHealth(nil)
		return nil
	}

	a.logger.Info("initializing ClickHouse storage",
		"hosts", cfg.Storage.ClickHouse.Hosts,
		"database", cfg.Storage.ClickHouse.Database,
	)
	client, err := storage.NewClickHouseClient(storage.ClickHouseConfig{
		Hosts:           cfg.Storage.ClickHouse.Hosts,
		Database:        cfg.Storage.ClickHouse.Database,
		Username:        cfg.Storage.ClickHouse.Username,
		Password:        cfg.Storage.ClickHouse.Password,
		MaxOpenConns:    cfg.Storage.ClickHouse.MaxOpenConns,
		MaxIdleConns:    cfg.Storage.ClickHouse.MaxIdleConns,
		ConnMaxLifetime: cfg.Storage.ClickHouse.ConnMaxLifetime,
		TLSEnabled:      cfg.Storage.ClickHouse.TLSEnabled,
		DialTimeout:     cfg.Storage.ClickHouse.DialTimeout,
	})
	if err != nil {
		return fmt.Errorf("connect to ClickHouse: %w", err)
	}
	a.chClient = client

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	a.logger.Info("running database migrations")
	if err := storage.NewMigrator(client).Run(ctx); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	retention := storage.NewRetentionManager(client, storage.RetentionConfig{
		EventsTTL:     cfg.Storage.Retention.EventsTTL,
		CriticalTTL:   cfg.Storage.Retention.CriticalTTL,
		QuarantineTTL: cfg.Storage.Retention.QuarantineTTL,
		AlertsTTL:     cfg.Storage.Retention.AlertsTTL,
	})
	if err := retention.ApplyTTLs(ctx); err != nil {
		a.logger.Warn("failed to apply retention policies", "error", err)
	}

	quarantineWriter := storage.NewQuarantineWriter(client)
	a.store = storage.NewBatchWriter(client, storage.BatchWriterConfig{
		BatchSize:     cfg.Storage.BatchWriter.BatchSize,
		FlushInterval: cfg.Storage.BatchWriter.FlushInterval,
		MaxRetries:    cfg.Storage.BatchWriter.MaxRetries,
		RetryDelay:    cfg.Storage.BatchWriter.RetryDelay,
		MaxPending:    cfg.Storage.BatchWriter.MaxPending,
		MaxRequeues:   cfg.Storage.BatchWriter.MaxRequeues,
	}, storage.WithDeadLetter(quarantineWriter.DeadLetter))
	a.quarantine = ingest.NewQuarantiner(quarantineWriter, quarantineBuffer)
	a.storage = newStorageHealth(client.Ping)

	a.logger.Info("storage initialized")
	return nil
}

// closeStorage releases what initStorage opened, for failed startups.
func (a *App) closeStorage() {
	if a.corrSink != nil {
		_ = a.corrSink.Close(context.Background())
	}
	if a.quarantine != nil {
		_ = a.quarantine.Close(context.Background())
	}
	if a.store != nil {
		_ = a.store.Close()
	}
	if a.chClient != nil {
		_ = a.chClient.Close()
	}
	a.cancelRun()
}

// initCorrelation builds the correlation engine with every rule, the alert
// manager (persisted to ClickHouse when available), notification channels
// and escalation.
func (a *App) initCorrelation() error {
	cfg := a.cfg
	a.engine = correlation.NewEngine(correlation.EngineConfig{
		MaxStateEntries:    cfg.Correlation.MaxStateEntries,
		StateCleanupFreq:   cfg.Correlation.StateCleanupFreq,
		WorkerCount:        cfg.Correlation.WorkerCount,
		DedupWindow:        cfg.Correlation.DedupWindow,
		RecurrenceInterval: cfg.Correlation.RecurrenceInterval,
		EventChannelSize:   cfg.Correlation.EventChannelSize,
		AlertChannelSize:   cfg.Correlation.AlertChannelSize,
	})

	detection := detectionrules.GetAllRules()
	for _, rule := range detection {
		if err := a.engine.AddRule(rule); err != nil {
			a.logger.Warn("failed to add detection rule", "rule_id", rule.ID, "error", err)
		}
	}
	chains := correlation.BuiltinChains()
	for _, chain := range chains {
		if err := a.engine.AddRule(correlation.ChainToRule(chain)); err != nil {
			a.logger.Warn("failed to add kill chain rule", "chain_id", chain.ID, "error", err)
		}
	}

	// Alert manager, persisted when ClickHouse is available.
	managerCfg := alerting.DefaultManagerConfig()
	if cfg.Alerting.DedupWindow > 0 {
		managerCfg.DeduplicationWindow = cfg.Alerting.DedupWindow
	}
	if cfg.Alerting.RetentionPeriod > 0 {
		managerCfg.RetentionPeriod = cfg.Alerting.RetentionPeriod
	}
	if cfg.Alerting.MaxAlerts > 0 {
		managerCfg.MaxAlerts = cfg.Alerting.MaxAlerts
	}
	if a.chClient != nil {
		a.alertMgr = alerting.NewManager(managerCfg, a.chClient.DB())
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		n, err := a.alertMgr.LoadFromDB(ctx)
		cancel()
		if err != nil {
			a.logger.Warn("failed to restore alerts from ClickHouse", "error", err)
		} else {
			a.logger.Info("alerts restored from ClickHouse", "count", n)
		}
	} else {
		a.alertMgr = alerting.NewManager(managerCfg, nil)
		a.logger.Warn("alerts are kept in memory only (storage disabled) and are lost on restart")
	}

	a.escalation = alerting.NewEscalationEngine(a.alertMgr)
	for _, policy := range alerting.BuiltinEscalationPolicies() {
		a.escalation.AddPolicy(policy)
	}
	channels, err := alerting.SetupNotifications(cfg.Alerting.Notifications, a.alertMgr, a.escalation)
	if err != nil {
		return fmt.Errorf("invalid alerting.notifications configuration: %w", err)
	}
	a.logger.Info("notification channels registered", "channels", channels)

	a.engine.AddHandler(func(ctx context.Context, alert *correlation.Alert) error {
		return a.alertMgr.HandleCorrelationAlert(ctx, alert)
	})
	reinjector := correlation.NewAlertReinjector(a.engine)
	a.engine.AddHandler(func(_ context.Context, alert *correlation.Alert) error {
		reinjector.Reinject(alert)
		return nil
	})

	// Custom and community rules. The shipped rules are copied into the
	// API-writable rules directory the first time.
	if n, err := seedRules(cfg.Correlation.RulesDir, cfg.Correlation.SeedRulesDir); errors.Is(err, errSeedDirMissing) {
		a.logger.Warn("shipped community rules not loaded: seed rules directory not found; "+
			"set correlation.seed_rules_dir or SIEM_SEED_RULES_DIR (empty disables seeding)",
			"seed_rules_dir", cfg.Correlation.SeedRulesDir, "rules_dir", cfg.Correlation.RulesDir)
	} else if err != nil {
		a.logger.Warn("failed to seed rules directory", "rules_dir", cfg.Correlation.RulesDir,
			"seed_rules_dir", cfg.Correlation.SeedRulesDir, "error", err)
	} else if n > 0 {
		a.logger.Info("seeded rules directory with the shipped rules", "rules_dir", cfg.Correlation.RulesDir, "files", n)
	}
	a.rules = correlation.NewRuleHandler(a.engine, cfg.Correlation.RulesDir)
	if err := a.rules.LoadCustomRules(); err != nil {
		a.logger.Warn("failed to load custom rules", "rules_dir", cfg.Correlation.RulesDir, "error", err)
	}
	if err := a.engine.CheckDependencies(); err != nil {
		a.logger.Warn("correlation rules depend on unknown rules", "error", err)
	}
	a.logger.Info("correlation rules registered",
		"total", len(a.engine.GetRules()),
		"detection", len(detection),
		"kill_chains", len(chains),
		"rules_dir", cfg.Correlation.RulesDir,
	)

	a.corrSink = consumer.NewAsyncSink("correlation", cfg.Correlation.EventChannelSize, a.engine.ProcessEvent)
	return nil
}

// initTransports builds the CEF servers and the EVM poller.
func (a *App) initTransports() error {
	cfg := a.cfg
	parser := cef.NewParser(cef.ParserConfig{
		StrictMode:    cfg.Ingest.CEF.Parser.StrictMode,
		MaxExtensions: cfg.Ingest.CEF.Parser.MaxExtensions,
	})
	normalizer := cef.NewNormalizer(cef.NormalizerConfig{
		DefaultTenantID: cfg.Ingest.CEF.Normalizer.DefaultTenantID,
	})

	if c := cfg.Ingest.CEF.UDP; c.Enabled {
		a.udp = ingest.NewUDPServer(ingest.UDPServerConfig{
			Address:        c.Address,
			BufferSize:     c.BufferSize,
			Workers:        c.Workers,
			MaxMessageSize: c.MaxMessageSize,
		}, parser, normalizer, a.validator, a.queue)
	}
	if c := cfg.Ingest.CEF.TCP; c.Enabled {
		a.tcp = ingest.NewTCPServer(ingest.TCPServerConfig{
			Address:        c.Address,
			TLSEnabled:     c.TLSEnabled,
			TLSCertFile:    c.TLSCertFile,
			TLSKeyFile:     c.TLSKeyFile,
			MaxConnections: c.MaxConnections,
			IdleTimeout:    c.IdleTimeout,
			MaxLineLength:  c.MaxLineLength,
		}, parser, normalizer, a.validator, a.queue)
	}
	if c := cfg.Ingest.CEF.DTLS; c.Enabled {
		srv, err := ingest.NewDTLSServer(ingest.DTLSServerConfig{
			Address:           c.Address,
			CertFile:          c.CertFile,
			KeyFile:           c.KeyFile,
			CAFile:            c.CAFile,
			RequireClientCert: c.RequireClientCert,
			Workers:           c.Workers,
			MaxMessageSize:    c.MaxMessageSize,
			ConnectionTimeout: c.ConnectionTimeout,
			MaxConnections:    c.MaxConnections,
			IdleTimeout:       c.IdleTimeout,
			AllowInsecure:     c.AllowInsecure,
		}, parser, normalizer, a.validator, a.queue, a.logger)
		if err != nil {
			return fmt.Errorf("CEF DTLS server: %w", err)
		}
		a.dtls = srv
	}

	// Rejected CEF messages go to events_quarantine, like rejected JSON.
	if a.quarantine != nil {
		if a.udp != nil {
			a.udp.WithQuarantine(a.quarantine)
		}
		if a.tcp != nil {
			a.tcp.WithQuarantine(a.quarantine)
		}
		if a.dtls != nil {
			a.dtls.WithQuarantine(a.quarantine)
		}
	}

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
		a.evm = evm.NewPoller(evmCfg, a.queue)
	}
	return nil
}

// initHTTP builds the HTTP API, the WebSocket hub and the server.
func (a *App) initHTTP() error {
	cfg := a.cfg

	a.handler = ingest.NewHandler(a.validator, a.queue).
		WithMaxPayload(cfg.Ingest.MaxPayloadSize).
		WithMaxBatch(cfg.Ingest.MaxBatchSize).
		WithDefaultTenant(cfg.Ingest.CEF.Normalizer.DefaultTenantID).
		WithComponents(a.components).
		WithSources(a.sources).
		WithMetrics(a.metrics).
		WithAuthRequired(cfg.Auth.Enabled)
	if a.quarantine != nil {
		a.handler.WithQuarantine(a.quarantine)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/events", a.handler.HandleEvents)
	mux.HandleFunc("GET /health", a.handler.HealthCheck)
	mux.HandleFunc("GET /ready", a.handler.Ready)
	mux.HandleFunc("GET /metrics", a.handler.Metrics)
	mux.HandleFunc("GET /api/system/dreaming", a.handler.Dreaming)

	if a.chClient != nil {
		searchHandler := search.NewHandler(search.NewExecutor(a.chClient.DB()),
			search.WithDefaultTenant(cfg.Ingest.CEF.Normalizer.DefaultTenantID))
		searchHandler.RegisterRoutes(mux)
		a.searchStats = statsFunc(searchHandler)
	} else {
		search.RegisterUnavailableRoutes(mux, "search unavailable: storage is disabled (storage.enabled: false)")
	}

	alerting.NewHandler(a.alertMgr).RegisterRoutes(mux)
	a.rules.RegisterRoutes(mux)

	if cfg.WebSocket.Enabled {
		keys := cfg.Auth.APIKeys
		a.hub = ws.NewHub(ws.Config{
			AuthEnabled:    cfg.Auth.Enabled,
			APIKeyValid:    func(key string) bool { return ingest.ValidAPIKey(key, keys) },
			CORSEnabled:    cfg.CORS.Enabled,
			AllowedOrigins: cfg.CORS.AllowedOrigins,
			MaxClients:     cfg.WebSocket.MaxClients,
			SendQueueSize:  cfg.WebSocket.SendQueueSize,
			WriteTimeout:   cfg.WebSocket.WriteTimeout,
		}, a.logger)
		mux.Handle("GET /ws/events", a.hub)
		mux.Handle("GET /ws", a.hub)
		// New alerts reach the dashboard through a notification channel;
		// lifecycle changes through the API are broadcast by
		// alertChangeNotifier below.
		a.alertMgr.AddChannel(&wsAlertChannel{hub: a.hub})
	}

	if cfg.Server.WebDir != "" {
		static, err := ingest.NewStaticHandler(cfg.Server.WebDir)
		if err != nil {
			return err
		}
		mux.Handle("GET /", static)
		a.logger.Info("serving web dashboard", "dir", cfg.Server.WebDir)
	}

	var root http.Handler = mux
	if a.hub != nil {
		root = alertChangeNotifier(root, a.alertMgr, a.hub)
	}
	wrapped, stop := ingest.WithMiddleware(root, cfg)
	a.stopRateLimiter = stop

	readHeaderTimeout := 10 * time.Second
	if cfg.Server.ReadTimeout > 0 && cfg.Server.ReadTimeout < readHeaderTimeout {
		readHeaderTimeout = cfg.Server.ReadTimeout
	}
	a.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler:           wrapped,
		ReadTimeout:       cfg.Server.ReadTimeout,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
	}
	if a.hub != nil {
		// Hijacked WebSocket connections are not closed by Shutdown.
		a.server.RegisterOnShutdown(a.hub.Close)
	}
	return nil
}

// Start starts the pipeline, then the ingest listeners. The HTTP listener
// opens last, once everything behind it runs.
func (a *App) Start() error {
	ctx := a.runCtx
	cfg := a.cfg

	a.engine.Start(ctx)
	a.escalation.Start(ctx, cfg.Alerting.EscalationInterval)
	a.consumer.Start(ctx)
	a.startBackground()

	if a.udp != nil {
		if err := a.udp.Start(ctx); err != nil {
			return fmt.Errorf("start CEF UDP server: %w", err)
		}
	}
	if a.tcp != nil {
		if err := a.tcp.Start(ctx); err != nil {
			return fmt.Errorf("start CEF TCP server: %w", err)
		}
	}
	if a.dtls != nil {
		if err := a.dtls.Start(ctx); err != nil {
			return fmt.Errorf("start CEF DTLS server: %w", err)
		}
	}
	if a.evm != nil {
		a.evm.Start(ctx)
	}

	if a.listener == nil {
		ln, err := net.Listen("tcp", a.server.Addr)
		if err != nil {
			return fmt.Errorf("listen on %s: %w", a.server.Addr, err)
		}
		a.listener = ln
	}
	go func() {
		a.logger.Info("starting ingest server", "address", a.listener.Addr().String())
		if err := a.server.Serve(a.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.serveErr <- err
		}
	}()

	a.started.Store(true)
	return nil
}

// Err reports a fatal HTTP server error after Start.
func (a *App) Err() <-chan error {
	return a.serveErr
}

// Addr returns the HTTP listen address once started.
func (a *App) Addr() string {
	if a.listener == nil {
		return ""
	}
	return a.listener.Addr().String()
}

// startBackground starts the periodic tasks: storage health checks, alert
// retention cleanup and WebSocket stats pushes.
func (a *App) startBackground() {
	ctx := a.runCtx
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		a.storage.run(ctx, func() uint64 { return a.consumer.Metrics().FlushFailures })
	}()

	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n := a.alertMgr.Cleanup(ctx); n > 0 {
					a.logger.Info("removed old resolved alerts from memory", "count", n)
				}
			}
		}
	}()

	if a.hub != nil && a.searchStats != nil && a.cfg.WebSocket.StatsInterval > 0 {
		a.bg.Add(1)
		go func() {
			defer a.bg.Done()
			pushStats(ctx, a.hub, a.searchStats, a.cfg.WebSocket.StatsInterval, a.logger)
		}()
	}
}

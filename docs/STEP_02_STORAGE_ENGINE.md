# Step 2: Storage Engine

**Objective:** Implement ClickHouse storage with batch inserts, retention policies, and a queue consumer that persists events.

**Estimated Complexity:** Medium-High
**Dependencies:** Step 1 (Ingest Foundation)

---

## Why This Step?

With events flowing into the queue, we need durable storage. ClickHouse provides:

1. **Columnar storage** - Optimized for time-series security data
2. **Compression** - 10-15x reduction in storage costs
3. **Fast queries** - Sub-second searches across billions of events
4. **Built-in TTL** - Automatic retention policy enforcement

After this step, events are persisted and queryable.

---

## Deliverables

### 1. Project Structure Additions

```
boundary-siem/
├── internal/
│   ├── storage/
│   │   ├── clickhouse.go           # ClickHouse client wrapper
│   │   ├── clickhouse_test.go
│   │   ├── batch_writer.go         # Batch insert logic
│   │   ├── batch_writer_test.go
│   │   ├── quarantine.go           # Invalid event storage
│   │   └── migrations/
│   │       ├── 001_create_events.sql
│   │       ├── 002_create_quarantine.sql
│   │       └── migrator.go
│   └── consumer/
│       ├── queue_consumer.go       # Reads from queue, writes to storage
│       └── queue_consumer_test.go
├── deployments/
│   └── clickhouse/
│       ├── docker-compose.yaml
│       ├── config.xml
│       └── users.xml
└── scripts/
    ├── init-clickhouse.sh
    └── test-queries.sh
```

### 2. ClickHouse Schema

```sql
-- internal/storage/migrations/001_create_events.sql

-- Main events table with time-based partitioning
CREATE TABLE IF NOT EXISTS events (
    -- Primary identifiers
    event_id UUID,
    tenant_id LowCardinality(String),

    -- Timestamps
    timestamp DateTime64(6, 'UTC'),
    received_at DateTime64(6, 'UTC') DEFAULT now64(6),

    -- Source information
    source_product LowCardinality(String),
    source_host String,
    source_instance_id String,
    source_version LowCardinality(String),

    -- Actor information
    actor_type LowCardinality(Enum8(
        'user' = 1,
        'process' = 2,
        'service' = 3,
        'system' = 4,
        'unknown' = 5
    )),
    actor_id String,
    actor_name String,
    actor_email String,
    actor_ip String,

    -- Event details
    action LowCardinality(String),
    target String,
    outcome LowCardinality(Enum8('success' = 1, 'failure' = 2, 'unknown' = 3)),
    severity UInt8,

    -- Schema metadata
    schema_version LowCardinality(String),

    -- Raw and metadata (compressed)
    raw String CODEC(ZSTD(3)),
    metadata String CODEC(ZSTD(3)),

    -- Bloom filter indices for fast lookups
    INDEX idx_action action TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_actor_id actor_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_target target TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_source_host source_host TYPE bloom_filter(0.01) GRANULARITY 4,

    -- Token-based full-text index on raw
    INDEX idx_raw_tokens raw TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, source_product, toStartOfHour(timestamp), event_id)
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS
    index_granularity = 8192,
    ttl_only_drop_parts = 1;

-- Materialized view for hourly aggregations (useful for dashboards later)
CREATE MATERIALIZED VIEW IF NOT EXISTS events_hourly_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, source_product, action, outcome, hour)
AS SELECT
    tenant_id,
    source_product,
    action,
    outcome,
    toStartOfHour(timestamp) AS hour,
    count() AS event_count,
    sum(severity) AS severity_sum,
    max(severity) AS severity_max
FROM events
GROUP BY tenant_id, source_product, action, outcome, hour;

-- Table for high-severity events (faster queries on critical events)
CREATE TABLE IF NOT EXISTS events_critical (
    event_id UUID,
    tenant_id LowCardinality(String),
    timestamp DateTime64(6, 'UTC'),
    source_product LowCardinality(String),
    action LowCardinality(String),
    actor_id String,
    target String,
    severity UInt8,
    raw String CODEC(ZSTD(3))
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp, event_id)
TTL timestamp + INTERVAL 365 DAY DELETE;

-- Trigger to copy high-severity events
CREATE MATERIALIZED VIEW IF NOT EXISTS events_critical_mv
TO events_critical
AS SELECT
    event_id,
    tenant_id,
    timestamp,
    source_product,
    action,
    actor_id,
    target,
    severity,
    raw
FROM events
WHERE severity >= 8;
```

### 3. Quarantine Table

```sql
-- internal/storage/migrations/002_create_quarantine.sql

CREATE TABLE IF NOT EXISTS events_quarantine (
    -- Quarantine metadata
    quarantine_id UUID DEFAULT generateUUIDv4(),
    quarantined_at DateTime64(6, 'UTC') DEFAULT now64(6),

    -- Original event data
    raw_event String CODEC(ZSTD(3)),
    source_ip String,
    source_format LowCardinality(String),  -- 'json', 'cef'

    -- Error information
    validation_errors Array(String),
    error_code LowCardinality(String),

    -- Reprocessing tracking
    reprocess_attempts UInt8 DEFAULT 0,
    reprocessed Boolean DEFAULT false,
    reprocessed_at Nullable(DateTime64(6, 'UTC')),
    reprocessed_event_id Nullable(UUID)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(quarantined_at)
ORDER BY (quarantined_at, quarantine_id)
TTL quarantined_at + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;
```

### 4. ClickHouse Client

```go
// internal/storage/clickhouse.go
package storage

import (
    "context"
    "crypto/tls"
    "fmt"
    "time"

    "github.com/ClickHouse/clickhouse-go/v2"
    "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

type ClickHouseConfig struct {
    Hosts           []string
    Database        string
    Username        string
    Password        string
    MaxOpenConns    int
    MaxIdleConns    int
    ConnMaxLifetime time.Duration
    TLSEnabled      bool
    Compression     bool
}

type ClickHouseClient struct {
    conn   driver.Conn
    config ClickHouseConfig
}

func NewClickHouseClient(cfg ClickHouseConfig) (*ClickHouseClient, error) {
    opts := &clickhouse.Options{
        Addr: cfg.Hosts,
        Auth: clickhouse.Auth{
            Database: cfg.Database,
            Username: cfg.Username,
            Password: cfg.Password,
        },
        Settings: clickhouse.Settings{
            "max_execution_time": 60,
        },
        Compression: &clickhouse.Compression{
            Method: clickhouse.CompressionZSTD,
        },
        DialTimeout:     10 * time.Second,
        MaxOpenConns:    cfg.MaxOpenConns,
        MaxIdleConns:    cfg.MaxIdleConns,
        ConnMaxLifetime: cfg.ConnMaxLifetime,
    }

    if cfg.TLSEnabled {
        opts.TLS = &tls.Config{
            InsecureSkipVerify: false,
        }
    }

    conn, err := clickhouse.Open(opts)
    if err != nil {
        return nil, fmt.Errorf("failed to connect to ClickHouse: %w", err)
    }

    // Verify connection
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := conn.Ping(ctx); err != nil {
        return nil, fmt.Errorf("failed to ping ClickHouse: %w", err)
    }

    return &ClickHouseClient{
        conn:   conn,
        config: cfg,
    }, nil
}

func (c *ClickHouseClient) Close() error {
    return c.conn.Close()
}

func (c *ClickHouseClient) Ping(ctx context.Context) error {
    return c.conn.Ping(ctx)
}

func (c *ClickHouseClient) Conn() driver.Conn {
    return c.conn
}

// Stats returns connection pool statistics
func (c *ClickHouseClient) Stats() driver.Stats {
    return c.conn.Stats()
}
```

### 5. Batch Writer

```go
// internal/storage/batch_writer.go
package storage

import (
    "context"
    "encoding/json"
    "fmt"
    "sync"
    "time"

    "github.com/ClickHouse/clickhouse-go/v2/lib/driver"
    "boundary-siem/internal/schema"
)

type BatchWriterConfig struct {
    BatchSize     int           // Events per batch
    FlushInterval time.Duration // Max time between flushes
    MaxRetries    int
    RetryDelay    time.Duration
}

type BatchWriter struct {
    client  *ClickHouseClient
    config  BatchWriterConfig

    buffer  []*schema.Event
    mu      sync.Mutex

    flushTimer *time.Timer
    done       chan struct{}

    // Metrics
    totalWritten uint64
    totalFailed  uint64
    batchCount   uint64
}

func NewBatchWriter(client *ClickHouseClient, cfg BatchWriterConfig) *BatchWriter {
    bw := &BatchWriter{
        client: client,
        config: cfg,
        buffer: make([]*schema.Event, 0, cfg.BatchSize),
        done:   make(chan struct{}),
    }

    // Start flush timer
    bw.flushTimer = time.AfterFunc(cfg.FlushInterval, bw.timerFlush)

    return bw
}

func (bw *BatchWriter) Write(event *schema.Event) error {
    bw.mu.Lock()
    defer bw.mu.Unlock()

    bw.buffer = append(bw.buffer, event)

    if len(bw.buffer) >= bw.config.BatchSize {
        return bw.flushLocked()
    }

    return nil
}

func (bw *BatchWriter) timerFlush() {
    bw.mu.Lock()
    defer bw.mu.Unlock()

    if len(bw.buffer) > 0 {
        bw.flushLocked()
    }

    // Reset timer
    bw.flushTimer.Reset(bw.config.FlushInterval)
}

func (bw *BatchWriter) flushLocked() error {
    if len(bw.buffer) == 0 {
        return nil
    }

    events := bw.buffer
    bw.buffer = make([]*schema.Event, 0, bw.config.BatchSize)

    // Perform batch insert with retries
    var lastErr error
    for attempt := 0; attempt <= bw.config.MaxRetries; attempt++ {
        if attempt > 0 {
            time.Sleep(bw.config.RetryDelay * time.Duration(attempt))
        }

        if err := bw.insertBatch(events); err != nil {
            lastErr = err
            continue
        }

        bw.totalWritten += uint64(len(events))
        bw.batchCount++
        return nil
    }

    bw.totalFailed += uint64(len(events))
    return fmt.Errorf("batch insert failed after %d retries: %w", bw.config.MaxRetries, lastErr)
}

func (bw *BatchWriter) insertBatch(events []*schema.Event) error {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    batch, err := bw.client.Conn().PrepareBatch(ctx, `
        INSERT INTO events (
            event_id, tenant_id, timestamp, received_at,
            source_product, source_host, source_instance_id, source_version,
            actor_type, actor_id, actor_name, actor_email, actor_ip,
            action, target, outcome, severity,
            schema_version, raw, metadata
        )
    `)
    if err != nil {
        return fmt.Errorf("failed to prepare batch: %w", err)
    }

    for _, event := range events {
        metadata, _ := json.Marshal(event.Metadata)

        actorType := "unknown"
        actorID := ""
        actorName := ""
        actorEmail := ""
        actorIP := ""

        if event.Actor != nil {
            actorType = string(event.Actor.Type)
            actorID = event.Actor.ID
            actorName = event.Actor.Name
            actorEmail = event.Actor.Email
            actorIP = event.Actor.IPAddress
        }

        err := batch.Append(
            event.EventID,
            event.TenantID,
            event.Timestamp,
            event.ReceivedAt,
            event.Source.Product,
            event.Source.Host,
            event.Source.InstanceID,
            event.Source.Version,
            actorType,
            actorID,
            actorName,
            actorEmail,
            actorIP,
            event.Action,
            event.Target,
            string(event.Outcome),
            event.Severity,
            event.SchemaVersion,
            event.Raw,
            string(metadata),
        )
        if err != nil {
            return fmt.Errorf("failed to append event: %w", err)
        }
    }

    return batch.Send()
}

func (bw *BatchWriter) Flush() error {
    bw.mu.Lock()
    defer bw.mu.Unlock()
    return bw.flushLocked()
}

func (bw *BatchWriter) Close() error {
    bw.flushTimer.Stop()
    close(bw.done)
    return bw.Flush()
}

func (bw *BatchWriter) Metrics() (written, failed, batches uint64) {
    bw.mu.Lock()
    defer bw.mu.Unlock()
    return bw.totalWritten, bw.totalFailed, bw.batchCount
}
```

### 6. Quarantine Writer

```go
// internal/storage/quarantine.go
package storage

import (
    "context"
    "fmt"
    "time"

    "github.com/google/uuid"
)

type QuarantineEntry struct {
    RawEvent         string
    SourceIP         string
    SourceFormat     string
    ValidationErrors []string
    ErrorCode        string
}

type QuarantineWriter struct {
    client *ClickHouseClient
}

func NewQuarantineWriter(client *ClickHouseClient) *QuarantineWriter {
    return &QuarantineWriter{client: client}
}

func (qw *QuarantineWriter) Write(ctx context.Context, entry *QuarantineEntry) error {
    query := `
        INSERT INTO events_quarantine (
            quarantine_id, raw_event, source_ip, source_format,
            validation_errors, error_code
        ) VALUES (?, ?, ?, ?, ?, ?)
    `

    return qw.client.Conn().Exec(ctx, query,
        uuid.New(),
        entry.RawEvent,
        entry.SourceIP,
        entry.SourceFormat,
        entry.ValidationErrors,
        entry.ErrorCode,
    )
}

func (qw *QuarantineWriter) WriteBatch(ctx context.Context, entries []*QuarantineEntry) error {
    batch, err := qw.client.Conn().PrepareBatch(ctx, `
        INSERT INTO events_quarantine (
            quarantine_id, raw_event, source_ip, source_format,
            validation_errors, error_code
        )
    `)
    if err != nil {
        return fmt.Errorf("failed to prepare quarantine batch: %w", err)
    }

    for _, entry := range entries {
        err := batch.Append(
            uuid.New(),
            entry.RawEvent,
            entry.SourceIP,
            entry.SourceFormat,
            entry.ValidationErrors,
            entry.ErrorCode,
        )
        if err != nil {
            return fmt.Errorf("failed to append quarantine entry: %w", err)
        }
    }

    return batch.Send()
}

// GetPendingReprocess returns quarantined events that haven't been reprocessed
func (qw *QuarantineWriter) GetPendingReprocess(ctx context.Context, limit int) ([]QuarantineEntry, error) {
    query := `
        SELECT raw_event, source_ip, source_format, validation_errors, error_code
        FROM events_quarantine
        WHERE reprocessed = false AND reprocess_attempts < 3
        ORDER BY quarantined_at ASC
        LIMIT ?
    `

    rows, err := qw.client.Conn().Query(ctx, query, limit)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var entries []QuarantineEntry
    for rows.Next() {
        var entry QuarantineEntry
        if err := rows.Scan(
            &entry.RawEvent,
            &entry.SourceIP,
            &entry.SourceFormat,
            &entry.ValidationErrors,
            &entry.ErrorCode,
        ); err != nil {
            return nil, err
        }
        entries = append(entries, entry)
    }

    return entries, nil
}
```

### 7. Queue Consumer

```go
// internal/consumer/queue_consumer.go
package consumer

import (
    "context"
    "log/slog"
    "sync"
    "time"

    "boundary-siem/internal/queue"
    "boundary-siem/internal/storage"
)

type QueueConsumerConfig struct {
    Workers       int
    PollInterval  time.Duration
    ShutdownWait  time.Duration
}

type QueueConsumer struct {
    queue       *queue.RingBuffer
    batchWriter *storage.BatchWriter
    config      QueueConsumerConfig

    wg     sync.WaitGroup
    done   chan struct{}

    // Metrics
    consumed uint64
    errors   uint64
}

func NewQueueConsumer(
    q *queue.RingBuffer,
    bw *storage.BatchWriter,
    cfg QueueConsumerConfig,
) *QueueConsumer {
    return &QueueConsumer{
        queue:       q,
        batchWriter: bw,
        config:      cfg,
        done:        make(chan struct{}),
    }
}

func (c *QueueConsumer) Start(ctx context.Context) {
    for i := 0; i < c.config.Workers; i++ {
        c.wg.Add(1)
        go c.worker(ctx, i)
    }

    slog.Info("queue consumer started", "workers", c.config.Workers)
}

func (c *QueueConsumer) worker(ctx context.Context, id int) {
    defer c.wg.Done()

    slog.Debug("consumer worker started", "worker_id", id)

    for {
        select {
        case <-ctx.Done():
            return
        case <-c.done:
            return
        default:
            event, err := c.queue.Pop()
            if err != nil {
                // Queue empty, wait before polling again
                time.Sleep(c.config.PollInterval)
                continue
            }

            if err := c.batchWriter.Write(event); err != nil {
                slog.Error("failed to write event",
                    "worker_id", id,
                    "event_id", event.EventID,
                    "error", err,
                )
                c.errors++
                continue
            }

            c.consumed++
        }
    }
}

func (c *QueueConsumer) Stop() {
    close(c.done)

    // Wait for workers with timeout
    done := make(chan struct{})
    go func() {
        c.wg.Wait()
        close(done)
    }()

    select {
    case <-done:
        slog.Info("queue consumer stopped gracefully")
    case <-time.After(c.config.ShutdownWait):
        slog.Warn("queue consumer shutdown timed out")
    }

    // Final flush
    c.batchWriter.Flush()
}

func (c *QueueConsumer) Metrics() (consumed, errors uint64) {
    return c.consumed, c.errors
}
```

### 8. Database Migrator

```go
// internal/storage/migrations/migrator.go
package migrations

import (
    "context"
    "embed"
    "fmt"
    "log/slog"
    "sort"
    "strings"

    "boundary-siem/internal/storage"
)

//go:embed *.sql
var migrationFiles embed.FS

type Migration struct {
    Version int
    Name    string
    SQL     string
}

type Migrator struct {
    client *storage.ClickHouseClient
}

func NewMigrator(client *storage.ClickHouseClient) *Migrator {
    return &Migrator{client: client}
}

func (m *Migrator) Run(ctx context.Context) error {
    // Create migrations tracking table
    if err := m.createMigrationsTable(ctx); err != nil {
        return fmt.Errorf("failed to create migrations table: %w", err)
    }

    // Load migrations
    migrations, err := m.loadMigrations()
    if err != nil {
        return fmt.Errorf("failed to load migrations: %w", err)
    }

    // Get applied migrations
    applied, err := m.getAppliedMigrations(ctx)
    if err != nil {
        return fmt.Errorf("failed to get applied migrations: %w", err)
    }

    // Run pending migrations
    for _, migration := range migrations {
        if applied[migration.Version] {
            slog.Debug("migration already applied", "version", migration.Version, "name", migration.Name)
            continue
        }

        slog.Info("applying migration", "version", migration.Version, "name", migration.Name)

        if err := m.client.Conn().Exec(ctx, migration.SQL); err != nil {
            return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
        }

        if err := m.recordMigration(ctx, migration.Version, migration.Name); err != nil {
            return fmt.Errorf("failed to record migration %d: %w", migration.Version, err)
        }

        slog.Info("migration applied", "version", migration.Version, "name", migration.Name)
    }

    return nil
}

func (m *Migrator) createMigrationsTable(ctx context.Context) error {
    query := `
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version UInt32,
            name String,
            applied_at DateTime DEFAULT now()
        )
        ENGINE = MergeTree()
        ORDER BY version
    `
    return m.client.Conn().Exec(ctx, query)
}

func (m *Migrator) loadMigrations() ([]Migration, error) {
    entries, err := migrationFiles.ReadDir(".")
    if err != nil {
        return nil, err
    }

    var migrations []Migration
    for _, entry := range entries {
        if !strings.HasSuffix(entry.Name(), ".sql") {
            continue
        }

        content, err := migrationFiles.ReadFile(entry.Name())
        if err != nil {
            return nil, err
        }

        // Parse version from filename (e.g., 001_create_events.sql)
        var version int
        var name string
        fmt.Sscanf(entry.Name(), "%03d_%s", &version, &name)
        name = strings.TrimSuffix(name, ".sql")

        migrations = append(migrations, Migration{
            Version: version,
            Name:    name,
            SQL:     string(content),
        })
    }

    sort.Slice(migrations, func(i, j int) bool {
        return migrations[i].Version < migrations[j].Version
    })

    return migrations, nil
}

func (m *Migrator) getAppliedMigrations(ctx context.Context) (map[int]bool, error) {
    rows, err := m.client.Conn().Query(ctx, "SELECT version FROM schema_migrations")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    applied := make(map[int]bool)
    for rows.Next() {
        var version int
        if err := rows.Scan(&version); err != nil {
            return nil, err
        }
        applied[version] = true
    }

    return applied, nil
}

func (m *Migrator) recordMigration(ctx context.Context, version int, name string) error {
    return m.client.Conn().Exec(ctx,
        "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
        version, name,
    )
}
```

### 9. Configuration Updates

```yaml
# configs/config.example.yaml (additions)

storage:
  clickhouse:
    hosts:
      - "localhost:9000"
    database: siem
    username: default
    password: ""
    max_open_conns: 10
    max_idle_conns: 5
    conn_max_lifetime: 1h
    tls_enabled: false

  batch_writer:
    batch_size: 1000
    flush_interval: 5s
    max_retries: 3
    retry_delay: 1s

consumer:
  workers: 4
  poll_interval: 10ms
  shutdown_wait: 30s
```

### 10. Docker Compose for ClickHouse

```yaml
# deployments/clickhouse/docker-compose.yaml
version: '3.8'

services:
  clickhouse:
    image: clickhouse/clickhouse-server:23.8
    container_name: siem-clickhouse
    ports:
      - "8123:8123"   # HTTP interface
      - "9000:9000"   # Native interface
      - "9009:9009"   # Interserver (for clusters)
    volumes:
      - clickhouse_data:/var/lib/clickhouse
      - clickhouse_logs:/var/log/clickhouse-server
      - ./config.xml:/etc/clickhouse-server/config.d/custom.xml:ro
      - ./users.xml:/etc/clickhouse-server/users.d/custom.xml:ro
    environment:
      - CLICKHOUSE_DB=siem
      - CLICKHOUSE_USER=siem
      - CLICKHOUSE_PASSWORD=siem_password
    ulimits:
      nofile:
        soft: 262144
        hard: 262144
    healthcheck:
      test: ["CMD", "clickhouse-client", "--query", "SELECT 1"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  clickhouse_data:
  clickhouse_logs:
```

```xml
<!-- deployments/clickhouse/config.xml -->
<clickhouse>
    <logger>
        <level>information</level>
        <console>1</console>
    </logger>

    <max_connections>4096</max_connections>
    <keep_alive_timeout>3</keep_alive_timeout>
    <max_concurrent_queries>100</max_concurrent_queries>

    <merge_tree>
        <max_suspicious_broken_parts>5</max_suspicious_broken_parts>
    </merge_tree>

    <!-- Compression settings -->
    <compression>
        <case>
            <min_part_size>10000000000</min_part_size>
            <min_part_size_ratio>0.01</min_part_size_ratio>
            <method>zstd</method>
            <level>3</level>
        </case>
    </compression>
</clickhouse>
```

```xml
<!-- deployments/clickhouse/users.xml -->
<clickhouse>
    <users>
        <siem>
            <password>siem_password</password>
            <networks>
                <ip>::/0</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
        </siem>
    </users>
</clickhouse>
```

### 11. Updated Main Entry Point

```go
// cmd/siem-ingest/main.go (updated)
package main

import (
    "context"
    "log/slog"
    "os"
    "os/signal"
    "syscall"

    "boundary-siem/internal/config"
    "boundary-siem/internal/consumer"
    "boundary-siem/internal/ingest"
    "boundary-siem/internal/queue"
    "boundary-siem/internal/schema"
    "boundary-siem/internal/storage"
    "boundary-siem/internal/storage/migrations"
)

func main() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Load config
    cfg, err := config.Load()
    if err != nil {
        slog.Error("failed to load config", "error", err)
        os.Exit(1)
    }

    // Initialize ClickHouse
    chClient, err := storage.NewClickHouseClient(cfg.Storage.ClickHouse)
    if err != nil {
        slog.Error("failed to connect to ClickHouse", "error", err)
        os.Exit(1)
    }
    defer chClient.Close()

    // Run migrations
    migrator := migrations.NewMigrator(chClient)
    if err := migrator.Run(ctx); err != nil {
        slog.Error("failed to run migrations", "error", err)
        os.Exit(1)
    }

    // Initialize components
    validator := schema.NewValidator()
    eventQueue := queue.NewRingBuffer(cfg.Queue.Size)
    batchWriter := storage.NewBatchWriter(chClient, cfg.Storage.BatchWriter)
    quarantine := storage.NewQuarantineWriter(chClient)

    handler := ingest.NewHandler(validator, eventQueue, quarantine)

    // Start queue consumer
    queueConsumer := consumer.NewQueueConsumer(eventQueue, batchWriter, cfg.Consumer)
    queueConsumer.Start(ctx)

    // Setup and start HTTP server
    server := setupHTTPServer(cfg, handler)
    go startHTTPServer(server)

    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    slog.Info("shutting down...")
    cancel()

    server.Shutdown(context.Background())
    queueConsumer.Stop()
    batchWriter.Close()

    slog.Info("shutdown complete")
}
```

---

## Testing Scripts

### Initialize ClickHouse

```bash
#!/bin/bash
# scripts/init-clickhouse.sh

set -e

echo "Starting ClickHouse..."
docker-compose -f deployments/clickhouse/docker-compose.yaml up -d

echo "Waiting for ClickHouse to be ready..."
until docker exec siem-clickhouse clickhouse-client --query "SELECT 1" > /dev/null 2>&1; do
    sleep 1
done

echo "ClickHouse is ready!"
```

### Test Queries

```bash
#!/bin/bash
# scripts/test-queries.sh

CH_HOST="localhost:8123"
CH_DB="siem"

# Count events
echo "=== Event Count ==="
curl -s "$CH_HOST/?query=SELECT%20count()%20FROM%20$CH_DB.events"

# Events by source
echo -e "\n=== Events by Source ==="
curl -s "$CH_HOST/?query=SELECT%20source_product,%20count()%20FROM%20$CH_DB.events%20GROUP%20BY%20source_product"

# Recent high-severity events
echo -e "\n=== Recent High-Severity Events ==="
curl -s "$CH_HOST/?query=SELECT%20timestamp,%20action,%20severity%20FROM%20$CH_DB.events%20WHERE%20severity%20%3E=%207%20ORDER%20BY%20timestamp%20DESC%20LIMIT%2010"

# Quarantine count
echo -e "\n=== Quarantined Events ==="
curl -s "$CH_HOST/?query=SELECT%20count()%20FROM%20$CH_DB.events_quarantine"
```

---

## Testing Checklist

### Unit Tests

- [ ] `ClickHouseClient` connects and pings successfully
- [ ] `BatchWriter` batches events correctly
- [ ] `BatchWriter` flushes on size threshold
- [ ] `BatchWriter` flushes on time interval
- [ ] `BatchWriter` retries on failure
- [ ] `QuarantineWriter` stores invalid events
- [ ] `QueueConsumer` processes events from queue
- [ ] `Migrator` applies migrations in order
- [ ] `Migrator` skips already-applied migrations

### Integration Tests

- [ ] End-to-end: HTTP ingest → queue → ClickHouse
- [ ] Batch of 10,000 events stored correctly
- [ ] Invalid events go to quarantine table
- [ ] Data persists across restarts
- [ ] Materialized views populate correctly

### Performance Tests

- [ ] Sustain 5,000 EPS for 10 minutes
- [ ] Query 24h of data in < 2 seconds
- [ ] No memory leaks under sustained load

---

## Acceptance Criteria

This step is complete when:

1. **ClickHouse running** with schema applied via migrations
2. **Queue consumer** reads from ring buffer and writes to ClickHouse
3. **Batch inserts** work with configurable size and flush interval
4. **Invalid events** are quarantined (not dropped)
5. **Materialized views** for hourly aggregations work
6. **High-severity events** are copied to critical table
7. **Metrics exposed** for monitoring batch writer performance
8. **Integration test** proves end-to-end event persistence

---

## Next Steps (Preview)

**Step 3: CEF Ingestion**
- UDP/TCP listeners for CEF format
- CEF parser with field extraction
- Normalization to canonical schema
- Integration with existing ingest pipeline

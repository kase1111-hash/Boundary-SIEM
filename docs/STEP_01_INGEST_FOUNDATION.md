# Step 1: Ingest Foundation

**Objective:** Build the foundational ingest layer with JSON HTTP ingestion and canonical event schema validation.

**Estimated Complexity:** Medium
**Dependencies:** None (this is the first step)

---

## Why Start Here?

The ingest layer is the entry point for all security events. Without it, nothing else can function. We start with:

1. **Canonical Event Schema** - Must exist before storage, correlation, or search
2. **JSON HTTP Endpoint** - Simpler than CEF, enables immediate testing
3. **Schema Validation** - Enforces data discipline from day one
4. **Backpressure Queue** - Prevents data loss under load

This provides a working foundation that can accept events from `boundary-daemon` immediately.

---

## Deliverables

### 1. Project Structure

```
boundary-siem/
├── cmd/
│   └── siem-ingest/
│       └── main.go              # Entry point
├── internal/
│   ├── schema/
│   │   ├── event.go             # Canonical event struct
│   │   ├── validator.go         # JSON Schema validation
│   │   └── validator_test.go
│   ├── ingest/
│   │   ├── http_handler.go      # HTTP POST /v1/events
│   │   ├── http_handler_test.go
│   │   └── middleware.go        # Auth, rate limiting
│   ├── queue/
│   │   ├── ring_buffer.go       # Backpressure queue
│   │   └── ring_buffer_test.go
│   └── config/
│       └── config.go            # Configuration loading
├── api/
│   └── openapi.yaml             # OpenAPI 3.0 spec
├── configs/
│   └── config.example.yaml
├── scripts/
│   └── test-ingest.sh           # Manual testing script
├── go.mod
├── go.sum
└── Makefile
```

### 2. Canonical Event Schema (Go Struct)

```go
// internal/schema/event.go
package schema

import (
    "time"
    "github.com/google/uuid"
)

// Event represents the canonical SIEM event format.
// All ingested events are normalized to this structure.
type Event struct {
    // Required fields
    EventID   uuid.UUID `json:"event_id" validate:"required"`
    Timestamp time.Time `json:"timestamp" validate:"required"`
    Source    Source    `json:"source" validate:"required"`
    Action    string    `json:"action" validate:"required,action_format"`
    Outcome   Outcome   `json:"outcome" validate:"required,oneof=success failure unknown"`
    Severity  int       `json:"severity" validate:"required,min=1,max=10"`

    // Optional fields
    Actor    *Actor            `json:"actor,omitempty"`
    Target   string            `json:"target,omitempty"`
    Raw      string            `json:"raw,omitempty"`
    Metadata map[string]any    `json:"metadata,omitempty"`

    // Internal fields (set by system)
    SchemaVersion string    `json:"schema_version"`
    ReceivedAt    time.Time `json:"received_at"`
    TenantID      string    `json:"tenant_id"`
}

type Source struct {
    Product    string `json:"product" validate:"required,max=256"`
    Host       string `json:"host,omitempty" validate:"max=256"`
    InstanceID string `json:"instance_id,omitempty" validate:"max=128"`
    Version    string `json:"version,omitempty"`
}

type Actor struct {
    Type      ActorType `json:"type,omitempty" validate:"omitempty,oneof=user process service system unknown"`
    ID        string    `json:"id,omitempty" validate:"max=256"`
    Name      string    `json:"name,omitempty" validate:"max=256"`
    Email     string    `json:"email,omitempty" validate:"omitempty,email"`
    IPAddress string    `json:"ip_address,omitempty" validate:"omitempty,ip"`
}

type Outcome string

const (
    OutcomeSuccess Outcome = "success"
    OutcomeFailure Outcome = "failure"
    OutcomeUnknown Outcome = "unknown"
)

type ActorType string

const (
    ActorUser    ActorType = "user"
    ActorProcess ActorType = "process"
    ActorService ActorType = "service"
    ActorSystem  ActorType = "system"
    ActorUnknown ActorType = "unknown"
)
```

### 3. HTTP Ingest Handler

```go
// internal/ingest/http_handler.go
package ingest

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/google/uuid"
    "boundary-siem/internal/schema"
    "boundary-siem/internal/queue"
)

type IngestHandler struct {
    validator *schema.Validator
    queue     *queue.RingBuffer
}

type IngestRequest struct {
    Events []schema.Event `json:"events"`
}

type IngestResponse struct {
    Success   bool     `json:"success"`
    Accepted  int      `json:"accepted"`
    Rejected  int      `json:"rejected"`
    Errors    []string `json:"errors,omitempty"`
    RequestID string   `json:"request_id"`
}

func (h *IngestHandler) HandleEvents(w http.ResponseWriter, r *http.Request) {
    requestID := uuid.New().String()

    // Parse request
    var req IngestRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        respondError(w, http.StatusBadRequest, "Invalid JSON", requestID)
        return
    }

    // Validate and enqueue events
    var accepted, rejected int
    var errors []string

    for i, event := range req.Events {
        // Generate event_id if missing
        if event.EventID == uuid.Nil {
            event.EventID = uuid.New()
        }

        // Set system fields
        event.ReceivedAt = time.Now().UTC()
        event.SchemaVersion = "1.0.0"

        // Validate
        if err := h.validator.Validate(&event); err != nil {
            rejected++
            errors = append(errors, fmt.Sprintf("event[%d]: %s", i, err.Error()))
            // TODO: Send to quarantine
            continue
        }

        // Enqueue for processing
        if err := h.queue.Push(&event); err != nil {
            rejected++
            errors = append(errors, fmt.Sprintf("event[%d]: queue full", i))
            continue
        }

        accepted++
    }

    respondJSON(w, http.StatusOK, IngestResponse{
        Success:   rejected == 0,
        Accepted:  accepted,
        Rejected:  rejected,
        Errors:    errors,
        RequestID: requestID,
    })
}
```

### 4. Ring Buffer Queue

```go
// internal/queue/ring_buffer.go
package queue

import (
    "errors"
    "sync"

    "boundary-siem/internal/schema"
)

var (
    ErrQueueFull  = errors.New("queue is full")
    ErrQueueEmpty = errors.New("queue is empty")
)

type RingBuffer struct {
    buffer   []*schema.Event
    size     int
    head     int
    tail     int
    count    int
    mu       sync.Mutex
    notEmpty *sync.Cond
    notFull  *sync.Cond

    // Metrics
    totalPushed  uint64
    totalPopped  uint64
    totalDropped uint64
}

func NewRingBuffer(size int) *RingBuffer {
    rb := &RingBuffer{
        buffer: make([]*schema.Event, size),
        size:   size,
    }
    rb.notEmpty = sync.NewCond(&rb.mu)
    rb.notFull = sync.NewCond(&rb.mu)
    return rb
}

func (rb *RingBuffer) Push(event *schema.Event) error {
    rb.mu.Lock()
    defer rb.mu.Unlock()

    if rb.count == rb.size {
        rb.totalDropped++
        return ErrQueueFull
    }

    rb.buffer[rb.tail] = event
    rb.tail = (rb.tail + 1) % rb.size
    rb.count++
    rb.totalPushed++

    rb.notEmpty.Signal()
    return nil
}

func (rb *RingBuffer) Pop() (*schema.Event, error) {
    rb.mu.Lock()
    defer rb.mu.Unlock()

    if rb.count == 0 {
        return nil, ErrQueueEmpty
    }

    event := rb.buffer[rb.head]
    rb.buffer[rb.head] = nil // Allow GC
    rb.head = (rb.head + 1) % rb.size
    rb.count--
    rb.totalPopped++

    rb.notFull.Signal()
    return event, nil
}

func (rb *RingBuffer) Len() int {
    rb.mu.Lock()
    defer rb.mu.Unlock()
    return rb.count
}

func (rb *RingBuffer) Metrics() (pushed, popped, dropped uint64) {
    rb.mu.Lock()
    defer rb.mu.Unlock()
    return rb.totalPushed, rb.totalPopped, rb.totalDropped
}
```

### 5. Schema Validator

```go
// internal/schema/validator.go
package schema

import (
    "fmt"
    "regexp"
    "time"

    "github.com/go-playground/validator/v10"
)

var actionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

type Validator struct {
    validate *validator.Validate
    maxAge   time.Duration
    maxFuture time.Duration
}

func NewValidator() *Validator {
    v := validator.New()

    // Register custom validation for action format
    v.RegisterValidation("action_format", func(fl validator.FieldLevel) bool {
        return actionPattern.MatchString(fl.Field().String())
    })

    return &Validator{
        validate:  v,
        maxAge:    7 * 24 * time.Hour,  // 7 days
        maxFuture: 5 * time.Minute,
    }
}

func (v *Validator) Validate(event *Event) error {
    // Struct validation
    if err := v.validate.Struct(event); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }

    // Timestamp bounds check
    now := time.Now().UTC()
    if event.Timestamp.Before(now.Add(-v.maxAge)) {
        return fmt.Errorf("timestamp too old: %v (max age: %v)", event.Timestamp, v.maxAge)
    }
    if event.Timestamp.After(now.Add(v.maxFuture)) {
        return fmt.Errorf("timestamp in future: %v (max future: %v)", event.Timestamp, v.maxFuture)
    }

    return nil
}
```

### 6. Configuration

```yaml
# configs/config.example.yaml
server:
  http_port: 8080
  read_timeout: 30s
  write_timeout: 30s

ingest:
  max_batch_size: 1000
  max_payload_size: 10485760  # 10MB

queue:
  size: 100000
  overflow_policy: drop_oldest  # drop_oldest | block | reject

validation:
  max_event_age: 168h     # 7 days
  max_future: 5m
  strict_mode: true

auth:
  api_key_header: X-API-Key
  # Keys loaded from environment or secrets manager

logging:
  level: info
  format: json
```

### 7. Main Entry Point

```go
// cmd/siem-ingest/main.go
package main

import (
    "context"
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
    // Load config
    cfg, err := config.Load()
    if err != nil {
        slog.Error("failed to load config", "error", err)
        os.Exit(1)
    }

    // Initialize components
    validator := schema.NewValidator()
    eventQueue := queue.NewRingBuffer(cfg.Queue.Size)
    handler := ingest.NewHandler(validator, eventQueue)

    // Setup HTTP server
    mux := http.NewServeMux()
    mux.HandleFunc("POST /v1/events", handler.HandleEvents)
    mux.HandleFunc("GET /health", handler.HealthCheck)
    mux.HandleFunc("GET /metrics", handler.Metrics)

    server := &http.Server{
        Addr:         fmt.Sprintf(":%d", cfg.Server.HTTPPort),
        Handler:      ingest.WithMiddleware(mux, cfg),
        ReadTimeout:  cfg.Server.ReadTimeout,
        WriteTimeout: cfg.Server.WriteTimeout,
    }

    // Start server
    go func() {
        slog.Info("starting ingest server", "port", cfg.Server.HTTPPort)
        if err := server.ListenAndServe(); err != http.ErrServerClosed {
            slog.Error("server error", "error", err)
            os.Exit(1)
        }
    }()

    // Start queue consumer (placeholder for Step 2: Storage)
    go consumeQueue(eventQueue)

    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    slog.Info("shutting down...")
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    server.Shutdown(ctx)
    slog.Info("server stopped")
}

func consumeQueue(q *queue.RingBuffer) {
    // Placeholder: In Step 2, this will write to ClickHouse
    for {
        event, err := q.PopBlocking()
        if err != nil {
            continue
        }
        slog.Debug("event received", "event_id", event.EventID, "action", event.Action)
    }
}
```

---

## API Specification

### POST /v1/events

**Request:**
```http
POST /v1/events HTTP/1.1
Host: localhost:8080
Content-Type: application/json
X-API-Key: sk_test_xxxxxxxxxxxx

{
  "events": [
    {
      "timestamp": "2026-01-01T12:00:00Z",
      "source": {
        "product": "boundary-daemon",
        "host": "prod-server-01"
      },
      "action": "session.created",
      "actor": {
        "type": "user",
        "id": "user_123"
      },
      "target": "database:prod-db",
      "outcome": "success",
      "severity": 3
    }
  ]
}
```

**Response (Success):**
```json
{
  "success": true,
  "accepted": 1,
  "rejected": 0,
  "request_id": "req_abc123"
}
```

**Response (Partial Failure):**
```json
{
  "success": false,
  "accepted": 1,
  "rejected": 1,
  "errors": [
    "event[1]: validation failed: severity must be between 1 and 10"
  ],
  "request_id": "req_abc123"
}
```

### GET /health

```json
{
  "status": "healthy",
  "queue_depth": 1234,
  "uptime_seconds": 3600
}
```

---

## Testing Checklist

### Unit Tests

- [ ] `schema.Validator` correctly validates all required fields
- [ ] `schema.Validator` rejects invalid action formats
- [ ] `schema.Validator` rejects timestamps outside bounds
- [ ] `queue.RingBuffer.Push` adds events correctly
- [ ] `queue.RingBuffer.Pop` returns events in order
- [ ] `queue.RingBuffer` handles full queue correctly
- [ ] `ingest.Handler` accepts valid single event
- [ ] `ingest.Handler` accepts valid batch of events
- [ ] `ingest.Handler` rejects malformed JSON
- [ ] `ingest.Handler` generates event_id when missing

### Integration Tests

- [ ] End-to-end: POST event → validate → queue
- [ ] Batch of 1000 events processed correctly
- [ ] Invalid events are rejected with proper error messages
- [ ] Rate limiting works (if implemented)
- [ ] API key authentication works

### Manual Testing Script

```bash
#!/bin/bash
# scripts/test-ingest.sh

API_URL="http://localhost:8080"
API_KEY="sk_test_development"

# Test single event
curl -X POST "$API_URL/v1/events" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "events": [{
      "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
      "source": {"product": "test-client"},
      "action": "test.ping",
      "outcome": "success",
      "severity": 1
    }]
  }'

# Test batch events
curl -X POST "$API_URL/v1/events" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "events": [
      {"timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'", "source": {"product": "boundary-daemon"}, "action": "auth.login", "outcome": "success", "severity": 2},
      {"timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'", "source": {"product": "boundary-daemon"}, "action": "auth.failure", "outcome": "failure", "severity": 5}
    ]
  }'

# Test health endpoint
curl "$API_URL/health"
```

---

## Acceptance Criteria

This step is complete when:

1. **HTTP server starts** and accepts connections on port 8080
2. **POST /v1/events** accepts JSON events and validates them
3. **Schema validation** rejects invalid events with clear error messages
4. **Event ID generation** works for events without an ID
5. **Ring buffer queue** stores validated events for downstream processing
6. **Health endpoint** returns queue depth and status
7. **Unit tests** pass with >80% coverage on new code
8. **Integration test** demonstrates end-to-end event flow

---

## Next Steps (Preview)

**Step 2: Storage Engine**
- ClickHouse schema creation
- Queue consumer that writes to ClickHouse
- Batch inserts for efficiency
- Basic health checks for storage

**Step 3: CEF Ingestion**
- UDP/TCP listeners
- CEF parser
- Normalization to canonical schema

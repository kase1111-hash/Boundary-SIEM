# Boundary-SIEM

Blockchain-native Security Information and Event Management (SIEM) platform designed for decentralized infrastructure, validator networks, and AI agent ecosystems.

## Tech Stack

- **Language**: Go 1.26 (`go.mod`: `go 1.26.0`, toolchain `go1.26.8`)
- **Database**: ClickHouse (events, quarantine, alerts; tested with 23.8)
- **Queue**: In-process ring buffer (100K events, backpressure)
- **TUI Framework**: Charmbracelet (Bubbletea + Lipgloss)
- **Web Dashboard**: React 18 + Vite + TypeScript + Tailwind (Node.js 22.12+)
- **Parsing**: CEF, JSON, EVM JSON-RPC

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│              USER INTERFACES                         │
│  ├─ Terminal UI (TUI) - Dashboard & Event Browser    │
│  ├─ Web dashboard (served at / when web_dir is set)  │
│  ├─ REST API (/v1/*, X-API-Key)                      │
│  └─ WebSocket (/ws/events: alerts and stats)         │
├─────────────────────────────────────────────────────┤
│          siem-ingest (one process, internal/app)     │
│  ├─ JSON HTTP ingestion (POST /v1/events)            │
│  ├─ CEF listeners (UDP 5514 / TCP 5515 / DTLS 5516)  │
│  ├─ EVM JSON-RPC poller                              │
│  ├─ Schema validation, rejects -> events_quarantine  │
│  ├─ Ring buffer -> consumer -> correlation + storage │
│  ├─ Correlation engine (138 rules loaded)            │
│  └─ Alerting (log/webhook/slack/discord/pagerduty/   │
│     email/telegram) + escalation                     │
├─────────────────────────────────────────────────────┤
│            STORAGE                                   │
│  └─ ClickHouse: events, events_quarantine, alerts    │
│     (TTL retention, migrations at startup)           │
└─────────────────────────────────────────────────────┘
```

**Three entry points:**
- `cmd/siem-ingest/` - Server; a thin wrapper around `internal/app`
- `cmd/boundary-siem/` - Terminal UI client (`-server`, `-api-key` or `SIEM_API_KEY`)
- `cmd/siem-rules/` - YAML rule validator (`validate`, `list`)

Rules loaded at startup: 130 built-in detection rules (`internal/detection/rules`)
+ 3 kill chains (`correlation.BuiltinChains`) + 5 community YAML rules
(`rules/*.yaml`, seeded into `correlation.rules_dir`) = 138.

## Directory Structure

```
boundary-siem/
├── cmd/
│   ├── siem-ingest/          # Server entry point
│   ├── boundary-siem/        # TUI client entry point
│   └── siem-rules/           # Rule validator CLI
├── internal/
│   ├── app/                  # Server assembly, routes, /health, /ready, shutdown
│   ├── ingest/               # HTTP handler, middleware (auth, CORS), CEF servers, EVM poller, quarantine
│   ├── schema/               # Canonical event schema + validator
│   ├── queue/                # Ring buffer queue (backpressure)
│   ├── consumer/             # Queue consumer -> storage + correlation
│   ├── storage/              # ClickHouse client, batch writer, migrations, retention
│   ├── search/               # Query parser/executor, search API
│   ├── correlation/          # Correlation engine, baselines, chaining, rules API
│   ├── detection/rules/      # 130 built-in detection rules
│   ├── alerting/             # Alert manager, channels, escalation, ClickHouse persistence
│   ├── ws/                   # WebSocket hub
│   ├── middleware/           # Rate limiting
│   ├── config/               # Configuration loading + env overrides
│   ├── startup/              # Startup diagnostics
│   ├── errors/               # Production error sanitization
│   └── tui/                  # Terminal User Interface
├── web/                      # React dashboard
├── rules/                    # Community YAML rules
├── deploy/                   # Dockerfile, compose, Kubernetes, systemd, security policies
├── deployments/clickhouse/   # Docker Compose for ClickHouse
├── configs/                  # config.yaml
└── docs/                     # Documentation & roadmap
```

Not used by `siem-ingest` yet (library code with tests only): `internal/api`
(OAuth/SAML/OIDC/LDAP, RBAC, Redis sessions, dashboard, reports),
`internal/blockchain`, `internal/kafka`, `internal/storage/s3`,
`internal/security` (audit log, TPM, USB), `internal/infrastructure`,
`internal/secrets`, `internal/encryption`, `internal/detection/playbook`,
`internal/detection/threat`. There is no GraphQL API, Redis, Kafka or S3 in
the running service.

## Development Commands

```bash
# Build
make deps           # Download dependencies
make build          # Build siem-ingest, boundary-siem and siem-rules into ./bin
make build-ingest   # Build only server
make build-tui      # Build only client
make build-rules    # Build only the rule validator

# Run (from the repository root: config paths are relative)
make run            # Run ingest service
make run-tui        # Run TUI

# Test
make test           # Full test suite with race detection
make test-coverage  # Generate coverage reports
make test-unit      # Unit tests only (-short flag)

# Quality
make lint           # go vet + golangci-lint
make security       # gosec scanner
make ci             # All checks: lint, security, test
```

## Key Modules

### Ingest Layer (`internal/ingest/`)
- `POST /v1/events`: `{"events":[...]}`, a JSON array, or one event; 200/207/400/413, 503 + `Retry-After` when the queue is full
- CEF over UDP/TCP/DTLS; rejected JSON and CEF go to `events_quarantine`
- Auth middleware: `X-API-Key`; `/health`, `/ready`, `/metrics` and the `/ws` handshakes are public
- Rate limiting: 1000 requests/min per IP (burst 50) by default

### Storage (`internal/storage/`)
- ClickHouse batch writer with retries, re-queues and dead-lettering to `events_quarantine`
- Retention TTLs: events 90d, critical 365d, quarantine 30d, alerts 365d
- Migrations run at startup; the database is created if missing

### Correlation and Detection (`internal/correlation/`, `internal/detection/rules/`)
- Threshold, sequence, aggregate and absence rules; kill chains; baselines
- 130 built-in rules (35 with MITRE ATT&CK mappings)
- Rules API (`/v1/rules`) writes custom rules and overrides to `correlation.rules_dir`

### Alerting (`internal/alerting/`)
- Channels from `alerting.notifications.channels` (default: a log channel named `default`)
- Built-in escalation policies notify `default`
- Alerts persisted to `siem.alerts` and restored on restart (in memory without storage)

## Code Conventions

### Error Handling
- Use `internal/errors` package for production error sanitization
- Errors automatically strip paths, IPs, and SQL details in production mode
- Return safe error messages for user-facing responses

### Configuration
- YAML config in `configs/config.yaml` (`SIEM_CONFIG_PATH` overrides the path)
- Environment overrides use the `SIEM_` prefix (`SIEM_API_KEY`, `SIEM_HTTP_PORT`, `SIEM_STORAGE_ENABLED`, `SIEM_RULES_DIR`, `SIEM_WEB_DIR`, `SIEM_SHUTDOWN_TIMEOUT`, ...) plus `CLICKHOUSE_HOST/DATABASE/USER/PASSWORD`
- Notification secrets may be `${ENV_VAR}` references

### Testing
- Table-driven tests preferred
- Run with `-race` flag for race detection
- Mock external services; ClickHouse integration tests run only when `CLICKHOUSE_TEST_ADDR` (host:port) is set

### API Design
- RESTful endpoints under `/v1/*`
- JSON request/response
- Consistent error format with status codes

## Common Tasks

### Adding a New Detection Rule
1. Add a YAML rule under `rules/` and validate it with `./bin/siem-rules validate ./rules/`, or
2. Add a built-in rule in `internal/detection/rules/` (map it to MITRE ATT&CK where it applies)
3. Add tests in the corresponding `_test.go` file
4. Run `make test` to verify

### Adding a New API Endpoint
1. Define the handler in its package (`internal/search`, `internal/alerting`, `internal/correlation`, ...)
2. Register the route in `internal/app/app.go` (`initHTTP`)
3. Routes are authenticated by default; public paths are listed in `internal/ingest/middleware.go`
4. Add tests (see `internal/app/app_test.go`)

### Modifying Event Schema
1. Update schema in `internal/schema/`
2. Add migration in `internal/storage/migrations/`
3. Update normalizers in `internal/ingest/`
4. Run full test suite

## Testing Requirements

- All PRs must pass `make ci` (lint + security + tests)
- Security scanning: gosec, govulncheck, Trivy
- Zero vulnerabilities policy enforced
- Coverage reports generated with `make test-coverage`

## Environment Setup

```bash
# Start ClickHouse (set CLICKHOUSE_PASSWORD in deployments/clickhouse/.env first)
docker compose -f deployments/clickhouse/docker-compose.yaml up -d

# Build and run
make deps
make build
export SIEM_API_KEY=dev-key-change-me CLICKHOUSE_USER=siem CLICKHOUSE_PASSWORD=<password>
make run      # Start server (terminal 1)
make run-tui  # Start TUI (terminal 2; reads SIEM_API_KEY)
```

## Sample Event Ingestion

```bash
curl -s -X POST http://localhost:8080/v1/events \
  -H "X-API-Key: $SIEM_API_KEY" -H 'Content-Type: application/json' \
  -d '{"timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","source":{"product":"my-app","host":"web-01"},"action":"auth.login","outcome":"failure","severity":5,"actor":{"type":"user","id":"alice","ip_address":"203.0.113.7"}}'
```

# Boundary SIEM

![Version](https://img.shields.io/badge/version-1.0.0--beta-blue)
![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)
![License](https://img.shields.io/badge/license-MIT-green)

A focused **Security Information and Event Management (SIEM)** platform designed for blockchain infrastructure. Boundary-SIEM provides real-time event ingestion, correlation-based detection, and alerting. Out of the box it loads **138 rules**: 130 built-in detection rules (validators, consensus, transactions, smart contracts, MEV, DeFi, exchanges, infrastructure and cross-system threats), 3 kill-chain rules and 5 community YAML rules.

## Architecture

```
+----------------------------------------------------+
|       Web Dashboard (React)  |  Terminal UI        |
|  Alert Triage | Event Search | Rule Manager | Live |
+----------------------------------------------------+
|     REST API (X-API-Key)  +  WebSocket stream      |
| /v1/events | /v1/search | /v1/alerts | /v1/rules   |
| /health | /ready | /metrics | /ws/events           |
+----------------------------------------------------+
|            Ingestion Layer                         |
| JSON HTTP | CEF (UDP/TCP/DTLS) | EVM JSON-RPC      |
| Schema validation -> rejects quarantined           |
+----------------------------------------------------+
|     Ring buffer queue (100K, backpressure)         |
+----------------------------------------------------+
|  Correlation Engine         |  Storage + Search    |
|  Threshold | Sequence       |  ClickHouse (TTL,    |
|  Aggregate | Absence | Chain|  partitioned, FTS):  |
|  130 built-in + 3 chains    |  events, quarantine, |
|  + custom YAML rules        |  alerts              |
+----------------------------------------------------+
|            Alerting + Escalation                   |
| Log | Webhook | Slack | Discord | PagerDuty        |
| Email | Telegram | Dedup | Escalation policies     |
+----------------------------------------------------+
```

Everything above runs in one process, `siem-ingest`. Every accepted event goes
HTTP/CEF/EVM -> queue -> consumer -> correlation engine and ClickHouse.

## Features

### Event Ingestion
- **JSON HTTP**: `POST /v1/events` with schema validation. Accepts `{"events":[...]}`, a JSON array, or a single event object; answers 200 (all accepted), 207 (partial), 400, 413, or 503 with `Retry-After` when the queue is full or the server is shutting down
- **CEF (Common Event Format)**: UDP, TCP (optional TLS) and DTLS transports with configurable workers
- **EVM JSON-RPC**: Multi-chain blockchain poller (Ethereum, Polygon, etc.) that normalizes blocks and transactions to the canonical event schema
- **Quarantine**: Rejected JSON and CEF events (parse or validation failures) are stored in the `events_quarantine` table with the error, the sender's IP and the raw payload (storage enabled)
- **Ring buffer queue**: 100K-event backpressure-safe queue between ingestion, correlation and storage

### Correlation Engine
- **Rule types**: Threshold, Sequence, Aggregate and Absence, plus kill chains built from sequences of rule alerts
- **Behavioral baselines**: Rules with a `baseline` block get rolling P50/P95/P99 statistics and adaptive thresholds after a warmup period
- **Rule chaining**: Fired alerts are re-injected as synthetic events, enabling multi-stage attack chain detection
- **3 built-in kill chains**: Recon-Exploit-Drain, Credential Theft, Validator Compromise
- **Rule management**: Custom rules and built-in rule toggles made through the API persist under `correlation.rules_dir`

### Detection Rules (138 loaded by default)
| Category | Rules | Examples |
|----------|-------|---------|
| Validator | 10 | Slashing, double/surround votes, missed attestations, sync committee |
| Consensus | 8 | Sync failures, finality delay, reorgs, invalid blocks |
| Transactions | 8 | Large transfers, gas anomalies, failed-transaction bursts, nonce gaps |
| Smart contracts | 10 | Ownership/proxy changes, unlimited approvals, flash loans, reentrancy |
| MEV | 8 | Sandwich, front/back-running, JIT liquidity |
| DeFi | 7 | Liquidity removal, oracle manipulation, stablecoin depeg |
| Exchange | 6 | Withdrawal volume, hot wallet balance, wash trading |
| Infrastructure | 8 | CPU/memory/disk, crashes, certificate expiry |
| Security, API, network | 18 | RPC abuse, SSH brute force, key export, port scans, API key abuse |
| Key management, cloud, compliance | 20 | Key import/rotation, IAM policy changes, OFAC-sanctioned addresses, mixers |
| Cross-system ecosystem | 27 | Multi-system auth failures, data exfiltration chains, chain integrity, agent anomalies |
| Kill chains | 3 | Multi-stage chains built on the rules above |
| Community YAML | 5 | `rules/*.yaml` (brute-force login, EVM transfers, recon-then-exploit, ...) |

Rules can carry MITRE ATT&CK mappings; 35 of the built-in rules do.

### Alerting and Escalation
- **7 notification channel types**: Log, Webhook, Slack, Discord, PagerDuty, Email (SMTP), Telegram, configured under `alerting.notifications.channels`; secrets may be `${ENV_VAR}` references
- **Deduplication**: 15-minute window (configurable) prevents alert fatigue from repeated rule matches
- **Escalation policies**: Built-in time-based policies re-notify the channel named `default` when critical alerts stay unacknowledged (15 min, 30 min, 1 h) and high alerts (30 min, 2 h)
- **Alert lifecycle**: Acknowledge, resolve, notes and assignment through the API, pushed live to WebSocket clients
- **Persistence**: Alerts are stored in ClickHouse (`siem.alerts`) and restored on restart. Without storage they are kept in memory only

### Storage and Search
- **ClickHouse**: Time-partitioned MergeTree tables with Bloom filter indexes, full-text search on raw events
- **Retention policies**: TTLs applied at startup (events: 90d, critical: 365d, quarantine: 30d, alerts: 365d)
- **Query engine**: Field-based, time-range and boolean queries with parentheses, quoted phrases, aggregations and EXPLAIN support
- **Schema migrations**: The database is created and migrated automatically at startup
- **Back-pressure and retries**: Failed batch writes are retried and re-queued; events that keep failing are dead-lettered to `events_quarantine`

### Web Dashboard
- **React 18 SPA**: Vite + TypeScript + Tailwind CSS, served by `siem-ingest` when `server.web_dir` is set
- **Alert triage**: Filterable alert list, bulk acknowledge/resolve, assignment, notes, MITRE ATT&CK display
- **Event search**: Query bar with field suggestions, saved searches, time histogram, expandable result rows
- **Rule management**: List, enable/disable, test, create/edit custom rules via JSON editor
- **Real-time**: WebSocket connection with auto-reconnect and connection status indicator
- Asks for the API key in the browser and keeps it in session storage (or local storage, if you choose)

### Terminal UI (TUI)
- Real-time dashboard with health status, event metrics, and queue statistics
- Events browser with storage-backed search
- System information panel
- Cross-platform (Windows, macOS, Linux)

## Quick Start

### Prerequisites
- Go 1.26+ (`go.mod` declares `go 1.26.0`)
- ClickHouse 23.8+ for storage, search and alert persistence (tested with 23.8). Without it, events are still correlated and alerts kept in memory
- Node.js 22.12+ (only to build or develop the web dashboard)

### Build

```bash
git clone https://github.com/kase1111-hash/Boundary-SIEM.git
cd Boundary-SIEM

# Build all binaries to ./bin/: siem-ingest (server), boundary-siem (TUI), siem-rules (rule validator)
make build
```

### Start ClickHouse

```bash
cp deployments/clickhouse/.env.example deployments/clickhouse/.env   # then set CLICKHOUSE_PASSWORD
docker compose -f deployments/clickhouse/docker-compose.yaml up -d
```

`siem-ingest` connects over the native protocol (port 9000), creates the
database (default `siem`) and runs the migrations itself.

### Run the Server

`siem-ingest` takes no flags. It reads `configs/config.yaml` (or the file named
by `SIEM_CONFIG_PATH`), then applies environment overrides. The paths in the
config (`configs/`, `rules/`, `data/rules`) are relative, so run it from the
repository root.

```bash
export SIEM_API_KEY=dev-key-change-me        # adds an API key and enables auth
export CLICKHOUSE_HOST=localhost:9000
export CLICKHOUSE_USER=siem
export CLICKHOUSE_PASSWORD=<password from .env>
./bin/siem-ingest                            # or: make run
```

The shipped `configs/config.yaml` enables authentication with no keys, so every
API call returns 401 until a key is set through `SIEM_API_KEY` or
`auth.api_keys` (a startup warning says so). It also enables storage:
`siem-ingest` exits at startup if ClickHouse is unreachable. To run without
ClickHouse, set `storage.enabled: false`; search endpoints are then not
registered.

### Send Events

```bash
curl -s http://localhost:8080/health
curl -s http://localhost:8080/ready

# One event
curl -s -X POST http://localhost:8080/v1/events \
  -H "X-API-Key: $SIEM_API_KEY" -H 'Content-Type: application/json' \
  -d '{"timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","source":{"product":"my-app","host":"web-01"},"action":"auth.login","outcome":"failure","severity":5,"actor":{"type":"user","id":"alice","ip_address":"203.0.113.7"}}'

# A batch: -d '{"events":[{...},{...}]}'

# CEF over TCP
echo 'CEF:0|Acme|Firewall|1.0|100|Login failed|5|src=198.51.100.9 suser=bob outcome=failure' | nc -q1 localhost 5515
```

Required event fields: `timestamp` (RFC 3339, within the last 7 days and at
most 5 minutes in the future), `source.product`, `action` (lowercase dotted,
e.g. `auth.login`), `outcome` (`success`, `failure` or `unknown`) and
`severity` (1-10). Optional: `event_id`, `actor`, `network`, `target`, `raw`,
`metadata`. The tenant is always `ingest.cef.normalizer.default_tenant_id`
(default `default`); clients cannot set it.

Sending 20 or more `auth.login` failures from one `actor.ip_address` within 5
minutes raises `community-brute-force-login`.

### Search, Alerts and Rules

```bash
curl -s -H "X-API-Key: $SIEM_API_KEY" 'http://localhost:8080/v1/search?q=action:auth.login&limit=10'
curl -s -X POST -H "X-API-Key: $SIEM_API_KEY" -H 'Content-Type: application/json' \
  http://localhost:8080/v1/search -d '{"query":"outcome:failure","limit":10}'
curl -s -H "X-API-Key: $SIEM_API_KEY" http://localhost:8080/v1/stats
curl -s -H "X-API-Key: $SIEM_API_KEY" http://localhost:8080/v1/alerts
curl -s -H "X-API-Key: $SIEM_API_KEY" http://localhost:8080/v1/rules
curl -s http://localhost:8080/metrics
```

### Web Dashboard and TUI

```bash
# Dashboard: build it and let siem-ingest serve it at http://localhost:8080/
cd web && npm ci && npm run build && cd ..
SIEM_WEB_DIR=web/dist ./bin/siem-ingest
# ...or develop with the Vite dev server (proxies /v1, /api, /health and /ws to :8080)
cd web && npm run dev

# TUI (separate terminal); reads SIEM_API_KEY, or pass -api-key
./bin/boundary-siem -server http://localhost:8080

# Validate community rules
./bin/siem-rules validate ./rules/
```

The dashboard asks for the API key in the browser. With `server.web_dir` set,
the dashboard's static files are served without a key; `/v1/*` and `/api/*`
still need one.

## Authentication

API keys are sent in the `X-API-Key` header (configurable via
`auth.api_key_header`). Keys come from `auth.api_keys` and `SIEM_API_KEY`.

| Path | Key required |
|------|--------------|
| `GET /health`, `GET /ready`, `GET /metrics` | No |
| `GET /ws/events`, `GET /ws` (handshake) | No; the socket authenticates in its first message |
| Dashboard files (`server.web_dir`, GET/HEAD outside `/v1` and `/api`) | No |
| Everything under `/v1/*` and `/api/*` | Yes |

A missing or wrong key gets `401` with
`{"success":false,"error":"missing API key"}` or `"invalid API key"`.

## Configuration

The server reads `configs/config.yaml` (override with `SIEM_CONFIG_PATH`). If
the file is missing, built-in defaults are used (storage off, auth off, CEF TCP
on `:5515`) and environment overrides still apply. Key sections:

```yaml
server:
  http_port: 8080
  shutdown_timeout: 8s        # keep below the orchestrator's grace period (Docker: 10s)
  # web_dir: web/dist         # serve the built dashboard at /

ingest:
  cef:
    tcp: {enabled: true, address: ":5515"}
    udp: {enabled: false, address: ":5514"}    # plain UDP, unencrypted
    dtls: {enabled: false, address: ":5516"}   # needs cert_file/key_file
  evm:
    enabled: false
    chains:
      - {name: ethereum, chain_id: 1, rpc_url: "http://localhost:8545", enabled: false}

auth:
  enabled: true
  api_keys: []                # or SIEM_API_KEY

storage:
  enabled: true
  clickhouse:
    hosts: ["localhost:9000"]
    database: siem
  batch_writer:
    batch_size: 1000
    max_requeues: 0           # 0 = 3; then events are dead-lettered to events_quarantine

correlation:
  rules_dir: data/rules       # custom rules and overrides written by the rules API
  seed_rules_dir: rules       # copied into rules_dir on first start

alerting:
  dedup_window: 15m
  notifications:
    channels:                 # none: a log channel named "default" is used
      - name: default
        type: slack           # log | webhook | slack | discord | pagerduty | email | telegram
        url: "${SLACK_WEBHOOK_URL}"

websocket:
  enabled: true
  max_clients: 100
```

See `configs/config.yaml` for every option and its default.

### Environment Variables

| Variable | Effect |
|----------|--------|
| `SIEM_CONFIG_PATH` | Config file (default `configs/config.yaml`) |
| `SIEM_HTTP_PORT` | `server.http_port` |
| `SIEM_LOG_LEVEL` | `debug` for debug logging |
| `SIEM_API_KEY` | Adds an API key and enables auth |
| `SIEM_STORAGE_ENABLED=true` | Enables ClickHouse storage |
| `CLICKHOUSE_HOST` | `host:port` (native protocol, 9000) |
| `CLICKHOUSE_DATABASE`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD` | ClickHouse database and credentials |
| `SIEM_RULES_DIR` | `correlation.rules_dir` |
| `SIEM_SEED_RULES_DIR` | `correlation.seed_rules_dir` |
| `SIEM_WEB_DIR` | `server.web_dir` |
| `SIEM_SHUTDOWN_TIMEOUT` | `server.shutdown_timeout` (a duration such as `8s`) |
| `SIEM_CORS_ENABLED=false`, `SIEM_CORS_ORIGINS` | CORS on/off, comma-separated origins |
| `SIEM_RATELIMIT_ENABLED=false`, `SIEM_RATELIMIT_RPS`, `SIEM_RATELIMIT_BURST` | Per-IP rate limiting |
| `SIEM_DEV_MODE=true` | Disables production error sanitization |
| `SIEM_IGNORE_ERRORS=true` | Start despite failed startup diagnostics (dev mode only) |

Notification secrets in the config may reference any variable as `${NAME}`.
The `SIEM_SECRETS_*`, `VAULT_*` and `SIEM_ENCRYPTION_*` variables set config
fields for the secrets and encryption packages, which `siem-ingest` does not
use yet.

## API Reference

### Events and Search
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/events` | Ingest events (`{"events":[...]}`, an array, or one event) |
| GET | `/v1/events/{id}` | Get event by ID |
| POST | `/v1/search` | Search events (`{"query":"...","limit":N}`) |
| GET | `/v1/search?q=...&limit=N` | Search events (GET) |
| POST | `/v1/aggregations` | Aggregations (`{"query":"...","type":"terms","field":"action","top_n":5}`) |
| GET | `/v1/stats` | Event statistics |
| GET | `/v1/fields/{field}/values` | Distinct field values |
| POST | `/v1/search/explain` | Explain a query plan |

All endpoints except `POST /v1/events` need storage; without it they are not registered.

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/alerts` | List alerts (filter by status, severity, rule_id, since, until, limit, offset) |
| GET | `/v1/alerts/{id}` | Get alert by ID |
| POST | `/v1/alerts/{id}/acknowledge` | Acknowledge alert (`{"user":"..."}`) |
| POST | `/v1/alerts/{id}/resolve` | Resolve alert |
| POST | `/v1/alerts/{id}/notes` | Add note (`{"author":"...","content":"..."}`) |
| POST | `/v1/alerts/{id}/assign` | Assign alert (`{"assignee":"..."}`) |
| GET | `/v1/alerts/stats` | Alert counts by status and severity |

### Rules
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/rules` | List all rules (built-in + custom; filter by type, enabled, category) |
| GET | `/v1/rules/{id}` | Get rule details |
| POST | `/v1/rules` | Create custom rule (JSON/YAML) |
| PUT | `/v1/rules/{id}` | Update custom rule; built-in rules can only toggle `enabled` |
| DELETE | `/v1/rules/{id}` | Delete custom rule |
| POST | `/v1/rules/{id}/test` | Validate a rule and report its status |

### System
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Liveness and component status (always 200) |
| GET | `/ready` | Readiness: 200 `{"status":"ready"}` or 503 `{"status":"not_ready","reasons":[...]}` |
| GET | `/metrics` | Prometheus metrics |
| GET | `/api/system/dreaming` | Activity summary (needs the API key) |
| WS | `/ws/events` (alias `/ws`) | Live alert and stats stream |

`/health` reports `status` (`healthy` or `degraded`), the queue depth and
capacity, uptime, and `components` (storage, cef_udp, cef_tcp, cef_dtls, evm,
correlation, websocket), each `up`, `degraded`, `down` or `disabled`. Use
`/ready` for load balancers and Kubernetes readiness: it fails while shutting
down, when the queue is more than 90% full, or when an enabled component (for
example storage) is down. Storage is probed every 5 seconds.

Metrics include `siem_events_total`, `siem_events_ingested_total{transport}`,
`siem_cef_*{transport}`, `siem_queue_*`, `siem_quarantine_written_total`,
`siem_correlation_events_total`, `siem_correlation_events_dropped_total`,
`siem_correlation_rules`, `siem_alerts`, `siem_storage_*` (including
`siem_storage_up`), `siem_websocket_*`, `siem_component_up{component}` and
`siem_uptime_seconds`.

### WebSocket Protocol

1. Connect to `/ws/events` and send `{"type":"auth","api_key":"<key>"}` within 10 seconds.
2. The server answers `{"type":"auth_ok"}`, or closes with code 4401 and reason `missing API key`, `invalid API key` or `authentication required`. With auth disabled any auth message is accepted.
3. The server then pushes `{"type":"alert","data":<alert as in GET /v1/alerts/{id}>}` for new alerts and for acknowledge/resolve/notes/assign changes, and `{"type":"stats","data":<GET /v1/stats body>}` every `websocket.stats_interval` (storage only). `{"type":"ping"}` gets `{"type":"pong"}`.

Browser origins are accepted when same-origin or allowed by the CORS config.
Slow clients are disconnected (close code 1013), shutdown closes with 1001,
and beyond `websocket.max_clients` the handshake gets 503.

### Shutdown

On SIGTERM or SIGINT, `siem-ingest` stops its listeners, drains every accepted
event into storage and correlation, flushes, and exits within
`server.shutdown_timeout` (default 8s). The last log line is `shutdown complete`
with `events_accepted` and `events_lost`, or `shutdown complete with lost
events` (ERROR) if storage could not take them in time.

## Community Rules

Boundary-SIEM supports YAML-defined detection rules. The shipped rules in
`rules/` are copied into `correlation.rules_dir` (default `data/rules`) on
first start; existing files are never overwritten (delete `data/rules/.seeded`
to copy missing shipped rules again).

```yaml
id: community-evm-high-value-transfer
name: "EVM High-Value Token Transfer"
type: threshold
enabled: true
severity: 8
category: "Fund Movement"
tags: [evm, high-value]
mitre:
  tactic_id: "TA0010"
  technique_id: "T1041"
conditions:
  match:
    - field: action
      operator: eq
      value: "evm.transaction"
    - field: metadata.value_eth
      operator: gt
      value: 500
threshold:
  count: 1
  operator: gte
window: 5m
group_by: [metadata.from]
```

Validate rules before deploying:

```bash
./bin/siem-rules validate ./rules/
./bin/siem-rules list ./rules/
```

## Deployment

| Target | Files |
|--------|-------|
| Docker | `deploy/container/Dockerfile`, `deploy/container/docker-compose.yml` (siem-ingest + ClickHouse) |
| Kubernetes | `deploy/kubernetes/siem.yaml` (single replica, probes on `/health` and `/ready`) |
| systemd | `deploy/systemd/boundary-siem.service` |
| ClickHouse only | `deployments/clickhouse/docker-compose.yaml` |

```bash
export SIEM_API_KEY=... CLICKHOUSE_PASSWORD=...
docker compose -f deploy/container/docker-compose.yml up -d --build
```

Run a single `siem-ingest` instance per ClickHouse database: correlation state
and alert deduplication live in the process.

## Project Structure

```
boundary-siem/
+-- cmd/
|   +-- boundary-siem/       # TUI entry point
|   +-- siem-ingest/          # SIEM server entry point (thin wrapper around internal/app)
|   +-- siem-rules/           # Rule validation CLI
+-- internal/
|   +-- app/                  # Server assembly: pipeline, HTTP routes, health, shutdown
|   +-- alerting/             # Alert manager, notification channels, escalation, persistence
|   +-- config/               # Configuration loading, defaults, environment overrides
|   +-- consumer/             # Queue consumer workers
|   +-- correlation/          # Correlation engine, rules, baselines, chaining, rules API
|   +-- detection/rules/      # Built-in detection rules (130)
|   +-- errors/               # Error sanitization for production
|   +-- ingest/               # HTTP ingestion, CEF parser/normalizer/servers, EVM poller, quarantine
|   +-- middleware/           # Rate limiting
|   +-- queue/                # Ring buffer event queue
|   +-- schema/               # Canonical event schema
|   +-- search/               # ClickHouse query parser and executor, search API
|   +-- startup/              # Startup diagnostics
|   +-- storage/              # ClickHouse client, batch writer, migrations, retention
|   +-- ws/                   # WebSocket hub
|   +-- tui/                  # Terminal UI
+-- web/                      # React dashboard (Vite + TypeScript + Tailwind)
+-- rules/                    # Community YAML detection rules
+-- configs/                  # Server configuration
+-- deploy/                   # Deployment configs (Docker, Kubernetes, systemd, security)
+-- deployments/              # Docker Compose for ClickHouse
+-- scripts/                  # Test and utility scripts
+-- docs/                     # Technical documentation and roadmaps
```

The repository also holds packages that `siem-ingest` does not use yet:
`internal/api` (OAuth/SAML/RBAC, dashboard, reports), `internal/blockchain`,
`internal/kafka`, `internal/storage/s3`, `internal/security` (audit log, TPM,
USB), `internal/infrastructure`, `internal/secrets`, `internal/encryption`,
`internal/detection/playbook` and `internal/detection/threat`.

## Testing

```bash
# Run all tests with race detection and coverage
make test

# Run unit tests only (faster, skips integration tests)
make test-unit

# Run tests with HTML coverage report
make test-coverage

# Run specific package
go test -v ./internal/correlation/...

# Run all CI checks (lint, security, test)
make ci
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure `make ci` passes (lint, security, test)
5. Validate any new rules: `./bin/siem-rules validate ./rules/`
6. Open a Pull Request

Community detection rules are welcome as YAML files in the `rules/` directory.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

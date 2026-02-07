# Boundary SIEM

![Version](https://img.shields.io/badge/version-1.0.0--beta-blue)
![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)
![License](https://img.shields.io/badge/license-MIT-green)

A focused **Security Information and Event Management (SIEM)** platform designed for blockchain infrastructure. Boundary-SIEM provides real-time event ingestion, correlation-based detection, and alerting with 143+ blockchain-specific detection rules covering validator monitoring, transaction analysis, smart contract security, and DeFi protocol threats.

## Architecture

```
+---------------------------------------------------+
|              Web Dashboard (React)                 |
|  Alert Triage | Event Search | Rule Manager | Live |
+---------------------------------------------------+
|            REST API + WebSocket                    |
| /v1/alerts  | /v1/events  | /v1/rules  | /ws      |
+---------------------------------------------------+
|            Correlation Engine                      |
| Threshold | Sequence | Aggregate | Absence | Chain |
| Static thresholds + Behavioral baselines           |
+---------------------------------------------------+
|            Detection Rules                         |
| 143 built-in blockchain rules + Custom YAML rules  |
+---------------------------------------------------+
|            Ingestion Layer                          |
| CEF (UDP/TCP/DTLS) | JSON HTTP | EVM JSON-RPC     |
+---------------------------------------------------+
|            Storage + Search                        |
| ClickHouse (FTS, partitioned, TTL) | Ring buffer   |
+---------------------------------------------------+
|            Alerting + Escalation                   |
| Webhook | Slack | PagerDuty | Email | Telegram     |
| Retry with backoff | Dead letter | Escalation      |
+---------------------------------------------------+
```

## Features

### Event Ingestion
- **CEF (Common Event Format)**: UDP, TCP, and DTLS transports with configurable workers
- **JSON HTTP**: `POST /v1/events` with schema validation and quarantine for malformed events
- **EVM JSON-RPC**: Multi-chain blockchain poller (Ethereum, Polygon, etc.) that normalizes blocks and transactions to the canonical event schema
- **Ring buffer queue**: 100K-event backpressure-safe queue between ingestion and storage

### Correlation Engine
- **5 rule types**: Threshold, Sequence, Aggregate, Absence, and Kill Chain
- **Behavioral baselines**: Rolling P50/P95/P99 statistics with adaptive thresholds and a configurable warmup period
- **Rule chaining**: Fired alerts are re-injected as synthetic events, enabling multi-stage attack chain detection
- **3 built-in kill chains**: Recon-Exploit-Drain, Credential Theft, Validator Compromise

### Detection Rules (143+)
| Category | Rules | Examples |
|----------|-------|---------|
| Validator Security | 10 | Slashing, missed attestations, sync committee |
| Transaction Analysis | 12 | Gas anomalies, large transfers, MEV |
| Smart Contract | 15 | Reentrancy, access control, upgrades |
| DeFi Security | 18 | Flash loans, oracle manipulation, liquidity |
| Bridge Security | 8 | Cross-chain exploits, signature validation |
| Governance | 6 | Voting manipulation, proposal attacks |
| Infrastructure | 7 | Node health, P2P network, RPC abuse |
| Custom YAML | - | User-contributed rules via `rules/` directory |

All built-in rules are mapped to MITRE ATT&CK techniques.

### Alerting and Escalation
- **7 notification channels**: Webhook, Slack, Discord, PagerDuty, Email (SMTP), Telegram, Log
- **Reliable delivery**: Exponential backoff retries (1s, 2s, 4s, 8s, 16s), dead letter queue for failed deliveries, per-alert delivery tracking
- **Escalation policies**: Time-based escalation chains (e.g., "if not ACK'd in 15 min, re-notify; 30 min, escalate to management")
- **Suppression windows**: Define maintenance periods where alerting is paused
- **Deduplication**: 15-minute window prevents alert fatigue from repeated rule matches

### Storage and Search
- **ClickHouse**: Time-partitioned MergeTree tables with Bloom filter indexes, full-text search on raw events
- **Retention policies**: Configurable TTLs (events: 90d, critical: 365d, quarantine: 30d, alerts: 365d)
- **Query engine**: Field-based, time-range, boolean queries with parentheses, phrase matching, aggregations, and EXPLAIN support
- **Schema migrations**: Automatic table creation and migration tracking on first startup

### Web Dashboard
- **React 18 SPA**: Vite + TypeScript + Tailwind CSS
- **Alert triage**: Filterable alert list, bulk acknowledge/resolve, assignment, notes, MITRE ATT&CK display
- **Event search**: Query bar with field autocomplete, saved searches, time histogram, expandable result rows
- **Rule management**: List, enable/disable, test, create/edit custom rules via JSON editor
- **Real-time**: WebSocket connection with auto-reconnect and connection status indicator

### Terminal UI (TUI)
- Real-time dashboard with health status, event metrics, and queue statistics
- Events browser with storage-backed search
- System information panel
- Cross-platform (Windows, macOS, Linux)

## Quick Start

### Prerequisites
- Go 1.21+
- Node.js 18+ (for web dashboard development)
- ClickHouse 23.8+ (optional, for persistent storage)

### Build and Run

```bash
# Clone
git clone https://github.com/kase1111-hash/Boundary-SIEM.git
cd Boundary-SIEM

# Build all binaries (server, TUI, rule validator)
go build ./cmd/...

# Run the SIEM server
./siem-ingest

# (Optional) Build the web dashboard
cd web && npm install && npm run build && cd ..

# Run the TUI (separate terminal)
./boundary-siem

# Validate community rules
./siem-rules validate ./rules/
```

### Send a Test Event

```bash
curl -X POST http://localhost:8080/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-02-07T10:30:00Z",
    "source": {"product": "test", "host": "node-1"},
    "action": "validator.attestation.missed",
    "outcome": "failure",
    "severity": 7
  }'
```

### Configuration

The server reads `configs/config.yaml`. Key sections:

```yaml
server:
  http_port: 8080

ingest:
  cef:
    tcp:
      enabled: true
      address: ":5515"
  evm:
    enabled: false
    poll_interval: 12s
    chains:
      - name: ethereum
        chain_id: 1
        rpc_url: "http://localhost:8545"
        enabled: false

storage:
  enabled: true
  clickhouse:
    hosts: ["localhost:9000"]
    database: siem

queue:
  size: 100000

consumer:
  workers: 4
```

## API Reference

### Events
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/events` | Ingest a JSON event |
| GET | `/v1/events/{id}` | Get event by ID |
| POST | `/v1/search` | Search events with query DSL |
| GET | `/v1/search?query=...` | Search events (GET) |
| POST | `/v1/aggregations` | Run aggregations on events |
| GET | `/v1/stats` | Event statistics |
| GET | `/v1/fields/{field}/values` | Get distinct field values |
| POST | `/v1/search/explain` | Explain a query plan |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/alerts` | List alerts (filter by status, severity, rule_id, since, until) |
| GET | `/v1/alerts/{id}` | Get alert by ID |
| POST | `/v1/alerts/{id}/acknowledge` | Acknowledge alert |
| POST | `/v1/alerts/{id}/resolve` | Resolve alert |
| POST | `/v1/alerts/{id}/notes` | Add note to alert |
| POST | `/v1/alerts/{id}/assign` | Assign alert to user |
| GET | `/v1/alerts/stats` | Alert statistics by status and severity |

### Rules
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/rules` | List all rules (built-in + custom) |
| GET | `/v1/rules/{id}` | Get rule details |
| POST | `/v1/rules` | Create custom rule (JSON/YAML) |
| PUT | `/v1/rules/{id}` | Update custom rule |
| DELETE | `/v1/rules/{id}` | Delete custom rule |
| POST | `/v1/rules/{id}/test` | Dry-run rule against recent events |

### System
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/metrics` | Prometheus metrics |
| WS | `/ws` | WebSocket event stream |

## Community Rules

Boundary-SIEM supports YAML-defined detection rules in the `rules/` directory:

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
./siem-rules validate ./rules/
./siem-rules list ./rules/
```

## Project Structure

```
boundary-siem/
+-- cmd/
|   +-- boundary-siem/       # TUI entry point
|   +-- siem-ingest/          # SIEM server entry point
|   +-- siem-rules/           # Rule validation CLI
+-- internal/
|   +-- alerting/             # Alert manager, notification channels, delivery, escalation
|   +-- api/                  # REST API (auth, dashboard, reports)
|   +-- blockchain/           # Blockchain-specific modules (validator, consensus, mempool)
|   +-- config/               # Configuration loading and defaults
|   +-- consumer/             # Queue consumer workers
|   +-- correlation/          # Correlation engine, rules, baselines, chaining
|   +-- detection/            # Detection rule definitions (143+ rules)
|   +-- encryption/           # AES-256-GCM encryption at rest
|   +-- errors/               # Error sanitization for production
|   +-- ingest/               # CEF parser/normalizer, EVM poller, HTTP ingestion
|   +-- middleware/            # Rate limiting, security headers
|   +-- queue/                # Ring buffer event queue
|   +-- schema/               # Canonical event schema
|   +-- search/               # ClickHouse query executor
|   +-- storage/              # ClickHouse client, batch writer, migrations, retention
|   +-- tui/                  # Terminal UI
+-- web/                      # React dashboard (Vite + TypeScript + Tailwind)
+-- rules/                    # Community YAML detection rules
+-- configs/                  # Server configuration
+-- deployments/              # Docker Compose for ClickHouse
```

## Testing

```bash
# Run all tests
go test ./...

# Run with race detector
go test -race ./...

# Run specific package
go test ./internal/correlation/...

# Run with coverage
go test -cover ./...
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure `go build ./cmd/...` and `go vet ./...` pass
5. Validate any new rules: `./siem-rules validate ./rules/`
6. Open a Pull Request

Community detection rules are welcome as YAML files in the `rules/` directory.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

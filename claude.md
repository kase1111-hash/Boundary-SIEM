# Boundary-SIEM

Blockchain-native Security Information and Event Management (SIEM) platform designed for decentralized infrastructure, validator networks, and AI agent ecosystems.

## Tech Stack

- **Language**: Go 1.24.7
- **Database**: ClickHouse (time-series analytics)
- **Message Queue**: Kafka
- **Session Store**: Redis
- **TUI Framework**: Charmbracelet (Bubbletea + Lipgloss)
- **Encryption**: AES-256-GCM
- **Parsing**: CEF, JSON, Syslog

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│              USER INTERFACES                         │
│  ├─ Terminal UI (TUI) - Dashboard & Event Browser  │
│  ├─ REST API (/api/v1/*)                            │
│  ├─ GraphQL (/graphql)                              │
│  └─ WebSocket (Real-time alerts)                    │
├─────────────────────────────────────────────────────┤
│          APPLICATION TIER (INGEST SERVICE)           │
│  ├─ CEF Parser (UDP 5514/TCP 5515/DTLS 5516)       │
│  ├─ JSON HTTP Ingestion                              │
│  ├─ Event Normalization & Schema Validation         │
│  ├─ Correlation Engine                               │
│  ├─ Detection Engine (143 blockchain rules)         │
│  └─ Alerting (Webhook/Slack/Email)                  │
├─────────────────────────────────────────────────────┤
│            STORAGE & PERSISTENCE LAYER               │
│  ├─ ClickHouse (Hot/Warm/Cold tiering)             │
│  ├─ Kafka (Stream buffering)                         │
│  ├─ S3 (Long-term archive)                           │
│  └─ Redis (Session management)                       │
└─────────────────────────────────────────────────────┘
```

**Two main entry points:**
- `cmd/siem-ingest/` - Backend event processing server
- `cmd/boundary-siem/` - Terminal UI client

## Directory Structure

```
boundary-siem/
├── cmd/
│   ├── siem-ingest/          # Server entry point
│   └── boundary-siem/        # TUI client entry point
├── internal/
│   ├── ingest/               # Event ingestion (CEF/JSON/syslog)
│   ├── schema/               # Canonical event schema
│   ├── storage/              # ClickHouse integration + S3 archival
│   ├── queue/                # Ring buffer queue (backpressure)
│   ├── search/               # Query execution & aggregations
│   ├── correlation/          # Correlation engine
│   ├── detection/            # Detection rules & alerting
│   ├── blockchain/           # Blockchain-specific modules
│   ├── api/                  # REST/GraphQL API + auth
│   ├── tui/                  # Terminal User Interface
│   ├── config/               # Configuration management
│   ├── encryption/           # AES-256-GCM at rest
│   ├── secrets/              # Vault/env/file secret providers
│   ├── middleware/           # Rate limiting, security headers
│   ├── enterprise/           # HA, retention, GraphQL
│   ├── infrastructure/       # Metrics, logging, observability
│   ├── security/             # Audit logging, TPM support
│   ├── advanced/             # Threat hunting, forensics, SOAR
│   └── errors/               # Production error sanitization
├── deploy/kubernetes/        # K8s manifests
├── deployments/clickhouse/   # Docker Compose for dependencies
├── configs/                  # YAML config files
└── docs/                     # Documentation & roadmap
```

## Development Commands

```bash
# Build
make deps           # Download dependencies
make build          # Build both binaries
make build-ingest   # Build only server
make build-tui      # Build only client

# Run
make run            # Run ingest service
make run-tui        # Run TUI

# Test
make test           # Full test suite with race detection
make test-coverage  # Generate coverage reports
make test-unit      # Unit tests only (-short flag)

# Quality
make lint           # golangci-lint + go vet
make security       # gosec scanner
make ci             # All checks: lint, security, test
```

## Key Modules

### Ingest Layer (`internal/ingest/`)
- CEF parser for UDP/TCP/DTLS
- JSON HTTP handler at `/v1/events`
- Ring buffer queue with backpressure (100K events)
- Rate limiting: 1000 req/min per IP

### Storage (`internal/storage/`)
- ClickHouse batch writer with retry logic
- Tiered retention: Hot (7d) → Warm (30d) → Cold (365d) → S3
- Auto-migrations with backward compatibility

### Detection (`internal/detection/`)
- 143 blockchain detection rules across 12 categories
- Rule-based correlation with time windows
- MITRE ATT&CK mapping
- Incident playbooks for automated response

### Authentication (`internal/api/auth/`)
- OAuth 2.0, SAML 2.0, OIDC, LDAP support
- MFA, RBAC (7 roles × 16 permissions)
- Redis-backed sessions with encryption
- Account lockout after 5 failed attempts

### Blockchain (`internal/blockchain/`)
- Validator monitoring and slashing detection
- Ethereum event parsing
- Smart contract analysis
- Mempool/MEV detection

## Code Conventions

### Error Handling
- Use `internal/errors` package for production error sanitization
- Errors automatically strip paths, IPs, and SQL details in production mode
- Return safe error messages for user-facing responses

### Configuration
- YAML-based config in `configs/config.yaml`
- Environment variables use `BOUNDARY_` prefix
- Secret providers: Vault → Environment → File (fallback chain)

### Testing
- Table-driven tests preferred
- Run with `-race` flag for race detection
- Mock external services
- 664 test functions across 45 test files

### API Design
- RESTful endpoints under `/v1/*`
- JSON request/response
- Consistent error format with status codes

## Common Tasks

### Adding a New Detection Rule
1. Add rule definition in `internal/detection/rules/`
2. Map to MITRE ATT&CK framework
3. Add tests in corresponding `_test.go` file
4. Run `make test` to verify

### Adding a New API Endpoint
1. Define handler in `internal/api/`
2. Add route in router configuration
3. Implement middleware (auth, rate limiting) as needed
4. Add integration tests

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
# Start dependencies
docker-compose -f deployments/clickhouse/docker-compose.yaml up -d

# Build and run
make deps
make build
make run      # Start server (terminal 1)
make run-tui  # Start TUI (terminal 2)
```

## Sample Event Ingestion

```bash
curl -X POST http://localhost:8080/v1/events \
  -H "Content-Type: application/json" \
  -d '{"timestamp":"2024-01-15T10:30:00Z","source":{"product":"test"},"severity":3}'
```

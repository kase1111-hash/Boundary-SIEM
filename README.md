# Boundary SIEM

A comprehensive Security Information and Event Management (SIEM) platform designed for blockchain infrastructure protection. Built in Go with high-performance event processing, blockchain-specific detection rules, and enterprise-grade features.

## Features

### Core SIEM Capabilities
- **Event Ingestion**: CEF (UDP/TCP), JSON HTTP, syslog with backpressure-safe queuing
- **Canonical Schema**: Versioned event schema with strict validation and quarantine
- **Storage Engine**: ClickHouse-based with time-partitioned tables and tiered retention
- **Search & Query**: Time-range, field-based, and full-text search with pagination
- **Correlation Engine**: Rule-based correlation with time windows, thresholds, and sequences
- **Alerting**: Webhook, Slack, email with deduplication and rate limiting

### Blockchain Security (103+ Detection Rules)
- **Validator Monitoring**: Attestation tracking, slashing detection, sync committee analysis
- **Transaction Analysis**: Gas anomalies, MEV detection, flash loan identification
- **Smart Contract Security**: Reentrancy detection, access control analysis, upgrade monitoring
- **DeFi Protocol Monitoring**: Liquidity events, oracle manipulation, governance attacks
- **Cross-Chain**: Bridge exploit detection, multi-chain asset tracking

### Enterprise Features
- **High Availability**: Kubernetes StatefulSet with HPA, PDB, and pod anti-affinity
- **Data Streaming**: Kafka integration with ClickHouse clustering
- **Tiered Retention**: Hot (7 days) → Warm (30 days) → Cold (365 days) → S3 Archive
- **API Framework**: REST, GraphQL, and SDK generation (Go, Python, TypeScript, Java)
- **Authentication**: OAuth 2.0, SAML 2.0, OIDC, LDAP with MFA support
- **RBAC**: 7 roles, 16 permissions, multi-tenancy, audit logging
- **Compliance Reports**: SOC 2 Type II, ISO 27001, NIST CSF, PCI DSS, GDPR

### Advanced Capabilities
- **Threat Hunting**: 10 built-in templates, 7 hunt types, 6 query languages
- **Forensics Toolkit**: 12 artifact types, case management, fund flow analysis
- **SOAR**: 8 response workflows, 8 integrations, approval-based automation

### Platform Security
- **Tamper-Evident Audit Logging**: Hash chain integrity with SHA-256, cryptographic signatures
- **Immutable Log Support**: Linux file attributes (chattr +a/+i) for append-only/immutable logs
- **Remote Syslog Forwarding**: UDP/TCP/TLS to external SIEM (RFC 3164, RFC 5424, CEF, JSON)
- **Container Isolation**: Docker seccomp/AppArmor, Kubernetes NetworkPolicy, Pod Security Standards
- **Hardware Key Storage**: TPM 2.0 support with PCR policy binding and software fallback

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Boundary SIEM                                   │
├─────────────────────────────────────────────────────────────────────────┤
│  Ingestion Layer                                                         │
│  ├── CEF Parser (UDP 514, TCP 1514)                                     │
│  ├── JSON HTTP (POST /api/v1/events)                                    │
│  ├── Syslog (RFC 5424)                                                  │
│  └── Ring Buffer Queue (100K events, backpressure)                      │
├─────────────────────────────────────────────────────────────────────────┤
│  Processing Pipeline                                                     │
│  ├── Schema Validation & Normalization                                  │
│  ├── Blockchain Event Enrichment                                        │
│  ├── Threat Intelligence Lookup (OFAC, Chainalysis)                     │
│  └── Correlation Engine (Rule-based + Sequences)                        │
├─────────────────────────────────────────────────────────────────────────┤
│  Storage Layer                                                           │
│  ├── ClickHouse (Hot: 7d, Warm: 30d, Cold: 365d)                       │
│  ├── Kafka (Event Streaming)                                            │
│  └── S3 (Archive)                                                        │
├─────────────────────────────────────────────────────────────────────────┤
│  API Layer                                                               │
│  ├── REST API (/api/v1/*)                                               │
│  ├── GraphQL (/graphql)                                                 │
│  ├── WebSocket (Real-time alerts)                                       │
│  └── gRPC (Internal services)                                           │
├─────────────────────────────────────────────────────────────────────────┤
│  Detection & Response                                                    │
│  ├── 103 Blockchain Detection Rules                                     │
│  ├── 9 Incident Playbooks                                               │
│  ├── 8 SOAR Workflows                                                   │
│  └── MITRE ATT&CK Mappings                                              │
└─────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Go 1.21+
- ClickHouse 23.8+
- Kafka 3.5+ (optional, for HA)
- Docker & Docker Compose (for development)

### Development Setup

```bash
# Clone repository
git clone https://github.com/boundary-siem/boundary-siem.git
cd boundary-siem

# Start dependencies
docker-compose -f deployments/clickhouse/docker-compose.yaml up -d

# Build
go build -o bin/siem-ingest ./cmd/siem-ingest

# Run
./bin/siem-ingest

# Run tests
go test ./...
```

### Configuration

```yaml
# configs/config.yaml
server:
  bind_address: "0.0.0.0"
  http_port: 8080
  grpc_port: 9090

storage:
  clickhouse:
    hosts: ["localhost:9000"]
    database: "siem"

kafka:
  brokers: ["localhost:9092"]
  topic: "siem-events"

retention:
  hot_days: 7
  warm_days: 30
  cold_days: 365

logging:
  level: info
  format: json
```

### Sending Events

```bash
# JSON HTTP
curl -X POST http://localhost:8080/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-01-15T10:30:00Z",
    "source": {"product": "boundary-daemon", "host": "node-1"},
    "action": "validator.attestation",
    "outcome": "success",
    "severity": 3
  }'

# CEF (TCP)
echo 'CEF:0|Boundary|Daemon|1.0|100|Validator Attestation|3|src=node-1' | nc localhost 1514
```

## Project Structure

```
boundary-siem/
├── cmd/
│   └── siem-ingest/          # Main entry point
├── internal/
│   ├── ingest/               # Event ingestion (CEF, JSON, syslog)
│   ├── schema/               # Canonical event schema
│   ├── storage/              # ClickHouse storage engine
│   ├── search/               # Query execution
│   ├── correlation/          # Correlation engine
│   ├── queue/                # Ring buffer queue
│   ├── consumer/             # Event consumers
│   ├── blockchain/           # Blockchain-specific modules
│   │   ├── validator/        # Validator monitoring
│   │   ├── ethereum/         # Ethereum parser
│   │   ├── mempool/          # Mempool monitoring
│   │   ├── contracts/        # Smart contract events
│   │   └── consensus/        # Consensus parsing
│   ├── infrastructure/       # Metrics, logging, cloud
│   ├── detection/            # Detection engine
│   │   ├── rules/            # 103 blockchain rules
│   │   ├── playbook/         # Incident playbooks
│   │   └── threat/           # Threat intelligence
│   ├── api/                  # REST API
│   │   ├── auth/             # Authentication & RBAC
│   │   ├── dashboard/        # SOC dashboard
│   │   └── reports/          # Compliance reports
│   ├── enterprise/           # Enterprise features
│   │   ├── ha/               # High availability
│   │   ├── retention/        # Data retention
│   │   └── api/              # REST/GraphQL/SDK
│   ├── advanced/             # Advanced features
│   │   ├── hunting/          # Threat hunting
│   │   ├── forensics/        # Forensics toolkit
│   │   └── soar/             # SOAR automation
│   └── security/             # Platform security
│       ├── audit/            # Tamper-evident audit logging
│       ├── hardware/         # TPM/HSM key storage
│       ├── kernel/           # Kernel security modules
│       ├── privilege/        # Privilege management
│       └── trust/            # Trust verification
├── deploy/
│   ├── kubernetes/           # K8s manifests
│   └── container/            # Container security configs
├── deployments/
│   └── clickhouse/           # Docker Compose
├── configs/                  # Configuration files
└── docs/                     # Documentation
```

## Detection Rules

### Categories (103 Rules)

| Category | Rules | Description |
|----------|-------|-------------|
| Validator Security | 10 | Slashing, attestation, sync committee |
| Transaction Analysis | 12 | Gas anomalies, large transfers, MEV |
| Smart Contract | 15 | Reentrancy, access control, upgrades |
| DeFi Security | 18 | Flash loans, oracle manipulation, liquidity |
| Bridge Security | 8 | Cross-chain exploits, signature validation |
| Governance | 6 | Voting manipulation, proposal attacks |
| NFT Security | 5 | Wash trading, metadata exploits |
| Wallet Security | 8 | Drainers, phishing, approvals |
| Infrastructure | 7 | Node health, P2P network, RPC |
| Compliance | 6 | OFAC, Chainalysis, reporting |
| MEV | 4 | Sandwich, frontrunning, backrunning |
| Oracle | 4 | Price manipulation, staleness |

### MITRE ATT&CK Mapping

All 103 rules are mapped to MITRE ATT&CK techniques for standardized threat classification.

## API Reference

### Events

```bash
# List events
GET /api/v1/events?start=2024-01-01&end=2024-01-31&severity=8

# Get event by ID
GET /api/v1/events/{id}

# Create event
POST /api/v1/events
```

### Alerts

```bash
# List alerts
GET /api/v1/alerts?status=open&severity=critical

# Acknowledge alert
POST /api/v1/alerts/{id}/acknowledge

# Close alert
POST /api/v1/alerts/{id}/close
```

### Search

```bash
# Execute search
POST /api/v1/search
{
  "query": "action:validator.* AND severity:>=8",
  "time_range": {"start": "2024-01-01", "end": "2024-01-31"},
  "limit": 100
}
```

### GraphQL

```graphql
query {
  events(filter: {severity: {gte: 8}}, limit: 10) {
    id
    timestamp
    action
    severity
  }
  alerts(status: OPEN) {
    id
    ruleName
    severity
    createdAt
  }
}
```

## Kubernetes Deployment

```bash
# Apply manifests
kubectl apply -f deploy/kubernetes/siem.yaml

# Check status
kubectl get pods -n boundary-siem

# Scale
kubectl scale statefulset siem --replicas=5 -n boundary-siem
```

### Resources

- StatefulSet with 3 replicas (auto-scales to 10)
- HPA based on CPU (70%), memory (80%), events/sec (5000)
- PodDisruptionBudget (minAvailable: 2)
- Pod anti-affinity for HA
- 100Gi SSD per pod

## Container Security

### Docker Deployment

```bash
# Set up container isolation
cd deploy/container
sudo ./setup-container-isolation.sh docker

# Start with Docker Compose
docker-compose up -d

# Verify networks
docker network ls | grep siem
```

### Security Features

- **Seccomp Profile**: Syscall allowlist restricting container capabilities
- **AppArmor Profile**: MAC enforcement for file/network access control
- **Network Isolation**: Three isolated networks (internal, ingestion, management)
- **Non-root Execution**: All containers run as non-privileged users
- **Read-only Filesystem**: Immutable container root with explicit writable mounts

### Kubernetes Security

```bash
# Apply pod security policies
kubectl apply -f deploy/container/pod-security-policy.yaml

# Apply network policies
kubectl apply -f deploy/container/network-policy.yaml
```

- **Pod Security Standards**: Restricted security context enforcement
- **Network Policies**: Default deny with explicit allow rules
- **OPA Gatekeeper**: Policy enforcement for non-root, read-only root, capability restrictions
- **Resource Quotas**: CPU/memory/storage limits per namespace

## Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package
go test ./internal/correlation/...

# Verbose output
go test -v ./internal/detection/...
```

### Test Coverage

| Package | Tests | Coverage |
|---------|-------|----------|
| internal/advanced | 30 | 85% |
| internal/api | 48 | 82% |
| internal/blockchain | 24 | 78% |
| internal/correlation | 18 | 90% |
| internal/detection | 24 | 88% |
| internal/enterprise | 56 | 85% |
| internal/ingest | 12 | 92% |
| internal/schema | 8 | 95% |
| internal/security | 45 | 88% |
| internal/storage | 15 | 80% |

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for planned features:

- ML/UEBA Anomaly Detection
- Advanced Visualizations (transaction flow graphs)
- Mobile Application (iOS/Android)
- Attack Simulation
- Multi-Chain Unified Dashboard

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`go test ./...`)
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [ClickHouse](https://clickhouse.com/) - High-performance analytics database
- [Kafka](https://kafka.apache.org/) - Distributed event streaming
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat classification framework

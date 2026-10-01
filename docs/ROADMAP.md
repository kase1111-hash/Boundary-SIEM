# Boundary SIEM Roadmap

This document outlines planned features and future enhancements for the Boundary SIEM platform.

## Current Features (Implemented)

### Running in `siem-ingest`
- ✅ Event ingestion: JSON HTTP (`POST /v1/events`), CEF over UDP/TCP/DTLS, EVM JSON-RPC poller
- ✅ Schema validation with quarantine of rejected events (`events_quarantine`)
- ✅ Ring buffer queue with backpressure (100K events)
- ✅ ClickHouse storage with migrations, TTL retention, retries and dead-lettering
- ✅ Search API: field, time-range, boolean and phrase queries, aggregations, EXPLAIN
- ✅ Correlation engine: threshold, sequence, aggregate and absence rules, baselines, rule chaining
- ✅ 138 rules loaded by default: 130 built-in detection rules (validator, consensus, transactions, contracts, MEV, DeFi, exchange, infrastructure, security, compliance, key management, cloud, network, API, 27 cross-system ecosystem rules), 3 kill chains, 5 community YAML rules
- ✅ MITRE ATT&CK mappings on 35 built-in rules
- ✅ Alerting: dedup, escalation policies, 7 channel types (log, webhook, Slack, Discord, PagerDuty, email, Telegram), alerts persisted in ClickHouse
- ✅ Alert and rules APIs; custom rules and toggles persisted on disk
- ✅ API-key authentication, per-IP rate limiting, CORS
- ✅ `/health`, `/ready`, Prometheus `/metrics`, WebSocket stream (`/ws/events`)
- ✅ React SOC dashboard and terminal UI
- ✅ `boundary-daemon` CEF signature mapping; `/api/system/dreaming` for Agent-OS

### In the repository, not used by `siem-ingest` yet
- Kafka producer/consumer (`internal/kafka`) and S3 archival (`internal/storage/s3`)
- OAuth/SAML/OIDC/LDAP provider framework, RBAC, Redis sessions, dashboard and compliance reports (`internal/api`)
- Blockchain monitors (`internal/blockchain`), infrastructure monitors (`internal/infrastructure`)
- Threat intelligence (OFAC, Chainalysis) and incident playbooks (`internal/detection/threat`, `internal/detection/playbook`)
- Tamper-evident audit logging, immutable logs, syslog forwarding, TPM 2.0 key storage (`internal/security`)
- Secrets providers (Vault, file, env) and AES-256-GCM encryption (`internal/secrets`, `internal/encryption`)

### Deployment
- ✅ Dockerfile and Docker Compose (siem-ingest + ClickHouse), seccomp/AppArmor profiles
- ✅ Kubernetes single-replica Deployment with probes and NetworkPolicy
- ✅ systemd unit, SELinux/AppArmor host policies, firewall rules

### Not implemented
- GraphQL API, SDK generation
- Kubernetes high availability or clustering (one `siem-ingest` per ClickHouse database)
- Multi-tenancy in the service (every event gets the configured default tenant)
- Per-system integrations (NatLangChain client and NLC-* rules, Value Ledger, ILR, Learning Contracts, Mediator Node, Memory Vault, Synth Mind, IntentLog, RRA rule sets); these systems can send events to `POST /v1/events`
- Threat hunting workbench, forensics toolkit, SOAR workflow automation

### CI/CD & DevOps
- ✅ GitHub Actions CI workflow (lint, security, test, build)
- ✅ GitHub Actions security workflow (gosec, govulncheck, dependency review)
- ✅ Makefile targets for local security scanning
- ✅ SARIF output for GitHub Security tab integration
- ✅ Daily scheduled security scans
- ✅ Race condition detection in tests

---

## Future Features (Planned)

The following features are planned for future releases. Contributions welcome!

### 1. ML/UEBA Anomaly Detection

**Priority:** High
**Complexity:** High
**Estimated Effort:** 4-6 sprints

Machine Learning and User/Entity Behavior Analytics for automated anomaly detection.

#### Planned Components:

```
internal/ml/
├── models/
│   ├── anomaly_detector.go      # Statistical anomaly detection
│   ├── time_series.go           # Time series forecasting
│   ├── clustering.go            # Transaction clustering
│   └── classification.go        # Threat classification
├── features/
│   ├── extractor.go             # Feature extraction pipeline
│   ├── normalization.go         # Data normalization
│   └── embeddings.go            # Wallet/contract embeddings
├── training/
│   ├── pipeline.go              # Training pipeline
│   ├── validation.go            # Model validation
│   └── versioning.go            # Model versioning
└── inference/
    ├── realtime.go              # Real-time inference
    ├── batch.go                 # Batch inference
    └── explainability.go        # Model explainability
```

#### Key Features:
- Baseline behavior modeling per wallet/validator
- Transaction pattern anomaly detection
- Gas price anomaly detection
- Smart contract interaction anomaly detection
- Real-time scoring with explainability
- Model retraining pipelines
- A/B testing framework for models

#### Algorithms to Implement:
- Isolation Forest for anomaly detection
- LSTM for time series prediction
- Graph Neural Networks for transaction flow analysis
- Autoencoders for behavioral anomaly detection

---

### 2. Advanced Visualizations

**Priority:** Medium
**Complexity:** Medium
**Estimated Effort:** 2-3 sprints

Rich interactive visualizations for blockchain data analysis.

#### Planned Components:

```
internal/visualization/
├── graphs/
│   ├── transaction_flow.go      # Transaction flow graphs
│   ├── wallet_clustering.go     # Wallet cluster visualization
│   ├── protocol_topology.go     # Protocol interaction maps
│   └── attack_timeline.go       # Attack timeline visualization
├── charts/
│   ├── realtime_metrics.go      # Real-time metric charts
│   ├── heatmaps.go              # Activity heatmaps
│   └── distributions.go         # Statistical distributions
└── export/
    ├── svg.go                   # SVG export
    ├── png.go                   # PNG export
    └── pdf.go                   # PDF export for reports
```

#### Key Features:
- Interactive transaction flow graphs (D3.js/Cytoscape)
- Fund flow Sankey diagrams
- Wallet relationship networks
- Time-based attack timelines
- Geographic distribution maps
- Real-time dashboard widgets
- Export to SVG/PNG/PDF

---

### 3. Mobile Application

**Priority:** Medium
**Complexity:** High
**Estimated Effort:** 4-5 sprints

Native mobile apps for iOS and Android for on-the-go monitoring.

#### Planned Components:

```
mobile/
├── ios/
│   └── BoundarySIEM/            # Swift/SwiftUI app
├── android/
│   └── app/                      # Kotlin app
└── shared/
    ├── api/                      # Shared API client
    ├── models/                   # Shared data models
    └── notifications/            # Push notification handling
```

#### Key Features:
- Real-time alert notifications (push)
- Dashboard summary views
- Alert triage and response
- Incident acknowledgment
- On-call schedule management
- Biometric authentication
- Offline caching
- Widget support (iOS/Android)

---

### 4. Attack Simulation

**Priority:** Low
**Complexity:** High
**Estimated Effort:** 3-4 sprints

Red team capabilities for testing detection rules and response procedures.

#### Planned Components:

```
internal/simulation/
├── scenarios/
│   ├── flash_loan.go            # Flash loan attack simulation
│   ├── reentrancy.go            # Reentrancy attack simulation
│   ├── front_running.go         # Front-running simulation
│   ├── governance.go            # Governance attack simulation
│   └── bridge.go                # Bridge exploit simulation
├── execution/
│   ├── testnet.go               # Testnet execution
│   ├── forked.go                # Forked mainnet execution
│   └── simulated.go             # Pure simulation mode
├── reporting/
│   ├── coverage.go              # Detection coverage report
│   ├── gaps.go                  # Gap analysis
│   └── recommendations.go       # Improvement recommendations
└── scheduling/
    ├── campaigns.go             # Scheduled simulation campaigns
    └── continuous.go            # Continuous testing mode
```

#### Key Features:
- Pre-built attack scenarios (flash loan, reentrancy, etc.)
- Custom attack scenario builder
- Detection rule coverage analysis
- Response time measurement
- Purple team exercises
- Scheduled simulation campaigns
- Safe testnet/forked chain execution

---

### 5. Multi-Chain Unified Dashboard

**Priority:** High
**Complexity:** Medium
**Estimated Effort:** 2-3 sprints

Unified view across all monitored blockchain networks.

#### Planned Components:

```
internal/multichain/
├── aggregation/
│   ├── metrics.go               # Cross-chain metric aggregation
│   ├── alerts.go                # Cross-chain alert correlation
│   └── assets.go                # Cross-chain asset tracking
├── normalization/
│   ├── events.go                # Event normalization
│   ├── addresses.go             # Address format normalization
│   └── values.go                # Value/currency normalization
├── correlation/
│   ├── bridge_tracking.go       # Cross-chain bridge tracking
│   ├── wallet_linking.go        # Cross-chain wallet linking
│   └── flow_analysis.go         # Cross-chain flow analysis
└── dashboard/
    ├── unified_view.go          # Unified dashboard API
    ├── chain_selector.go        # Chain filtering
    └── comparison.go            # Chain comparison views
```

#### Supported Chains (Planned):
- Ethereum (mainnet, testnets)
- Polygon
- Arbitrum
- Optimism
- BSC
- Avalanche
- Solana
- Cosmos ecosystem
- Bitcoin (via indexers)

#### Key Features:
- Unified alert view across all chains
- Cross-chain transaction tracing
- Multi-chain wallet profiling
- Bridge transaction monitoring
- Normalized metrics and dashboards
- Chain health comparison
- Cross-chain attack correlation

---

## Contributing

We welcome contributions to these planned features! Here's how to get started:

1. **Pick a Feature**: Choose a feature from the roadmap that interests you
2. **Open an Issue**: Create a GitHub issue to discuss your approach
3. **Design Doc**: For complex features, write a brief design document
4. **Implementation**: Fork the repo and implement your changes
5. **Testing**: Add comprehensive tests (minimum 80% coverage)
6. **Pull Request**: Submit a PR with clear description

### Development Guidelines

- Follow existing code patterns and architecture
- Write tests for all new functionality
- Update documentation as needed
- Use meaningful commit messages
- Ensure all CI checks pass

---

## Version History

| Version | Date | Features |
|---------|------|----------|
| 0.1.0-alpha | 2026-01-01 | Core SIEM, Blockchain Security, boundary-daemon & NatLangChain integrations |
| 0.1.1-alpha | 2026-01-02 | 11 ecosystem integrations, 200+ detection rules, cross-system correlation |
| 1.0.0-beta | 2026-01-09 | TUI, startup diagnostics, Windows support, security audit, key rotation |
| Unreleased | - | End-to-end siem-ingest pipeline, alert persistence, rules API, /ready, WebSocket stream, Go 1.26 |
| 1.1.0 | TBD | ML/UEBA (planned) |
| 1.2.0 | TBD | Advanced Visualizations (planned) |
| 1.3.0 | TBD | Mobile App (planned) |
| 1.4.0 | TBD | Attack Simulation (planned) |
| 2.0.0 | TBD | Multi-Chain Dashboard, GA Release |

---

## Contact

For questions about the roadmap or to propose new features, please open a GitHub issue or contact the maintainers.

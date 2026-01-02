# Boundary SIEM Roadmap

This document outlines planned features and future enhancements for the Boundary SIEM platform.

## Current Features (Implemented)

### Phase 1: Core SIEM Foundation
- ✅ Event ingestion pipeline with Kafka
- ✅ Structured logging and parsing
- ✅ Event correlation engine
- ✅ Alert generation and routing

### Phase 2: Blockchain Security
- ✅ Validator monitoring (attestations, slashing, sync status)
- ✅ Transaction analysis (gas, transfers, contract interactions)
- ✅ Smart contract security analysis
- ✅ DeFi protocol monitoring

### Phase 3: Infrastructure
- ✅ Metrics collection (Prometheus format)
- ✅ Log aggregation
- ✅ Network monitoring

### Phase 4: Detection & Response
- ✅ 200+ detection rules across all integrations
  - 80+ blockchain/infrastructure rules
  - 20 NatLangChain rules (NLC-001 to NLC-020)
  - 78 integration-specific rules (VL/ILR/LC/MN/MV/SM/IL/RRA)
  - 26 cross-system ecosystem rules (ECO-001 to ECO-065)
- ✅ MITRE ATT&CK mappings
- ✅ Threat intelligence integration (OFAC, Chainalysis)
- ✅ Incident playbooks (9 built-in)

### Phase 5: User Interface
- ✅ React-based SOC dashboard
- ✅ OAuth/SAML/OIDC/LDAP authentication
- ✅ RBAC with 7 roles and 16 permissions
- ✅ Multi-tenancy support
- ✅ Compliance reporting (SOC 2, ISO 27001, NIST CSF)

### Phase 6: Enterprise Features
- ✅ Kubernetes high availability (StatefulSet, HPA, PDB)
- ✅ Kafka streaming with ClickHouse clustering
- ✅ Tiered data retention (hot/warm/cold/frozen)
- ✅ S3 archival
- ✅ REST/GraphQL APIs
- ✅ SDK generation (Go, Python, TypeScript, Java)

### Phase 7: Advanced Features (Partial)
- ✅ Threat Hunting Workbench (10 templates)
- ✅ Forensics Toolkit (12 artifact types)
- ✅ SOAR Workflow Automation (8 workflows, 8 integrations)

### Phase 8: Platform Security
- ✅ Tamper-evident audit logging with hash chain integrity
- ✅ Linux immutable log support (chattr +a/+i)
- ✅ Remote syslog forwarding (UDP/TCP/TLS, RFC 3164/5424/CEF/JSON)
- ✅ Container isolation (Docker seccomp/AppArmor, K8s NetworkPolicy)
- ✅ TPM 2.0 hardware key storage with PCR policy binding

### Phase 9: External Integrations (11 Production-Ready)
- ✅ **boundary-daemon** - CEF protocol (UDP:5514/TCP:5515), session/auth/access events
- ✅ **NatLangChain** - Natural language blockchain (20 rules, NLC-001 to NLC-020)
- ✅ **Agent-OS** - `/api/system/dreaming` endpoint for system status
- ✅ **Value Ledger** - Financial tracking with vector scores (8 rules, VL-001 to VL-008)
- ✅ **ILR-Module** - Immutable License Registry disputes (10 rules, ILR-001 to ILR-010)
- ✅ **Learning Contracts** - Consent management (10 rules, LC-001 to LC-010)
- ✅ **Mediator Node** - Intent-aligned mediation (10 rules, MN-001 to MN-010)
- ✅ **Memory Vault** - Secure memory storage (10 rules, MV-001 to MV-010)
- ✅ **Synth Mind** - Agent-OS psychological modules (10 rules, SM-001 to SM-010)
- ✅ **IntentLog** - Prose-based version control (10 rules, IL-001 to IL-010)
- ✅ **RRA-Module** - Revenant Repo Agent (10 rules, RRA-001 to RRA-010)

See [ECOSYSTEM_COMPATIBILITY_REPORT.md](./ECOSYSTEM_COMPATIBILITY_REPORT.md) for full integration details.

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
| 0.2.0 | TBD | ML/UEBA (planned) |
| 0.3.0 | TBD | Advanced Visualizations (planned) |
| 0.4.0 | TBD | Mobile App (planned) |
| 0.5.0 | TBD | Attack Simulation (planned) |
| 1.0.0 | TBD | Multi-Chain Dashboard, GA Release |

---

## Contact

For questions about the roadmap or to propose new features, please open a GitHub issue or contact the maintainers.

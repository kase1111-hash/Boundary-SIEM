# Changelog

All notable changes to Boundary-SIEM will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha] - 2026-01-01

### Added

#### Core SIEM Platform
- Event ingestion pipeline with CEF (UDP/TCP), JSON HTTP, and syslog support
- Canonical event schema (v1.0.0) with strict validation
- Ring buffer queue with backpressure handling (100K event capacity)
- ClickHouse storage engine with time-partitioned tables
- Tiered retention: Hot (7 days) → Warm (30 days) → Cold (365 days) → S3 Archive
- Event correlation engine with threshold, sequence, and absence rules
- Search API with time-range, field-based, and full-text queries

#### Integrations
- **boundary-daemon**: Full CEF/JSON integration for session, auth, and access events
  - CEF parsing with signature ID mappings (100-501)
  - UDP listener (port 5514) and TCP listener (port 5515)
  - DTLS support for secure UDP transport
- **NatLangChain**: Natural language blockchain monitoring
  - REST API client for NatLangChain nodes
  - Event normalization for 25+ event types
  - Polling-based ingestion with configurable options
  - 20 detection rules (NLC-001 to NLC-020)

#### Blockchain Security (123+ Detection Rules)
- Validator monitoring: attestation tracking, slashing detection, sync committee analysis
- Transaction analysis: gas anomalies, MEV detection, flash loan identification
- Smart contract security: reentrancy detection, access control analysis, upgrade monitoring
- DeFi protocol monitoring: liquidity events, oracle manipulation, governance attacks
- Cross-chain: bridge exploit detection, multi-chain asset tracking
- NatLangChain: semantic drift detection, dispute monitoring, adversarial pattern detection

#### Enterprise Features
- Kubernetes high availability (StatefulSet, HPA, PDB, pod anti-affinity)
- Kafka integration for event streaming
- REST and GraphQL APIs
- OAuth 2.0, SAML 2.0, OIDC, LDAP authentication with MFA support
- RBAC with 7 roles and 16 permissions
- Multi-tenancy support
- Compliance reporting: SOC 2 Type II, ISO 27001, NIST CSF, PCI DSS, GDPR

#### Advanced Features
- Threat Hunting Workbench: 10 templates, 7 hunt types, 6 query languages
- Forensics Toolkit: 12 artifact types, case management, fund flow analysis
- SOAR Workflow Automation: 8 response workflows, 8 integrations

#### Platform Security
- Tamper-evident audit logging with SHA-256 hash chain integrity
- Linux immutable log support (chattr +a/+i)
- Remote syslog forwarding (UDP/TCP/TLS, RFC 3164/5424/CEF/JSON)
- Container isolation (Docker seccomp/AppArmor, Kubernetes NetworkPolicy)
- TPM 2.0 hardware key storage with PCR policy binding

#### Infrastructure
- Prometheus metrics collection
- Structured JSON logging with sensitive field redaction
- Docker and Kubernetes deployment manifests
- Comprehensive test coverage (35+ test files)

### Known Issues
- Build requires network access for dependency download (consider `go mod vendor`)
- ClickHouse storage disabled by default (requires ClickHouse deployment)

### Dependencies
- Go 1.24.7
- ClickHouse 23.8+
- Kafka 3.5+ (optional, for HA)
- Docker & Docker Compose (for development)

## [Unreleased]

### Planned
- ML/UEBA anomaly detection
- Advanced visualizations
- Mobile application
- Attack simulation framework
- Multi-chain unified dashboard

---

[0.1.0-alpha]: https://github.com/kase1111-hash/Boundary-SIEM/releases/tag/v0.1.0-alpha
[Unreleased]: https://github.com/kase1111-hash/Boundary-SIEM/compare/v0.1.0-alpha...HEAD

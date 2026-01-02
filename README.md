# Boundary SIEM

A comprehensive Security Information and Event Management (SIEM) platform designed for blockchain infrastructure protection. Built in Go with high-performance event processing, blockchain-specific detection rules, and enterprise-grade features.

## Features

### Core SIEM Capabilities
- **Event Ingestion**: CEF (UDP/TCP), JSON HTTP, syslog, NatLangChain with backpressure-safe queuing
- **Canonical Schema**: Versioned event schema with strict validation and quarantine
- **Storage Engine**: ClickHouse-based with time-partitioned tables and tiered retention
- **Search & Query**: Time-range, field-based, and full-text search with pagination
- **Correlation Engine**: Rule-based correlation with time windows, thresholds, and sequences
- **Alerting**: Webhook, Slack, email with deduplication and rate limiting

### Integrations
- **boundary-daemon**: CEF/JSON ingestion for session, auth, and access events
- **NatLangChain**: Natural language blockchain monitoring with 20 detection rules for semantic drift, disputes, and consensus events

### Blockchain Security (123+ Detection Rules)
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

# Install dependencies
make deps

# Start dependencies
docker-compose -f deployments/clickhouse/docker-compose.yaml up -d

# Build
make build

# Run
make run

# Run tests
make test

# Run security scan
make security

# Run all CI checks (lint, security, test)
make ci
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

auth:
  # Admin credentials configuration
  default_admin_username: "admin"
  default_admin_password: ""  # REQUIRED: Set via env var or config
  default_admin_email: "admin@boundary-siem.local"
  require_password_change: true
```

### Security Configuration

**⚠️ IMPORTANT: Admin Credentials**

For security, the default admin password is **no longer hardcoded**. You must configure it using one of these methods:

#### Method 1: Environment Variables (Recommended)
```bash
export BOUNDARY_ADMIN_PASSWORD='YourSecureP@ssw0rd123!'
export BOUNDARY_ADMIN_EMAIL='admin@yourdomain.com'
export BOUNDARY_REQUIRE_PASSWORD_CHANGE='true'
```

#### Method 2: Configuration File
```yaml
auth:
  default_admin_username: "admin"
  default_admin_password: "YourSecureP@ssw0rd123!"
  default_admin_email: "admin@yourdomain.com"
  require_password_change: true
```

#### Method 3: Auto-Generated (Development Only)
If no password is configured, the system will generate a secure random password and log it **once** during startup:

```
SECURITY: Generated random admin password - SAVE THIS PASSWORD
username=admin password=<random-24-char-password>
action_required="Change password immediately after first login"
```

**Password Requirements:**
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character (!@#$%^&*()etc.)

**Security Best Practices:**
1. Never commit passwords to version control
2. Use environment variables or secret management systems (Vault, AWS Secrets Manager)
3. Enable `require_password_change` to force password change on first login
4. Change auto-generated passwords immediately after first login
5. Use strong, unique passwords for production deployments

### Rate Limiting

**Built-in Protection Against Brute Force and DoS Attacks**

The SIEM includes enterprise-grade rate limiting with sensible defaults to protect against:
- Brute force authentication attempts
- Denial of Service (DoS) attacks
- API abuse
- Resource exhaustion

#### Configuration

```yaml
rate_limit:
  enabled: true              # Enable/disable rate limiting
  requests_per_ip: 1000      # Max requests per IP per window
  window_size: 1m            # Time window (1 minute)
  burst_size: 50             # Additional burst allowance
  cleanup_period: 5m         # Memory cleanup interval
  exempt_paths:              # Paths exempt from rate limiting
    - /health
    - /metrics
  trust_proxy: false         # Trust X-Forwarded-For header
```

#### Default Settings (Production-Ready)

- **1000 requests/minute per IP** - Generous limit for normal usage
- **50 burst allowance** - Handle traffic spikes gracefully
- **1-minute sliding window** - Fair, predictable limiting
- **Automatic cleanup** - Prevents memory leaks
- **Health/metrics exempt** - Monitoring never blocked
- **Standard headers** - RFC 6585 compliant

#### Rate Limit Headers

All responses include standard rate limit headers:

```http
X-RateLimit-Limit: 1050        # Total limit (base + burst)
X-RateLimit-Remaining: 1049    # Requests remaining
X-RateLimit-Reset: 1704200460  # Unix timestamp when limit resets
```

When rate limited (429 Too Many Requests):

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 42
Content-Type: application/json

{
  "code": "RATE_LIMITED",
  "message": "Too many requests. Please try again later.",
  "retry_after": 42
}
```

#### Environment Variables

Override configuration via environment variables:

```bash
export BOUNDARY_RATE_LIMIT_ENABLED='true'
export BOUNDARY_RATE_LIMIT_REQUESTS_PER_IP='500'
export BOUNDARY_RATE_LIMIT_WINDOW='1m'
export BOUNDARY_RATE_LIMIT_TRUST_PROXY='true'
```

#### Features

✅ **Per-IP Tracking** - Each client IP has independent limits
✅ **Sliding Window Algorithm** - Fair, predictable rate limiting
✅ **Burst Support** - Handles legitimate traffic spikes
✅ **Path Exemptions** - Exclude health checks, metrics, etc.
✅ **Proxy Support** - Respects X-Forwarded-For when configured
✅ **Auto Cleanup** - Efficient memory management
✅ **Standard Headers** - RFC 6585 compliant
✅ **Thread-Safe** - Handles concurrent requests safely

#### Use Cases

**Protecting Authentication Endpoints:**
```yaml
rate_limit:
  requests_per_ip: 10    # Only 10 login attempts per minute
  window_size: 1m
  burst_size: 0          # No burst for auth endpoints
```

**API Rate Limiting:**
```yaml
rate_limit:
  requests_per_ip: 1000  # 1000 API calls per minute
  window_size: 1m
  burst_size: 200        # Allow bursts up to 1200
```

**Development/Testing:**
```yaml
rate_limit:
  enabled: false  # Disable for local development
```

### Secrets Management

**Enterprise-Grade Secret Management with HashiCorp Vault Integration**

The SIEM includes a comprehensive secrets management system that supports multiple providers with automatic fallback:

- **HashiCorp Vault** - Enterprise secret management with versioning and audit logs
- **Environment Variables** - Simple, portable secret configuration
- **File-Based Secrets** - Docker secrets and Kubernetes mounted volumes

#### Configuration

```yaml
secrets:
  # Provider selection (in priority order: Vault → Env → File)
  enable_vault: false           # HashiCorp Vault (requires configuration)
  enable_env: true              # Environment variables (enabled by default)
  enable_file: false            # File-based secrets (for Docker/K8s)

  # Vault configuration
  vault_address: "https://vault.example.com:8200"
  vault_token: ""               # Set via VAULT_TOKEN env var
  vault_path: "secret/boundary-siem"
  vault_timeout: 10s

  # File provider configuration
  file_secrets_dir: "/etc/secrets"

  # Cache configuration
  cache_ttl: 5m                 # Cache secrets for 5 minutes
```

#### Method 1: Environment Variables (Default)

Simple and portable, ideal for development and small deployments:

```bash
# Admin credentials
export BOUNDARY_ADMIN_USERNAME='admin'
export BOUNDARY_ADMIN_PASSWORD='YourSecureP@ssw0rd123!'
export BOUNDARY_ADMIN_EMAIL='admin@yourdomain.com'

# Database credentials
export BOUNDARY_CLICKHOUSE_PASSWORD='db-password'

# API keys
export BOUNDARY_API_KEY='your-api-key'
```

The secrets manager automatically normalizes key names:
- `admin_password` → `BOUNDARY_ADMIN_PASSWORD`
- `database.password` → `BOUNDARY_DATABASE_PASSWORD`
- `app-api.key` → `BOUNDARY_APP_API_KEY`

#### Method 2: HashiCorp Vault (Recommended for Production)

Enterprise-grade secret management with versioning, audit logs, and dynamic secrets:

**1. Enable Vault in configuration:**

```yaml
secrets:
  enable_vault: true
  enable_env: true              # Fallback to env vars
  vault_address: "https://vault.example.com:8200"
  vault_path: "secret/boundary-siem"
```

**2. Configure Vault connection via environment:**

```bash
export VAULT_ADDR='https://vault.example.com:8200'
export VAULT_TOKEN='s.your-vault-token'
export VAULT_PATH='secret/boundary-siem'
```

**3. Store secrets in Vault:**

```bash
# Using Vault CLI
vault kv put secret/boundary-siem/admin_password value='SecureP@ssw0rd123!'
vault kv put secret/boundary-siem/database_password value='db-password'
vault kv put secret/boundary-siem/api_key value='your-api-key'

# Using Vault API
curl -X POST https://vault.example.com:8200/v1/secret/data/boundary-siem/admin_password \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"data": {"value": "SecureP@ssw0rd123!"}}'
```

**Vault Features:**
- ✅ **Secret Versioning** - Track changes and rollback
- ✅ **Audit Logging** - Complete access audit trail
- ✅ **Dynamic Secrets** - Generate time-limited credentials
- ✅ **Access Policies** - Fine-grained permission control
- ✅ **Encryption at Rest** - AES-256-GCM encryption
- ✅ **High Availability** - Clustered deployment support

#### Method 3: File-Based Secrets (Docker/Kubernetes)

Ideal for containerized deployments with Docker secrets or Kubernetes mounted volumes:

**1. Enable file provider:**

```yaml
secrets:
  enable_file: true
  file_secrets_dir: "/run/secrets"  # Docker secrets default path
```

**2. Mount secrets as files:**

**Docker:**
```bash
# Create secrets
echo "SecureP@ssw0rd123!" | docker secret create admin_password -

# Run container
docker service create \
  --name boundary-siem \
  --secret admin_password \
  --secret database_password \
  boundary-siem:latest
```

**Kubernetes:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: boundary-siem-secrets
type: Opaque
stringData:
  admin_password: "SecureP@ssw0rd123!"
  database_password: "db-password"
---
apiVersion: v1
kind: Pod
metadata:
  name: boundary-siem
spec:
  containers:
  - name: siem
    image: boundary-siem:latest
    volumeMounts:
    - name: secrets
      mountPath: "/etc/secrets"
      readOnly: true
  volumes:
  - name: secrets
    secret:
      secretName: boundary-siem-secrets
```

**File Format:**
- One secret per file
- Filename = secret key (normalized: `admin_password`, `database_password`)
- File content = secret value
- Newlines automatically trimmed

#### Provider Fallback Chain

The secrets manager tries providers in priority order until a secret is found:

```
1. HashiCorp Vault (if enabled)
   ↓ (secret not found)
2. Environment Variables (if enabled)
   ↓ (secret not found)
3. File-Based Secrets (if enabled)
   ↓ (secret not found)
4. Error: Secret not found
```

This allows flexible deployment strategies:
- **Development**: Environment variables only
- **Staging**: Environment + Vault for sensitive secrets
- **Production**: Vault primary, environment fallback
- **Kubernetes**: File-based secrets with environment fallback

#### Using Secrets in Code

```go
// Create secrets manager
mgr, err := cfg.NewSecretsManager()
if err != nil {
    log.Fatal(err)
}
defer mgr.Close()

// Get a secret
password, err := mgr.Get(ctx, "ADMIN_PASSWORD")
if err != nil {
    log.Fatal(err)
}

// Get with default fallback
apiKey := mgr.GetWithDefault(ctx, "API_KEY", "default-key")

// Resolve secret references
// Formats: "literal", "env:VAR", "vault:path", "file:/path"
value, err := mgr.ResolveSecret(ctx, "env:DATABASE_PASSWORD")
```

#### Environment Variables

Override secrets configuration via environment:

```bash
# Enable/disable providers
export SIEM_SECRETS_VAULT_ENABLED='true'
export SIEM_SECRETS_FILE_ENABLED='true'

# Vault configuration
export VAULT_ADDR='https://vault.example.com:8200'
export VAULT_TOKEN='s.your-token'
export VAULT_PATH='secret/boundary-siem'

# File provider
export SIEM_SECRETS_DIR='/run/secrets'
```

#### Security Best Practices

**1. Never Commit Secrets to Version Control**
```bash
# Add to .gitignore
.env
*.pem
*.key
secrets/
```

**2. Use Vault for Production**
- Centralized secret management
- Automatic rotation and revocation
- Complete audit trail
- Dynamic secret generation

**3. Rotate Secrets Regularly**
```bash
# Vault automatic rotation
vault write sys/leases/renew lease_id="secret/..."

# Manual rotation
vault kv put secret/boundary-siem/admin_password value='NewSecureP@ss!'
```

**4. Principle of Least Privilege**
```hcl
# Vault policy - read-only access
path "secret/data/boundary-siem/*" {
  capabilities = ["read"]
}
```

**5. Enable Secrets Caching**
```yaml
secrets:
  cache_ttl: 5m  # Cache for 5 minutes to reduce provider calls
```

**6. Monitor Secret Access**
- Enable Vault audit logging
- Monitor secrets manager metrics
- Alert on unusual access patterns

#### Troubleshooting

**Secret Not Found:**
```bash
# Check which providers are enabled
curl http://localhost:8080/health | jq '.secrets'

# Verify environment variable
echo $BOUNDARY_ADMIN_PASSWORD

# Check Vault
vault kv get secret/boundary-siem/admin_password

# Check file
cat /etc/secrets/admin_password
```

**Vault Connection Failed:**
```bash
# Verify Vault is accessible
curl -H "X-Vault-Token: $VAULT_TOKEN" \
  https://vault.example.com:8200/v1/sys/health

# Check Vault token
vault token lookup

# Verify path
vault kv list secret/boundary-siem
```

**Permission Denied:**
```bash
# Check Vault policy
vault token capabilities secret/boundary-siem/admin_password
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

## CI/CD & Security Scanning

### GitHub Actions

The project includes automated CI/CD pipelines:

| Workflow | Triggers | Jobs |
|----------|----------|------|
| `ci.yml` | Push, PR | Lint, Security, Test, Build |
| `security.yml` | Push, PR, Daily | Gosec, Govulncheck, Dependency Review |

### Local Security Scanning

```bash
# Run gosec security scanner
make security

# Generate detailed security reports (JSON + HTML)
make security-report

# Run all CI checks locally
make ci
```

### Security Tools

| Tool | Purpose |
|------|---------|
| [gosec](https://github.com/securego/gosec) | Go source code security analyzer |
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | Go dependency vulnerability scanner |
| [golangci-lint](https://golangci-lint.run/) | Go linters aggregator |

### Installing Security Tools

```bash
# Install gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Install govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest

# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

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
4. Run all CI checks locally (`make ci`)
5. Ensure security scanning passes (`make security`)
6. Commit changes (`git commit -m 'Add amazing feature'`)
7. Push to branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

All PRs trigger automated security scanning and must pass before merge.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [ClickHouse](https://clickhouse.com/) - High-performance analytics database
- [Kafka](https://kafka.apache.org/) - Distributed event streaming
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat classification framework

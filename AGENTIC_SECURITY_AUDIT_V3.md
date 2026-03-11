# Agentic Security Audit v3.0 — Boundary-SIEM

```
AUDIT METADATA
  Project:       Boundary-SIEM
  Date:          2026-03-11
  Auditor:       Claude Opus 4.6
  Commit:        c298b264d4ea3a171e78aa27323a10ed4de134b1
  Strictness:    STANDARD
  Context:       PRODUCTION

PROVENANCE ASSESSMENT
  Vibe-Code Confidence:   35%
  Human Review Evidence:  MODERATE

LAYER VERDICTS
  L1 Provenance:       WARN
  L2 Credentials:      WARN
  L3 Agent Boundaries: PASS
  L4 Supply Chain:     WARN
  L5 Infrastructure:   WARN
```

---

## L1: PROVENANCE & TRUST ORIGIN

### 1.1 Vibe-Code Detection

| Indicator | Status | Evidence |
|-----------|--------|----------|
| No tests | **PASS** | Tests exist across packages: `*_test.go` files in `alerting`, `api/auth`, `blockchain`, `config`, `correlation`, `encryption`, `ingest`, `kafka`, `middleware`, `queue`, `schema`, `search`, `secrets`, `security`, `storage`, `startup`, `tui`. Integration test at `internal/integration_test.go`. |
| No security config | **PASS** | Extensive security config: `.env.example` for ClickHouse, secrets manager (`internal/secrets/`), CSRF middleware, encryption at rest, security headers middleware, AppArmor/SELinux/seccomp profiles. |
| AI boilerplate | **WARN** | Some comments are thorough but uniform in style. Multiple docs (VIBE_CODE_AUDIT.md, REMEDIATION_PLAN.md, SECURITY_AUDIT_CHECKLIST.md) suggest prior AI-assisted audits. Not necessarily negative, but indicates AI-assisted development. |
| Rapid commit history | **WARN** | Git log shows large security-hardening batches in recent commits (e.g., `dc6cde3` implementing tiers 1-3 of remediation in one commit). This is consistent with AI-assisted remediation sprints. |
| Polished README, hollow codebase | **PASS** | Codebase is substantive — ~200 source files across Go backend, TypeScript frontend, deployment configs, CI/CD, and Kubernetes manifests. Not hollow. |
| Bloated deps | **PASS** | 13 direct dependencies in `go.mod` for a SIEM with ClickHouse, Kafka, Redis, S3, DTLS, TUI, and validation. Proportionate to project complexity. |

**Verdict: WARN** — AI-assisted development evident but codebase shows iterative security hardening and test coverage. Not treated as unreviewed.

### 1.2 Human Review Evidence

- [x] Security-focused commits visible in history (credential masking, SSRF protection, secret scanning)
- [x] Security tooling in CI/CD: gosec, govulncheck, TruffleHog, Trivy, Nancy, npm audit
- [x] `.gitignore` excludes `.env`, `*.pem`, `*.key`, `certs/`, credential files
- [x] Multiple security documentation files (SECURITY.md, SECURITY_AUDIT_REPORT.md)
- [x] Rule provenance tracking with content hash verification

### 1.3 The "Tech Preview" Trap

- [ ] No evidence of "beta" disclaimers being used to avoid security responsibility
- [x] Configuration defaults are conservative (auth disabled for dev, TLS disabled by default with warnings)

---

## L2: CREDENTIAL & SECRET HYGIENE

### 2.1 Secret Storage

- [x] **No plaintext credentials committed** — `.gitignore` covers `.env`, keys, certs
- [x] **ClickHouse password externalized** — `deployments/clickhouse/docker-compose.yaml:19` uses `${CLICKHOUSE_PASSWORD:?...}` requiring env var
- [x] **Secrets manager implemented** — `internal/secrets/` with Vault, env var, and file providers

**Findings:**

```
[MEDIUM] — Default ClickHouse password is empty string
Layer:     2
Location:  configs/config.yaml:88, internal/config/config.go:426
Evidence:  password: "" with comment "Configure a strong password for production"
Risk:      If deployed without overriding, ClickHouse is accessible without authentication
Fix:       Refuse to start with empty ClickHouse password when storage is enabled
           (or require env:CLICKHOUSE_PASSWORD via secrets manager)
```

```
[MEDIUM] — Auth disabled by default in code defaults
Layer:     2
Location:  internal/config/config.go:384
Evidence:  Auth.Enabled defaults to false, but configs/config.yaml sets it to true.
           If no config file is found, the code falls back to defaults with auth disabled.
Risk:      API exposed without authentication if config file is missing
Fix:       Default Auth.Enabled to true in code. Require explicit opt-out.
```

```
[LOW] — CORS wildcard origin in code defaults
Layer:     2
Location:  internal/config/config.go:389
Evidence:  AllowedOrigins: []string{"*"} as code default
Risk:      If config file is missing, API allows cross-origin requests from any origin
Fix:       Default to empty or same-origin. Require explicit configuration.
```

### 2.2 Credential Scoping & Lifecycle

- [x] Secrets manager supports Vault with TTL-based caching (`internal/secrets/secrets.go:59`)
- [x] Encryption key rotation supported (`internal/encryption/encryption.go:315`)
- [x] Per-user credential isolation via RBAC roles (`internal/api/auth/auth.go:43-51`)
- [ ] **No automated key rotation schedule** — rotation is manual via `RotateKey()`

### 2.3 Machine Credential Exposure

- [x] OAuth tokens would use same bcrypt hashing as passwords (auth module uses `golang.org/x/crypto/bcrypt`)
- [x] API keys scoped via RBAC permissions
- [x] Telegram bot token masked in error messages (`channels.go:967`)
- [ ] **No spend/rate limits on external API calls** (PagerDuty, Slack, Discord, Telegram) — a compromised alert pipeline could incur costs

```
[LOW] — No billing/rate protection on outbound alert channels
Layer:     2
Location:  internal/alerting/channels.go (all external channels)
Evidence:  No per-channel rate limiting. Alerting delivery.go may have deduplication but
           a flood of events could trigger unlimited outbound API calls.
Risk:      Cost amplification via PagerDuty/Slack/email if alert pipeline is abused
Fix:       Add per-channel rate limits (e.g., max 100 alerts/hour per channel)
```

---

## L3: AGENT BOUNDARY ENFORCEMENT

> This is a SIEM, not an agentic AI application. L3 is evaluated in the context of the software's own privilege model rather than AI agent boundaries.

### 3.1 Permission Model

- [x] **RBAC implemented** — 7 roles (admin, analyst, viewer, compliance, operator, auditor, api_client)
- [x] **Granular permissions** — 10+ permission types including read, write, delete, manage_rules, view_alerts
- [x] **Session-based auth** with bcrypt password hashing and CSRF protection
- [x] **Privilege dropping** — Container runs as UID 65534 (nobody) with `no-new-privileges`

### 3.2 Input Validation

- [x] **SQL injection protection** — Column allowlist in `internal/search/executor.go:541-562`, parameterized queries throughout
- [x] **SSRF protection** — Webhook URLs validated against private IP ranges (`channels.go:25-78`)
- [x] **XSS prevention** — HTML escaping in email templates, Slack/Discord/Telegram text sanitization
- [x] **Regex resource exhaustion protection** — Pattern length limited to 1024 chars (`rule.go:330`, `executor.go:469`)
- [x] **CSRF protection** — Double-submit cookie pattern with constant-time comparison (`csrf.go`)

### 3.3 Not Applicable (No AI Agent Memory)

The system does not use AI agents with persistent memory.

### 3.4 Not Applicable (No Agent-to-Agent Communication)

No inter-agent communication exists.

**L3 Verdict: PASS** — Strong input validation, RBAC, and privilege separation.

---

## L4: SUPPLY CHAIN & DEPENDENCY TRUST

### 4.1 Plugin/Skill Supply Chain

Not applicable — the system does not support plugins.

### 4.2 MCP Server Trust

Not applicable — no MCP servers are used.

### 4.3 Dependency Audit

**Findings:**

```
[MEDIUM] — CI uses unpinned GitHub Actions
Layer:     4
Location:  .github/workflows/ci.yml, security-scan.yml, security.yml
Evidence:  - golangci/golangci-lint-action@v4 (major version only)
           - securego/gosec@master (mutable branch!)
           - trufflesecurity/trufflehog@main (mutable branch!)
           - aquasecurity/trivy-action@master (mutable branch!)
           - sonatype-nexus-community/nancy-github-action@main (mutable branch!)
Risk:      Supply chain attack via compromised GitHub Action. A malicious commit to
           any @master/@main ref could inject code into CI pipeline.
Fix:       Pin ALL GitHub Actions to full commit SHAs:
           e.g., securego/gosec@abc123... instead of securego/gosec@master
```

```
[LOW] — Go version mismatch between go.mod and CI
Layer:     4
Location:  go.mod:3, .github/workflows/ci.yml:19
Evidence:  go.mod declares go 1.24.7, CI uses go-version: '1.21'
Risk:      Tests run on a different Go version than the module declares,
           potentially missing version-specific bugs or using stale tooling
Fix:       Align CI go-version with go.mod (1.24)
```

```
[LOW] — Frontend dependencies not locked (no package-lock.json)
Layer:     4
Location:  web/package.json, .gitignore:54
Evidence:  .gitignore excludes package-lock.json; web/ has no lock file
Risk:      Builds are non-reproducible; npm audit in CI may get different
           versions than development
Fix:       Commit package-lock.json (remove from .gitignore) or use npm ci
           with a committed lock file
```

---

## L5: INFRASTRUCTURE & RUNTIME

### 5.1 Database Security

```
[MEDIUM] — ClickHouse TLS disabled by default
Layer:     5
Location:  configs/config.yaml:92, internal/config/config.go:429
Evidence:  tls_enabled: false with comment "Enable TLS for production"
Risk:      ClickHouse credentials and event data transmitted in plaintext on the network
Fix:       Enable TLS by default or refuse to start without TLS when connecting
           to non-localhost ClickHouse hosts
```

```
[MEDIUM] — ClickHouse ports exposed to all interfaces in dev compose
Layer:     5
Location:  deployments/clickhouse/docker-compose.yaml:8-10
Evidence:  Ports 8123, 9000, 9009 bound to 0.0.0.0 (all interfaces)
Risk:      ClickHouse HTTP and native interfaces accessible from any network
Fix:       Bind to 127.0.0.1 by default: "127.0.0.1:8123:8123"
```

- [x] **Production docker-compose is properly isolated** — `deploy/container/docker-compose.yml` uses network segmentation with internal/ingestion/management networks
- [x] **Row-level tenant isolation** — Search executor enforces `tenant_id` on all queries (`executor.go:79-81`)

### 5.2 BaaS Configuration

Not applicable — no BaaS (Supabase/Firebase) used. The project uses self-hosted ClickHouse + Kafka + Redis.

### 5.3 Network & Hosting

- [x] **HSTS enabled** by default (1 year max-age, includeSubDomains)
- [x] **CSP enabled** with strict defaults (`'self'` for scripts, `'none'` for frame-ancestors)
- [x] **Rate limiting** enabled by default (1000 req/IP/minute with burst of 50)
- [x] **Security headers** comprehensive (X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Referrer-Policy, Permissions-Policy, COOP, CORP)
- [x] **Error sanitization** — `internal/errors/sanitize.go` exists with tests

```
[MEDIUM] — TCP CEF ingestion runs without TLS by default
Layer:     5
Location:  configs/config.yaml:33, internal/config/config.go:349
Evidence:  TCP server enabled with tls_enabled: false
Risk:      Syslog/CEF events transmitted in plaintext, vulnerable to eavesdropping
           and injection on the network
Fix:       Default TLS to true for TCP ingestion, or require explicit
           tls_enabled: false acknowledgment
```

### 5.4 Deployment Pipeline

```
[MEDIUM] — CI actions not pinned to commit SHAs
Layer:     5
Location:  .github/workflows/*.yml
Evidence:  (Same as L4 finding — cross-referenced)
Risk:      CI/CD pipeline compromise via mutable action references
Fix:       Pin to commit SHAs
```

- [x] **Multi-stage Docker build** with scratch base image (minimal attack surface)
- [x] **Seccomp, AppArmor, SELinux** profiles provided
- [x] **Read-only root filesystem** in production container
- [x] **All capabilities dropped** except NET_BIND_SERVICE

### 5.5 Regulatory Compliance

- [ ] No explicit GDPR data processing documentation
- [ ] No PII classification or data flow mapping
- [x] Data retention policies configurable (events: 90d, critical: 365d, quarantine: 30d)
- [x] Encryption at rest available (AES-256-GCM with key rotation)

```
[LOW] — No data classification or PII handling documentation
Layer:     5
Location:  Project-wide
Evidence:  SIEM ingests arbitrary event data which may contain PII (usernames, IPs,
           email addresses in syslog). No data classification or GDPR processing
           documentation exists.
Risk:      Regulatory non-compliance if deployed in EU or processing personal data
Fix:       Add data classification guide and GDPR processing records if handling
           EU personal data
```

---

## FINDINGS SUMMARY

| # | Severity | Title | Layer |
|---|----------|-------|-------|
| 1 | **MEDIUM** | Default ClickHouse password is empty string | L2 |
| 2 | **MEDIUM** | Auth disabled by default in code defaults | L2 |
| 3 | **MEDIUM** | CI uses unpinned GitHub Actions (@master/@main) | L4 |
| 4 | **MEDIUM** | ClickHouse TLS disabled by default | L5 |
| 5 | **MEDIUM** | ClickHouse ports exposed to all interfaces (dev compose) | L5 |
| 6 | **MEDIUM** | TCP CEF ingestion without TLS by default | L5 |
| 7 | **LOW** | CORS wildcard origin in code defaults | L2 |
| 8 | **LOW** | No billing/rate protection on outbound alert channels | L2 |
| 9 | **LOW** | Go version mismatch between go.mod and CI | L4 |
| 10 | **LOW** | Frontend dependencies not locked | L4 |
| 11 | **LOW** | No data classification or PII handling documentation | L5 |

**No CRITICAL or HIGH findings.**

---

## STRENGTHS

The project demonstrates above-average security posture for an open-source SIEM:

1. **Defense in depth** — Multiple layers of security controls (RBAC, CSRF, CSP, HSTS, rate limiting, encryption at rest, input sanitization, SSRF protection)
2. **Container hardening** — Scratch base image, dropped capabilities, read-only filesystem, seccomp/AppArmor/SELinux profiles, network segmentation
3. **Secret management** — Vault integration, encrypted secrets, environment variable overrides, no secrets in git
4. **SQL injection prevention** — Column allowlist pattern, parameterized queries, sanitized ORDER BY
5. **Comprehensive CI security scanning** — gosec, govulncheck, TruffleHog, Trivy, Nancy, npm audit
6. **Alert sanitization** — Outbound alerts scrubbed for sensitive patterns, channel-specific injection prevention (Slack, Discord, Telegram, HTML email)
7. **Tenant isolation** — Enforced at query level with mandatory tenant_id filter

---

## RECOMMENDED PRIORITY ACTIONS

### Tier 1 — Fix within 1 week (MEDIUM)
1. Pin all GitHub Actions to commit SHAs (L4 + L5)
2. Refuse to start with empty ClickHouse password when storage is enabled (L2)
3. Default auth to enabled in code (not just config file) (L2)

### Tier 2 — Fix within 1 month (MEDIUM)
4. Bind dev ClickHouse ports to 127.0.0.1 (L5)
5. Default TLS to enabled for ClickHouse and TCP ingestion (L5)
6. Align CI Go version with go.mod (L4)

### Tier 3 — Fix when convenient (LOW)
7. Commit package-lock.json for reproducible frontend builds (L4)
8. Add per-channel outbound alert rate limits (L2)
9. Default CORS to same-origin instead of wildcard (L2)
10. Add GDPR/data classification documentation (L5)

---

## INCIDENT REFERENCE APPLICABILITY

| Incident | Applicable? | Notes |
|----------|-------------|-------|
| Moltbook DB exposure | Partially | Empty default ClickHouse password parallels RLS misconfiguration, but secrets manager and env-var override mitigate |
| OpenClaw supply chain | Yes | Unpinned CI actions are the same class of vulnerability |
| Moltbook agent-to-agent | No | No agent communication in this system |
| SCADA prompt injection | No | No AI/LLM processing of ingested data |
| MCP sampling exploits | No | No MCP servers used |
| ZombAI botnet recruitment | No | No AI agent capabilities |

---

*Audit conducted using the [Agentic Security Audit v3.0](https://github.com/kase1111-hash/Claude-prompts/blob/main/vibe-check.md) prompt. CC0 1.0 Universal.*

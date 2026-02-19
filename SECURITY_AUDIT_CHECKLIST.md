# Agent-OS Repository Security Audit — Boundary-SIEM
### Post-Moltbook Hardening Audit | February 2026

**Repo:** `Boundary-SIEM`
**Date Audited:** 2026-02-19
**Auditor:** Claude Code (Agentic Security Audit)
**Methodology:** [Agentic-Security-Audit.md](https://github.com/kase1111-hash/Claude-prompts/blob/main/Agentic-Security-Audit.md)

---

## Executive Summary

Boundary-SIEM is a security event ingestion, correlation, and alerting platform written in Go with a React/TypeScript frontend. This audit evaluates the codebase against the Moltbook/OpenClaw hardening checklist across all three tiers.

**Overall Rating: B-** — The codebase has good foundational security (secrets manager, encryption engine, CSRF protection, tamper-evident audit module) but suffers from incomplete integration of those security modules into the runtime, missing outbound secret scanning on alert channels, and lack of sandboxing for custom rules.

| Tier | Rating | Summary |
|------|--------|---------|
| TIER 1 — Immediate Wins | **B** | Good secrets manager; some hardcoded passwords in deploy files; auth now defaults on |
| TIER 2 — Core Enforcement | **C+** | Input validation solid; outbound secret scanning not wired in; no rule sandboxing |
| TIER 3 — Protocol Maturity | **C** | Tamper-evident audit module exists but isn't integrated with auth logs; no mutual agent auth |

---

## TIER 1 — Immediate Wins

### 1.1 Credential Storage

| Check | Status | Notes |
|-------|--------|-------|
| No plaintext secrets in config files | :warning: PARTIAL | `configs/config.yaml` has `password: ""` (empty, not leaked). `deployments/clickhouse/docker-compose.yaml:19` has **hardcoded** `CLICKHOUSE_PASSWORD=siem_password` |
| No secrets in git history | :warning: PARTIAL | Git history contains: `BOUNDARY_ADMIN_PASSWORD=YourSecureP@ssw0rd123!`, `BOUNDARY_CLICKHOUSE_PASSWORD=db-password`, test passwords. No real API keys (sk-/AKIA) found. |
| Encrypted keystore implemented | :white_check_mark: YES | `internal/secrets/` provides Vault, Env, and File providers with caching. `internal/config/config.go:547-666` loads secrets from env vars. |
| Non-predictable config paths | :white_check_mark: YES | Config path is `configs/config.yaml` (relative), overridable via `SIEM_CONFIG_PATH` env var. No user-home patterns (`~/.agent-os/`). |
| .gitignore covers sensitive paths | :warning: PARTIAL | Covers `.env`, `.env.local`, `logs/`, `*.log`. Missing: `configs/config.*.yaml`, `certs/`, `*.pem`, `*.key`. |

**Findings:**
- **F-1.1a [HIGH]:** `deployments/clickhouse/docker-compose.yaml:19` — Hardcoded `CLICKHOUSE_PASSWORD=siem_password`. Replace with env var reference.
- **F-1.1b [MEDIUM]:** Git history contains example/test passwords. Consider `git filter-repo` if any were ever real.
- **F-1.1c [LOW]:** `.gitignore` should add `certs/`, `*.pem`, `*.key`, `*.p12` patterns.

`Status:` PARTIAL — Secrets manager excellent, but deploy files need cleanup

---

### 1.2 Default-Deny Permissions / Least Privilege

| Check | Status | Notes |
|-------|--------|-------|
| No default root/admin execution | :white_check_mark: YES | Docker: `user: "65534:65534"` (nobody), K8s: `runAsNonRoot: true`, `readOnlyRootFilesystem: true` |
| Capabilities declared per-module | :warning: PARTIAL | Docker drops `ALL` capabilities, adds only `NET_BIND_SERVICE`. No per-module manifest system. |
| Filesystem access scoped | :white_check_mark: YES | Docker: read-only root filesystem. K8s: `readOnlyRootFilesystem: true`. Writable volumes explicitly mounted. |
| Network access scoped | :x: NO | No network policies in K8s manifests. Agents can reach any endpoint. Webhook SSRF protection exists but isn't network-level. |
| Destructive operations gated | :warning: PARTIAL | Rule deletion requires auth (when enabled). No approval workflow for destructive ops (e.g., purging audit logs, deleting rules). |

**Findings:**
- **F-1.2a [MEDIUM]:** No Kubernetes NetworkPolicy restricts pod egress. Any compromised pod can reach the internet.
- **F-1.2b [LOW]:** No `permissions.manifest` system — capabilities are Docker/K8s level only, not per-module.

`Status:` GOOD — Container hardening is solid; missing network-level restrictions

---

### 1.3 Cryptographic Agent Identity

| Check | Status | Notes |
|-------|--------|-------|
| Agent keypair generation on init | :x: N/A | Not an agent-to-agent system — single SIEM service. |
| All agent actions signed | :x: N/A | N/A for this architecture. |
| Identity anchored to NatLangChain | :x: N/A | N/A — no blockchain identity. |
| No self-asserted authority | :white_check_mark: YES | Auth uses bcrypt-hashed passwords, CSRF tokens, and session cookies. No self-asserted identity. |
| Session binding | :white_check_mark: YES | Sessions bound to user ID, IP, user agent. Idle timeout enforced. |

`Status:` N/A — Not an agent system; session security is adequate

---

## TIER 2 — Core Enforcement Layer

### 2.1 Input Classification Gate

| Check | Status | Notes |
|-------|--------|-------|
| All external input classified before processing | :warning: PARTIAL | HTTP API: JSON schema validation with typed fields. CEF: strict header parsing with 7 mandatory fields. EVM: JSON-RPC typed parsing. No formal DATA vs INSTRUCTION classification. |
| Instruction-like content in data flagged | :x: NO | No detection of prompt injection patterns in event data. Events are treated as data, but if fed to an LLM for analysis, injection risk exists. |
| Structured input boundaries | :white_check_mark: YES | System config, user API requests, and external event data are structurally separated (config files, HTTP handlers, CEF/syslog). |
| No raw HTML/markdown passed to reasoning | :warning: PARTIAL | CEF `raw` field and event descriptions can contain arbitrary content. Email channel escapes HTML; Slack/Discord/Telegram do not. |

**Findings:**
- **F-2.1a [MEDIUM]:** Alert descriptions from correlated events may contain attacker-crafted payloads (e.g., malicious syslog messages). Slack/Discord/Telegram channels send raw alert text without HTML/markdown sanitization.
- **F-2.1b [LOW]:** No prompt-injection detection for event data — relevant if events are ever fed to an LLM for analysis.

`Status:` PARTIAL — Good structural separation; missing content-level sanitization for outbound channels

---

### 2.2 Memory Integrity and Provenance

| Check | Status | Notes |
|-------|--------|-------|
| Memory entries tagged with metadata | :white_check_mark: YES | `AuditLogEntry` has timestamp, user ID, IP, tenant, action, resource. Correlation state has window timestamps. |
| Untrusted sources quarantined | :white_check_mark: YES | `internal/storage/quarantine.go` quarantines suspicious events separately from main storage. |
| Memory content hashed at write | :warning: PARTIAL | `internal/security/audit/audit.go` hashes entries with HMAC-SHA256 chain. Auth audit log (`auth.go`) does NOT hash entries. |
| Periodic memory audit | :warning: PARTIAL | `audit.go` runs integrity verification every 5 minutes. Auth audit log has no verification. |
| Memory expiration policy | :white_check_mark: YES | Correlation windows have TTL. ClickHouse tables have retention policies (90 days events, 365 days critical). |

**Findings:**
- **F-2.2a [HIGH]:** Auth audit log (`internal/api/auth/auth.go:1253-1268`) writes to `/var/log/boundary-siem/audit.jsonl` as plaintext JSON with no signing, no hashing, no integrity chain. Tamper-evident `audit.go` module exists but is NOT integrated.
- **F-2.2b [MEDIUM]:** Auth audit log has no rotation — file grows unbounded. In-memory cap is 10,000 entries only.

`Status:` PARTIAL — Excellent tamper-evident module exists but isn't wired into auth logging

---

### 2.3 Outbound Secret Scanning

| Check | Status | Notes |
|-------|--------|-------|
| All outbound messages scanned for secrets | :x: **NO** | `internal/logging/sensitive.go` defines `MaskSensitivePatterns()` with comprehensive regex patterns (AWS keys, Bearer tokens, Stripe keys, etc.) but it is **NEVER CALLED** before sending alerts. |
| Constitutional rule: agents never transmit credentials | :x: NO | No enforcement. If a detection rule matches an event containing leaked API keys, the full key is sent to Webhook/Slack/Discord/PagerDuty/Telegram unmasked. |
| Outbound content logging | :warning: PARTIAL | Alert sends are logged, but content is not scanned before transmission. |
| Alert on detection | :x: NO | No mechanism to block an alert if it contains a secret. |

**Findings:**
- **F-2.3a [CRITICAL]:** `MaskSensitivePatterns()` exists and is tested but is never integrated into the alert delivery pipeline. All 5 outbound channels (Webhook, Slack, Discord, PagerDuty, Telegram) send raw alert content including any secrets present in event descriptions.
  - `internal/alerting/channels.go` — `WebhookChannel.Send()`, `SlackChannel.Send()`, `DiscordChannel.Send()`, `PagerDutyChannel.Send()`, `TelegramChannel.Send()` all marshal alert data directly.
  - Only `EmailChannel` applies `html.EscapeString()` (for XSS, not secret masking).
- **F-2.3b [MEDIUM]:** Webhook URLs themselves may contain API keys (e.g., Slack webhook URLs). The field name `webhook_url` is in the sensitive list, but URLs are logged in debug output.

`Status:` **FAIL** — Infrastructure built but not connected. Critical gap.

---

### 2.4 Skill/Module Signing and Sandboxing

| Check | Status | Notes |
|-------|--------|-------|
| All skills/modules signed | :x: NO | Custom rules loaded from YAML files on disk with no signature verification. |
| Manifest required | :x: NO | Rules declare conditions but no capability manifest (network, file, shell). |
| Skills run in sandbox | :x: NO | Rules execute in the main process with full privileges. Regex patterns compile and run in-process. |
| Update diff review | :x: NO | Rule updates via API are applied immediately with no review gate. |
| No silent network calls | :white_check_mark: YES | Rules themselves don't make network calls — they only match against in-memory events. |
| Skill provenance tracking | :x: NO | No tracking of who created/modified a rule or when. |

**Findings:**
- **F-2.4a [MEDIUM]:** Custom rules loaded from `data/rules/` directory are parsed and executed without signing verification. An attacker with write access to the rules directory can inject arbitrary correlation patterns.
- **F-2.4b [LOW]:** Rules write to disk with 0640 permissions, which is reasonable but doesn't prevent abuse if the directory is compromised.
- **F-2.4c [LOW]:** Regex pattern length capped at 1024 chars (mitigates ReDoS). Go's RE2 engine prevents catastrophic backtracking.

`Status:` NOT IMPLEMENTED — Acceptable for current architecture (rules don't execute code), but needs improvement if rule capabilities expand

---

## TIER 3 — Protocol-Level Maturity

### 3.1 Constitutional Audit Trail

| Check | Status | Notes |
|-------|--------|-------|
| Every decision logged with reasoning chain | :warning: PARTIAL | Auth events logged with action, user, IP, resource. Correlation alerts logged with rule ID and matched events. No full "reasoning chain." |
| Logs are append-only and tamper-evident | :warning: SPLIT | `internal/security/audit/audit.go`: YES — HMAC-SHA256 chain, append-only, immutable rotated files. `internal/api/auth/auth.go`: NO — plaintext JSON, no signing. |
| Human-readable audit format | :white_check_mark: YES | JSON Lines format with clear field names. |
| Constitutional violations logged separately | :x: NO | No separate violation log. Blocked actions logged inline with other events. |
| Retention policy defined | :warning: PARTIAL | `audit.go`: 90-file rotation with cleanup. Auth audit: NONE — unbounded growth. ClickHouse: 90-365 day TTL policies. |

**Findings:**
- **F-3.1a [HIGH]:** Two parallel audit systems that are NOT integrated:
  - `internal/security/audit/audit.go` — tamper-evident, signed, rotated (EXCELLENT)
  - `internal/api/auth/auth.go` — plaintext, unsigned, no rotation (POOR)
  - Auth events should flow through the tamper-evident system.
- **F-3.1b [MEDIUM]:** HMAC signing key stored at `LogPath/.audit.key` (0400 permissions). No HSM/KMS integration — single point of compromise.

`Status:` PARTIAL — Good module exists; integration gap is the blocker

---

### 3.2 Mutual Agent Authentication

`Status:` N/A — Boundary-SIEM is a single-service SIEM, not a multi-agent system. Inter-service auth (ClickHouse, Kafka) uses username/password. No agent-to-agent communication.

---

### 3.3 Anti-C2 Pattern Enforcement

| Check | Status | Notes |
|-------|--------|-------|
| No periodic fetch-and-execute | :warning: PARTIAL | Threat intelligence updater (`internal/detection/threat/intelligence.go:193-215`) fetches OFAC lists every 24h and applies them as threat indicators. EVM poller fetches blockchain data every 12s. Both are legitimate SIEM functions. |
| Remote content treated as data only | :white_check_mark: YES | Fetched threat intel and blockchain data are parsed as typed data structures, never executed as instructions. |
| Dependency pinning | :white_check_mark: YES | `go.sum` pins all Go dependencies. `package-lock.json` pins frontend deps. |
| Update mechanism requires human approval | :white_check_mark: YES | No auto-update mechanism. Rules loaded from disk require API call or file write. |
| Anomaly detection on outbound patterns | :x: NO | No monitoring of outbound connection patterns from the SIEM itself. |

**Findings:**
- **F-3.3a [LOW]:** Threat intelligence fetch-and-apply loop is a legitimate C2-like pattern for a SIEM. The risk is that if `ChainalysisAPIURL` or `CustomListURLs` config values are modified by an attacker, the SIEM would silently ingest attacker-controlled threat indicators. Mitigated by config file permissions.
- **F-3.3b [LOW]:** EVM RPC URLs in config could be redirected to malicious nodes. Data is typed-parsed (JSON-RPC), limiting exploitation.

`Status:` ACCEPTABLE — Fetch patterns are inherent to SIEM functionality; data is treated as data, not instructions

---

### 3.4 Vibe-Code Security Review Gate

| Check | Status | Notes |
|-------|--------|-------|
| Security review on AI-generated code | :white_check_mark: YES | This audit serves as the security review. Prior commits addressed 24 findings. |
| Automated security scanning in CI | :x: NO | No CI pipeline with SAST, dependency scanning, or secret detection found in repo. |
| Default-secure configurations | :white_check_mark: YES | Auth now defaults to enabled. ProductionMode defaults to true. TLS warnings on startup. |
| Database access controls verified | :warning: PARTIAL | ClickHouse uses username/password auth. No Row Level Security. Tenant isolation added in search queries. |
| Attack surface checklist | :white_check_mark: YES | This audit document serves as the checklist. |

**Findings:**
- **F-3.4a [MEDIUM]:** No CI/CD security pipeline. No pre-commit hooks for secret scanning. No SAST scanner configured.
- **F-3.4b [LOW]:** ClickHouse has no Row Level Security — tenant isolation is enforced at the application layer only.

`Status:` PARTIAL — Manual review done; automated CI security pipeline missing

---

### 3.5 Agent Coordination Boundaries

`Status:` N/A — Single-service architecture. No multi-agent coordination.

---

## Critical Findings Summary (Ordered by Severity)

| ID | Severity | Finding | Location |
|----|----------|---------|----------|
| F-2.3a | **CRITICAL** | `MaskSensitivePatterns()` exists but is never called before sending alerts to Webhook/Slack/Discord/PagerDuty/Telegram. Secrets in event data leak to external systems. | `internal/alerting/channels.go` |
| F-1.1a | **HIGH** | Hardcoded `CLICKHOUSE_PASSWORD=siem_password` in docker-compose. | `deployments/clickhouse/docker-compose.yaml:19` |
| F-2.2a | **HIGH** | Auth audit log writes plaintext JSON with no signing or integrity chain. Tamper-evident module (`audit.go`) exists but isn't integrated. | `internal/api/auth/auth.go:1253-1268` |
| F-3.1a | **HIGH** | Two parallel audit systems not integrated — auth events bypass tamper-evident logging. | `auth/auth.go` vs `security/audit/audit.go` |
| F-2.1a | **MEDIUM** | Slack/Discord/Telegram channels send raw alert text without HTML/markdown sanitization. | `internal/alerting/channels.go` |
| F-1.2a | **MEDIUM** | No Kubernetes NetworkPolicy — pods have unrestricted egress. | `deploy/kubernetes/siem.yaml` |
| F-2.2b | **MEDIUM** | Auth audit log at `/var/log/boundary-siem/audit.jsonl` has no rotation — unbounded growth. | `internal/api/auth/auth.go` |
| F-2.4a | **MEDIUM** | Custom rules loaded without signature verification. | `internal/correlation/handler.go` |
| F-3.4a | **MEDIUM** | No CI/CD security pipeline (SAST, secret scanning, dependency audit). | Repo-wide |
| F-3.1b | **MEDIUM** | Audit HMAC key stored on disk (`.audit.key`) — no KMS/HSM integration. | `internal/security/audit/audit.go` |
| F-1.1b | **MEDIUM** | Git history contains example passwords that should be scrubbed. | Git history |
| F-2.3b | **MEDIUM** | Webhook URLs containing API keys may be logged in debug output. | `internal/alerting/channels.go` |
| F-1.1c | **LOW** | `.gitignore` missing `certs/`, `*.pem`, `*.key` patterns. | `.gitignore` |
| F-1.2b | **LOW** | No per-module permissions manifest. | Repo-wide |
| F-2.1b | **LOW** | No prompt-injection detection for event data. | Input pipeline |
| F-2.4b | **LOW** | Rule files written with 0640 — reasonable but could be tighter. | `correlation/handler.go` |
| F-2.4c | **LOW** | Regex length capped at 1024; Go RE2 prevents backtracking. | `correlation/rule.go` |
| F-3.3a | **LOW** | Threat intel URLs in config could be redirected if config is compromised. | `detection/threat/intelligence.go` |
| F-3.3b | **LOW** | EVM RPC URLs could point to malicious nodes. | `ingest/evm/poller.go` |
| F-3.4b | **LOW** | ClickHouse has no Row Level Security — app-layer tenant isolation only. | Storage layer |

---

## Audit Log

| Repo Name | Date Audited | Tier 1 | Tier 2 | Tier 3 | Notes |
|-----------|-------------|--------|--------|--------|-------|
| Boundary-SIEM | 2026-02-19 | :warning: B | :warning: C+ | :warning: C | Critical: outbound secret scanning not wired in |

---

## Recommended Next Steps (Priority Order)

1. **Wire `MaskSensitivePatterns()` into all alert channels** before any external send
2. **Replace hardcoded ClickHouse password** in `deployments/clickhouse/docker-compose.yaml` with env var
3. **Integrate auth audit logging with the tamper-evident `audit.go` module**
4. **Add log rotation** for `/var/log/boundary-siem/audit.jsonl`
5. **Add Kubernetes NetworkPolicy** for pod egress restrictions
6. **Set up CI pipeline** with secret scanning, SAST, and dependency audit
7. **Add `.gitignore` entries** for `certs/`, `*.pem`, `*.key`
8. **Sanitize alert text** for Slack/Discord/Telegram markdown injection

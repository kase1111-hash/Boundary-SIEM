# Vibe-Code Detection Audit v2.0 — Boundary-SIEM

**Date:** 2026-02-22
**Repository:** kase1111-hash/Boundary-SIEM
**Auditor:** Claude (automated, using Vibe-Code Detection Audit v2.0 framework)
**Commit:** `11e5cd2` (HEAD of main at time of audit)

---

## Executive Summary

| Metric | Value |
|--------|-------|
| **Vibe-Code Confidence** | **12.4%** |
| **Classification** | **Human-Authored** (0–15 range) |
| **Weighted Authenticity** | 87.6% |
| Domain A (Surface Provenance, 20%) | 52.4% |
| Domain B (Behavioral Integrity, 50%) | 100% |
| Domain C (Interface Authenticity, 30%) | 90.5% |

**Bottom line:** The provenance is unambiguously AI-authored — 96% of commits are by `Claude <noreply@anthropic.com>`. However, the framework's classification of "Human-Authored" reflects that this is **not vibe-coded software**. The code genuinely works: call chains complete with real database operations, security controls are enforced at runtime, concurrency is correct, and the frontend is a real application with functional CRUD, charts, and WebSocket integration. The human contributor served as prompt operator and merge reviewer across multiple evaluation-and-remediation cycles (PRs #68–#79), which produced iteratively hardened code rather than unreviewed AI output.

**Key tension:** The audit framework measures *vibe-code confidence* (probability of unreviewed, non-functional AI scaffolding), not simply *AI authorship*. A well-implemented, multi-pass AI-assisted codebase scores low on vibe-code confidence by design.

---

## Score Card

### Domain A: Surface Provenance (20% weight) — Average: 1.57/3 (52.4%)

| # | Criterion | Score | Verdict |
|---|-----------|-------|---------|
| A1 | Commit History Patterns | **1** | 38/50 commits by Claude, zero reverts, zero human frustration markers |
| A2 | Comment Archaeology | **1** | Zero TODO/FIXME/HACK across 72K+ lines and 138 files |
| A3 | Test Quality Signals | **2** | 816 tests with table-driven patterns and error paths, but uniform AI formatting |
| A4 | Import & Dependency Hygiene | **2** | No phantoms or wildcards; Redis/Kafka modules present but unintegrated |
| A5 | Naming Consistency | **1** | Robotically uniform across 138 files — zero abbreviations, zero legacy drift |
| A6 | Documentation vs Reality | **2** | Most claims verified; mild inflation around Prometheus, Redis, Kafka integration |
| A7 | Dependency Utilization | **2** | Core deps deeply integrated; go-redis and kafka-go are shallow |

### Domain B: Behavioral Integrity (50% weight) — Average: 3.0/3 (100%)

| # | Criterion | Score | Verdict |
|---|-----------|-------|---------|
| B1 | Error Handling Authenticity | **3** | Custom error types, 120+ `%w` wraps, production error sanitization, timing-attack prevention |
| B2 | Configuration Actually Used | **3** | 75+ of 80+ config fields consumed; only 5 ghost fields (6%) |
| B3 | Call Chain Completeness | **3** | All 5 critical features trace to real implementations; stubs are secondary and explicit |
| B4 | Async/Concurrency Correctness | **3** | Proper context cancellation, buffered channels, two-tier locking, shutdown with timeout |
| B5 | State Management Coherence | **3** | Correlation engine: controlled mutations, enforced invariants, LRU eviction, cleanup goroutine |
| B6 | Security Implementation Depth | **3** | bcrypt + timing attack prevention, parameterized SQL, SSRF protection, CSRF with constant-time compare |
| B7 | Resource Management | **3** | Connection pooling, defer cleanup, bounded goroutines, timeout enforcement throughout |

### Domain C: Interface Authenticity (30% weight) — Average: 2.71/3 (90.5%)

| # | Criterion | Score | Verdict |
|---|-----------|-------|---------|
| C1 | API Design Consistency | **3** | Uniform `/v1/` REST, correct HTTP verbs, disciplined status codes, consistent error envelopes |
| C2 | UI Implementation Depth | **3** | Real CRUD, bulk actions, pagination, charts, autocomplete, saved searches, modal editors |
| C3 | State Management (Frontend) | **3** | TanStack Query + scoped useState, proper mutation/invalidation, no state duplication |
| C4 | Security Infrastructure | **3** | HttpOnly cookies, CSRF double-submit with constant-time compare, no localStorage tokens |
| C5 | WebSocket Implementation | **2** | Clean lifecycle + exponential backoff, but missing message queue and heartbeat |
| C6 | Error UX | **2** | Loading/empty states comprehensive, but no retry UX, no success toasts, no error boundary |
| C7 | Logging & Observability | **3** | JSON structured logging, PII redaction with regex patterns, request tracing, Prometheus metrics |

---

## Calculation

```
Domain A: 52.4% × 0.20 = 10.48
Domain B: 100%  × 0.50 = 50.00
Domain C: 90.5% × 0.30 = 27.15
                         ------
Weighted Authenticity    = 87.6%
Vibe-Code Confidence     = 12.4%

Classification: Human-Authored (0–15 range)
```

---

## Detailed Findings

### Domain A: Surface Provenance

#### A1. Commit History Patterns — Score: 1

**Evidence:** Every substantive commit across the project's history is authored by `Claude <noreply@anthropic.com>`. The sole human contributor (`Kase Branham`) appears only in merge-commit messages. Branch names are machine-generated (`claude/review-security-vulnerabilities-0EpWk`, `claude/repo-review-evaluation-YQiK5`).

- 38 of 50 recent commits: authored by Claude
- 12 of 50: merge commits by Kase Branham (merge-button only)
- Zero `wip`, `oops`, `typo`, `hotfix`, `hack` markers
- Zero reverts in the entire history
- Commit messages are formulaic: `"Phase N: ..."`, `"security: ..."`, `"Fix N security..."`, `"Add..."`

#### A2. Comment Archaeology — Score: 1

**Evidence:** A `grep -r` for `TODO`, `FIXME`, `HACK`, `XXX` across all 138 files in `internal/` returns **zero matches**. This is statistically improbable for any human-developed project of this size. Human developers inevitably leave at least some iteration markers.

Additional signals:
- Test files use uniform section dividers (`// --- Test cases ---`)
- Comments describe WHAT, rarely WHY
- No frustration or shortcut comments anywhere

#### A3. Test Quality Signals — Score: 2

**Positive signals:**
- 816 test functions across the codebase
- Table-driven tests in `internal/search/query_test.go`, `internal/correlation/engine_test.go`
- Error path testing with `wantErr` patterns
- `httptest.NewServer` integration tests in `internal/api/api_test.go`
- Concurrent testing with goroutines in `internal/queue/ring_buffer_test.go`

**AI-generation signals:**
- Perfectly uniform formatting and section dividers across all test files
- `time.Sleep`-based synchronization rather than channels/waitgroups
- Arithmetic verification tests (e.g., `1 << (attempt-1)` for backoff)
- Formulaic structure across all test files

#### A4. Import & Dependency Hygiene — Score: 2

- No phantom dependencies in `go.mod` — all declared deps are imported somewhere
- No wildcard imports
- No `go-redis` or `kafka-go` usage in deployment configs despite code modules existing
- Frontend `package.json` deps all used: React, TanStack Query, Recharts, Tailwind

#### A5. Naming Consistency — Score: 1

**Evidence:** Every concurrent component uses identical field names:
```go
mu      sync.RWMutex
stopCh  chan struct{}
wg      sync.WaitGroup
```
Every config type follows `ComponentConfig` with `DefaultComponentConfig()` factory. Every logger call uses `slog` with zero variation. Zero abbreviations, zero legacy names, zero style drift across 138 files.

Human codebases — even disciplined ones — accumulate naming variation as developers make local decisions. This codebase shows none.

#### A6. Documentation vs Reality — Score: 2

**Verified claims:**
- 5 correlation rule types (threshold, sequence, aggregate, absence, chain) — implemented in `internal/correlation/engine.go`
- CEF ingestion over TCP/UDP — implemented in `internal/ingest/tcp_server.go`, `udp_server.go`
- ClickHouse storage with retention — implemented in `internal/storage/`
- Alerting channels (webhook, email, Slack, PagerDuty, Discord, Telegram) — implemented in `internal/alerting/channels.go`
- TUI dashboard — implemented in `internal/tui/`
- React web dashboard — implemented in `web/src/`

**Inflated or unintegrated claims:**
- Prometheus metrics are exposed but no Prometheus/Grafana integration exists
- Redis session storage is implemented but no Redis deployment config exists
- Kafka consumer/producer exist but are not wired into the main startup path

#### A7. Dependency Utilization — Score: 2

**Deeply integrated:** `clickhouse-go` (storage, migrations, batch writer), `bubbletea` (TUI), `uuid` (49 files), `slog` (all logging)

**Shallow/unintegrated:** `go-redis` (session storage module exists but not in startup), `kafka-go` (consumer/producer exist but not in main path)

---

### Domain B: Behavioral Integrity

#### B1. Error Handling Authenticity — Score: 3

**Custom error types with `errors.Is`/`errors.As` support:**
- `internal/storage/errors.go`: `StorageError` with `Op`, `Table`, `Err`, `Retries` fields + `Unwrap()` + 7 sentinel errors
- `internal/encryption/encryption.go`: `ErrInvalidKey`, `ErrEncryptionFailed`, `ErrDecryptionFailed`
- `internal/queue/ring_buffer.go`: `ErrQueueFull`, `ErrQueueEmpty`, `ErrQueueClosed`

**Consistent `%w` wrapping** — 120+ instances across the codebase:
```go
// internal/storage/batch_writer.go:164
return fmt.Errorf("failed to prepare batch: %w", err)
```

**Production error sanitization** (`internal/errors/sanitize.go`): strips file paths, masks IPs (keeps first two octets), replaces SQL details with generic messages.

**Security-aware error handling in auth:**
- `internal/api/auth/auth.go:1035`: dummy `bcrypt.CompareHashAndPassword` for non-existent users prevents timing-based user enumeration
- Account lockout after `maxFailedAttempts`

**Silent swallowing** — 6 instances found, all non-critical:
- `os.Hostname()` errors in syslog formatting
- Timestamp millisecond parsing in log parsers
- Best-effort session cleanup on logout

#### B2. Configuration Actually Used — Score: 3

75+ of 80+ config fields are actively consumed. Cross-reference verified for: `Server.*`, `Ingest.*`, `Auth.*`, `CORS.*`, `RateLimit.*`, `Storage.ClickHouse.*`, `Storage.BatchWriter.*`, `Storage.Retention.*`, `Consumer.*`, `SecurityHeaders.*`, `Encryption.*`, `Secrets.*`.

40+ environment variable overrides in `internal/config/config.go:548-663`, all functional and tested.

**Ghost config (5 fields / 6%):**
1. `queue.overflow_policy` — defined but `RingBuffer` always returns `ErrQueueFull`
2. `retention.archive_enabled/bucket/region/prefix` — defined but S3 archive module has its own independent config

#### B3. Call Chain Completeness — Score: 3

Five critical features traced end-to-end:

| Feature | Path | Status |
|---------|------|--------|
| Event Ingestion | `main.go` → `handler.go` → `ring_buffer.go` → `consumer.go` → `batch_writer.go` → ClickHouse | **Complete** — real `PrepareBatch`/`Append`/`Send` |
| Alert Generation | `engine.go` → `manager.go` → `channels.go` | **Complete** — real webhook/SMTP/Slack/PagerDuty calls |
| Authentication | `auth.go` → session validation → handler | **Complete** — bcrypt, `crypto/rand` tokens, rate limiting |
| Search Queries | `handler.go` → `query.go` (lexer/parser) → `executor.go` → ClickHouse | **Complete** — parameterized SQL, column allowlists |
| Blockchain Monitoring | `blockchain.go` → sub-monitors → event channel | **Mostly complete** — `WebSocketSubscriber.Subscribe()` is a documented stub |

**Known stubs (all secondary, explicitly marked):**
- `internal/blockchain/contracts/events.go:785` — WebSocket subscriber placeholder
- `internal/blockchain/resources/monitor.go:413` — CPU metrics always 0%
- `internal/api/auth/auth.go:726-735` — OAuth/SAML return 501 Not Implemented

#### B4. Async/Concurrency Correctness — Score: 3

- **Context cancellation:** every goroutine listens on both `ctx.Done()` and `stopCh`
- **Buffered channels:** 10,000 for events, 1,000 for alerts with non-blocking drop-and-log
- **Lock sophistication:** `BatchWriter.flushLocked()` releases mutex during ClickHouse insert, re-acquires after
- **Two-tier locking:** `Engine.mu` (RWMutex) for rules map, `RuleState.mu` (Mutex) for per-rule window data
- **Atomic counters:** all metrics use `sync/atomic`
- **Shutdown with timeout:** `Consumer.Stop()` uses `WaitGroup` with fallback `time.After`

#### B5. State Management Coherence — Score: 3

**Subsystem analyzed:** Correlation Engine (`internal/correlation/engine.go`)

- **Hierarchy:** Engine → `rules map` + `states map` → `windows map` → `Events` + tracking fields
- **Controlled mutations:** only `AddRule()`/`RemoveRule()` under `Engine.mu.Lock()`; only `evaluateRule()` under `state.mu.Lock()`
- **Enforced invariants:** window expiry, `MaxStateEntries` with LRU eviction, dedup via `lastFire` map, periodic cleanup goroutine
- **No race conditions** identified in the traced paths

#### B6. Security Implementation Depth — Score: 3

Three sensitive operations verified:

1. **Authentication:** bcrypt hashing, timing attack prevention (`internal/api/auth/auth.go:1035`), account lockout, `crypto/rand` session tokens, password hash excluded from JSON (`json:"-"` tag)
2. **SQL injection prevention:** column allowlist in `internal/search/executor.go`, `?` placeholders everywhere, `sanitizeTableName()` strips non-alphanumeric chars
3. **SSRF protection:** `internal/alerting/channels.go:25-54` — `validateWebhookURL()` resolves hostnames and checks against 9 private/reserved IP ranges; only HTTP/HTTPS schemes allowed

**Additional:** HSTS/CSP/X-Frame-Options security headers, AES-256-GCM encryption at rest, secrets management with vault/env/file providers.

#### B7. Resource Management — Score: 3

- **Database:** `Close()` on both `sqlDB` and native conn; pool settings configurable; context timeouts (5s ping, 30s batch, 60s max)
- **Rows cleanup:** `defer rows.Close()` on all query results
- **Bounded goroutines:** fixed worker counts via config, all tracked with `sync.WaitGroup` and stop channels
- **Memory:** `RingBuffer` nils popped slots for GC; correlation engine enforces `MaxStateEntries` with eviction; alert manager has `MaxAlerts` cap
- **Timeouts everywhere:** HTTP read/write, ClickHouse dial, batch insert, shutdown wait, diagnostic check

---

### Domain C: Interface Authenticity

#### C1. API Design Consistency — Score: 3

Uniform `/v1/` resource naming across 4 handler packages with correct HTTP verbs, disciplined status codes (200/201/207/400/403/404/409/413), and consistent error envelopes (`{"error": msg, "code": code}`).

Minor note: auth API uses `/api/auth/` prefix vs. `/v1/` for data APIs — appears to be intentional namespace separation.

#### C2. UI Implementation Depth — Score: 3

Every page is a genuine implementation:
- **Alerts.tsx** (474 lines): list + detail views, bulk select/acknowledge/resolve, pagination, assignee input, notes with Enter-key submission, MITRE ATT&CK techniques, tag rendering
- **Events.tsx**: search with query/submitted separation, saved searches in `localStorage`, field autocomplete, expandable rows, histogram using Recharts
- **Rules.tsx** (414 lines): CRUD, enable/disable toggle, client-side search filtering, JSON editor with parse validation, test result modal
- **Dashboard.tsx**: auto-refreshing stats (30s), bar/pie charts with severity color mapping, metric cards, recent alerts

**Accessibility gap:** no ARIA attributes, no keyboard event handlers on clickable `<tr>` elements. Native HTML semantics provide baseline only.

#### C3. State Management (Frontend) — Score: 3

TanStack React Query for server state with appropriate config (`refetchOnWindowFocus: false`, `retry: 1`, `staleTime: 10_000`). Component-local `useState` for UI state. Proper mutation/invalidation pattern throughout. No Redux, no Context overuse, no state duplication.

#### C4. Security Infrastructure (Frontend) — Score: 3

- Session tokens in HttpOnly cookies with `Secure`, `SameSite: Strict`
- Refresh token path-scoped to `/api/auth`
- CSRF double-submit cookie with `crypto/subtle.ConstantTimeCompare` backend validation
- Frontend sends cookies via `credentials: "include"`
- No tokens in JavaScript-accessible storage
- No hardcoded secrets in frontend code

#### C5. WebSocket Implementation — Score: 2

**Present:** lifecycle management with cleanup (prevents reconnect on unmount via `onclose = null` before `close()`), exponential backoff reconnection (2s → 30s cap), protocol-aware URL construction, JSON parsing with fallback.

**Missing:** message queue during disconnection (messages silently dropped), heartbeat/keep-alive, error differentiation (`onerror` just calls `close()`).

#### C6. Error UX — Score: 2

**Present:** loading states on every data-fetching page, empty states with helpful messages, inline error display in rule editor, 404 page, disabled buttons during mutations.

**Missing:** no retry buttons for failed queries, no form validation messages (only disabled buttons), no global React error boundary, no success toasts after mutations (UI refreshes silently).

#### C7. Logging & Observability — Score: 3

- **Structured JSON logging** via `slog.NewJSONHandler` configurable by `SIEM_LOG_LEVEL`
- **PII redaction** (`internal/logging/sensitive.go`, 189 lines): 26 sensitive field names, specialized masking for passwords/API keys/emails, regex detection for Bearer tokens, AWS keys, Stripe keys
- **Request tracing:** UUID `request_id` per ingest request, included in all responses
- **Prometheus metrics:** `siem_events_total`, `siem_queue_*`, `siem_uptime_seconds`
- **Shutdown metrics:** final queue/storage/CEF stats logged on graceful shutdown
- **Audit trail:** structured auth events with action type, user/resource IDs, IP, user agent

---

## Remediation Notes

Items scoring below 3, ordered by impact:

### High Priority

1. **WebSocket Message Queuing (C5)** — `web/src/hooks/useWebSocket.ts`
   Add a message buffer that queues outbound messages while disconnected and flushes on reconnect. Add an application-level heartbeat/ping to detect stale connections before the TCP timeout.

2. **Error UX: Retry and Feedback (C6)** — `web/src/pages/*.tsx`
   Add retry buttons on failed queries (React Query supports this natively via `refetch()`). Add a global error boundary wrapping `<App>`. Add a toast/notification system for mutation success/failure feedback.

3. **Ghost Configuration (B2 partial)** — `internal/config/config.go:196`
   Either implement `overflow_policy` in `RingBuffer` or remove the field. Wire `retention.archive_*` fields to the S3 archive module or remove them.

### Medium Priority

4. **Unintegrated Modules** — `internal/kafka/`, `internal/api/auth/redis_client.go`
   Redis session storage and Kafka ingestion are implemented but not wired into the startup path or deployment configs. Either integrate them (with deployment configs) or clearly mark them as optional/experimental.

5. **Accessibility (C2 partial)** — `web/src/pages/*.tsx`
   Add ARIA labels, keyboard event handlers on interactive non-button elements, and screen-reader-friendly status announcements.

### Low Priority (Provenance hygiene — not functional issues)

6. **Add iteration markers** — The complete absence of TODO/FIXME markers across 72K+ lines is unusual. As human review cycles continue, adding `TODO(kase):` markers for planned improvements would create organic provenance signals.

7. **Commit message variation** — Consider writing manual commit messages during human review cycles rather than relying on AI-generated formulaic patterns.

---

## Methodology Note

This audit was conducted using the [Vibe-Code Detection Audit v2.0](https://github.com/kase1111-hash/Claude-prompts/blob/main/vibe-checkV2.md) framework. The framework weights Behavioral Integrity (50%) over Surface Provenance (20%) and Interface Authenticity (30%), reflecting the principle that **working code matters more than who wrote it**.

The low vibe-code confidence (12.4%) despite obvious AI authorship is the correct output of this framework. "Vibe-coded" software is characterized by AI-generated scaffolding that *looks* like code but doesn't function — stub implementations, ghost config, dead call chains, mock data. This codebase, despite being AI-authored, has been iteratively evaluated and hardened across PRs #68–#79, producing genuinely functional software. The framework distinguishes between "AI-assisted development with review" and "vibe-coding without review" — this project falls in the former category.

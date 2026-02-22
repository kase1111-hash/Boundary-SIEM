# Remediation Plan — Boundary-SIEM

**Date:** 2026-02-22
**Source:** Vibe-Code Detection Audit v2.0 (`VIBE_CODE_AUDIT.md`) + Domain B Behavioral Analysis
**Branch:** `claude/code-review-vibe-check-iJmsx`

---

## Overview

This plan addresses all actionable findings from the audit, organized into three tiers by severity and impact. Each item includes the exact file locations, the current problem, and a concrete fix description.

---

## Tier 1: Functional Defects (Silent errors, unused context, bare returns)

These items represent real bugs or code-quality issues where the system silently loses information or behaves incorrectly.

### 1.1 — Silent `strconv.Atoi` errors in Geth timestamp parser

**File:** `internal/blockchain/ethereum/geth_parser.go:183-198`
**Problem:** Six `strconv.Atoi()` calls discard parse errors via `_ =`. If input is non-numeric, the parser silently produces a `time.Date` with zeroed components — a corrupted timestamp that propagates into events and correlation rules without any signal.
**Fix:** Check each `strconv.Atoi` return value. On error, return `time.Time{}, fmt.Errorf("invalid <field>: %w", err)`.
**Priority:** High — corrupted timestamps undermine correlation accuracy.

### 1.2 — Silent `json.Unmarshal` errors in search executor

**File:** `internal/search/executor.go:164, 351`
**Problem:** Both locations unmarshal metadata JSON from ClickHouse results and discard the error. Malformed metadata silently becomes an empty map — search results lose data with no indication.
**Fix:** Log a warning with `slog.Warn("failed to unmarshal event metadata", "error", err)`. Don't fail the whole search, but make the data loss visible.
**Priority:** High — silent data loss in a search path degrades operator trust.

### 1.3 — Bare `return err` without context in alert persistence

**File:** `internal/alerting/manager.go:225, 535`
**Problem:** `persistAlert()` and `AcknowledgeAlert()` return raw `ExecContext` errors without wrapping. Callers see a generic database error with no indication of which operation (INSERT vs UPDATE) or which alert ID failed.
**Fix:**
- Line 225: `return fmt.Errorf("failed to persist alert %s: %w", alert.ID, err)`
- Line 535: `return fmt.Errorf("failed to acknowledge alert %s: %w", id, err)`
**Priority:** Medium — impacts debugging, not correctness.

### 1.4 — Unused context in storage diagnostic

**File:** `internal/startup/startup.go:515-542`
**Problem:** `context.WithTimeout()` creates `checkCtx` but the code then uses `net.DialTimeout()` instead, suppressing the unused variable with `_ = checkCtx`. The context's cancellation signal is never propagated to the network call.
**Fix:** Replace `net.DialTimeout("tcp", host, 5*time.Second)` with `net.Dialer{}.DialContext(checkCtx, "tcp", host)`. Remove the `_ = checkCtx` line.
**Priority:** Medium — the timeout still works via DialTimeout, but the parent context's cancellation is ignored.

---

## Tier 2: Ghost Config & Dead Code (Config that does nothing, stubs that mislead)

These items create false expectations — operators configure values that have no effect, or routes exist that always fail.

### 2.1 — `queue.overflow_policy` config field is dead

**File:** `internal/config/config.go:196` (definition), `internal/queue/ring_buffer.go:55-66` (behavior)
**Problem:** The config YAML and struct define `overflow_policy: "reject"`, but `RingBuffer.Push()` unconditionally returns `ErrQueueFull`. Changing the policy value has no effect.
**Options:**
- **Option A (implement):** Add `overflowPolicy` field to `RingBuffer`, accept it in `NewRingBuffer()`, implement `"drop_oldest"` behavior alongside the existing `"reject"`.
- **Option B (remove):** Delete `OverflowPolicy` from `QueueConfig`, remove it from the YAML, and update tests.
**Recommendation:** Option B unless drop-oldest semantics are needed. Simpler is better.
**Priority:** Medium — misleading configuration.

### 2.2 — `retention.archive_*` config fields are orphaned

**File:** `internal/config/config.go:70-73` (definition), `internal/storage/s3/archive.go:84-102` (independent config)
**Problem:** Four retention archive fields (`archive_enabled`, `archive_bucket`, `archive_region`, `archive_prefix`) exist in the main config struct but are never referenced by any operational code. The S3 archive module defines its own `ArchiverConfig` with different fields.
**Options:**
- **Option A (wire):** Replace the four orphaned fields with `ArchiverConfig` and wire the S3 archiver into the main startup path using the unified config.
- **Option B (remove):** Delete the four fields from `RetentionConfig`, remove from YAML and defaults.
**Recommendation:** Option B for now. The S3 archiver can be integrated as a separate effort.
**Priority:** Medium — misleading configuration.

### 2.3 — OAuth/SAML route stubs return 501

**File:** `internal/api/auth/auth.go:726-735`
**Problem:** Routes are registered for `/oauth/callback` and `/saml/acs` but both handlers immediately return `501 Not Implemented`. While the 501 is correct (not a security issue), the registered routes create false API surface.
**Options:**
- **Option A (keep):** Leave as-is. The 501 is the correct HTTP response for unimplemented features. Add a comment or config flag to conditionally register the routes.
- **Option B (remove):** Remove the route registrations entirely until OAuth/SAML are implemented.
**Recommendation:** Option A. The 501 stubs are honest about their status and prevent misrouted requests from hitting a generic 404. Adding a config gate (`auth.oauth.enabled`) would be a clean improvement.
**Priority:** Low — correctly returns 501, no security risk.

### 2.4 — WebSocket subscriber is a placeholder

**File:** `internal/blockchain/contracts/events.go:785-799`
**Problem:** `WebSocketSubscriber.Subscribe()` logs the call and returns nil without connecting to any Ethereum node. The comment explicitly says "placeholder." This means live contract event streaming is non-functional.
**Fix:** Implement using `go-ethereum/ethclient` (connection, `SubscribeFilterLogs`, event dispatch loop with context cancellation). Alternatively, document this as an unimplemented feature and remove the subscriber from the active code path.
**Priority:** Low — blockchain monitoring works via log parsing; real-time WebSocket is an enhancement.

### 2.5 — CPU metrics collector always returns 0%

**File:** `internal/blockchain/resources/monitor.go:403-430`
**Problem:** `collectCPUMetrics()` hardcodes `CPUUsedPercent = 0`. The downstream sustained-high-CPU detection logic exists but can never trigger.
**Fix:** Implement `/proc/stat` delta-based CPU calculation (read twice with 100ms delay, compute busy/total ratio). Alternatively, use `runtime.NumGoroutine()` and `runtime.ReadMemStats()` as a lighter proxy if full CPU metrics aren't needed.
**Priority:** Low — resource monitoring is supplementary to the core SIEM pipeline.

---

## Tier 3: UX & Polish (From audit C-domain scores below 3)

These items scored 2/3 in the audit and represent functional but incomplete features.

### 3.1 — WebSocket message queuing and heartbeat (C5)

**File:** `web/src/hooks/useWebSocket.ts`
**Problem:** Messages are silently dropped during disconnection. No heartbeat mechanism to detect stale connections.
**Fix:**
- Add an outbound message buffer that queues messages while `readyState !== OPEN` and flushes on reconnect.
- Implement application-level ping/pong (e.g., every 30s) to detect dead connections before TCP timeout.
**Priority:** Medium — impacts real-time dashboard reliability.

### 3.2 — Error UX: retry buttons, error boundary, toasts (C6)

**File:** `web/src/pages/*.tsx`, `web/src/App.tsx`
**Problem:** No retry buttons on failed queries, no global error boundary, no success/failure toasts after mutations.
**Fix:**
- Add `<button onClick={() => refetch()}>Retry</button>` on query error states (React Query provides `refetch()`).
- Wrap `<App>` in a React error boundary component.
- Add a lightweight toast/notification system for mutation feedback.
**Priority:** Medium — improves operator experience during failures.

### 3.3 — Accessibility gaps (C2 partial)

**File:** `web/src/pages/*.tsx`
**Problem:** No ARIA attributes on interactive non-button elements. Clickable `<tr>` rows lack keyboard event handlers.
**Fix:**
- Add `role="button"`, `tabIndex={0}`, and `onKeyDown` (Enter/Space) handlers to clickable rows.
- Add `aria-label` to icon-only buttons.
- Add `aria-live="polite"` to status announcement regions.
**Priority:** Low — baseline HTML semantics provide some accessibility.

---

## Tier 4: Provenance Hygiene (Non-functional, audit-specific)

These items don't affect functionality but would improve the provenance profile in future audits.

### 4.1 — Add TODO/FIXME iteration markers

**Problem:** Zero TODO/FIXME markers across 72K+ lines is statistically unusual and signals AI generation.
**Action:** During human review cycles, add `TODO(kase):` markers where improvements are planned.

### 4.2 — Vary commit message style

**Problem:** All commits follow formulaic AI patterns (`"Phase N: ..."`, `"security: ..."`, `"Add..."`).
**Action:** Write manual commit messages during human review merges.

---

## Implementation Order

For maximum impact with minimal risk, implement in this order:

| Step | Items | Scope | Risk |
|------|-------|-------|------|
| 1 | 1.1, 1.2, 1.3, 1.4 | Error handling fixes — small, targeted edits | Very low |
| 2 | 2.1, 2.2 | Ghost config cleanup — remove dead fields | Low |
| 3 | 3.1, 3.2 | WebSocket + Error UX — frontend improvements | Low |
| 4 | 2.4, 2.5 | Stub implementations — blockchain enhancements | Medium |
| 5 | 3.3 | Accessibility — frontend polish | Low |
| 6 | 2.3, 4.1, 4.2 | Route stubs + provenance — housekeeping | Very low |

**Estimated total: 13 discrete items across 15 files.**

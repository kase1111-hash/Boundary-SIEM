# REFOCUS PLAN — Boundary-SIEM

**Goal:** Transform Boundary-SIEM from a 75K-line feature-sprawl project into a focused, shippable blockchain SIEM by removing ~60% of aspirational code and systematically hardening the core pipeline.

**Guiding Principle:** Ship one product well before starting the next. The core pipeline (ingest → correlate → alert → store → search) is the product. Everything else is a future product or a distraction.

---

## PHASE 0 — PRUNE DEAD WEIGHT

**Objective:** Delete all code with zero inbound dependencies that doesn't serve the core SIEM pipeline. No refactoring needed — these packages are completely isolated.

**Risk:** NONE. Dependency analysis confirms zero imports from production code for all targets below.

### 0A: Delete template-generated integration packages

These 14 packages all follow an identical structure (client.go, ingester.go, normalizer.go, detection_rules.go) and connect to external systems that do not exist publicly. They are AI-generated boilerplate with no functional value.

| Package | Action | Impact |
|---------|--------|--------|
| `internal/natlangchain/` | Delete directory | None — zero inbound imports |
| `internal/valueledger/` | Delete directory | None — zero inbound imports |
| `internal/ilrmodule/` | Delete directory | None — zero inbound imports |
| `internal/mediatornode/` | Delete directory | None — zero inbound imports |
| `internal/memoryvault/` | Delete directory | None — zero inbound imports |
| `internal/midnightpulse/` | Delete directory | None — zero inbound imports |
| `internal/synthmind/` | Delete directory | None — zero inbound imports |
| `internal/shredsquatch/` | Delete directory | None — zero inbound imports |
| `internal/longhome/` | Delete directory | None — zero inbound imports |
| `internal/finiteintent/` | Delete directory | None — zero inbound imports |
| `internal/intentlog/` | Delete directory | None — zero inbound imports |
| `internal/learningcontracts/` | Delete directory | None — zero inbound imports |
| `internal/medicagent/` | Delete directory | None — zero inbound imports |
| `internal/rramodule/` | Delete directory | None — zero inbound imports |

### 0B: Delete wrong-product security modules

These security modules belong in an OS hardening tool or endpoint agent, not a SIEM. They have zero inbound imports from core code.

| Package | Action | Impact |
|---------|--------|--------|
| `internal/security/hardware/` | Delete directory | None — TPM 2.0 is wrong product |
| `internal/security/kernel/` | Delete directory | None — kernel enforcement is wrong product |
| `internal/security/firewall/` | Delete directory | None — nftables/iptables management is wrong product |
| `internal/security/commitment/` | Delete directory | None — tamper-evident commitment scheme is over-engineered |
| `internal/security/watchdog/` | Delete directory | None — use systemd/supervisord instead |

### 0C: Delete aspirational product modules

These are separate product categories (SOAR, hunting, forensics) with no backing execution engine. Only referenced in their own test files.

| Package | Action | Impact |
|---------|--------|--------|
| `internal/advanced/soar/` | Delete directory | None — step executor never implemented |
| `internal/advanced/hunting/` | Delete directory | None — no query executor exists |
| `internal/advanced/forensics/` | Delete directory | None — no chain analyzer exists |
| `internal/advanced/advanced_test.go` | Delete file | Tests only the above modules |

### 0D: Delete aspirational enterprise modules

Only referenced in `internal/enterprise/enterprise_test.go`. Not wired into any binary.

| Package | Action | Impact |
|---------|--------|--------|
| `internal/enterprise/api/` | Delete directory | None — custom GraphQL parser with stub resolvers |
| `internal/enterprise/ha/` | Delete directory | None — fake leader election, hardcoded metrics |
| `internal/enterprise/enterprise_test.go` | Delete file | Tests only the above modules |

### 0E: Remove BoundaryDaemon integration (REQUIRES SURGERY)

This is the only aspirational package wired into production code. Removing it requires editing 2-3 files.

| File | Change Required |
|------|-----------------|
| `cmd/siem-ingest/main.go` | Remove import (line 14), remove ingester initialization (~lines 225-273), remove shutdown/metrics references (~lines 308-312) |
| `internal/config/config.go` | Remove `BoundaryDaemon BoundaryDaemonConfig` field (line 34), remove default config call (~line 467) |
| `internal/config/integrations.go` | Remove or gut the file — it only defines BoundaryDaemon config structs |
| `configs/config.yaml` | Remove `boundarydaemon:` section |
| `internal/boundarydaemon/` | Delete directory after above changes |

### Phase 0 Acceptance Criteria

- [ ] `go build ./cmd/...` compiles without errors
- [ ] `go test ./...` passes (with race detector)
- [ ] `go vet ./...` clean
- [ ] No import references to deleted packages remain
- [ ] README is NOT updated yet (that's Phase 1)

### Phase 0 Estimated Impact

- **~12,000-15,000 lines of Go code deleted** (plus associated tests)
- **24 packages removed** (from 40 internal packages down to ~16)
- **Zero functional regression** — none of this code was reachable from the 2 production binaries (except boundarydaemon, which is surgically removed)

---

## PHASE 1 — COMPLETE THE CORE API

**Objective:** The SIEM has an alerting manager, a search executor, and detection rules — but most of these capabilities have no HTTP endpoints. This phase exposes them via REST API so the web dashboard and external tools can use them.

**Why this is Phase 1:** Without API endpoints, the web dashboard can only show dashboard stats. Users can't search events, manage alerts, or configure rules. The product is unusable as a SIEM without these.

### 1A: Alert Management API

The alert manager (`internal/alerting/manager.go`) already has `ListAlerts`, `GetAlert`, `AcknowledgeAlert`, `ResolveAlert`, `AddNote`, and `AssignAlert` methods. They just aren't exposed as HTTP endpoints.

| Endpoint | Method | Backing Function | Status |
|----------|--------|-----------------|--------|
| `/api/alerts` | GET | `manager.ListAlerts()` (line 319) | Not exposed |
| `/api/alerts/{id}` | GET | `manager.GetAlert()` (line 235) | Not exposed |
| `/api/alerts/{id}/acknowledge` | POST | `manager.AcknowledgeAlert()` (line 384) | Not exposed |
| `/api/alerts/{id}/resolve` | POST | `manager.ResolveAlert()` (line 412) | Not exposed |
| `/api/alerts/{id}/notes` | POST | `manager.AddNote()` (line 440) | Not exposed |
| `/api/alerts/{id}/assign` | POST | `manager.AssignAlert()` (line 462) | Not exposed |

**Work required:** Create `internal/api/alerts/` handler package. Wire routes in the main HTTP mux. Add auth middleware to all endpoints.

### 1B: Event Search API

The search executor (`internal/search/executor.go`) has `Search`, `Aggregate`, `TimeHistogram`, and `TopN` methods. None are exposed via HTTP.

| Endpoint | Method | Backing Function | Status |
|----------|--------|-----------------|--------|
| `/api/events/search` | POST | `executor.Search()` (line 67) | Not exposed |
| `/api/events/{id}` | GET | — | Needs implementation |
| `/api/events/aggregate` | POST | `executor.Aggregate()` (line 165) | Not exposed |
| `/api/events/histogram` | POST | `executor.TimeHistogram()` (line 468) | Not exposed |
| `/api/events/top` | POST | `executor.TopN()` (line 528) | Not exposed |

**Work required:** Create `internal/api/events/` handler package. Add query parameter validation and pagination. Wire routes.

### 1C: Rule Management API

Currently, all 143 detection rules are hardcoded in Go. Users cannot add, modify, or disable rules without recompiling.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/rules` | GET | List all active rules with filtering |
| `/api/rules/{id}` | GET | Get rule details and match history |
| `/api/rules` | POST | Create custom rule (YAML/JSON body) |
| `/api/rules/{id}` | PUT | Update rule (threshold, window, enabled) |
| `/api/rules/{id}` | DELETE | Disable/delete custom rule |
| `/api/rules/{id}/test` | POST | Dry-run rule against historical events |

**Work required:**
1. Add a YAML/JSON rule loader alongside the hardcoded Go rules (don't remove the 143 built-in rules — make them immutable defaults)
2. Store custom rules in ClickHouse (new table: `custom_rules`)
3. Create `internal/api/rules/` handler package
4. Load custom rules on startup and merge with built-in rules in the correlation engine

### 1D: Fix the Absence rule type

The correlation engine declares `RuleTypeAbsence` (rule.go line 24) but never implements its evaluation in `engine.go` (line 372-379 has no case for it). This is a bug — 1 of the 5 advertised rule types doesn't work.

**Work required:** Implement absence detection in the correlation engine's evaluation loop. An absence rule fires when an expected event does NOT occur within a time window.

### Phase 1 Acceptance Criteria

- [ ] All 6 alert endpoints return correct responses with auth
- [ ] Event search returns paginated results with query filtering
- [ ] Custom rules can be created via API and are picked up by correlation engine
- [ ] Absence rule type fires correctly (new tests)
- [ ] API documentation updated in README
- [ ] Integration tests: ingest event → correlation fires → alert created → alert retrieved via API

---

## PHASE 2 — HARDEN STORAGE AND SEARCH

**Objective:** ClickHouse is connected but underutilized. The storage layer lacks retention policies, full-text search, and schema management. The search module has gaps in query parsing. Fix these to make the SIEM operationally viable at scale.

### 2A: Schema management and migrations

Currently `EnsureDatabase()` only creates the database — no table DDL, no migration tracking, no partition management.

| Task | Detail |
|------|--------|
| Table DDL | Create `events`, `alerts`, `custom_rules` tables with proper ClickHouse engines (MergeTree, partitioned by month) |
| Time partitioning | Partition events by `toYYYYMM(timestamp)` for efficient time-range queries and partition drops |
| Migration tracking | Add `schema_migrations` table to track applied DDL changes |
| Index configuration | Add Bloom filter indexes on `source`, `action`, `severity` for fast filtering |

### 2B: Retention policies

The README claims "Hot 7d → Warm 30d → Cold 365d → S3 Archive" but none of this is implemented.

| Task | Detail |
|------|--------|
| ClickHouse TTL | Add `TTL timestamp + INTERVAL 365 DAY` to events table for automatic deletion |
| Partition management | Create utility to detach and drop old partitions on schedule |
| S3 archival | Use AWS SDK (already a dependency) to archive cold partitions to S3 before deletion |
| Config integration | Wire retention periods to `configs/config.yaml` so they're operator-configurable |

### 2C: Full-text search

The search module uses `position()` for substring matching (executor.go line 412). This is inadequate for log searching.

| Task | Detail |
|------|--------|
| FTS index | Add `INDEX raw_idx raw TYPE full_text GRANULARITY 1` on the `raw` event field |
| Query syntax | Support quoted phrase matching (`"flash loan"`) and boolean operators in the search query parser |
| Field-level FTS | Allow full-text search on `raw`, `metadata`, and `action` fields |

### 2D: Fix search query parser limitations

The query parser (query.go) has known gaps:

| Issue | Location | Fix |
|-------|----------|-----|
| Parentheses parsed but not evaluated | query.go line 285-287 | Implement recursive descent for grouped expressions |
| Hard-coded TopN limit of 1000 | executor.go line 532-534 | Make configurable via query parameter |
| Metadata not queryable | executor.go line 99-115 | Deserialize JSON metadata for nested field queries |
| No query explain | executor.go | Add `EXPLAIN` pass-through for ClickHouse query plans |

### Phase 2 Acceptance Criteria

- [ ] Tables auto-created on first startup with proper schemas
- [ ] Old data automatically cleaned up per configured retention policy
- [ ] Full-text search returns relevant results for phrase queries on raw events
- [ ] Complex boolean queries with parentheses parse and execute correctly
- [ ] Benchmark: 10K events/sec sustained write throughput to ClickHouse

---

## PHASE 3 — DASHBOARD AND REAL-TIME UI

**Objective:** The React dashboard exists but only shows static dashboard stats. Add the alert triage, event search, and rule management UIs that operators actually need.

### 3A: Real-time event streaming

The backend has a WebSocket-capable endpoint (handler.go line 283, "Dreaming" endpoint), but the React frontend doesn't subscribe to it.

| Task | Detail |
|------|--------|
| WebSocket client | Add `useWebSocket` hook in React that connects to the event stream |
| Live event feed | New `EventFeed` component showing events in real-time (filterable by severity) |
| Alert toasts | Show browser notifications for HIGH/CRITICAL alerts |
| Connection management | Auto-reconnect with exponential backoff, connection status indicator |

### 3B: Alert triage UI

The Phase 1 API endpoints need a frontend.

| Component | Purpose |
|-----------|---------|
| `AlertList` | Sortable, filterable table of alerts (status, severity, rule, timestamp) |
| `AlertDetail` | Full alert view with timeline, related events, notes, assignment |
| `AlertActions` | Acknowledge, resolve, assign, add note — buttons wired to Phase 1 API |
| `BulkActions` | Select multiple alerts → bulk acknowledge/resolve |

### 3C: Event search UI

| Component | Purpose |
|-----------|---------|
| `SearchBar` | Query input with syntax highlighting and autocomplete for field names |
| `SearchResults` | Paginated event table with expandable rows for full event detail |
| `FieldExplorer` | Sidebar showing available fields with value distributions |
| `SavedSearches` | Save/load frequent queries (stored in localStorage initially) |
| `TimeHistogram` | Recharts bar chart showing event distribution over time above results |

### 3D: Rule management UI

| Component | Purpose |
|-----------|---------|
| `RuleList` | Table of all rules (built-in + custom) with enable/disable toggles |
| `RuleEditor` | Form or YAML editor for creating/editing custom rules |
| `RuleTestPanel` | Dry-run a rule against last N hours of data, show what would match |
| `RuleHistory` | Show when a rule last fired, match count, false positive rate |

### Phase 3 Acceptance Criteria

- [ ] Live events appear in the dashboard within 1 second of ingestion
- [ ] Operators can search events, triage alerts, and manage rules entirely from the web UI
- [ ] Dashboard degrades gracefully if WebSocket disconnects
- [ ] All new components have Vitest unit tests
- [ ] Lighthouse accessibility score > 80

---

## PHASE 4 — STRENGTHEN THE DIFFERENTIATOR

**Objective:** The 143 blockchain detection rules are Boundary-SIEM's competitive advantage. This phase makes the rule engine smarter and the blockchain coverage deeper.

### 4A: Behavioral baselines

Static thresholds cause false positives. A threshold of 10 failed logins is too low for a busy exchange and too high for a small validator.

| Task | Detail |
|------|--------|
| Baseline engine | Calculate rolling P50/P95/P99 for rule metrics over configurable windows (1h, 24h, 7d) |
| Adaptive thresholds | Allow rules to specify `threshold: baseline_p95 * 1.5` instead of hard numbers |
| Storage | Store baselines in ClickHouse materialized views (auto-aggregated) |
| Warm-up period | Rules using baselines start in "learning" mode for first 7 days, logging but not alerting |

### 4B: Rule chaining

Currently, an alert from one rule can't trigger another rule. This prevents multi-stage attack detection.

| Task | Detail |
|------|--------|
| Alert-as-event | Emit correlation alerts back into the event pipeline as synthetic events |
| Chain definition | Allow rules to specify `depends_on: [rule_id_1, rule_id_2]` for sequential matching |
| Kill chain detection | Pre-built chains for common blockchain attack patterns (recon → exploit → exfil) |

### 4C: EVM JSON-RPC ingestion

The project is a blockchain SIEM but can't ingest native blockchain data. This is the biggest missing piece.

| Task | Detail |
|------|--------|
| RPC poller | New ingest module that polls Ethereum JSON-RPC endpoints (eth_getLogs, eth_getBlock) |
| Event normalization | Map RPC responses to the canonical SIEM event schema |
| Multi-chain config | Support Ethereum, Polygon, Arbitrum, Base via configurable RPC URLs |
| Backfill | Allow ingesting historical blocks for incident investigation |

### 4D: Community rule contributions

Make the rule library a standalone asset that the community can contribute to.

| Task | Detail |
|------|--------|
| YAML rule format | Define a standard YAML schema for detection rules |
| Rule repository | Separate `rules/` directory with one YAML file per rule |
| Validation CLI | `boundary-siem rules validate ./rules/` command |
| Import/export | API endpoints for importing/exporting rule packs |

### Phase 4 Acceptance Criteria

- [ ] Adaptive thresholds reduce false positive rate by >50% compared to static thresholds on test data
- [ ] A 3-stage attack chain (recon → exploit → drain) is detected end-to-end
- [ ] EVM events from a live testnet are ingested and trigger detection rules
- [ ] Community rules can be submitted as YAML, validated, and loaded without recompiling

---

## PHASE 5 — PRODUCTION HARDENING

**Objective:** Prepare for real deployments. Fix operational gaps that would block production use.

### 5A: Notification reliability

Alert notifications are fire-and-forget (manager.go line 213-231). Failed deliveries are silently lost.

| Task | Detail |
|------|--------|
| Retry with backoff | Exponential backoff (1s, 2s, 4s, 8s, 16s) for failed channel deliveries |
| Dead letter queue | Store failed notifications in ClickHouse for manual retry |
| Delivery tracking | Record delivery status per alert per channel |
| Channel health | Dashboard widget showing notification channel success rates |

### 5B: Escalation policies

No escalation chain exists. If an alert isn't acknowledged, nothing happens.

| Task | Detail |
|------|--------|
| Escalation rules | Define escalation chains: "If not ACK'd in 15min → notify manager; 30min → page on-call" |
| On-call integration | Wire to PagerDuty escalation (PagerDuty channel already exists) |
| Suppression windows | Allow defining maintenance windows where alerting is suppressed |

### 5C: Documentation rewrite

The README mixes real features with aspirational ones. After Phase 0 pruning, rewrite it.

| Task | Detail |
|------|--------|
| Accurate feature list | Only document features that exist and work |
| Architecture diagram | Update to reflect actual package structure after pruning |
| Quick start guide | Test on fresh machine and fix any broken setup steps |
| API reference | Auto-generate from endpoint definitions |
| Roadmap section | Move future features to a separate ROADMAP.md |

### 5D: End-to-end integration tests

Testing is concentrated in unit tests. No end-to-end pipeline tests exist.

| Test | Covers |
|------|--------|
| Ingest → Store | Send CEF event via UDP → verify it lands in ClickHouse |
| Ingest → Correlate → Alert | Send events matching a threshold rule → verify alert created |
| Alert → Notify | Create alert → verify webhook notification sent (mock server) |
| Search → Results | Store 1000 events → search by field → verify correct results returned |
| API → Auth | Attempt unauthenticated API call → verify 401; authenticate → verify 200 |

### Phase 5 Acceptance Criteria

- [ ] Zero silent notification failures — all failures logged and retryable
- [ ] Escalation chain fires correctly on test alerts
- [ ] README accurately describes every feature — nothing aspirational
- [ ] All 5 integration test scenarios pass in CI
- [ ] A new developer can go from `git clone` to running SIEM with events flowing in < 15 minutes using only the README

---

## PHASE SUMMARY

| Phase | Focus | Estimated Scope | Prerequisite |
|-------|-------|-----------------|--------------|
| **0** | Prune dead weight | Delete ~15K lines, edit 3 files | None |
| **1** | Complete core API | New HTTP endpoints for alerts, events, rules; fix absence rule | Phase 0 |
| **2** | Harden storage/search | Schema management, retention, FTS, query parser fixes | Phase 0 |
| **3** | Dashboard and UI | Real-time streaming, alert triage, event search, rule editor | Phase 1 + 2 |
| **4** | Strengthen differentiator | Baselines, rule chaining, EVM ingestion, community rules | Phase 1 + 2 |
| **5** | Production hardening | Notification reliability, escalation, docs rewrite, E2E tests | Phase 3 + 4 |

**Phases 1 and 2 can run in parallel** — they touch different modules (API vs. storage/search).

**Phases 3 and 4 can run in parallel** — they touch different layers (frontend vs. backend engine).

**Phase 5 depends on everything** — it validates the whole system end-to-end.

---

## WHAT'S LEFT AFTER ALL PHASES

After completing Phases 0-5, Boundary-SIEM will be:

```
┌─────────────────────────────────────────────────────┐
│                 Web Dashboard (React)                │
│   Alert Triage │ Event Search │ Rule Manager │ Live  │
├─────────────────────────────────────────────────────┤
│                REST API + Auth + RBAC                │
│  /api/alerts  │ /api/events  │ /api/rules  │ /ws    │
├─────────────────────────────────────────────────────┤
│              Correlation Engine                      │
│  Threshold │ Sequence │ Aggregate │ Absence │ Chain  │
│  Static thresholds + Behavioral baselines            │
├─────────────────────────────────────────────────────┤
│              Detection Rules                         │
│  143 built-in blockchain rules + Custom YAML rules   │
├─────────────────────────────────────────────────────┤
│              Ingestion Layer                         │
│  CEF (UDP/TCP/DTLS) │ JSON HTTP │ EVM JSON-RPC      │
├─────────────────────────────────────────────────────┤
│              Storage + Search                        │
│  ClickHouse (FTS, partitioned, TTL) │ Kafka │ S3     │
├─────────────────────────────────────────────────────┤
│              Alerting                                │
│  Webhook │ Slack │ PagerDuty │ Email │ Escalation    │
└─────────────────────────────────────────────────────┘
```

**~16 focused packages** instead of 40. **One product**, done well.

# Security Hardening Plan — All 20 Audit Findings

Based on `SECURITY_AUDIT_CHECKLIST.md` (2026-02-19 audit). Ordered by commit grouping for minimal merge conflicts and logical dependency.

---

## Commit 1: Wire outbound secret scanning into all alert channels

**Finding:** F-2.3a [CRITICAL]
**Files:**
- `internal/alerting/channels.go`

**Changes:**
1. Add `import "boundary-siem/internal/logging"` to `channels.go`.
2. Add a helper function `sanitizeAlert(*Alert) *Alert` that deep-copies an alert and runs `logging.MaskSensitivePatterns()` on:
   - `alert.Title`
   - `alert.Description`
   - `alert.GroupKey`
   - Each element in `alert.Tags`
3. Call `sanitizeAlert(alert)` at the top of each channel's `Send()` method **before** marshaling:
   - `WebhookChannel.Send()` (line 126)
   - `SlackChannel.Send()` (line 180)
   - `DiscordChannel.Send()` (line 289)
   - `PagerDutyChannel.Send()` (line 383)
   - `TelegramChannel.Send()` (line 873)
   - `EmailChannel.Send()` (line 515) — already escapes HTML but needs secret masking too
   - `LogChannel.Send()` (line 459) — mask before structured logging too
4. Log a warning via `slog.Warn` when a secret is detected and masked, including the channel name and alert ID.

**Also covers:** F-2.3b [MEDIUM] — webhook URLs with embedded secrets are now masked if they appear in alert text.

---

## Commit 2: Sanitize alert text for Slack/Discord/Telegram markdown injection

**Finding:** F-2.1a [MEDIUM]
**Files:**
- `internal/alerting/channels.go`

**Changes:**
1. In `SlackChannel.Send()`: run `html.EscapeString()` on `alert.Description` and `alert.Title` in the payload (Slack accepts mrkdwn but raw `<script>` etc. should still be neutralized).
2. In `DiscordChannel.Send()`: sanitize `alert.Description` using a `sanitizeDiscordText()` helper that strips `@everyone`, `@here`, and Discord markdown injection patterns (`](http://...)`).
3. `TelegramChannel.Send()` already calls `escapeMarkdown()` — verify it covers all Telegram MarkdownV2 special chars. Currently using `Markdown` parse_mode (v1), which is less strict. Switch to `MarkdownV2` for stricter escaping since `escapeMarkdown()` already escapes the V2 set.

---

## Commit 3: Replace hardcoded ClickHouse password in docker-compose

**Finding:** F-1.1a [HIGH]
**Files:**
- `deployments/clickhouse/docker-compose.yaml`

**Changes:**
1. Replace `CLICKHOUSE_PASSWORD=siem_password` with `CLICKHOUSE_PASSWORD=${CLICKHOUSE_PASSWORD:?Set CLICKHOUSE_PASSWORD env var}` — this requires the env var to be set, failing with a clear error otherwise.
2. Add a `.env.example` in `deployments/clickhouse/` with placeholder values:
   ```
   CLICKHOUSE_PASSWORD=changeme
   ```
3. Add `deployments/clickhouse/.env` to `.gitignore`.

---

## Commit 4: Integrate auth audit logging with tamper-evident audit module

**Findings:** F-2.2a [HIGH], F-3.1a [HIGH], F-2.2b [MEDIUM]
**Files:**
- `internal/api/auth/auth.go`

**Changes:**
1. Add an optional `AuditLogger` field to the `AuthService` struct that accepts a `*audit.AuditLogger` interface (from `internal/security/audit`).
2. In `logAudit()` (line ~1210): if `s.auditLogger != nil`, also write the entry through the tamper-evident audit module using `s.auditLogger.Log()` with:
   - `EventType`: map auth actions → `audit.EventAuthSuccess`, `audit.EventAuthFailure`, `audit.EventAccessDenied`, etc.
   - `Actor`: `{ID: userID, IP: ip}`
   - `Target`: `{Resource: resource}`
   - `Success`: success flag
3. Keep the existing in-memory audit log as-is for backward compatibility and quick API reads.
4. In `persistAuditEntry()`: when `s.auditLogger != nil`, skip writing to the raw JSONL file — the tamper-evident module handles persistence with rotation. When `s.auditLogger == nil`, keep the existing JSONL fallback.

This makes the tamper-evident system the primary audit backend while the in-memory ring buffer stays for fast API access.

---

## Commit 5: Add Kubernetes NetworkPolicy for pod egress restrictions

**Finding:** F-1.2a [MEDIUM]
**Files:**
- `deploy/kubernetes/siem.yaml`

**Changes:**
1. Append a `NetworkPolicy` resource at the end of `siem.yaml`:
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: siem-network-policy
     namespace: boundary-siem
   spec:
     podSelector:
       matchLabels:
         app: siem
     policyTypes:
       - Egress
       - Ingress
     ingress:
       - from:
           - podSelector: {}  # Allow intra-namespace
         ports:
           - port: 8080
           - port: 9090
           - port: 7946
       - from: []  # Allow external ingestion
         ports:
           - port: 8080
     egress:
       - to:
           - podSelector: {}  # Allow intra-namespace (Kafka, ClickHouse)
       - to:  # Allow DNS
           - namespaceSelector: {}
             podSelector:
               matchLabels:
                 k8s-app: kube-dns
         ports:
           - port: 53
             protocol: UDP
           - port: 53
             protocol: TCP
       - to:  # Allow HTTPS for PagerDuty, Slack, Telegram, threat intel
           - ipBlock:
               cidr: 0.0.0.0/0
               except:
                 - 10.0.0.0/8
                 - 172.16.0.0/12
                 - 192.168.0.0/16
         ports:
           - port: 443
             protocol: TCP
   ```

---

## Commit 6: Add .gitignore entries for sensitive file types

**Finding:** F-1.1c [LOW]
**Files:**
- `.gitignore`

**Changes:**
1. Add the following block after the existing "Environment files" section:
   ```
   # Certificates and keys
   certs/
   *.pem
   *.key
   *.p12
   *.crt
   *.csr

   # Deployment secrets
   deployments/**/.env
   ```

---

## Commit 7: Add CI security pipeline with secret scanning and SAST

**Finding:** F-3.4a [MEDIUM]
**Files:**
- `.github/workflows/security.yaml` (new file)

**Changes:**
1. Create a GitHub Actions workflow that runs on every push and PR:
   - **Secret scanning:** Use `truffleHog` to scan for committed secrets in the diff.
   - **Go SAST:** Run `gosec` (Go Security Checker) against the codebase.
   - **Dependency audit:** Run `govulncheck` to check for known vulnerabilities in Go deps.
   - **Frontend deps:** Run `npm audit --audit-level=high` in the `web/` directory.
2. Workflow triggers: `push` to `main`, all `pull_request` events.
3. Fail the build on HIGH/CRITICAL findings from any tool.

---

## Commit 8: Add rule provenance tracking

**Finding:** F-2.4a [MEDIUM]
**Files:**
- `internal/correlation/handler.go` (or wherever rules are created/updated via API)

**Changes:**
1. Add `CreatedBy`, `CreatedAt`, `UpdatedBy`, `UpdatedAt` fields to the rule struct if not already present.
2. When rules are created or updated via the API, record the authenticated user ID and timestamp.
3. Add a SHA256 content hash field (`ContentHash`) to each rule, computed at load time from the YAML content. Log a warning on startup if a rule file's hash doesn't match the stored hash (detects manual tampering).

---

## Commit 9: Sanitize webhook URLs in debug logs

**Finding:** F-2.3b [MEDIUM]
**Files:**
- `internal/alerting/channels.go`

**Changes:**
1. In `NewSlackChannel()`, `NewDiscordChannel()`, `NewTelegramChannel()`: when logging the webhook URL at creation time, mask it using `logging.MaskString(url, 20, 5)` so only the domain portion is visible.
2. In any `slog.Debug` or `slog.Info` calls that log webhook URLs, use the masked version.

---

## Commit 10: Move HMAC audit key to secrets manager

**Finding:** F-3.1b [MEDIUM]
**Files:**
- `internal/security/audit/audit.go`

**Changes:**
1. Add an optional `KeyProvider func() ([]byte, error)` field to `AuditLoggerConfig`.
2. In `NewAuditLogger()`: if `KeyProvider` is set, call it to get the HMAC key instead of reading from/generating on disk.
3. Keep the existing file-based key as the fallback when no `KeyProvider` is configured.
4. Document the integration point for Vault/KMS in a code comment.

---

## Commit 11: Mask sensitive patterns in Telegram tag output

**Finding:** F-2.1a supplement
**Files:**
- `internal/alerting/channels.go`

**Changes:**
1. In `TelegramChannel.Send()` line 892: the tags are joined unsanitized. Apply `escapeMarkdown()` to each tag before joining.
2. In `SlackChannel.buildFields()`: escape tag values.

(This is minor and can be folded into Commit 2 if preferred.)

---

## Implementation Order

| Commit | Findings Fixed | Severity | Files Changed |
|--------|---------------|----------|---------------|
| 1 | F-2.3a, F-2.3b | CRITICAL, MEDIUM | `internal/alerting/channels.go` |
| 2 | F-2.1a | MEDIUM | `internal/alerting/channels.go` |
| 3 | F-1.1a | HIGH | `deployments/clickhouse/docker-compose.yaml`, `.gitignore` |
| 4 | F-2.2a, F-3.1a, F-2.2b | HIGH, HIGH, MEDIUM | `internal/api/auth/auth.go` |
| 5 | F-1.2a | MEDIUM | `deploy/kubernetes/siem.yaml` |
| 6 | F-1.1c | LOW | `.gitignore` |
| 7 | F-3.4a | MEDIUM | `.github/workflows/security.yaml` |
| 8 | F-2.4a | MEDIUM | `internal/correlation/handler.go` |
| 9 | F-2.3b | MEDIUM | `internal/alerting/channels.go` |
| 10 | F-3.1b | MEDIUM | `internal/security/audit/audit.go` |
| 11 | F-2.1a supplement | LOW | `internal/alerting/channels.go` |

### Findings NOT addressed (intentionally deferred)

| Finding | Severity | Reason |
|---------|----------|--------|
| F-1.1b | MEDIUM | Git history rewriting (`git filter-repo`) is destructive and requires repo-wide coordination. Flagged for manual review. |
| F-1.2b | LOW | Per-module manifest system is a major architectural addition — not appropriate for a hardening pass. |
| F-2.1b | LOW | Prompt-injection detection is speculative — only relevant if event data is fed to an LLM. |
| F-2.4b | LOW | Rule file permissions (0640) are reasonable for current threat model. |
| F-2.4c | LOW | Already mitigated by Go RE2 engine. No action needed. |
| F-3.3a | LOW | Threat intel URL redirection mitigated by config file permissions. |
| F-3.3b | LOW | EVM RPC URL redirection mitigated by typed JSON-RPC parsing. |
| F-3.4b | LOW | ClickHouse RLS requires schema changes and query rewrite — major effort. |

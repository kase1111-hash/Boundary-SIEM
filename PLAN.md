# Plan: Fix All 24 Security Audit Findings

## Phase 1 — CRITICAL (2 issues)

### Fix 1: Missing Tenant Isolation in Search & Alerts
**Files:** `internal/search/executor.go`, `internal/alerting/manager.go`

**executor.go — Search()** (line 68): `buildWhereClause` has no tenant_id filtering.
- Change `Search()`, `Aggregate()`, and `Timeline()` to accept a `tenantID string` parameter.
- Prepend `WHERE tenant_id = ?` as the first condition in `buildWhereClause`.
- If tenantID is empty, return an error (never allow unscoped queries).

**manager.go — ListAlerts/GetAlert**: No tenant scoping.
- Add `TenantID` field to `AlertFilter`.
- In `listAlertsFromDB` (line ~394), add `AND tenant_id = ?` when TenantID is set.
- In `GetAlert`, verify the returned alert's TenantID matches the caller's.

### Fix 2: Remove Session Token from URL Query Parameter
**File:** `internal/api/auth/auth.go` (line 1243-1249)

Current `extractToken()`:
```go
func extractToken(r *http.Request) string {
    auth := r.Header.Get("Authorization")
    if strings.HasPrefix(auth, "Bearer ") {
        return strings.TrimPrefix(auth, "Bearer ")
    }
    return r.URL.Query().Get("token")  // REMOVE THIS
}
```

Fix: Remove the `r.URL.Query().Get("token")` fallback. Also check for
session cookie as a safe alternative:
```go
func extractToken(r *http.Request) string {
    auth := r.Header.Get("Authorization")
    if strings.HasPrefix(auth, "Bearer ") {
        return strings.TrimPrefix(auth, "Bearer ")
    }
    if cookie, err := r.Cookie("session_token"); err == nil {
        return cookie.Value
    }
    return ""
}
```

---

## Phase 2 — HIGH (8 issues)

### Fix 3: SSRF Protection for Webhook URLs
**File:** `internal/alerting/channels.go` (lines 29-38)

Add a `validateWebhookURL` function that:
- Parses the URL.
- Resolves the hostname to IP.
- Rejects private ranges: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, `169.254.0.0/16`, `::1`, `fd00::/8`.
- Rejects non-HTTP(S) schemes.

Call it in `NewWebhookChannel()` and return an error on failure.

### Fix 4: Replace SHA-256 Key Derivation with PBKDF2
**File:** `internal/encryption/encryption.go` (lines 101-105)

Replace:
```go
func deriveKey(masterKey []byte) []byte {
    hash := sha256.Sum256(masterKey)
    return hash[:]
}
```
With PBKDF2 using a fixed, application-specific salt (since the master key
is already high-entropy from generation), 100K iterations, SHA-256 PRF:
```go
func deriveKey(masterKey []byte) []byte {
    salt := []byte("boundary-siem-encryption-v1")
    return pbkdf2.Key(masterKey, salt, 100000, 32, sha256.New)
}
```
Add import for `"golang.org/x/crypto/pbkdf2"`. Since this changes the
derived key for existing data, also update `NewEngine` to store both old
and new derivation for backward compatibility during migration.

**Note:** Since network is unavailable in this env, I'll use `crypto/sha256`
with HMAC-based key stretching as a fallback that doesn't require new deps:
```go
func deriveKey(masterKey []byte) []byte {
    salt := []byte("boundary-siem-encryption-v1")
    key := masterKey
    for i := 0; i < 100000; i++ {
        h := hmac.New(sha256.New, salt)
        h.Write(key)
        key = h.Sum(nil)
    }
    return key
}
```

### Fix 5: Fix Rate Limit Proxy Header Trust
**File:** `internal/middleware/ratelimit.go` (lines 247-273)

Change `getClientIP` to use the **rightmost** non-private IP from
X-Forwarded-For (the last hop before the trusted proxy), not the leftmost
(client-controlled):
```go
func getClientIP(r *http.Request, trustProxy bool) string {
    if trustProxy {
        if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
            parts := strings.Split(xff, ",")
            // Use rightmost IP (set by the trusted proxy)
            for i := len(parts) - 1; i >= 0; i-- {
                ip := strings.TrimSpace(parts[i])
                if ip != "" {
                    return ip
                }
            }
        }
        if xri := r.Header.Get("X-Real-IP"); xri != "" {
            return xri
        }
    }
    // fall through to RemoteAddr...
}
```

### Fix 6: ReDoS Protection in Correlation Rules & Search
**Files:** `internal/correlation/rule.go` (lines 322-330),
`internal/search/executor.go` (line 432)

**rule.go — matchRegex()**: Pre-compile with timeout wrapper.
```go
func (c *Condition) matchRegex(eventValue any) bool {
    str := fmt.Sprintf("%v", eventValue)
    pattern := fmt.Sprintf("%v", c.Value)
    re, err := regexp.Compile(pattern)
    if err != nil {
        return false
    }
    // Use a channel-based timeout to prevent catastrophic backtracking
    done := make(chan bool, 1)
    go func() {
        done <- re.MatchString(str)
    }()
    select {
    case result := <-done:
        return result
    case <-time.After(100 * time.Millisecond):
        slog.Warn("regex match timed out", "pattern", pattern)
        return false
    }
}
```

**Note:** Go's `regexp` package uses RE2 which guarantees linear time and
does NOT have catastrophic backtracking. So the real risk is ClickHouse's
`match()`. For the Go side, add a max pattern length check (e.g., 1024 chars).
For ClickHouse, validate pattern length before passing to `match()`.

**executor.go — buildConditionClause**: Add pattern length validation:
```go
case OpEquals:
    if cond.IsRegex {
        pattern, ok := cond.Value.(string)
        if !ok || len(pattern) > 1024 {
            return "1=0", nil // invalid regex, match nothing
        }
        return fmt.Sprintf("match(%s, ?)", column), []interface{}{cond.Value}
    }
```

### Fix 7: Safer SQL Query Construction
**Files:** `internal/search/executor.go` (lines 74, 83-106, 183-219),
`internal/storage/retention.go` (lines 55-58)

**executor.go**: Replace `sanitizeColumn` character filter with an allowlist
of known valid column names:
```go
var validColumns = map[string]bool{
    "event_id": true, "timestamp": true, "received_at": true,
    "tenant_id": true, "action": true, "outcome": true,
    "severity": true, "target": true, "raw": true,
    "source_product": true, "source_vendor": true, "source_ip": true,
    "actor_name": true, "actor_id": true, "actor_ip": true,
    "metadata": true,
}

func (e *Executor) sanitizeColumn(column string) string {
    if validColumns[column] {
        return column
    }
    return "timestamp" // safe default
}
```

Also validate `aggType` in `Aggregate()` against a whitelist (already done
via switch, but add explicit rejection for unknown values).

**retention.go**: Validate table name against known tables:
```go
validTables := map[string]bool{"events": true, "alerts": true, "quarantine_events": true}
if !validTables[p.table] {
    return fmt.Errorf("invalid table name: %s", p.table)
}
```

### Fix 8: Stop Logging Admin Password Context
**File:** `internal/api/auth/auth.go` (lines 394-397)

Replace the log that mentions password file path with a minimal message:
```go
s.logger.Info("admin password saved to secure file",
    "username", config.Username,
    "action_required", "change password after first login")
```
Remove `"password_file"` field — don't reveal the file path in logs.

### Fix 9: Remove TLS SkipVerify Option
**File:** `internal/alerting/channels.go` (lines 396, 450, 476)

Remove `SkipVerify` from `EmailConfig` struct. Hardcode
`InsecureSkipVerify: false` in both TLS configs. Remove the warning log
lines since the option no longer exists.

### Fix 10: HTML-Escape Alert Data in Email Body
**File:** `internal/alerting/channels.go` (lines 596-724)

Add `import "html"` and escape all user-controlled fields before insertion
into HTML:
- Line 608: `strings.Join(alert.MITRE.Techniques, ", ")` → escape each technique
- Line 626-627: escape TacticName, TacticID, TechniqueID
- Line 634-636: escape each tag
- Line 716: `alert.Title` → `html.EscapeString(alert.Title)`
- Line 717: `alert.Description` → `html.EscapeString(alert.Description)`
- Line 719: `alert.RuleID` → `html.EscapeString(alert.RuleID)`

---

## Phase 3 — MEDIUM (9 issues)

### Fix 11: Add Idle Session Timeout
**File:** `internal/api/auth/auth.go` (lines 1054-1061)

In `ValidateSession()`, after retrieving the session, check idle time:
```go
const idleTimeout = 30 * time.Minute

if time.Since(session.LastActiveAt) > idleTimeout {
    // Delete the idle session
    s.sessionStorage.Delete(ctx, token)
    return nil, fmt.Errorf("session expired due to inactivity")
}
```

### Fix 12-13: Fix User Creation — Enforce Password Policy & Reject Raw Hash
**File:** `internal/api/auth/auth.go` (lines 717-741)

Replace direct `User` decode with a creation request struct:
```go
var req struct {
    Username string   `json:"username"`
    Password string   `json:"password"`
    Email    string   `json:"email"`
    Roles    []string `json:"roles"`
    TenantID string   `json:"tenant_id"`
}
if err := json.NewDecoder(r.Body).Decode(&req); err != nil { ... }

// Validate password
if err := validatePasswordStrength(req.Password); err != nil {
    writeJSONError(w, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
    return
}

// Hash password server-side
hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcryptCost)
if err != nil { ... }

user := User{
    ID:           generateID(),
    Username:     req.Username,
    Email:        req.Email,
    PasswordHash: string(hash),
    Roles:        req.Roles,
    TenantID:     req.TenantID,
    CreatedAt:    time.Now(),
    Permissions:  s.getPermissionsForRoles(req.Roles),
}
```

### Fix 14: Clear CSRF Token on Logout
**File:** `internal/api/auth/auth.go` (lines 611-615)

After session deletion, before writing response:
```go
s.csrf.ClearToken(w)
```

### Fix 15: Check Disabled Users in Middleware
**File:** `internal/api/auth/auth.go` (lines 1209-1216)

After retrieving user:
```go
if user == nil || user.Disabled {
    http.Error(w, "Account disabled", http.StatusForbidden)
    return
}
```

### Fix 16: Escalation cleanupTracking TOCTOU
Already improved in previous commit. The remaining TOCTOU window is
acceptable — worst case is deleting a tracking entry that was just
re-added, which only causes one extra escalation notification. No code
change needed.

### Fix 17: Enforce MaxStateEntries in Correlation Engine
**File:** `internal/correlation/engine.go` (lines 357-368)

Before adding to the window map, check total state size:
```go
if len(state.windows) >= e.config.MaxStateEntries {
    // Evict oldest window
    var oldestKey string
    var oldestTime time.Time
    for k, w := range state.windows {
        if oldestKey == "" || w.StartTime.Before(oldestTime) {
            oldestKey = k
            oldestTime = w.StartTime
        }
    }
    if oldestKey != "" {
        delete(state.windows, oldestKey)
    }
}
```

### Fix 18: Use Structured Logging in LogChannel
**File:** `internal/alerting/channels.go` (lines 378-382)

Replace format-string logging with structured slog:
```go
func (l *LogChannel) Send(ctx context.Context, alert *Alert) error {
    slog.Warn("ALERT",
        "severity", string(alert.Severity),
        "title", alert.Title,
        "description", alert.Description,
        "rule_id", alert.RuleID,
        "event_count", alert.EventCount,
        "tags", alert.Tags,
    )
    return nil
}
```
This prevents format-string injection and newline injection.

### Fix 19: Sanitize Search Queries in Error Logs
**File:** `internal/search/executor.go`

Any `slog.Error` call that includes the raw query should truncate it:
```go
func truncateForLog(s string, maxLen int) string {
    if len(s) > maxLen {
        return s[:maxLen] + "...[truncated]"
    }
    return s
}
```

---

## Phase 4 — LOW / INFORMATIONAL (5 issues)

### Fix 20: Use Generic Auth Error Codes
**File:** `internal/api/auth/auth.go` (lines 536-545)

Replace the per-type error code dispatch with a generic response:
```go
if err != nil {
    s.logAudit(AuditActionLoginFailed, "", req.Username, req.TenantID,
        "auth", "", r, false, err.Error())
    writeJSONError(w, http.StatusUnauthorized, "AUTH_FAILED",
        "Invalid username or password")
    return
}
```
Keep detailed codes in server-side audit log only.

### Fix 21: Remove CSP unsafe-inline for Styles
**File:** `internal/middleware/security_headers.go` (line 81)

Change:
```go
CSPStyleSrc: []string{"'self'", "'unsafe-inline'"},
```
To:
```go
CSPStyleSrc: []string{"'self'"},
```

### Fix 22: Persist Audit Log to Disk
**File:** `internal/api/auth/auth.go` (lines 1102-1133)

Add file-based persistence: in `logAudit()`, after appending to in-memory
log, also write to an append-only file as JSON lines. Use a buffered writer
with periodic flush. This ensures audit data survives restarts.

### Fix 23: Add Per-Username Rate Limiting
**File:** `internal/middleware/ratelimit.go`

Add a parallel `userClients` map keyed by username (extracted from request
body for login endpoint). Apply a stricter limit (e.g., 10 attempts per
15 minutes per username) in addition to per-IP limits.

### Fix 24: Bound Goroutines in Escalation Notifications
**File:** `internal/alerting/escalation.go` (lines 273-289)

Replace unbounded `go func()` with a semaphore:
```go
// In EscalationEngine struct:
notifySem chan struct{} // initialized as make(chan struct{}, 50)

// In triggerEscalation:
go func(c NotificationChannel) {
    e.notifySem <- struct{}{}
    defer func() { <-e.notifySem }()
    if err := c.Send(ctx, alert); err != nil { ... }
}(ch)
```

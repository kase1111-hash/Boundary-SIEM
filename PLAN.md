# Remaining Security Issues — Implementation Plan

## Issues to fix (10 remaining from the Moltbook/OpenClaw review)

### 1. [HIGH] ProductionMode defaults to false — error sanitization is off
**File:** `internal/errors/sanitize.go:25`
**Problem:** `ProductionMode = false` and `SetProductionMode(true)` is never called from `cmd/siem-ingest/main.go`. Raw errors (file paths, SQL details, IPs) leak to API clients.

**Fix:**
- In `cmd/siem-ingest/main.go`, call `errors.SetProductionMode(true)` by default during startup, right after config loading.
- Only disable when `SIEM_DEV_MODE=true` env var is explicitly set.
- Add `import "boundary-siem/internal/errors"` to main.go.

---

### 2. [HIGH] Default config ships with auth disabled
**File:** `configs/config.yaml:72` — `auth.enabled: false`
**Problem:** API authentication is off by default. Anyone can ingest events, search data, manage rules.

**Fix:**
- Change `auth.enabled` to `true` in `configs/config.yaml`.
- Add a startup warning in `cmd/siem-ingest/main.go` that logs `slog.Warn("API authentication is DISABLED — not recommended for production")` when `cfg.Auth.Enabled == false`.

---

### 3. [HIGH] OAuth/SAML handlers are unauthenticated stubs
**File:** `internal/api/auth/auth.go:650-685`
**Problem:** `handleOAuthCallback` and `handleSAMLACS` accept any request and redirect to `/dashboard` without validating OAuth tokens or SAML assertions. Hitting `/api/auth/oauth/callback?code=x&state=y` immediately redirects to dashboard.

**Fix:**
- Replace the redirect with a `501 Not Implemented` JSON error response.
- Log a warning that OAuth/SAML is not yet implemented.
- Remove the `http.Redirect(w, r, "/dashboard", http.StatusFound)` line.

---

### 4. [HIGH] SIEM_IGNORE_ERRORS bypasses security checks unconditionally
**File:** `cmd/siem-ingest/main.go:66`
**Problem:** Setting `SIEM_IGNORE_ERRORS=true` bypasses all startup diagnostics including security validations, with no restrictions.

**Fix:**
- When `ProductionMode` is true (the new default from fix #1), refuse to honor `SIEM_IGNORE_ERRORS`.
- Only allow the bypass when `SIEM_DEV_MODE=true` is also set.

---

### 5. [HIGH] Session tokens returned in JSON body (XSS-exfiltrable)
**File:** `internal/api/auth/auth.go:574-579`
**Problem:** Session token and refresh token are in the JSON response body. Any XSS vulnerability lets an attacker exfiltrate them.

**Fix:**
- Set session token as `HttpOnly; Secure; SameSite=Strict; Path=/` cookie named `session_token`.
- Set refresh token as `HttpOnly; Secure; SameSite=Strict; Path=/api/auth` cookie named `refresh_token`.
- Remove `token` and `refresh_token` from the JSON body. Keep `expires_at`, `user`, `csrf_token`.

---

### 6. [MEDIUM] Frontend API client missing credentials and CSRF headers
**File:** `web/src/services/api.ts:17-33`
**Problem:** `request()` sends no cookies (`credentials` not set) and no CSRF token header on mutating requests.

**Fix:**
- Add `credentials: "include"` to all fetch calls.
- For POST/PUT/DELETE, read the `XSRF-TOKEN` cookie and set it as `X-CSRF-Token` header.
- Add a helper `getCsrfToken()` that reads the cookie value.

---

### 7. [MEDIUM] Default ClickHouse connection has no password and no TLS
**File:** `configs/config.yaml:89,93`
**Problem:** `password: ""` and `tls_enabled: false` for the database connection.

**Fix:**
- Add startup warnings in `cmd/siem-ingest/main.go` when storage is enabled but password is empty or TLS is disabled.
- Strengthen YAML comments to say `# SECURITY WARNING:`.

---

### 8. [MEDIUM] TCP CEF ingestion defaults to plaintext
**File:** `configs/config.yaml:33` — `tls_enabled: false`
**Problem:** TCP syslog ingestion is unencrypted by default.

**Fix:**
- Add a startup warning when `cfg.Ingest.CEF.TCP.Enabled && !cfg.Ingest.CEF.TCP.TLSEnabled`.
- Strengthen YAML comment.

---

### 9. [MEDIUM] Audit log endpoint returns all entries without pagination
**File:** `internal/api/auth/auth.go` — `handleAudit` GET handler
**Problem:** Returns all in-memory audit entries (up to 10,000) in one response with no limit/offset.

**Fix:**
- Add `limit` (default 100, max 1000) and `offset` query parameters.
- Apply pagination before returning the response.

---

### 10. [LOW] Encryption key derivation uses static salt
**File:** `internal/encryption/encryption.go:106`
**Problem:** `deriveKey()` uses hardcoded salt `"boundary-siem-encryption-v1"`. All installations derive identical keys from identical master keys.

**Fix:**
- Generate a random 16-byte salt on first initialization.
- Store the salt alongside encrypted data or in config.
- Fall back to static salt when decrypting old data for backward compatibility.

---

## Implementation order

| Commit | Issues | Files | Description |
|--------|--------|-------|-------------|
| 1 | #1, #2, #4, #7, #8 | `cmd/siem-ingest/main.go`, `configs/config.yaml`, `internal/errors/sanitize.go` | Enable production mode, auth, and add security startup warnings |
| 2 | #3 | `internal/api/auth/auth.go` | Replace OAuth/SAML stubs with 501 Not Implemented |
| 3 | #5 | `internal/api/auth/auth.go` | Move session tokens to HttpOnly cookies |
| 4 | #6 | `web/src/services/api.ts` | Add credentials and CSRF token to frontend API client |
| 5 | #9 | `internal/api/auth/auth.go` | Add audit log pagination |
| 6 | #10 | `internal/encryption/encryption.go` | Random salt for key derivation |

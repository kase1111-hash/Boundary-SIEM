# Boundary-SIEM Technical Specification

**Version:** 1.0.0
**Status:** Draft
**Last Updated:** 2026-01-01

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
3. [Component Specifications](#3-component-specifications)
4. [Data Flow & Processing Pipeline](#4-data-flow--processing-pipeline)
5. [API Specifications](#5-api-specifications)
6. [Canonical Event Schema](#6-canonical-event-schema)
7. [Correlation Engine](#7-correlation-engine)
8. [Alerting System](#8-alerting-system)
9. [Storage & Retention](#9-storage--retention)
10. [Security Requirements](#10-security-requirements)
11. [Performance Requirements](#11-performance-requirements)
12. [Deployment Architecture](#12-deployment-architecture)
13. [Monitoring & Observability](#13-monitoring--observability)
14. [Testing Strategy](#14-testing-strategy)
15. [Phase 2+ Roadmap](#15-phase-2-roadmap)

---

## 1. Executive Summary

### 1.1 Purpose

Boundary-SIEM is a Security Information and Event Management system designed to ingest, normalize, correlate, and alert on security events from multiple sources. The primary integration target is `boundary-daemon`, with extensibility to support additional security data sources.

### 1.2 MVP Definition

A system qualifies as a SIEM (not just log storage) when it:

- Ingests events from ≥2 sources
- Normalizes events into a canonical schema
- Stores and searches months of data
- Correlates events across sources
- Generates alerts from correlations

### 1.3 Design Principles

| Principle | Description |
|-----------|-------------|
| **Schema First** | All events conform to a versioned canonical schema before storage |
| **Simplicity** | Prefer simple, maintainable solutions over clever abstractions |
| **Operability** | Built-in observability and graceful degradation |
| **Security** | Zero-trust architecture; encrypt data at rest and in transit |
| **Extensibility** | Plugin architecture for new sources, rules, and destinations |

---

## 2. System Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              BOUNDARY-SIEM                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │   Sources    │    │   Sources    │    │   Sources    │                   │
│  │ boundary-    │    │  Auth Logs   │    │  Firewall    │                   │
│  │   daemon     │    │              │    │              │                   │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘                   │
│         │                   │                   │                            │
│         ▼                   ▼                   ▼                            │
│  ┌─────────────────────────────────────────────────────────────┐            │
│  │                    INGEST LAYER                              │            │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │            │
│  │  │ CEF Parser  │  │ JSON Parser │  │ Backpressure Queue  │  │            │
│  │  │ (UDP/TCP)   │  │  (HTTP)     │  │   (Ring Buffer)     │  │            │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │            │
│  └──────────────────────────┬──────────────────────────────────┘            │
│                             │                                                │
│                             ▼                                                │
│  ┌─────────────────────────────────────────────────────────────┐            │
│  │                 NORMALIZATION LAYER                          │            │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │            │
│  │  │   Schema    │  │  Timestamp  │  │    Quarantine       │  │            │
│  │  │ Validator   │  │ Normalizer  │  │     Handler         │  │            │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │            │
│  └──────────────────────────┬──────────────────────────────────┘            │
│                             │                                                │
│         ┌───────────────────┼───────────────────┐                           │
│         ▼                   ▼                   ▼                            │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐              │
│  │  STORAGE    │    │ CORRELATION │    │      SEARCH         │              │
│  │  ENGINE     │◄───│   ENGINE    │───►│      ENGINE         │              │
│  │(ClickHouse) │    │ (Streaming) │    │   (Query API)       │              │
│  └─────────────┘    └──────┬──────┘    └─────────────────────┘              │
│                            │                                                 │
│                            ▼                                                 │
│                     ┌─────────────┐                                          │
│                     │  ALERTING   │                                          │
│                     │   ENGINE    │                                          │
│                     │ (Webhook/   │                                          │
│                     │  Slack)     │                                          │
│                     └─────────────┘                                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Overview

| Component | Technology | Purpose |
|-----------|------------|---------|
| Ingest Layer | Go | Accept CEF (UDP/TCP) and JSON (HTTP) events |
| Normalization | Go | Transform to canonical schema, validate, quarantine invalid |
| Storage | ClickHouse | Time-series event storage with partitioning |
| Correlation | Go | Rule-based pattern detection with time windows |
| Search | HTTP API + CLI | Query events with filters, pagination |
| Alerting | Go | Deduplicated notifications via webhook/Slack |

---

## 3. Component Specifications

### 3.1 Ingest Layer

#### 3.1.1 CEF Ingestion (UDP/TCP)

```yaml
cef_ingest:
  protocols:
    - udp:
        port: 5514
        buffer_size: 65535
        max_message_size: 64KB
    - tcp:
        port: 5515
        max_connections: 1000
        idle_timeout: 300s
        tls:
          enabled: true
          cert_file: /etc/siem/certs/server.crt
          key_file: /etc/siem/certs/server.key
          min_version: TLS1.2

  parsing:
    cef_version: "0|1"
    strict_mode: false  # Allow minor format deviations
    max_extensions: 100
```

**CEF Format Parsing:**

```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

Example:
```
CEF:0|Boundary|boundary-daemon|1.0|100|Session Started|3|src=192.168.1.10 dst=10.0.0.5 duser=admin
```

#### 3.1.2 JSON over HTTP

```yaml
http_ingest:
  port: 8080
  tls:
    enabled: true
    cert_file: /etc/siem/certs/server.crt
    key_file: /etc/siem/certs/server.key

  endpoints:
    - path: /v1/events
      methods: [POST]
      auth:
        type: api_key
        header: X-API-Key
      rate_limit:
        requests_per_second: 10000
        burst: 50000

    - path: /v1/events/batch
      methods: [POST]
      max_batch_size: 1000
      max_payload_size: 10MB

  compression:
    accept: [gzip, deflate, zstd]
```

**Request Format:**

```http
POST /v1/events HTTP/1.1
Host: siem.example.com
Content-Type: application/json
X-API-Key: sk_live_xxxxxxxxxxxx

{
  "events": [
    {
      "timestamp": "2026-01-01T12:00:00Z",
      "source": "boundary-daemon",
      "action": "session.created",
      "actor": {
        "type": "user",
        "id": "user_123"
      },
      "target": "host:db-prod-01",
      "outcome": "success",
      "severity": 3,
      "metadata": {
        "session_id": "sess_abc123",
        "ip_address": "192.168.1.100"
      }
    }
  ]
}
```

#### 3.1.3 Backpressure Queue

```yaml
backpressure:
  type: ring_buffer

  buffer:
    size: 100000  # Events
    memory_limit: 512MB
    overflow_policy: drop_oldest  # drop_oldest | block | drop_newest

  persistence:
    enabled: true
    path: /var/lib/siem/buffer
    sync_interval: 1s
    max_disk_usage: 10GB

  health:
    high_water_mark: 0.8  # 80% triggers backpressure
    low_water_mark: 0.5   # 50% releases backpressure

  metrics:
    - events_queued
    - events_dropped
    - queue_latency_ms
    - memory_usage_bytes
```

### 3.2 Normalization Layer

#### 3.2.1 Schema Validator

```yaml
schema_validation:
  schema_version: "1.0.0"
  strict_mode: true

  validation_rules:
    - field: event_id
      type: uuid
      required: true
      generate_if_missing: true

    - field: timestamp
      type: datetime
      required: true
      format: ISO8601
      timezone: UTC
      max_age: 7d  # Reject events older than 7 days
      max_future: 5m  # Reject events more than 5 min in future

    - field: source.product
      type: string
      required: true
      max_length: 256

    - field: severity
      type: integer
      required: true
      min: 1
      max: 10

    - field: outcome
      type: enum
      required: true
      values: [success, failure, unknown]

  on_invalid:
    action: quarantine
    notify: true
    max_quarantine_age: 30d
```

#### 3.2.2 Timestamp Normalization

```yaml
timestamp_normalization:
  input_formats:
    - ISO8601
    - RFC3339
    - RFC2822
    - Unix epoch (seconds)
    - Unix epoch (milliseconds)
    - "YYYY-MM-DD HH:MM:SS"
    - "MMM DD HH:MM:SS"  # Syslog format

  output_format: "2006-01-02T15:04:05.000000Z"  # RFC3339 with microseconds

  timezone_handling:
    default_timezone: UTC
    convert_all_to: UTC
    preserve_original: true  # Store original in metadata
```

#### 3.2.3 Source Identity Tagging

```yaml
source_identity:
  auto_extract:
    - field: source_ip
      from_header: X-Forwarded-For
      fallback: connection.remote_addr

    - field: host
      from_payload: source.host
      from_header: X-Source-Host

    - field: daemon_id
      from_payload: source.instance_id
      from_api_key: true  # Extract from API key metadata

    - field: tenant_id
      from_api_key: true
      required: true

  enrichment:
    - type: dns_reverse
      field: source_ip
      target: source_hostname
      cache_ttl: 3600s
```

### 3.3 Storage Engine

#### 3.3.1 ClickHouse Configuration

```sql
-- Main events table
CREATE TABLE events (
    event_id UUID,
    timestamp DateTime64(6, 'UTC'),
    received_at DateTime64(6, 'UTC') DEFAULT now64(6),

    -- Source information
    source_product LowCardinality(String),
    source_host String,
    source_instance_id String,
    tenant_id LowCardinality(String),

    -- Actor information
    actor_type LowCardinality(String),
    actor_id String,

    -- Event details
    action LowCardinality(String),
    target String,
    outcome LowCardinality(Enum8('success' = 1, 'failure' = 2, 'unknown' = 3)),
    severity UInt8,

    -- Schema metadata
    schema_version LowCardinality(String),

    -- Raw event
    raw String CODEC(ZSTD(3)),

    -- Flexible metadata
    metadata String CODEC(ZSTD(3)),  -- JSON string

    -- Indexing helpers
    INDEX idx_action action TYPE bloom_filter GRANULARITY 4,
    INDEX idx_actor_id actor_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_target target TYPE bloom_filter GRANULARITY 4,
    INDEX idx_raw raw TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, source_product, timestamp, event_id)
TTL timestamp + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- Quarantine table for invalid events
CREATE TABLE events_quarantine (
    quarantine_id UUID DEFAULT generateUUIDv4(),
    quarantined_at DateTime64(6, 'UTC') DEFAULT now64(6),

    raw_event String CODEC(ZSTD(3)),
    source_ip String,
    source_format LowCardinality(String),

    validation_errors Array(String),

    reprocessed Boolean DEFAULT false,
    reprocessed_at Nullable(DateTime64(6, 'UTC'))
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(quarantined_at)
ORDER BY (quarantined_at, quarantine_id)
TTL quarantined_at + INTERVAL 30 DAY DELETE;
```

#### 3.3.2 Retention Policy

```yaml
retention:
  tiers:
    hot:
      storage: nvme
      duration: 7d
      replicas: 2

    warm:
      storage: ssd
      duration: 30d
      replicas: 1
      compression: zstd

    cold:
      storage: hdd
      duration: 90d
      replicas: 1
      compression: zstd_high

  policies:
    - name: high_severity
      condition: "severity >= 8"
      retention: 365d

    - name: authentication_events
      condition: "action LIKE 'auth.%'"
      retention: 180d

    - name: default
      retention: 90d

  deletion:
    batch_size: 100000
    schedule: "0 2 * * *"  # 2 AM daily
    dry_run_first: true
```

### 3.4 Search Engine

#### 3.4.1 Query API

```yaml
search_api:
  endpoints:
    search:
      path: /v1/search
      methods: [POST, GET]

    aggregate:
      path: /v1/aggregate
      methods: [POST]

    export:
      path: /v1/export
      methods: [POST]
      max_results: 1000000

  defaults:
    limit: 100
    max_limit: 10000
    default_time_range: 24h
    max_time_range: 90d

  rate_limits:
    search: 100/minute
    aggregate: 50/minute
    export: 10/hour
```

**Query DSL:**

```json
{
  "query": {
    "time_range": {
      "start": "2026-01-01T00:00:00Z",
      "end": "2026-01-01T23:59:59Z"
    },
    "filters": [
      { "field": "severity", "op": "gte", "value": 7 },
      { "field": "source_product", "op": "eq", "value": "boundary-daemon" },
      { "field": "outcome", "op": "eq", "value": "failure" }
    ],
    "text_search": {
      "field": "raw",
      "query": "authentication",
      "mode": "contains"
    }
  },
  "sort": [
    { "field": "timestamp", "order": "desc" }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0
  },
  "fields": ["event_id", "timestamp", "action", "actor_id", "severity"]
}
```

#### 3.4.2 CLI Interface

```bash
# Basic search
siem-cli search --severity ">= 7" --source boundary-daemon --last 24h

# Time range search
siem-cli search --from "2026-01-01T00:00:00Z" --to "2026-01-01T12:00:00Z"

# Full-text search
siem-cli search --text "failed authentication" --action "auth.*"

# Export results
siem-cli search --severity ">= 8" --last 7d --format json --output alerts.json

# Aggregate queries
siem-cli aggregate --group-by action --count --last 24h

# Watch mode (streaming)
siem-cli watch --severity ">= 7" --follow
```

---

## 4. Data Flow & Processing Pipeline

### 4.1 Event Lifecycle

```
┌─────────┐   ┌─────────┐   ┌──────────┐   ┌─────────┐   ┌─────────┐
│ Receive │──►│  Parse  │──►│ Validate │──►│  Store  │──►│Correlate│
└─────────┘   └─────────┘   └──────────┘   └─────────┘   └─────────┘
     │             │              │              │              │
     ▼             ▼              ▼              ▼              ▼
  Metrics      Metrics     ┌──────────┐      Metrics       Metrics
                           │Quarantine│
                           │(invalid) │
                           └──────────┘
```

### 4.2 Processing Guarantees

| Guarantee | Level | Notes |
|-----------|-------|-------|
| Delivery | At-least-once | Deduplication via event_id |
| Ordering | Per-source | Events from same source processed in order |
| Durability | Persisted | Events persisted before acknowledgment |
| Latency | P99 < 500ms | From receipt to storage |

### 4.3 Error Handling

```yaml
error_handling:
  parsing_errors:
    action: quarantine
    retry: false
    alert_threshold: 100/minute

  validation_errors:
    action: quarantine
    retry: false
    preserve_raw: true

  storage_errors:
    action: retry
    max_retries: 3
    backoff:
      initial: 100ms
      max: 10s
      multiplier: 2
    fallback: local_buffer

  correlation_errors:
    action: log_and_continue
    alert_on_repeated: true
```

---

## 5. API Specifications

### 5.1 REST API Overview

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/events` | POST | Ingest single/batch events |
| `/v1/search` | POST | Query events |
| `/v1/aggregate` | POST | Aggregate queries |
| `/v1/rules` | GET/POST/PUT/DELETE | Manage correlation rules |
| `/v1/alerts` | GET | List triggered alerts |
| `/v1/health` | GET | Health check |
| `/v1/metrics` | GET | Prometheus metrics |

### 5.2 Authentication

```yaml
authentication:
  methods:
    - type: api_key
      header: X-API-Key
      prefix: "sk_"

    - type: jwt
      header: Authorization
      prefix: "Bearer "
      issuer: "https://auth.example.com"
      audience: "siem-api"

  api_keys:
    scopes:
      - ingest:write
      - search:read
      - rules:read
      - rules:write
      - admin

    rotation:
      max_age: 90d
      warning_before: 14d
```

### 5.3 Response Format

```json
{
  "success": true,
  "data": { },
  "meta": {
    "request_id": "req_abc123",
    "duration_ms": 45,
    "timestamp": "2026-01-01T12:00:00Z"
  },
  "pagination": {
    "total": 1500,
    "limit": 100,
    "offset": 0,
    "has_more": true
  }
}
```

Error Response:

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid timestamp format",
    "details": {
      "field": "timestamp",
      "received": "not-a-date",
      "expected": "ISO8601"
    }
  },
  "meta": {
    "request_id": "req_xyz789"
  }
}
```

---

## 6. Canonical Event Schema

### 6.1 Schema Definition (JSON Schema)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://boundary-siem.io/schemas/event/v1.0.0",
  "title": "Boundary-SIEM Canonical Event",
  "type": "object",
  "required": ["event_id", "timestamp", "source", "action", "outcome", "severity"],

  "properties": {
    "event_id": {
      "type": "string",
      "format": "uuid",
      "description": "Unique identifier for this event"
    },

    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "When the event occurred (UTC)"
    },

    "schema_version": {
      "type": "string",
      "pattern": "^\\d+\\.\\d+\\.\\d+$",
      "default": "1.0.0"
    },

    "source": {
      "type": "object",
      "required": ["product"],
      "properties": {
        "product": {
          "type": "string",
          "maxLength": 256,
          "examples": ["boundary-daemon", "auth-service", "firewall"]
        },
        "host": {
          "type": "string",
          "maxLength": 256
        },
        "instance_id": {
          "type": "string",
          "maxLength": 128
        },
        "version": {
          "type": "string"
        }
      }
    },

    "actor": {
      "type": "object",
      "properties": {
        "type": {
          "type": "string",
          "enum": ["user", "process", "service", "system", "unknown"]
        },
        "id": {
          "type": "string",
          "maxLength": 256
        },
        "name": {
          "type": "string",
          "maxLength": 256
        },
        "email": {
          "type": "string",
          "format": "email"
        },
        "ip_address": {
          "type": "string",
          "format": "ipv4"
        }
      }
    },

    "action": {
      "type": "string",
      "maxLength": 256,
      "pattern": "^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)*$",
      "examples": ["auth.login", "session.created", "file.accessed", "network.connection"]
    },

    "target": {
      "type": "string",
      "maxLength": 1024,
      "description": "The resource or entity affected"
    },

    "outcome": {
      "type": "string",
      "enum": ["success", "failure", "unknown"]
    },

    "severity": {
      "type": "integer",
      "minimum": 1,
      "maximum": 10,
      "description": "1=informational, 5=warning, 8=high, 10=critical"
    },

    "raw": {
      "type": "string",
      "maxLength": 65536,
      "description": "Original event payload"
    },

    "metadata": {
      "type": "object",
      "additionalProperties": true,
      "description": "Additional context-specific fields"
    }
  }
}
```

### 6.2 Severity Scale

| Level | Name | Description | Example |
|-------|------|-------------|---------|
| 1-2 | Informational | Normal operations | User login, session created |
| 3-4 | Low | Minor anomalies | Failed single login attempt |
| 5-6 | Medium | Potential issues | Multiple failed logins |
| 7-8 | High | Likely security issue | Brute force detected |
| 9-10 | Critical | Active incident | Data exfiltration, breach |

### 6.3 Action Taxonomy

```yaml
action_categories:
  auth:
    - auth.login
    - auth.logout
    - auth.failure
    - auth.mfa_challenge
    - auth.mfa_success
    - auth.mfa_failure
    - auth.password_change
    - auth.token_issued
    - auth.token_revoked

  session:
    - session.created
    - session.terminated
    - session.expired
    - session.hijack_detected

  access:
    - access.granted
    - access.denied
    - access.elevated
    - access.delegated

  data:
    - data.read
    - data.write
    - data.delete
    - data.export
    - data.share

  network:
    - network.connection
    - network.disconnection
    - network.blocked
    - network.tunneled

  system:
    - system.startup
    - system.shutdown
    - system.config_change
    - system.update
```

---

## 7. Correlation Engine

### 7.1 Rule Definition Format

```yaml
# Example: Brute Force Detection
rules:
  - id: brute_force_detection
    name: "Brute Force Login Attempt"
    description: "Detects multiple failed authentication attempts"
    enabled: true
    version: "1.0.0"

    # Match criteria
    match:
      action: "auth.failure"
      outcome: "failure"

    # Correlation logic
    correlation:
      type: threshold
      group_by:
        - actor.id
        - source.host
      threshold: 5
      window: 2m

    # Output
    emit:
      action: "threat.brute_force_detected"
      severity: 8
      outcome: "unknown"
      metadata:
        rule_id: "brute_force_detection"
        failed_attempts: "{{ count }}"
        time_window: "2m"

    # Alert configuration
    alert:
      enabled: true
      channels:
        - slack
        - webhook
      dedup_key: "{{ actor.id }}-{{ source.host }}"
      dedup_window: 15m

  # Example: Privilege Escalation
  - id: privilege_escalation
    name: "Potential Privilege Escalation"
    description: "User access elevated after multiple failures"
    enabled: true

    correlation:
      type: sequence
      steps:
        - match:
            action: "auth.failure"
            outcome: "failure"
          min_count: 3
          window: 5m
        - match:
            action: "access.elevated"
            outcome: "success"
          within: 1m
          same_fields:
            - actor.id

    emit:
      action: "threat.privilege_escalation"
      severity: 9
      metadata:
        rule_id: "privilege_escalation"
        sequence: "failures_then_elevation"

  # Example: Impossible Travel
  - id: impossible_travel
    name: "Impossible Travel Detection"
    description: "Login from geographically distant locations"
    enabled: true

    match:
      action: "auth.login"
      outcome: "success"

    correlation:
      type: custom
      handler: impossible_travel
      config:
        max_speed_kmh: 1000
        window: 24h
        group_by: actor.id

    emit:
      action: "threat.impossible_travel"
      severity: 7
```

### 7.2 Correlation Types

| Type | Description | Use Case |
|------|-------------|----------|
| `threshold` | Count events in time window | Brute force, rate limiting |
| `sequence` | Detect ordered event patterns | Attack chains, privilege escalation |
| `absence` | Alert when expected event doesn't occur | Heartbeat monitoring |
| `statistical` | Deviation from baseline | Anomaly detection (Phase 2) |
| `custom` | Plugin-based correlation | Complex logic, external data |

### 7.3 Correlation Engine Architecture

```yaml
correlation_engine:
  workers: 8

  state_store:
    type: redis
    host: localhost
    port: 6379
    db: 0
    key_prefix: "siem:corr:"

  windows:
    max_duration: 24h
    cleanup_interval: 1m

  rules:
    path: /etc/siem/rules/
    hot_reload: true
    validation: strict

  metrics:
    - rules_evaluated_total
    - rules_matched_total
    - correlation_latency_ms
    - state_entries_count
```

---

## 8. Alerting System

### 8.1 Alert Configuration

```yaml
alerting:
  channels:
    webhook:
      enabled: true
      endpoints:
        - name: security_team
          url: https://hooks.example.com/security
          method: POST
          headers:
            Authorization: "Bearer {{ env.WEBHOOK_TOKEN }}"
          retry:
            max_attempts: 3
            backoff: exponential
          timeout: 10s

    slack:
      enabled: true
      workspaces:
        - name: security_alerts
          webhook_url: "{{ env.SLACK_WEBHOOK_URL }}"
          channel: "#security-alerts"
          username: "Boundary-SIEM"
          icon_emoji: ":shield:"

    email:
      enabled: false  # Phase 2
      smtp_host: smtp.example.com
      smtp_port: 587
      from: siem@example.com

  deduplication:
    enabled: true
    default_window: 15m
    max_window: 24h
    strategy: first  # first | last | count

  rate_limiting:
    enabled: true
    global:
      max_per_minute: 100
      max_per_hour: 500
    per_channel:
      slack:
        max_per_minute: 10
      webhook:
        max_per_minute: 50

  escalation:
    enabled: false  # Phase 2
```

### 8.2 Alert Payload Format

```json
{
  "alert_id": "alert_abc123",
  "triggered_at": "2026-01-01T12:00:00Z",
  "rule": {
    "id": "brute_force_detection",
    "name": "Brute Force Login Attempt",
    "version": "1.0.0"
  },
  "severity": 8,
  "summary": "5 failed login attempts from user 'admin' on host 'db-prod-01' in 2 minutes",
  "correlated_events": [
    {
      "event_id": "evt_001",
      "timestamp": "2026-01-01T11:58:00Z",
      "action": "auth.failure"
    },
    {
      "event_id": "evt_002",
      "timestamp": "2026-01-01T11:58:30Z",
      "action": "auth.failure"
    }
  ],
  "context": {
    "actor_id": "admin",
    "source_host": "db-prod-01",
    "failed_attempts": 5,
    "time_window": "2m"
  },
  "links": {
    "investigate": "https://siem.example.com/search?rule_id=brute_force_detection&alert_id=alert_abc123",
    "silence": "https://siem.example.com/api/v1/alerts/alert_abc123/silence"
  }
}
```

### 8.3 Slack Message Format

```json
{
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "🚨 Security Alert: Brute Force Detected"
      }
    },
    {
      "type": "section",
      "fields": [
        { "type": "mrkdwn", "text": "*Severity:*\n🔴 High (8/10)" },
        { "type": "mrkdwn", "text": "*Rule:*\nBrute Force Detection" },
        { "type": "mrkdwn", "text": "*Actor:*\nadmin" },
        { "type": "mrkdwn", "text": "*Target:*\ndb-prod-01" }
      ]
    },
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "5 failed login attempts detected in 2 minute window"
      }
    },
    {
      "type": "actions",
      "elements": [
        {
          "type": "button",
          "text": { "type": "plain_text", "text": "Investigate" },
          "url": "https://siem.example.com/search?alert_id=abc123"
        },
        {
          "type": "button",
          "text": { "type": "plain_text", "text": "Silence 1h" },
          "style": "danger",
          "url": "https://siem.example.com/api/v1/alerts/abc123/silence?duration=1h"
        }
      ]
    }
  ]
}
```

---

## 9. Storage & Retention

### 9.1 Capacity Planning

| Metric | Calculation | Example (10K EPS) |
|--------|-------------|-------------------|
| Events/day | EPS × 86400 | 864M events |
| Raw storage/day | Events × avg_size | ~500GB (600 bytes avg) |
| Compressed/day | Raw × 0.15 | ~75GB |
| 90-day retention | Daily × 90 | ~6.75TB |
| Hot tier (7 days) | Daily × 7 | ~525GB |

### 9.2 Index Strategy

```sql
-- Primary indices (included in ORDER BY)
ORDER BY (tenant_id, source_product, timestamp, event_id)

-- Secondary indices for common queries
INDEX idx_action action TYPE bloom_filter GRANULARITY 4
INDEX idx_actor_id actor_id TYPE bloom_filter GRANULARITY 4
INDEX idx_severity severity TYPE minmax GRANULARITY 4
INDEX idx_outcome outcome TYPE set(3) GRANULARITY 4

-- Full-text index for raw event search
INDEX idx_raw raw TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
```

### 9.3 Backup & Recovery

```yaml
backup:
  schedule: "0 3 * * *"  # 3 AM daily

  full_backup:
    frequency: weekly
    day: sunday
    retention: 4  # Keep 4 weekly backups

  incremental:
    frequency: daily
    retention: 7  # Keep 7 daily incrementals

  destination:
    type: s3
    bucket: siem-backups
    prefix: "clickhouse/"
    encryption: AES-256

  verification:
    enabled: true
    sample_queries: 10

  recovery:
    rto: 4h  # Recovery Time Objective
    rpo: 24h # Recovery Point Objective
```

---

## 10. Security Requirements

### 10.1 Authentication & Authorization

```yaml
security:
  authentication:
    api_keys:
      algorithm: sha256
      min_length: 32
      rotation_policy: 90d

    jwt:
      algorithm: RS256
      expiry: 1h
      refresh_enabled: true
      refresh_expiry: 7d

  authorization:
    model: RBAC
    roles:
      - name: admin
        permissions: ["*"]
      - name: analyst
        permissions: ["search:read", "alerts:read", "rules:read"]
      - name: ingest_only
        permissions: ["events:write"]
      - name: viewer
        permissions: ["search:read"]

    resource_isolation:
      enabled: true
      field: tenant_id
      enforce_on: ["search", "aggregate", "export"]
```

### 10.2 Encryption

```yaml
encryption:
  in_transit:
    tls:
      min_version: "1.2"
      cipher_suites:
        - TLS_AES_256_GCM_SHA384
        - TLS_CHACHA20_POLY1305_SHA256
      certificate_rotation: 30d

  at_rest:
    enabled: true
    algorithm: AES-256-GCM
    key_management:
      type: vault
      path: secret/siem/encryption
      rotation: 90d

    fields:  # Field-level encryption
      - raw
      - metadata
      - actor.email
```

### 10.3 Audit Logging

```yaml
audit:
  enabled: true

  events:
    - type: api_access
      log: all
    - type: search_query
      log: all
    - type: rule_change
      log: all
    - type: alert_silence
      log: all
    - type: data_export
      log: all

  storage:
    separate_index: true
    retention: 365d
    immutable: true

  format:
    timestamp: ISO8601
    include_request_body: false  # Privacy
    include_response_summary: true
    mask_fields:
      - password
      - api_key
      - token
```

### 10.4 Network Security

```yaml
network:
  ingress:
    allowed_cidrs:
      ingest: ["10.0.0.0/8", "172.16.0.0/12"]
      api: ["0.0.0.0/0"]  # Behind load balancer

    rate_limiting:
      global: 100000/s
      per_ip: 10000/s

    ddos_protection:
      enabled: true
      provider: cloudflare

  egress:
    allowed_destinations:
      - "*.slack.com:443"
      - "smtp.example.com:587"
      - webhook_endpoints

    firewall:
      default: deny
```

---

## 11. Performance Requirements

### 11.1 Service Level Objectives (SLOs)

| Metric | Target | Measurement |
|--------|--------|-------------|
| Ingest throughput | 10,000 EPS | Events per second sustained |
| Ingest latency (P99) | < 100ms | Time to acknowledge |
| Search latency (P95) | < 2s | Simple queries, 24h range |
| Search latency (P99) | < 10s | Complex queries, 7d range |
| Correlation latency (P99) | < 500ms | Rule evaluation time |
| Alert delivery (P99) | < 30s | From event to notification |
| Availability | 99.9% | Uptime monthly |

### 11.2 Resource Sizing

```yaml
sizing:
  small:  # Up to 1K EPS
    ingest:
      replicas: 2
      cpu: 2
      memory: 4Gi
    storage:
      replicas: 3
      cpu: 4
      memory: 16Gi
      disk: 500Gi SSD
    correlation:
      replicas: 2
      cpu: 2
      memory: 4Gi

  medium:  # Up to 10K EPS
    ingest:
      replicas: 4
      cpu: 4
      memory: 8Gi
    storage:
      replicas: 3
      cpu: 8
      memory: 64Gi
      disk: 2Ti NVMe
    correlation:
      replicas: 4
      cpu: 4
      memory: 8Gi

  large:  # Up to 100K EPS
    ingest:
      replicas: 8
      cpu: 8
      memory: 16Gi
    storage:
      replicas: 6
      cpu: 16
      memory: 128Gi
      disk: 10Ti NVMe
    correlation:
      replicas: 8
      cpu: 8
      memory: 16Gi
```

### 11.3 Performance Testing

```yaml
performance_tests:
  ingest:
    - name: sustained_load
      rate: 10000  # EPS
      duration: 1h
      success_criteria:
        - latency_p99 < 100ms
        - error_rate < 0.01%

    - name: burst_load
      rate: 50000  # EPS
      duration: 5m
      success_criteria:
        - no_data_loss: true
        - recovery_time < 2m

  search:
    - name: simple_query
      queries_per_second: 100
      query_type: filter_by_severity
      time_range: 24h
      success_criteria:
        - latency_p95 < 500ms

    - name: complex_query
      queries_per_second: 10
      query_type: full_text_with_aggregation
      time_range: 7d
      success_criteria:
        - latency_p95 < 5s
```

---

## 12. Deployment Architecture

### 12.1 Kubernetes Deployment

```yaml
# Namespace
apiVersion: v1
kind: Namespace
metadata:
  name: boundary-siem
  labels:
    app.kubernetes.io/name: boundary-siem

---
# Ingest Service
apiVersion: apps/v1
kind: Deployment
metadata:
  name: siem-ingest
  namespace: boundary-siem
spec:
  replicas: 4
  selector:
    matchLabels:
      app: siem-ingest
  template:
    metadata:
      labels:
        app: siem-ingest
    spec:
      containers:
        - name: ingest
          image: boundary-siem/ingest:1.0.0
          ports:
            - containerPort: 8080  # HTTP
            - containerPort: 5514  # CEF UDP
            - containerPort: 5515  # CEF TCP
          resources:
            requests:
              cpu: "2"
              memory: "4Gi"
            limits:
              cpu: "4"
              memory: "8Gi"
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
          env:
            - name: CLICKHOUSE_HOST
              valueFrom:
                configMapKeyRef:
                  name: siem-config
                  key: clickhouse_host
---
# Correlation Engine
apiVersion: apps/v1
kind: Deployment
metadata:
  name: siem-correlation
  namespace: boundary-siem
spec:
  replicas: 4
  selector:
    matchLabels:
      app: siem-correlation
  template:
    metadata:
      labels:
        app: siem-correlation
    spec:
      containers:
        - name: correlation
          image: boundary-siem/correlation:1.0.0
          resources:
            requests:
              cpu: "4"
              memory: "8Gi"
            limits:
              cpu: "8"
              memory: "16Gi"
          env:
            - name: REDIS_HOST
              valueFrom:
                configMapKeyRef:
                  name: siem-config
                  key: redis_host
```

### 12.2 Docker Compose (Development)

```yaml
version: '3.8'

services:
  ingest:
    build: ./services/ingest
    ports:
      - "8080:8080"
      - "5514:5514/udp"
      - "5515:5515"
    environment:
      - CLICKHOUSE_HOST=clickhouse
      - REDIS_HOST=redis
    depends_on:
      - clickhouse
      - redis
    volumes:
      - ./config:/etc/siem

  correlation:
    build: ./services/correlation
    environment:
      - CLICKHOUSE_HOST=clickhouse
      - REDIS_HOST=redis
    depends_on:
      - clickhouse
      - redis
    volumes:
      - ./rules:/etc/siem/rules

  search-api:
    build: ./services/search-api
    ports:
      - "8081:8081"
    environment:
      - CLICKHOUSE_HOST=clickhouse
    depends_on:
      - clickhouse

  alerting:
    build: ./services/alerting
    environment:
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
    depends_on:
      - redis

  clickhouse:
    image: clickhouse/clickhouse-server:23.8
    ports:
      - "8123:8123"
      - "9000:9000"
    volumes:
      - clickhouse_data:/var/lib/clickhouse
      - ./clickhouse/config.xml:/etc/clickhouse-server/config.d/custom.xml

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  clickhouse_data:
  redis_data:
```

### 12.3 Infrastructure Requirements

| Component | Development | Production |
|-----------|-------------|------------|
| Kubernetes | Minikube/Kind | EKS/GKE/AKS |
| ClickHouse | Single node | 3+ node cluster |
| Redis | Single node | Redis Cluster |
| Load Balancer | - | ALB/NLB |
| Certificate Manager | Self-signed | Let's Encrypt / ACM |
| Secrets Management | .env files | HashiCorp Vault |
| Monitoring | Prometheus local | Prometheus + Grafana |

---

## 13. Monitoring & Observability

### 13.1 Metrics (Prometheus)

```yaml
metrics:
  ingest:
    - name: siem_events_received_total
      type: counter
      labels: [source, format]
    - name: siem_events_processed_total
      type: counter
      labels: [source, status]
    - name: siem_events_quarantined_total
      type: counter
      labels: [reason]
    - name: siem_ingest_latency_seconds
      type: histogram
      buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1.0]
    - name: siem_queue_depth
      type: gauge

  storage:
    - name: siem_storage_events_total
      type: counter
    - name: siem_storage_bytes_total
      type: counter
    - name: siem_query_duration_seconds
      type: histogram
    - name: siem_query_rows_returned
      type: histogram

  correlation:
    - name: siem_rules_evaluated_total
      type: counter
      labels: [rule_id]
    - name: siem_alerts_generated_total
      type: counter
      labels: [rule_id, severity]
    - name: siem_correlation_state_entries
      type: gauge
      labels: [rule_id]

  alerting:
    - name: siem_alerts_sent_total
      type: counter
      labels: [channel, status]
    - name: siem_alerts_deduplicated_total
      type: counter
    - name: siem_alert_delivery_seconds
      type: histogram
```

### 13.2 Logging

```yaml
logging:
  format: json
  level: info

  fields:
    - timestamp
    - level
    - service
    - trace_id
    - message
    - error

  outputs:
    - type: stdout
    - type: file
      path: /var/log/siem/
      rotation:
        max_size: 100MB
        max_age: 7d

  sampling:
    enabled: true
    rate: 0.1  # Sample 10% of debug logs
    exclude:
      - level: error
      - level: warn
```

### 13.3 Tracing

```yaml
tracing:
  enabled: true
  provider: opentelemetry

  exporter:
    type: otlp
    endpoint: http://jaeger:4317

  sampling:
    type: probabilistic
    rate: 0.01  # 1% of requests

  propagation:
    - tracecontext
    - baggage
```

### 13.4 Alerting on SIEM Health

```yaml
health_alerts:
  - name: high_ingest_latency
    condition: siem_ingest_latency_seconds{quantile="0.99"} > 0.5
    duration: 5m
    severity: warning

  - name: queue_backpressure
    condition: siem_queue_depth > 50000
    duration: 2m
    severity: critical

  - name: storage_error_rate
    condition: rate(siem_events_processed_total{status="error"}[5m]) > 0.01
    duration: 5m
    severity: critical

  - name: correlation_lag
    condition: siem_correlation_lag_seconds > 30
    duration: 5m
    severity: warning
```

---

## 14. Testing Strategy

### 14.1 Unit Tests

```yaml
unit_tests:
  coverage_target: 80%

  focus_areas:
    - CEF parser edge cases
    - JSON schema validation
    - Timestamp normalization
    - Correlation rule evaluation
    - Deduplication logic

  frameworks:
    go: go test
    rust: cargo test
```

### 14.2 Integration Tests

```yaml
integration_tests:
  environment: docker-compose

  scenarios:
    - name: end_to_end_ingest
      steps:
        - send 1000 CEF events via UDP
        - send 1000 JSON events via HTTP
        - verify all events in ClickHouse
        - verify schema compliance

    - name: correlation_rules
      steps:
        - load test rules
        - send events matching rule criteria
        - verify alerts generated
        - verify deduplication works

    - name: search_functionality
      steps:
        - ingest test dataset
        - execute various query types
        - verify results accuracy
        - verify pagination
```

### 14.3 Load Tests

```yaml
load_tests:
  tool: k6

  scenarios:
    - name: sustained_ingest
      vus: 100
      duration: 30m
      target_eps: 10000

    - name: search_under_load
      vus: 50
      duration: 15m
      queries_per_second: 100

    - name: spike_test
      stages:
        - duration: 1m, target: 10
        - duration: 30s, target: 200
        - duration: 1m, target: 200
        - duration: 30s, target: 10
```

### 14.4 Security Tests

```yaml
security_tests:
  static_analysis:
    - gosec
    - semgrep
    - trivy (container scanning)

  dynamic_analysis:
    - OWASP ZAP (API scanning)
    - nuclei (vulnerability scanning)

  penetration_testing:
    frequency: quarterly
    scope:
      - API authentication bypass
      - Injection attacks
      - Authorization bypass
      - Data exfiltration
```

---

## 15. Phase 2+ Roadmap

### 15.1 UI & Visualization (Phase 2)

- [ ] Web-based dashboard
- [ ] Saved searches
- [ ] Timeline views
- [ ] Severity heatmaps
- [ ] Real-time event streaming

### 15.2 Case Management (Phase 2)

- [ ] Alert → Case workflow
- [ ] Evidence attachment
- [ ] Status tracking
- [ ] Case timelines
- [ ] Analyst assignment

### 15.3 Advanced Correlation (Phase 3)

- [ ] Stateful correlations
- [ ] Graph-based relationships
- [ ] Sequence detection (A → B → C)
- [ ] Behavioral baselines

### 15.4 Threat Intelligence (Phase 3)

- [ ] IP reputation feeds
- [ ] CVE mappings
- [ ] Geo-IP enrichment
- [ ] MITRE ATT&CK mapping

### 15.5 Multi-Tenancy (Phase 3)

- [ ] Organization isolation
- [ ] Role-based access control
- [ ] Field-level security
- [ ] Custom retention policies

---

## Appendix A: Configuration Reference

```yaml
# /etc/siem/config.yaml
server:
  http_port: 8080
  grpc_port: 9090
  metrics_port: 9091

ingest:
  cef:
    udp_port: 5514
    tcp_port: 5515
    tls_enabled: true
  json:
    max_batch_size: 1000
    max_payload_size: 10MB

storage:
  clickhouse:
    hosts:
      - clickhouse-0.clickhouse:9000
      - clickhouse-1.clickhouse:9000
      - clickhouse-2.clickhouse:9000
    database: siem
    username: siem
    password: ${CLICKHOUSE_PASSWORD}

correlation:
  redis:
    host: redis:6379
    password: ${REDIS_PASSWORD}
  rules_path: /etc/siem/rules/

alerting:
  slack:
    webhook_url: ${SLACK_WEBHOOK_URL}
  dedup_window: 15m
  rate_limit: 100/hour
```

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| CEF | Common Event Format - a standard log format |
| EPS | Events Per Second |
| SLO | Service Level Objective |
| RTO | Recovery Time Objective |
| RPO | Recovery Point Objective |
| RBAC | Role-Based Access Control |
| SIEM | Security Information and Event Management |
| SOC | Security Operations Center |

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-01 | Boundary-SIEM Team | Initial specification |

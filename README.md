# Boundary-SIEM
SIEM MVP vs Nice-to-Have
🎯 MVP Definition (Non-Negotiable)

If these aren’t present, it’s not a SIEM — it’s log storage.

1. Ingest Layer (MVP)

Goal: Accept security events from boundary-daemon and at least one other source.

Required

CEF ingestion (UDP or TCP)

JSON over HTTP (POST)

Backpressure-safe ingestion (queue or buffer)

Event timestamp normalization

Source identity tagging (host, daemon ID, tenant)

Explicitly Not in MVP

100s of vendor formats

Syslog edge cases

Agent management

Why:
CEF + JSON covers boundary-daemon and gives you extensibility without parsing hell.

2. Canonical Event Schema (MVP)

Goal: Everything becomes one shape before storage.

Required Fields
{
  "event_id": "uuid",
  "timestamp": "UTC",
  "source": {
    "product": "boundary-daemon",
    "host": "...",
    "instance_id": "..."
  },
  "actor": {
    "type": "user|process|service",
    "id": "..."
  },
  "action": "string",
  "target": "string",
  "outcome": "success|failure|unknown",
  "severity": 1-10,
  "raw": "original event payload"
}

Required Behavior

Versioned schema (schema_version)

Strict validation at ingest

Invalid events are quarantined, not dropped

Why:
Schema discipline is what makes correlation possible later.
Skip this and your SIEM dies quietly in 6 months.

3. Storage Engine (MVP)

Goal: Store, query, and retain events at scale.

Required

Elasticsearch or ClickHouse

Time-partitioned indices

Retention policy (hot → warm → delete)

Indexed fields for:

timestamp

source

action

severity

outcome

Explicitly Not in MVP

Cold archive

Multi-region replication

Custom storage engines

Why:
Search speed and retention matter more than cleverness.

4. Search & Query (MVP)

Goal: Answer “what happened?” quickly.

Required

Time-range search

Field-based filtering

Full-text search on raw

JSON query API

Pagination & limits

UI Requirement

Minimal web UI or CLI

No dashboards yet

No drag-and-drop nonsense

Why:
If you can’t search, you can’t investigate.
Pretty comes later.

5. Correlation Engine (MVP – Minimal)

Goal: Detect relationships, not just events.

Required

Time-window correlation (e.g. N events in T seconds)

Cross-source matching (same actor / target)

Rule-based correlation (YAML or JSON)

Emit derived events (alerts are events)

Example:

rule: multiple_auth_failures
when:
  action: auth_failure
  count: 5
  window: 2m
then:
  severity: 8
  emit: brute_force_suspected

Explicitly Not in MVP

Graph databases

ML / anomaly detection

Probabilistic reasoning

Why:
This is the line between log aggregation and SIEM.

6. Alerting (MVP)

Goal: Get attention when it matters.

Required

Webhook output

Email or Slack (pick one)

Deduplication / rate limiting

Alert = correlated event + notification

Explicitly Not in MVP

PagerDuty escalation trees

On-call schedules

Case ownership

Why:
Alerts without spam control are worse than no alerts.

7. Multi-Source Support (MVP Lite)

Goal: Prove it’s not single-vendor.

Required

boundary-daemon

One non-boundary source (e.g. auth logs, firewall, or app logs)

Why:
If it only works with your own tool, it’s not a SIEM — it’s a feature.

✅ MVP Exit Criteria

You can say “this is a SIEM” when:

You ingest events from ≥2 sources

You normalize them into one schema

You store and search months of data

You correlate across sources

You generate alerts from correlations

Anything less = log platform.

🌱 Nice-to-Have (Phase 2+)

These add power, not identity.

A. UI & Visualization

Dashboards

Saved searches

Timeline views

Severity heatmaps

Value: Faster human cognition
Risk: UI bloat if done too early

B. Case Management

Alerts → cases

Evidence attachment

Status & notes

Case timelines

Value: SOC workflows
Risk: Turns into a ticket system

C. Advanced Correlation

Stateful correlations

Graph-based relationships

Sequence detection (A → B → C)

Sliding behavioral baselines

Value: Fewer false positives
Risk: Complexity explosion

D. Anomaly Detection (Careful)

Statistical baselines

Seasonality-aware thresholds

Optional ML models

Rule:
If you can’t explain it, don’t alert on it.

E. Threat Intelligence Enrichment

IP reputation feeds

CVE mappings

Geo-IP enrichment

Value: Context
Risk: False authority

F. Storage Enhancements

Cold storage (S3)

Rehydration

Compliance retention modes

G. Alert Destinations

PagerDuty

OpsGenie

SMS

SOAR integrations

H. Multi-Tenancy & RBAC

Org isolation

Role-based access

Field-level security

🚨 Strong Warnings (Learned the Hard Way)

Do not start with dashboards

Do not start with ML

Do not support “every log format”

Do not skip schema enforcement

Do not let correlation mutate raw events

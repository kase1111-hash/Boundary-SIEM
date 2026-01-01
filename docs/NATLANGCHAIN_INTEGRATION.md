# NatLangChain Integration

This document describes the integration between Boundary-SIEM and NatLangChain, a blockchain protocol where natural language prose serves as the primary ledger substrate.

## Overview

NatLangChain is a blockchain that uses "Proof of Understanding" consensus via LLM validators. Instead of computational puzzles, validators demonstrate comprehension by paraphrasing intent and reaching semantic agreement through dialectic debate.

Boundary-SIEM provides comprehensive security monitoring for NatLangChain deployments, including:

- **Event Ingestion**: Real-time ingestion of blockchain events
- **Threat Detection**: 20 built-in detection rules for NatLangChain-specific threats
- **Semantic Monitoring**: Detection of semantic drift and manipulation attempts
- **Audit Trail**: Complete audit logging of all blockchain activity

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NatLangChain Node                                │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  REST API (212+ endpoints)                                          │ │
│  │  /api/v1/chains, /api/v1/entries, /api/v1/disputes, etc.           │ │
│  └──────────────────────────────┬──────────────────────────────────────┘ │
└─────────────────────────────────┼───────────────────────────────────────┘
                                  │ HTTP/HTTPS
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Boundary-SIEM                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │  NatLangChain Ingester (Polling)                                    │ │
│  │  - Blocks & Entries                                                  │ │
│  │  - Disputes & Contracts                                              │ │
│  │  - Negotiations & Validations                                        │ │
│  │  - Semantic Drift Events                                             │ │
│  └──────────────────────────────┬──────────────────────────────────────┘ │
│                                  │                                       │
│  ┌──────────────────────────────▼──────────────────────────────────────┐ │
│  │  Normalizer                                                          │ │
│  │  Maps NatLangChain events to canonical SIEM schema                  │ │
│  └──────────────────────────────┬──────────────────────────────────────┘ │
│                                  │                                       │
│  ┌──────────────────────────────▼──────────────────────────────────────┐ │
│  │  Detection Engine (20 NatLangChain Rules)                           │ │
│  │  - Semantic drift detection                                          │ │
│  │  - Dispute escalation monitoring                                     │ │
│  │  - Adversarial pattern detection                                     │ │
│  │  - Validator misbehavior detection                                   │ │
│  └──────────────────────────────┬──────────────────────────────────────┘ │
│                                  │                                       │
│  ┌──────────────────────────────▼──────────────────────────────────────┐ │
│  │  Storage (ClickHouse) & Alerting                                    │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

## Configuration

### Enabling the Integration

Edit `configs/config.yaml` to enable NatLangChain integration:

```yaml
natlangchain:
  enabled: true
  client:
    base_url: "http://your-natlangchain-node:5000"
    api_key: "your-api-key"
    chain_id: "main"
    timeout: 30s
  ingester:
    poll_interval: 30s
    ingest_entries: true
    ingest_blocks: true
    ingest_disputes: true
    ingest_contracts: true
    ingest_negotiations: true
    ingest_validation: true
    ingest_semantic_drift: true
    min_drift_severity: "low"
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `enabled` | Enable NatLangChain integration | `false` |
| `client.base_url` | NatLangChain node URL | `http://localhost:5000` |
| `client.api_key` | API key for authentication | (empty) |
| `client.chain_id` | Chain to monitor | `main` |
| `client.timeout` | Request timeout | `30s` |
| `ingester.poll_interval` | Polling interval | `30s` |
| `ingester.ingest_entries` | Ingest entry events | `true` |
| `ingester.ingest_blocks` | Ingest block events | `true` |
| `ingester.ingest_disputes` | Ingest dispute events | `true` |
| `ingester.ingest_contracts` | Ingest contract events | `true` |
| `ingester.ingest_negotiations` | Ingest negotiation events | `true` |
| `ingester.ingest_validation` | Ingest validation events | `true` |
| `ingester.ingest_semantic_drift` | Ingest drift events | `true` |
| `ingester.min_drift_severity` | Minimum drift severity | `low` |

## Event Types

### Entry Events

| Action | Description | Severity |
|--------|-------------|----------|
| `nlc.entry.created` | New entry posted | 2-3 |
| `nlc.entry.validated` | Entry validated by consensus | 2 |
| `nlc.entry.rejected` | Entry rejected by validators | 6 |
| `nlc.entry.modified` | Entry modified | 2 |

### Block Events

| Action | Description | Severity |
|--------|-------------|----------|
| `nlc.block.mined` | New block created | 2 |
| `nlc.block.validated` | Block validated | 2 |
| `nlc.block.rejected` | Block rejected | 6 |

### Dispute Events

| Action | Description | Severity |
|--------|-------------|----------|
| `nlc.dispute.filed` | Dispute filed | 5 |
| `nlc.dispute.resolved` | Dispute resolved | 3 |
| `nlc.dispute.escalated` | Dispute escalated | 7 |
| `nlc.dispute.dismissed` | Dispute dismissed | 3 |

### Contract Events

| Action | Description | Severity |
|--------|-------------|----------|
| `nlc.contract.created` | Contract created | 3 |
| `nlc.contract.matched` | Contract matched | 3 |
| `nlc.contract.completed` | Contract completed | 3 |
| `nlc.contract.cancelled` | Contract cancelled | 4 |

### Negotiation Events

| Action | Description | Severity |
|--------|-------------|----------|
| `nlc.negotiation.started` | Negotiation started | 3 |
| `nlc.negotiation.round` | Negotiation round | 2 |
| `nlc.negotiation.completed` | Negotiation completed | 3 |
| `nlc.negotiation.failed` | Negotiation failed | 5 |
| `nlc.negotiation.timeout` | Negotiation timed out | 5 |

### Validation Events

| Action | Description | Severity |
|--------|-------------|----------|
| `nlc.validation.paraphrase` | Validator paraphrased entry | 2 |
| `nlc.validation.debate` | Dialectic debate occurred | 2 |
| `nlc.validation.consensus` | Consensus reached | 2 |
| `nlc.validation.rejection` | Validation rejected | 5 |

### Semantic Events

| Action | Description | Severity |
|--------|-------------|----------|
| `nlc.semantic.drift` | Semantic drift detected | 3-7 |
| `nlc.semantic.drift.critical` | Critical semantic drift | 9 |

### Security Events

| Action | Description | Severity |
|--------|-------------|----------|
| `nlc.security.adversarial` | Adversarial pattern detected | 9 |
| `nlc.security.manipulation` | Manipulation attempt | 8 |
| `nlc.security.impersonation` | Impersonation attempt | 9 |

## Detection Rules

The integration includes 20 detection rules for NatLangChain-specific threats:

### Semantic Security (NLC-001 to NLC-002)

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| NLC-001 | Critical Semantic Drift | Critical interpretation divergence detected | 9 |
| NLC-002 | High Semantic Drift Volume | Multiple drifts in short period | 7 |

### Dispute Monitoring (NLC-003 to NLC-004)

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| NLC-003 | Dispute Escalation | Dispute escalated to higher authority | 7 |
| NLC-004 | Dispute Storm | Rapid dispute filing (potential attack) | 8 |

### Entry Validation (NLC-005 to NLC-006)

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| NLC-005 | Entry Rejection | Entry rejected by validators | 5 |
| NLC-006 | Repeated Rejections | Same author has multiple rejections | 7 |

### Consensus Monitoring (NLC-007 to NLC-008)

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| NLC-007 | Validation Rejection | Validation rejected during consensus | 6 |
| NLC-008 | Validator Debate Failure | Dialectic debate resulted in rejection | 5 |

### Negotiation Monitoring (NLC-009 to NLC-010)

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| NLC-009 | Negotiation Failure | Negotiation failed or timed out | 4 |
| NLC-010 | Negotiation Failure Spike | Multiple failures in short period | 6 |

### Contract Monitoring (NLC-011 to NLC-012)

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| NLC-011 | Contract Cancellation | Contract was cancelled | 4 |
| NLC-012 | Mass Cancellation | Multiple contracts cancelled by same user | 7 |

### Chain Health (NLC-013 to NLC-014)

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| NLC-013 | Block Production Stall | No new blocks in expected window | 8 |
| NLC-014 | Low Validation Confidence | Unusually low confidence scores | 5 |

### Security Threats (NLC-015 to NLC-017)

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| NLC-015 | Adversarial Pattern | Potential adversarial content | 9 |
| NLC-016 | Manipulation Attempt | Semantic manipulation detected | 8 |
| NLC-017 | Impersonation Attempt | Identity spoofing detected | 9 |

### Anomaly Detection (NLC-018 to NLC-020)

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| NLC-018 | Unusual Entry Volume | Abnormally high entry rate from user | 6 |
| NLC-019 | Rapid Dispute Resolution | Suspiciously fast dispute resolution | 5 |
| NLC-020 | Validator Misbehavior | Same validator rejecting many entries | 7 |

## Event Metadata

All NatLangChain events include metadata prefixed with `nlc_`:

| Field | Description |
|-------|-------------|
| `nlc_entry_id` | Entry identifier |
| `nlc_chain_id` | Chain identifier |
| `nlc_block_number` | Block number |
| `nlc_block_hash` | Block hash |
| `nlc_content_hash` | Content hash (SHA-256) |
| `nlc_entry_type` | Entry type (prose, contract, etc.) |
| `nlc_validated` | Whether entry is validated |
| `nlc_validator_id` | Validator identifier |
| `nlc_drift_score` | Semantic drift score (0-1) |
| `nlc_confidence` | Validation confidence (0-1) |
| `nlc_dispute_id` | Dispute identifier |
| `nlc_contract_id` | Contract identifier |
| `nlc_negotiation_id` | Negotiation identifier |

## Querying NatLangChain Events

### Find all NatLangChain events

```sql
SELECT * FROM events
WHERE source_product = 'natlangchain'
ORDER BY timestamp DESC
LIMIT 100
```

### Find semantic drift events

```sql
SELECT * FROM events
WHERE action LIKE 'nlc.semantic.drift%'
ORDER BY severity DESC, timestamp DESC
```

### Find entries from a specific author

```sql
SELECT * FROM events
WHERE source_product = 'natlangchain'
  AND action LIKE 'nlc.entry%'
  AND actor_id = 'user-123'
ORDER BY timestamp DESC
```

### Find disputes

```sql
SELECT * FROM events
WHERE action LIKE 'nlc.dispute%'
  AND metadata->>'nlc_dispute_status' = 'escalated'
ORDER BY timestamp DESC
```

## Troubleshooting

### Connection Issues

If the ingester cannot connect to NatLangChain:

1. Verify the `base_url` is correct
2. Check that the NatLangChain node is running (`/health/ready` endpoint)
3. Verify API key is valid if authentication is required
4. Check network connectivity and firewall rules

### Missing Events

If events are not being ingested:

1. Verify `enabled: true` in configuration
2. Check feature toggles (e.g., `ingest_entries: true`)
3. Review logs for error messages
4. Verify the chain ID matches the target chain

### High Latency

If ingestion is slow:

1. Increase `poll_interval` to reduce API load
2. Reduce batch sizes if responses are large
3. Consider running multiple SIEM instances for different event types

## Security Considerations

### API Key Protection

- Store API keys in environment variables or secrets management
- Use TLS for all connections to NatLangChain nodes
- Rotate API keys regularly

### Event Integrity

- All events include content hashes for integrity verification
- Block hashes are included for chain continuity verification
- Validator signatures can be verified against known validators

### Access Control

- Apply RBAC to limit who can view NatLangChain events
- Consider tenant isolation for multi-chain deployments
- Audit access to sensitive dispute and contract data

## Integration with boundary-daemon

NatLangChain events can be correlated with boundary-daemon events for comprehensive security monitoring:

```sql
-- Find auth failures correlated with rejected entries
SELECT
  e1.timestamp as auth_time,
  e1.action as auth_action,
  e2.timestamp as entry_time,
  e2.action as entry_action
FROM events e1
JOIN events e2 ON e1.actor_id = e2.actor_id
WHERE e1.action = 'auth.failure'
  AND e2.action = 'nlc.entry.rejected'
  AND e2.timestamp > e1.timestamp
  AND e2.timestamp < e1.timestamp + INTERVAL 1 HOUR
ORDER BY e1.timestamp DESC
```

This enables detection of scenarios where a compromised session attempts blockchain manipulation.

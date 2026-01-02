# Boundary-SIEM Future Roadmap

## Strategic Vision: Agent-Native Security Intelligence Platform

**Target State**: An Agent-Native Security Intelligence Platform with Verifiable Reasoning

> SIEM becomes a subsystem, not the product.

### The Category Shift

Traditional SIEMs compete on:
- Ingest volume
- Dashboard count
- Query speed

**Boundary-SIEM will compete on**:
- Most explainable security decisions
- Lowest false-positive rate
- Fastest Mean-Time-to-Understanding (MTTU)
- Auditability of AI actions
- Composable agent security

### Unfair Advantages

| Capability | Traditional SIEM | Boundary-SIEM |
|------------|------------------|---------------|
| Agentic AI flows | Copilots that suggest | Autonomous agents with goals |
| Natural language | Search queries only | First-class data type |
| Decision tracking | Audit logs | Ledger-backed reasoning |
| Ecosystem | Standalone product | Integrated platform (Boundary, Agent-OS, IntentLog, NatLangChain, Medic) |

---

## Horizon 1: Agentic AI Foundation
*The Crown Jewel*

### Phase A: Security Agents as First-Class Entities

**Priority**: Critical
**Target**: Q2 2026

Define agents like services with goals, permissions, and memory:

```yaml
agent:
  name: ThreatTriage
  goals:
    - Minimize false positives
    - Escalate only verifiable threats
  permissions:
    - read: logs
    - write: cases
    - execute: containment
  memory:
    short_term: 24h
    long_term: ledger
```

#### Planned Components

```
internal/agents/
├── core/
│   ├── agent.go              # Agent definition and lifecycle
│   ├── goals.go              # Goal specification and tracking
│   ├── permissions.go        # Bounded permission system
│   └── memory.go             # Short-term and long-term memory
├── types/
│   ├── triage.go             # Threat triage agent
│   ├── forensics.go          # Forensics investigation agent
│   ├── intel.go              # Intelligence lookup agent
│   ├── remediation.go        # Remediation action agent
│   └── adversarial.go        # Red-team/challenger agent
├── spawn/
│   ├── manager.go            # Sub-agent spawning
│   ├── coordination.go       # Multi-agent coordination
│   └── lifecycle.go          # Agent lifecycle management
└── registry/
    ├── registry.go           # Agent registry
    ├── discovery.go          # Agent capability discovery
    └── health.go             # Agent health monitoring
```

#### Key Features

- **Goal-Driven Agents**: Agents operate on objectives, not scripts
- **Bounded Permissions**: Fine-grained access control per agent
- **Sub-Agent Spawning**: Agents can delegate to specialized sub-agents
- **Memory Hierarchy**: Short-term (24h in-memory) + long-term (ledger-backed)
- **Agent Registry**: Centralized discovery and management

#### Agent Types (Initial Set)

| Agent | Purpose | Permissions |
|-------|---------|-------------|
| ThreatTriage | Initial threat assessment | read: logs, write: cases |
| ForensicsAgent | Deep investigation | read: all, write: reports |
| IntelLookup | Threat intelligence enrichment | read: logs, external: intel-feeds |
| RemediationAgent | Containment actions | execute: containment |
| ChallengerAgent | Adversarial validation | read: all, test: detections |

---

### Phase B: Intent-Driven Workflows

**Priority**: Critical
**Target**: Q2 2026

Replace alert-centric with intent-centric detection:

#### Current Model (Alert-Driven)
```
Rule fired → Alert → Human review → Action
```

#### Target Model (Intent-Driven)
```
Intent defined → Violation detected → Agent investigation → Confirmation → Escalation
```

#### Example Intent Definition

```yaml
intent:
  name: ValidatorIntegrity
  description: "Production validator nodes should never exhibit entropy drift + unsigned block proposals"
  conditions:
    - entropy_variance: < 0.05
    - block_proposals: all_signed
  violation_handling:
    - agent: ThreatTriage
    - confirm_with: ForensicsAgent
    - escalate_if: both_agree
```

#### Planned Components

```
internal/intents/
├── definition/
│   ├── intent.go             # Intent specification
│   ├── condition.go          # Condition evaluation
│   └── parser.go             # YAML/JSON intent parsing
├── violation/
│   ├── detector.go           # Violation detection engine
│   ├── partial.go            # Partial violation handling
│   └── escalation.go         # Escalation logic
├── investigation/
│   ├── workflow.go           # Investigation workflow
│   ├── confirmation.go       # Multi-agent confirmation
│   └── decision.go           # Decision recording
└── library/
    ├── validator.go          # Validator integrity intents
    ├── transaction.go        # Transaction security intents
    ├── access.go             # Access control intents
    └── compliance.go         # Compliance intents
```

#### Key Features

- **Intent Library**: Pre-built intents for common security objectives
- **Partial Violation Handling**: Detect and investigate near-misses
- **Multi-Agent Confirmation**: Require consensus before escalation
- **Investigation Workflows**: Structured agent-driven investigation
- **Alert Fatigue Reduction**: Only escalate confirmed, verifiable threats

---

### Phase C: Self-Critiquing & Red-Team Agents

**Priority**: High
**Target**: Q3 2026

> Industry leaders do not do this. We should.

#### Adversarial Agent System

Every detection rule has:
- A **challenger agent** that attempts to break it
- A **confidence score** based on challenge results
- A **reasoning trace** explaining the decision

```
internal/adversarial/
├── challenger/
│   ├── engine.go             # Challenge execution engine
│   ├── strategies.go         # Attack strategies
│   └── coverage.go           # Detection coverage analysis
├── simulation/
│   ├── insider.go            # Insider threat simulation
│   ├── ambiguous.go          # Ambiguous signal injection
│   └── evasion.go            # Evasion technique testing
├── scoring/
│   ├── confidence.go         # Confidence score calculation
│   ├── robustness.go         # Rule robustness metrics
│   └── drift.go              # Detection drift monitoring
└── trace/
    ├── reasoning.go          # Reasoning trace generation
    ├── explanation.go        # Human-readable explanations
    └── ledger.go             # Trace ledger integration
```

#### Challenger Agent Capabilities

| Capability | Description |
|------------|-------------|
| Logic Breaking | Attempt to bypass detection logic |
| Insider Simulation | Simulate insider threat patterns |
| Signal Injection | Inject ambiguous signals to test discrimination |
| Evasion Testing | Test detection against known evasion techniques |
| Coverage Analysis | Identify gaps in detection coverage |

#### Continuous Validation

```yaml
detection_rule:
  id: VALIDATOR-001
  description: Double-vote detection
  challenger:
    enabled: true
    frequency: daily
    strategies:
      - timing_manipulation
      - signature_edge_cases
      - partial_evidence
  last_challenge:
    timestamp: 2026-01-15T00:00:00Z
    result: passed
    confidence: 0.94
    reasoning_trace_id: trace-abc123
```

---

## Horizon 2: Natural-Language Blockchain
*The Defensible Moat*

### Phase A: Ledger the Reasoning, Not the Event

**Priority**: Critical
**Target**: Q3 2026

> Do not ledger raw logs (expensive, pointless). Ledger decisions.

#### What Gets Ledgered

| Category | Examples |
|----------|----------|
| Agent Decisions | Triage outcomes, escalation choices |
| Investigative Conclusions | Root cause analysis, threat attribution |
| Justifications | Why this action was taken |
| Confidence Levels | Certainty scores with supporting evidence |
| Human Overrides | When humans disagree with AI |

#### Ledger Entry Schema

```yaml
ledger_entry:
  timestamp: 2026-01-02T14:30:00Z
  agent: ThreatTriage
  conclusion: "Probable MEV manipulation"
  evidence:
    - type: block_timing_anomaly
      value: "σ=4.1"
    - type: validator_entropy_mismatch
      value: "0.08 vs baseline 0.02"
    - type: historical_pattern_similarity
      value: "92%"
  confidence: 0.87
  human_override: null
  reasoning_trace_id: trace-xyz789
```

#### Benefits

- **Audit-Ready**: Complete decision history
- **Forensically Valuable**: Evidence chain preservation
- **Court-Defensible**: Explainable AI decisions
- **Compliance-Friendly**: SOC 2, ISO 27001 ready

#### Planned Components

```
internal/ledger/
├── entries/
│   ├── decision.go           # Decision entry type
│   ├── conclusion.go         # Conclusion entry type
│   ├── override.go           # Human override entry type
│   └── schema.go             # Ledger schema definitions
├── writer/
│   ├── sync.go               # Synchronous ledger writes
│   ├── batch.go              # Batched ledger writes
│   └── verification.go       # Write verification
├── query/
│   ├── query.go              # Ledger querying
│   ├── timeline.go           # Timeline reconstruction
│   └── export.go             # Evidence export
└── integration/
    ├── natlangchain.go       # NatLangChain integration
    ├── valueledger.go        # Value Ledger integration
    └── intentlog.go          # IntentLog integration
```

---

### Phase B: Natural Language as Query, Storage, and Output

**Priority**: High
**Target**: Q3-Q4 2026

> Turn SIEM from search engine → explainable system

#### NL Capabilities Matrix

| Capability | Description | Example |
|------------|-------------|---------|
| NL Ingestion | Accept natural language event descriptions | "Validator 0x123 missed 5 attestations" |
| NL Correlation | Correlate events using semantic similarity | Similar descriptions, different sources |
| NL Querying | Query in plain English | "Show incidents where human overrode agent" |
| NL Reporting | Generate human-readable reports | Narrative incident summaries |

#### Example Queries

```
"Show me all incidents where human override contradicted agent confidence > 0.8"

"Why was this alert escalated instead of auto-remediated?"

"What patterns preceded the last 5 slashing events?"

"Summarize validator health for the past week in plain English"
```

#### Planned Components

```
internal/natlang/
├── ingestion/
│   ├── parser.go             # NL event parsing
│   ├── normalizer.go         # Semantic normalization
│   └── embeddings.go         # Event embeddings
├── query/
│   ├── interpreter.go        # NL query interpretation
│   ├── planner.go            # Query plan generation
│   └── executor.go           # Query execution
├── correlation/
│   ├── semantic.go           # Semantic correlation
│   ├── similarity.go         # Similarity scoring
│   └── clustering.go         # Event clustering
├── output/
│   ├── narrative.go          # Narrative generation
│   ├── summary.go            # Summarization
│   └── report.go             # Report generation
└── models/
    ├── embeddings.go         # Embedding model interface
    ├── generation.go         # Text generation interface
    └── fine_tuning.go        # Domain fine-tuning
```

---

### Phase C: Proof-of-Understanding (PoU)

**Priority**: High
**Target**: Q4 2026

> Verifiable AI reasoning, not black-box automation

Before an agent can take critical action, it must:

1. **Summarize** the situation in natural language
2. **Pass validation** by another agent or human
3. **Commit the summary** to the ledger

#### PoU Workflow

```
┌─────────────────────────────────────────────────────────┐
│                    Agent Action Request                  │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              Generate NL Situation Summary               │
│  "Validator 0x123 has exhibited 3 anomalies in 1 hour:  │
│   - 2 missed attestations                                │
│   - 1 entropy drift (σ=3.2)                              │
│   - Peer connectivity fluctuation                        │
│   Recommending: Temporary isolation for investigation"   │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                   Validation Check                       │
│  ┌──────────────┐    ┌──────────────┐                   │
│  │ Peer Agent   │ OR │ Human Review │                   │
│  │ Validation   │    │              │                   │
│  └──────────────┘    └──────────────┘                   │
└─────────────────────────────────────────────────────────┘
                            │
                    ┌───────┴───────┐
                    ▼               ▼
            ┌───────────┐   ┌───────────────┐
            │  Approved │   │   Rejected    │
            └───────────┘   └───────────────┘
                    │               │
                    ▼               ▼
            ┌───────────┐   ┌───────────────┐
            │  Commit   │   │ Log Rejection │
            │ to Ledger │   │ + Reasoning   │
            │ + Execute │   └───────────────┘
            └───────────┘
```

#### PoU Action Tiers

| Action | Risk | PoU Requirement |
|--------|------|-----------------|
| Enrich intel | Low | Agent self-validation |
| Log annotation | Low | Agent self-validation |
| Isolate container | Medium | Peer agent validation |
| Pause validator | High | Dual-agent validation |
| Halt production | Critical | Human validation required |

---

## Horizon 3: Detection Evolution
*From Rules to Models*

### Phase A: Behavioral Models with Narratives

**Priority**: High
**Target**: Q1 2027

#### Current State (Rules)
```
IF (missed_attestations > 5) AND (time_window = 1h) THEN alert
```

#### Target State (Narratives)
```yaml
behavioral_model:
  name: ValidatorBehavior
  baseline_narrative: |
    A healthy validator exhibits consistent attestation timing,
    stable entropy levels, and predictable block proposal patterns.
    Network delays may cause occasional (1-2 per day) missed attestations.

  deviation_types:
    - timing_anomaly:
        generates: story
        hypothesis_tree: true
    - entropy_drift:
        generates: story
        hypothesis_tree: true
    - proposal_irregularity:
        generates: story
        hypothesis_tree: true
```

#### Hypothesis Tree Example

```
Observation: Validator 0x123 missed 7 attestations in 1 hour

Hypothesis Tree:
├── H1: Network connectivity issue (40%)
│   ├── Evidence: Peer count stable
│   └── Counter: No other validators affected
├── H2: Key management problem (25%)
│   ├── Evidence: Signing delays observed
│   └── Counter: No key access anomalies
├── H3: Compromised validator (20%)
│   ├── Evidence: Unusual entropy pattern
│   └── Supporting: Recent credential exposure attempt
└── H4: Scheduled maintenance (15%)
    └── Counter: No maintenance window registered

Recommendation: Investigate H3 with elevated priority
```

#### Planned Components

```
internal/behavioral/
├── models/
│   ├── validator.go          # Validator behavior model
│   ├── transaction.go        # Transaction behavior model
│   ├── access.go             # Access pattern model
│   └── network.go            # Network behavior model
├── baseline/
│   ├── learner.go            # Baseline learning
│   ├── narrative.go          # Narrative generation
│   └── update.go             # Baseline updates
├── deviation/
│   ├── detector.go           # Deviation detection
│   ├── story.go              # Story generation
│   └── hypothesis.go         # Hypothesis tree building
└── output/
    ├── investigation.go      # Investigation output
    ├── recommendation.go     # Action recommendations
    └── confidence.go         # Confidence scoring
```

---

### Phase B: Composable Detection Primitives

**Priority**: Medium
**Target**: Q1-Q2 2027

Expose low-level signals as primitives that agents can compose dynamically:

#### Signal Primitives

| Primitive | Description | Type |
|-----------|-------------|------|
| time_skew | Temporal deviation from expected | Float |
| entropy_variance | Randomness deviation | Float |
| intent_drift | Deviation from stated intent | Float |
| identity_ambiguity | Identity verification uncertainty | Float |
| pattern_similarity | Similarity to known patterns | Float |
| peer_correlation | Correlation with peer behavior | Float |
| historical_deviation | Deviation from historical baseline | Float |

#### Dynamic Composition

```yaml
composed_detection:
  name: SophisticatedValidatorCompromise
  primitives:
    - signal: entropy_variance
      threshold: "> 0.1"
      weight: 0.3
    - signal: intent_drift
      threshold: "> 0.2"
      weight: 0.25
    - signal: time_skew
      threshold: "> 2σ"
      weight: 0.2
    - signal: peer_correlation
      threshold: "< 0.5"
      weight: 0.15
    - signal: historical_deviation
      threshold: "> 0.3"
      weight: 0.1
  aggregation: weighted_sum
  alert_threshold: 0.7
```

#### Benefits

- **Flexibility**: Agents create detections on-the-fly
- **Adaptability**: Adjust weights based on context
- **Explainability**: Clear primitive contributions
- **Testability**: Test primitives independently

---

## Horizon 4: Autonomous Response (Safely)
*Graded Autonomy*

### Phase A: Risk-Tiered Response System

**Priority**: Critical
**Target**: Q2 2027

#### Response Action Matrix

| Action | Risk Tier | Confidence Needed | Approval Required |
|--------|-----------|-------------------|-------------------|
| Enrich intel | 1 (Low) | 0.2 | Agent |
| Add to watchlist | 1 (Low) | 0.3 | Agent |
| Annotate event | 1 (Low) | 0.2 | Agent |
| Isolate container | 2 (Medium) | 0.6 | Agent |
| Rate limit endpoint | 2 (Medium) | 0.5 | Agent |
| Quarantine wallet | 2 (Medium) | 0.7 | Agent |
| Halt validator | 3 (High) | 0.85 | Dual-agent |
| Pause bridge | 3 (High) | 0.9 | Dual-agent |
| Kill production access | 4 (Critical) | 0.95 | Human |
| Emergency shutdown | 4 (Critical) | 0.99 | Human + secondary |

#### Planned Components

```
internal/response/
├── actions/
│   ├── registry.go           # Action registry
│   ├── enrich.go             # Enrichment actions
│   ├── isolate.go            # Isolation actions
│   ├── halt.go               # Halt/pause actions
│   └── emergency.go          # Emergency actions
├── approval/
│   ├── engine.go             # Approval engine
│   ├── agent.go              # Agent approval
│   ├── dual.go               # Dual-agent approval
│   └── human.go              # Human approval
├── execution/
│   ├── executor.go           # Action execution
│   ├── rollback.go           # Rollback capability
│   └── verification.go       # Execution verification
├── tiers/
│   ├── definition.go         # Tier definitions
│   ├── mapping.go            # Action-tier mapping
│   └── override.go           # Tier override logic
└── audit/
    ├── trail.go              # Audit trail
    ├── ledger.go             # Ledger integration
    └── report.go             # Action reports
```

#### Dual-Agent Approval Flow

```
┌─────────────────────────────────────────────────────────┐
│              High-Risk Action Request                    │
│           (e.g., Halt Validator)                         │
└─────────────────────────────────────────────────────────┘
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
┌───────────────────────┐     ┌───────────────────────┐
│   Primary Agent       │     │   Validation Agent    │
│   Assessment          │     │   Independent Review  │
└───────────────────────┘     └───────────────────────┘
            │                               │
            └───────────────┬───────────────┘
                            ▼
                    ┌───────────────┐
                    │   Consensus?  │
                    └───────────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
        ┌───────────┐           ┌───────────┐
        │   Yes     │           │    No     │
        │ (Execute) │           │ (Escalate │
        │           │           │ to Human) │
        └───────────┘           └───────────┘
```

---

## Horizon 5: Human Trust & UX
*Non-Negotiable*

### Phase A: Explainability UI

**Priority**: Critical
**Target**: Q2-Q3 2027

Every incident must show:

- **Timeline**: Complete event sequence
- **Agent Decisions**: What each agent decided and why
- **Competing Hypotheses**: Alternative explanations considered
- **Rejection Reasoning**: Why alternatives were rejected

#### UI Components

```
web/src/components/explainability/
├── Timeline/
│   ├── EventTimeline.tsx     # Event timeline view
│   ├── AgentTimeline.tsx     # Agent action timeline
│   └── DecisionPoints.tsx    # Key decision markers
├── Decisions/
│   ├── DecisionCard.tsx      # Individual decision display
│   ├── ReasoningChain.tsx    # Reasoning trace view
│   └── ConfidenceMeter.tsx   # Confidence visualization
├── Hypotheses/
│   ├── HypothesisTree.tsx    # Interactive hypothesis tree
│   ├── EvidencePanel.tsx     # Supporting evidence
│   └── RejectionLog.tsx      # Rejection reasoning
└── Override/
    ├── OverrideButton.tsx    # "Disagree With AI" button
    ├── OverrideForm.tsx      # Override justification
    └── OverrideHistory.tsx   # Override audit trail
```

### Phase B: "Disagree With the AI" Button

**Priority**: Critical
**Target**: Q3 2027

Every AI decision must have a visible "Disagree" option that:

1. Records the disagreement
2. Captures human reasoning
3. Commits to the audit ledger
4. Triggers review workflow

```yaml
human_override:
  timestamp: 2026-01-15T10:30:00Z
  decision_id: dec-abc123
  agent: ThreatTriage
  original_conclusion: "Probable attack"
  original_confidence: 0.82
  human_action: disagree
  human_reasoning: |
    This pattern matches scheduled maintenance window.
    Validator team confirmed planned update at 10:25.
  new_classification: false_positive
  reviewed_by: analyst-jsmith
  ledger_entry_id: ledger-xyz789
```

#### Benefits

- **Builds Trust**: Humans maintain control
- **Improves Models**: Disagreements become training data
- **Audit-Ready**: Complete decision history
- **Calms Stakeholders**: CISOs, auditors, and lawyers appreciate this

---

## Horizon 6: Ecosystem Integration
*Where We Win Big*

### Integration Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    BOUNDARY-SIEM                         │
│              Security Intelligence Brain                 │
└─────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│   Agent-OS    │   │   IntentLog   │   │ Medic Agent   │
│               │   │               │   │               │
│ • Agent runs  │   │ • Intent      │   │ • Auto-triage │
│ • Permissions │   │   violations  │   │ • Recovery    │
│ • Lifecycle   │   │ • Behavior    │   │   planning    │
│               │   │   mismatches  │   │               │
└───────────────┘   └───────────────┘   └───────────────┘
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│Boundary-Daemon│   │ NatLangChain  │   │ Value Ledger  │
│               │   │               │   │               │
│ • Telemetry   │   │ • NL storage  │   │ • Financial   │
│ • Low-level   │   │ • NL querying │   │   tracking    │
│   signals     │   │ • Reasoning   │   │ • Compliance  │
│               │   │   ledger      │   │               │
└───────────────┘   └───────────────┘   └───────────────┘
```

### Integration Specifications

#### Agent-OS Integration

```yaml
integration:
  name: agent-os
  direction: bidirectional
  capabilities:
    inbound:
      - agent lifecycle events
      - permission changes
      - system status
    outbound:
      - security policies
      - agent restrictions
      - threat context
```

#### IntentLog Integration

```yaml
integration:
  name: intentlog
  direction: bidirectional
  capabilities:
    inbound:
      - intent violations
      - behavior mismatches
      - intent change history
    outbound:
      - security intent definitions
      - violation responses
      - compliance intents
```

#### Medic Agent Integration

```yaml
integration:
  name: medic-agent
  direction: bidirectional
  capabilities:
    inbound:
      - system health status
      - recovery progress
      - remediation results
    outbound:
      - compromise detection
      - recovery triggers
      - remediation workflows
```

---

## Implementation Timeline

### 2026

| Quarter | Focus | Key Deliverables |
|---------|-------|------------------|
| Q2 | Agentic Foundation | Agent definitions, permissions, basic spawning |
| Q2-Q3 | Intent-Driven Workflows | Intent library, violation detection, workflows |
| Q3 | Ledger Reasoning | Decision ledger, reasoning traces |
| Q3-Q4 | NL Query/Output | Natural language querying, narrative reports |
| Q4 | Proof-of-Understanding | PoU validation, action tiers |

### 2027

| Quarter | Focus | Key Deliverables |
|---------|-------|------------------|
| Q1 | Behavioral Models | Narrative baselines, hypothesis trees |
| Q1-Q2 | Composable Primitives | Signal primitives, dynamic composition |
| Q2 | Autonomous Response | Risk-tiered actions, dual-agent approval |
| Q2-Q3 | Explainability UI | Timeline, decisions, hypotheses views |
| Q3 | Human Override | Disagree button, override audit trail |
| Q4 | Ecosystem Integration | Full Agent-OS, IntentLog, Medic integration |

### 2028

| Quarter | Focus | Key Deliverables |
|---------|-------|------------------|
| Q1 | Adversarial Validation | Challenger agents, continuous validation |
| Q2 | Advanced NL | Semantic correlation, NL ingestion |
| Q3 | Platform Hardening | Security, compliance, audit certifications |
| Q4 | GA Release | 1.0 launch with full feature set |

---

## Success Metrics

### Category Leadership Indicators

| Metric | Target | Measurement |
|--------|--------|-------------|
| False Positive Rate | < 5% | Confirmed FPs / Total alerts |
| Mean Time to Understanding | < 15 min | Time from alert to root cause |
| Decision Explainability | 100% | Decisions with reasoning traces |
| Human Override Rate | < 10% | Overrides / Automated decisions |
| Audit Compliance | 100% | Ledgered decisions / Total decisions |
| Agent Confidence Accuracy | > 90% | Confidence vs. actual outcome |

### Competitive Positioning

**Not competing on**:
- Biggest ingest volume (Splunk wins)
- Most dashboards (Datadog wins)
- Fastest queries (ClickHouse wins)

**Competing on**:
- Most explainable security decisions
- Lowest false-positive rate
- Fastest mean-time-to-understanding
- Auditability of AI actions
- Composable agent security

### Industry Leadership Path

> If executed correctly, Boundary-SIEM will be:
> - The first agent-native SIEM
> - The first ledger-verifiable SOC
> - The first explainable autonomous security system

That's not incremental improvement. That's a new category.

---

## Appendix: Agent Configuration Examples

### ThreatTriage Agent

```yaml
agent:
  name: ThreatTriage
  version: 1.0.0
  type: triage

  goals:
    primary:
      - "Minimize false positives while catching real threats"
      - "Escalate only verifiable, confirmed threats"
    secondary:
      - "Reduce analyst workload by pre-investigating alerts"
      - "Maintain detailed reasoning for audit purposes"

  permissions:
    read:
      - logs.all
      - alerts.all
      - intel.threatfeeds
    write:
      - cases.create
      - cases.annotate
      - alerts.classify
    execute:
      - enrichment.all
    deny:
      - containment.*
      - production.*

  memory:
    short_term:
      type: in_memory
      ttl: 24h
      max_entries: 10000
    long_term:
      type: ledger
      provider: natlangchain
      retention: indefinite

  behavior:
    confidence_threshold: 0.6
    escalation_threshold: 0.85
    max_investigation_time: 5m
    peer_confirmation: optional
    human_escalation:
      threshold: 0.95
      required_for:
        - severity: critical
        - impact: production

  spawnable_agents:
    - forensics
    - intel_lookup
    - pattern_analysis

  reporting:
    frequency: realtime
    ledger_all_decisions: true
    generate_reasoning_traces: true
```

### ForensicsAgent

```yaml
agent:
  name: ForensicsAgent
  version: 1.0.0
  type: investigation

  goals:
    primary:
      - "Conduct thorough investigation of security incidents"
      - "Preserve evidence chain for legal/audit purposes"
    secondary:
      - "Identify root cause and attack vectors"
      - "Generate court-defensible investigation reports"

  permissions:
    read:
      - logs.all
      - events.all
      - blockchain.transactions
      - blockchain.contracts
      - memory_vault.secure
    write:
      - reports.forensics
      - evidence.chain
      - cases.update
    execute:
      - analysis.deepdive
      - timeline.reconstruct
    deny:
      - containment.*
      - production.*

  memory:
    short_term:
      type: in_memory
      ttl: 72h
      max_entries: 50000
    long_term:
      type: ledger
      provider: natlangchain
      retention: 7_years
      legal_hold_enabled: true

  behavior:
    investigation_depth: thorough
    evidence_preservation: strict
    timeline_reconstruction: automatic
    hypothesis_generation: enabled
    peer_review:
      required: true
      minimum_reviewers: 1
```

### ChallengerAgent

```yaml
agent:
  name: ChallengerAgent
  version: 1.0.0
  type: adversarial

  goals:
    primary:
      - "Challenge and validate detection rule effectiveness"
      - "Identify gaps in detection coverage"
    secondary:
      - "Simulate sophisticated attack patterns"
      - "Improve overall detection confidence scores"

  permissions:
    read:
      - rules.all
      - detections.all
      - logs.all
    write:
      - rules.confidence_scores
      - coverage.reports
      - challenges.results
    execute:
      - simulation.controlled
      - test.detection_logic
    deny:
      - production.*
      - containment.*
      - real_actions.*

  memory:
    short_term:
      type: in_memory
      ttl: 7d
    long_term:
      type: ledger
      provider: natlangchain
      retention: indefinite

  behavior:
    challenge_frequency: daily
    strategies:
      - timing_manipulation
      - edge_case_testing
      - evasion_simulation
      - ambiguous_signals
    safe_mode: true
    simulation_only: true
    production_impact: none
```

---

## Appendix: Intent Definition Examples

### Validator Integrity Intent

```yaml
intent:
  id: INT-VAL-001
  name: ValidatorIntegrity
  version: 1.0.0
  category: blockchain.validator

  description: |
    Production validators must maintain consistent behavior patterns.
    Anomalies may indicate compromise, misconfiguration, or attack.

  baseline:
    narrative: |
      A healthy production validator exhibits:
      - Consistent attestation timing (within 2σ of peer average)
      - Stable entropy levels (variance < 0.05)
      - Regular block proposals when elected
      - Stable peer connectivity (fluctuation < 10%)

  conditions:
    - id: attestation_timing
      metric: attestation.delay_ms
      threshold: "< peer_avg + 2σ"
      weight: 0.3

    - id: entropy_stability
      metric: validator.entropy_variance
      threshold: "< 0.05"
      weight: 0.25

    - id: proposal_regularity
      metric: block.proposal_success_rate
      threshold: "> 0.98"
      weight: 0.25

    - id: peer_stability
      metric: network.peer_fluctuation
      threshold: "< 0.10"
      weight: 0.2

  violation:
    partial_threshold: 0.5
    full_threshold: 0.8

    handling:
      partial:
        - agent: ThreatTriage
        - action: investigate
        - escalate: false

      full:
        - agent: ThreatTriage
        - confirm_with: ForensicsAgent
        - escalate_if: both_agree
        - response_tier: 3

  response_options:
    tier_1:
      - annotate_logs
      - enrich_context
    tier_2:
      - increase_monitoring
      - alert_on_call
    tier_3:
      - isolate_validator
      - preserve_evidence
    tier_4:
      - halt_validator
      - notify_stakeholders
```

### Transaction Security Intent

```yaml
intent:
  id: INT-TXN-001
  name: TransactionSecurity
  version: 1.0.0
  category: blockchain.transaction

  description: |
    Transactions should follow expected patterns.
    Anomalies may indicate MEV attacks, theft, or manipulation.

  baseline:
    narrative: |
      Normal transaction behavior includes:
      - Gas prices within 2σ of network average
      - Value transfers proportional to historical patterns
      - Contract interactions matching known ABIs
      - No interaction with sanctioned addresses

  conditions:
    - id: gas_normality
      metric: transaction.gas_price_deviation
      threshold: "< 2σ"
      weight: 0.25

    - id: value_proportionality
      metric: transaction.value_vs_historical
      threshold: "< 3σ"
      weight: 0.25

    - id: contract_known
      metric: transaction.contract_abi_match
      threshold: "> 0.8"
      weight: 0.25

    - id: address_clean
      metric: transaction.sanctioned_interaction
      threshold: "= 0"
      weight: 0.25

  violation:
    handling:
      sanctioned_interaction:
        - immediate: true
        - agent: ComplianceAgent
        - escalate: always
        - human_required: true

      other:
        - agent: ThreatTriage
        - escalate_threshold: 0.7
```

---

## Appendix: Ledger Entry Examples

### Decision Ledger Entry

```yaml
ledger_entry:
  type: decision
  id: led-dec-20260115-001
  timestamp: 2026-01-15T14:30:00Z

  agent:
    name: ThreatTriage
    version: 1.0.0
    instance_id: triage-abc123

  context:
    alert_id: alert-xyz789
    incident_id: inc-456
    intent_id: INT-VAL-001

  decision:
    conclusion: "Probable MEV manipulation"
    classification: true_positive
    severity: high
    confidence: 0.87

  evidence:
    - type: block_timing_anomaly
      description: "Block timing deviation"
      value: "σ=4.1"
      weight: 0.35

    - type: validator_entropy_mismatch
      description: "Entropy variance exceeded threshold"
      value: "0.08 vs baseline 0.02"
      weight: 0.30

    - type: historical_pattern_similarity
      description: "Matches known MEV attack pattern"
      value: "92% similarity"
      weight: 0.25

    - type: peer_correlation
      description: "Low correlation with peer validators"
      value: "0.3 vs expected 0.8"
      weight: 0.10

  reasoning_trace:
    steps:
      - step: 1
        action: "Evaluated intent conditions"
        result: "3 of 4 conditions violated"
      - step: 2
        action: "Checked historical patterns"
        result: "High similarity to MEV-2024-001"
      - step: 3
        action: "Calculated confidence"
        result: "0.87 based on evidence weights"
      - step: 4
        action: "Determined classification"
        result: "True positive - MEV manipulation"

  alternatives_considered:
    - hypothesis: "Network latency issue"
      confidence: 0.12
      rejection_reason: "Peer validators unaffected"

    - hypothesis: "Scheduled maintenance"
      confidence: 0.01
      rejection_reason: "No maintenance window registered"

  action_taken:
    type: escalate
    target: ForensicsAgent
    pou_required: true
    pou_validated: true
    pou_validator: ForensicsAgent

  human_override: null

  audit:
    hash: "sha256:abc123..."
    previous_hash: "sha256:xyz789..."
    signature: "sig:..."
```

### Human Override Entry

```yaml
ledger_entry:
  type: human_override
  id: led-ovr-20260115-001
  timestamp: 2026-01-15T15:00:00Z

  original_decision:
    ledger_id: led-dec-20260115-001
    agent: ThreatTriage
    conclusion: "Probable MEV manipulation"
    confidence: 0.87

  override:
    actor:
      type: human
      id: analyst-jsmith
      role: senior_analyst

    action: reclassify
    new_classification: false_positive

    reasoning: |
      After reviewing validator team communications,
      this pattern matches a scheduled client update.
      The update was not properly registered in the
      maintenance calendar, causing the detection.

      Validator team confirmed update window at 14:25.
      Pattern will resume normal after update completion.

    evidence_added:
      - type: communication
        description: "Slack message from validator team"
        reference: "slack://validator-ops/msg-123"

      - type: timeline
        description: "Update start confirmed"
        timestamp: 2026-01-15T14:25:00Z

  impact:
    alert_status: closed
    incident_status: resolved
    actions_reversed:
      - "Escalation to ForensicsAgent cancelled"

  training_feedback:
    submitted: true
    category: missed_maintenance_context
    recommendation: |
      Integrate maintenance calendar into intent
      evaluation to reduce similar false positives

  audit:
    hash: "sha256:def456..."
    previous_hash: "sha256:abc123..."
    signature: "sig:..."
```

---

*This roadmap represents the strategic vision for Boundary-SIEM's evolution into an Agent-Native Security Intelligence Platform. Features and timelines are subject to adjustment based on community feedback and development progress.*

**Last Updated**: January 2026
**Version**: 2.0.0

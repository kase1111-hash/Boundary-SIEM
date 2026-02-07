// Types matching the backend Go API responses

// Alert types (internal/alerting/manager.go)
export type AlertStatus =
  | "new"
  | "acknowledged"
  | "in_progress"
  | "resolved"
  | "suppressed";

export type Severity = "low" | "medium" | "high" | "critical";

export interface Alert {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: Severity;
  status: AlertStatus;
  title: string;
  description: string;
  created_at: string;
  updated_at: string;
  acked_at?: string;
  acked_by?: string;
  resolved_at?: string;
  resolved_by?: string;
  group_key?: string;
  event_count: number;
  event_ids?: string[];
  tags?: string[];
  mitre?: MITREMapping;
  metadata?: Record<string, unknown>;
  notes?: Note[];
  assigned_to?: string;
}

export interface Note {
  id: string;
  author: string;
  content: string;
  created_at: string;
}

export interface MITREMapping {
  tactic_id: string;
  tactic_name: string;
  technique_id: string;
  technique_name: string;
}

export interface AlertListResponse {
  alerts: Alert[];
  total: number;
}

export interface AlertFilter {
  status?: AlertStatus;
  severity?: Severity;
  rule_id?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

// Search types (internal/search/executor.go)
export interface SearchResult {
  event_id: string;
  timestamp: string;
  received_at: string;
  tenant_id: string;
  action: string;
  outcome: string;
  severity: number;
  target?: string;
  raw?: string;
  source_product: string;
  source_vendor: string;
  source_ip?: string;
  actor_name?: string;
  actor_id?: string;
  actor_ip?: string;
  metadata?: Record<string, unknown>;
}

export interface SearchResponse {
  query: string;
  total_count: number;
  results: SearchResult[];
  took_ms: number;
  limit: number;
  offset: number;
}

export interface SearchRequest {
  query: string;
  start_time?: string;
  end_time?: string;
  limit?: number;
  offset?: number;
  order_by?: string;
  order_desc?: boolean;
}

export interface AggregationRequest {
  query?: string;
  field: string;
  type: string;
  interval?: string;
  top_n?: number;
}

export interface AggregationBucket {
  key: string | number;
  count: number;
  value?: number;
}

export interface AggregationResult {
  buckets: AggregationBucket[];
  total: number;
}

// Rule types (internal/correlation/rule.go)
export type RuleType =
  | "threshold"
  | "sequence"
  | "aggregate"
  | "absence"
  | "custom";

export interface Rule {
  id: string;
  name: string;
  description: string;
  type: RuleType;
  enabled: boolean;
  severity: number;
  category?: string;
  tags?: string[];
  mitre?: MITREMapping;
  conditions?: {
    match?: MatchCondition[];
  };
  group_by?: string[];
  window: string;
  threshold?: ThresholdConfig;
  sequence?: SequenceConfig;
  aggregate?: AggregateConfig;
  absence?: AbsenceConfig;
  actions?: RuleAction[];
  metadata?: Record<string, unknown>;
  source?: "builtin" | "custom";
}

export interface MatchCondition {
  field: string;
  operator: string;
  value: unknown;
}

export interface ThresholdConfig {
  count: number;
  window?: string;
}

export interface SequenceConfig {
  steps: unknown[];
  max_span?: string;
}

export interface AggregateConfig {
  field: string;
  function: string;
  threshold: number;
}

export interface AbsenceConfig {
  expected_event: Record<string, unknown>;
  window: string;
}

export interface RuleAction {
  type: string;
  config?: Record<string, unknown>;
}

export interface RuleListResponse {
  rules: Rule[];
  total: number;
}

// Stats types
export interface EventStats {
  total_events: number;
  by_severity?: AggregationBucket[];
  by_action?: AggregationBucket[];
  by_outcome?: AggregationBucket[];
  time_histogram?: AggregationBucket[];
}

// WebSocket event types
export interface WSEvent {
  type: "event" | "alert" | "stats";
  data: SearchResult | Alert | EventStats;
}

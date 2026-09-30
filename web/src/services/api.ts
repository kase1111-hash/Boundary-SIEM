import type {
  AlertFilter,
  AlertListResponse,
  Alert,
  SearchRequest,
  SearchResponse,
  AggregationRequest,
  AggregationResult,
  SearchResult,
  RuleListResponse,
  Rule,
  EventStats,
} from "../types/api";

import { API_KEY_HEADER, getApiKey, handleUnauthorized } from "./auth";

const BASE = "";

const MUTATING_METHODS = new Set(["POST", "PUT", "DELETE", "PATCH"]);

function getCsrfToken(): string | undefined {
  if (typeof document === "undefined") return undefined;
  const match = document.cookie
    .split("; ")
    .find((row) => row.startsWith("XSRF-TOKEN="));
  return match ? decodeURIComponent(match.split("=")[1]) : undefined;
}

async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init?.headers as Record<string, string>) ?? {}),
  };

  // siem-ingest authenticates with a static API key (auth.api_key_header)
  const apiKey = getApiKey();
  if (apiKey) {
    headers[API_KEY_HEADER] = apiKey;
  }

  // Attach CSRF token for state-changing requests
  const method = (init?.method ?? "GET").toUpperCase();
  if (MUTATING_METHODS.has(method)) {
    const csrf = getCsrfToken();
    if (csrf) {
      headers["X-CSRF-Token"] = csrf;
    }
  }

  const res = await fetch(`${BASE}${path}`, {
    ...init,
    credentials: "include",
    headers,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const message: string = body.error || res.statusText || `HTTP ${res.status}`;
    if (res.status === 401) {
      // Drop the rejected key and let the UI prompt for a new one
      handleUnauthorized(apiKey, message);
    }
    throw new ApiError(res.status, message, body.code);
  }
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** Human-readable explanation of a failed request for error banners. */
export function describeError(err: unknown): string {
  if (err instanceof ApiError && err.status === 401) {
    return `Authentication required: ${err.message}. Enter a valid API key.`;
  }
  if (err instanceof ApiError && err.status === 403) {
    return `Access denied: ${err.message}`;
  }
  if (err instanceof Error && err.message) {
    return err.message;
  }
  return "Request failed";
}

/** True for errors that retrying without a new API key cannot fix. */
export function isAuthError(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 401 || err.status === 403);
}

// --- Alerts ---

export async function listAlerts(
  filter: AlertFilter = {},
): Promise<AlertListResponse> {
  const params = new URLSearchParams();
  if (filter.status) params.set("status", filter.status);
  if (filter.severity) params.set("severity", filter.severity);
  if (filter.rule_id) params.set("rule_id", filter.rule_id);
  if (filter.since) params.set("since", filter.since);
  if (filter.until) params.set("until", filter.until);
  if (filter.limit) params.set("limit", String(filter.limit));
  if (filter.offset) params.set("offset", String(filter.offset));
  const qs = params.toString();
  return request<AlertListResponse>(`/v1/alerts${qs ? `?${qs}` : ""}`);
}

export async function getAlert(id: string): Promise<Alert> {
  return request<Alert>(`/v1/alerts/${id}`);
}

export async function acknowledgeAlert(
  id: string,
  user: string,
): Promise<void> {
  await request(`/v1/alerts/${id}/acknowledge`, {
    method: "POST",
    body: JSON.stringify({ user }),
  });
}

export async function resolveAlert(id: string, user: string): Promise<void> {
  await request(`/v1/alerts/${id}/resolve`, {
    method: "POST",
    body: JSON.stringify({ user }),
  });
}

export async function addAlertNote(
  id: string,
  author: string,
  content: string,
): Promise<void> {
  await request(`/v1/alerts/${id}/notes`, {
    method: "POST",
    body: JSON.stringify({ author, content }),
  });
}

export async function assignAlert(
  id: string,
  assignee: string,
): Promise<void> {
  await request(`/v1/alerts/${id}/assign`, {
    method: "POST",
    body: JSON.stringify({ assignee }),
  });
}

export async function getAlertStats(): Promise<Record<string, unknown>> {
  return request("/v1/alerts/stats");
}

// --- Search ---

export async function searchEvents(
  req: SearchRequest,
): Promise<SearchResponse> {
  return request<SearchResponse>("/v1/search", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function getEvent(id: string): Promise<SearchResult> {
  return request<SearchResult>(`/v1/events/${id}`);
}

export async function aggregate(
  req: AggregationRequest,
): Promise<AggregationResult> {
  return request<AggregationResult>("/v1/aggregations", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

export async function getFieldValues(
  field: string,
  limit = 20,
): Promise<AggregationResult> {
  return request<AggregationResult>(
    `/v1/fields/${field}/values?limit=${limit}`,
  );
}

export async function getEventStats(
  start?: string,
  end?: string,
): Promise<EventStats> {
  const params = new URLSearchParams();
  if (start) params.set("start", start);
  if (end) params.set("end", end);
  const qs = params.toString();
  return request<EventStats>(`/v1/stats${qs ? `?${qs}` : ""}`);
}

// --- Rules ---

export async function listRules(filter?: {
  type?: string;
  enabled?: string;
  category?: string;
}): Promise<RuleListResponse> {
  const params = new URLSearchParams();
  if (filter?.type) params.set("type", filter.type);
  if (filter?.enabled) params.set("enabled", filter.enabled);
  if (filter?.category) params.set("category", filter.category);
  const qs = params.toString();
  return request<RuleListResponse>(`/v1/rules${qs ? `?${qs}` : ""}`);
}

export async function getRule(
  id: string,
): Promise<{ rule: Rule; source: string }> {
  return request(`/v1/rules/${id}`);
}

export async function createRule(
  rule: Partial<Rule>,
): Promise<{ rule: Rule; source: string }> {
  return request("/v1/rules", {
    method: "POST",
    body: JSON.stringify(rule),
  });
}

export async function updateRule(
  id: string,
  rule: Partial<Rule>,
): Promise<{ rule: Rule; source: string }> {
  return request(`/v1/rules/${id}`, {
    method: "PUT",
    body: JSON.stringify(rule),
  });
}

export async function deleteRule(id: string): Promise<void> {
  await request(`/v1/rules/${id}`, { method: "DELETE" });
}

export async function testRule(
  id: string,
): Promise<Record<string, unknown>> {
  return request(`/v1/rules/${id}/test`, { method: "POST" });
}

// --- Health ---

export async function healthCheck(): Promise<Record<string, unknown>> {
  return request("/health");
}

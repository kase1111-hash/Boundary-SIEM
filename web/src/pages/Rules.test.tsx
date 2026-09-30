import React from "react";
import { describe, expect, it } from "vitest";
import { renderToString } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiError } from "../services/api";
import type { Rule, RuleListResponse } from "../types/api";
import { RulesPage, filterRules, summarizeRules } from "./Rules";

// Regression tests for R08/R09 (web side): the Rules page showed blank rows
// for rules missing fields, crashed when searching them, and presented a
// 401 as "No rules found".

const partial = (r: Record<string, unknown>) => r as unknown as Rule;

function newClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, retryOnMount: false } },
  });
}

function render(client: QueryClient): string {
  return renderToString(
    <QueryClientProvider client={client}>
      <RulesPage />
    </QueryClientProvider>,
  );
}

function renderWith(data: unknown): string {
  const client = newClient();
  client.setQueryData(["rules", ""], data as RuleListResponse);
  return render(client);
}

describe("RulesPage", () => {
  it("renders rules that lack optional fields", () => {
    const html = renderWith({
      rules: [
        partial({ id: "only-id" }),
        {
          id: "full",
          name: "Brute force",
          description: "many failures",
          type: "threshold",
          enabled: true,
          severity: 8,
          window: "5m",
          source: "custom",
        },
      ],
    });

    expect(html).toContain("only-id"); // id is shown when name is missing
    expect(html).toContain("Brute force");
    expect(html).not.toContain("undefined");
    expect(html).not.toContain("()"); // no empty severity number
    expect(html).toMatch(/Total: (<!-- -->)?2/); // falls back to rules.length
    expect(html).toMatch(/Enabled: (<!-- -->)?1/);
  });

  it("handles a null rules list", () => {
    const html = renderWith({ rules: null, total: 0 });
    expect(html).toContain("No rules found");
  });

  it("shows an authentication error instead of an empty list", async () => {
    const client = newClient();
    await client.prefetchQuery({
      queryKey: ["rules", ""],
      queryFn: () => Promise.reject(new ApiError(401, "missing API key")),
    });

    const html = render(client);

    expect(html).not.toContain("No rules found");
    expect(html).toContain("missing API key");
    expect(html).toContain("API key");
  });
});

describe("filterRules", () => {
  const rules = [
    partial({ id: "no-name" }),
    partial({ name: "No id" }),
    partial({ id: "r3", name: "SSH brute force", category: "auth", description: "ssh" }),
  ];

  it("searches rules with missing name, id or description", () => {
    expect(() => filterRules(rules, { search: "ssh", category: "" })).not.toThrow();
    expect(filterRules(rules, { search: "ssh", category: "" })).toHaveLength(1);
    expect(filterRules(rules, { search: "no", category: "" })).toHaveLength(2);
  });

  it("filters by category", () => {
    expect(filterRules(rules, { search: "", category: "auth" })).toHaveLength(1);
  });
});

describe("summarizeRules", () => {
  it("counts enabled and custom rules across the whole list", () => {
    const summary = summarizeRules({
      rules: [
        partial({ id: "a", enabled: true, source: "custom" }),
        partial({ id: "b", enabled: false }),
        partial({ id: "c" }),
      ],
    } as unknown as RuleListResponse);
    expect(summary).toEqual({ total: 3, enabled: 1, custom: 1 });
  });
});

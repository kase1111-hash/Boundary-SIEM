import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listRules,
  updateRule,
  createRule,
  deleteRule,
  testRule,
  describeError,
} from "../services/api";
import type { Rule, RuleListResponse, RuleType, Severity } from "../types/api";
import { severityClass } from "../services/severity";

// --- Severity number to label (the class the rule's alerts get) ---
const severityTextColors: Record<Severity, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
};

function severityColor(sev: number): string {
  return severityTextColors[severityClass(sev)];
}

/** The rule's time window as shown in the table ("—" when it has none). */
export function ruleWindow(rule: Rule): string {
  const w = rule.window;
  if (typeof w !== "string" || w === "" || w === "0s") return "—";
  return w;
}

// Rules come from the API and may lack fields the type marks as required
// (older servers, custom rules); every accessor below tolerates that.

function ruleName(rule: Rule): string {
  return rule.name || rule.id || "(unnamed rule)";
}

/** Applies the search box and category filter. */
export function filterRules(
  rules: Rule[],
  { search, category }: { search: string; category: string },
): Rule[] {
  const q = search.toLowerCase();
  return rules.filter((rule) => {
    if (category && rule.category !== category) return false;
    if (!q) return true;
    return [rule.name, rule.id, rule.description].some((field) =>
      String(field ?? "").toLowerCase().includes(q),
    );
  });
}

/** Counts for the summary line, over all returned rules. */
export function summarizeRules(data: RuleListResponse | undefined): {
  total: number;
  enabled: number;
  custom: number;
} {
  const rules = data?.rules ?? [];
  return {
    total: data?.total ?? rules.length,
    enabled: rules.filter((r) => r.enabled === true).length,
    custom: rules.filter((r) => r.source === "custom").length,
  };
}

const ruleTypeLabels: Record<RuleType, string> = {
  threshold: "Threshold",
  sequence: "Sequence",
  aggregate: "Aggregate",
  absence: "Absence",
  custom: "Custom",
};

// --- RuleList ---

export const RulesPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [search, setSearch] = useState("");
  const [showEditor, setShowEditor] = useState(false);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [testResults, setTestResults] = useState<Record<string, unknown> | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [detailRule, setDetailRule] = useState<Rule | null>(null);

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["rules", typeFilter],
    queryFn: () =>
      listRules({
        type: typeFilter || undefined,
      }),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      updateRule(id, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["rules"] });
    },
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => testRule(id),
    onSuccess: (data, id) => {
      setTestResults(data);
      setTestingId(id);
    },
  });

  const rules = data?.rules ?? [];

  // Get unique categories for filter
  const categories = Array.from(
    new Set(
      rules
        .map((r) => r.category)
        .filter((c): c is string => typeof c === "string" && c !== ""),
    ),
  );

  // Filter rules
  const filtered = filterRules(rules, {
    search,
    category: categoryFilter,
  });
  const summary = summarizeRules(data);

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-white">Detection Rules</h2>
        <button
          onClick={() => {
            setEditingRule(null);
            setShowEditor(true);
          }}
          className="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700"
        >
          Create Rule
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search rules..."
          className="flex-1 bg-gray-800 text-white text-sm px-3 py-1.5 rounded border border-gray-700 focus:border-blue-500 focus:outline-none"
        />
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="bg-gray-800 text-gray-300 text-sm rounded px-3 py-1.5 border border-gray-700"
        >
          <option value="">All Types</option>
          <option value="threshold">Threshold</option>
          <option value="sequence">Sequence</option>
          <option value="aggregate">Aggregate</option>
          <option value="absence">Absence</option>
          <option value="custom">Custom</option>
        </select>
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="bg-gray-800 text-gray-300 text-sm rounded px-3 py-1.5 border border-gray-700"
        >
          <option value="">All Categories</option>
          {categories.map((cat) => (
            <option key={cat} value={cat}>
              {cat}
            </option>
          ))}
        </select>
      </div>

      {/* Rules summary */}
      <div className="flex gap-4 text-sm text-gray-400">
        <span>Total: {summary.total}</span>
        <span>Enabled: {summary.enabled}</span>
        <span>Custom: {summary.custom}</span>
      </div>

      {/* Rules table */}
      <div className="bg-gray-800 rounded-lg overflow-hidden">
        {isError ? (
          <div className="p-8 text-center">
            <p className="text-red-400 mb-2">
              Failed to load rules: {describeError(error)}
            </p>
            <button
              onClick={() => refetch()}
              className="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-500"
            >
              Retry
            </button>
          </div>
        ) : isLoading ? (
          <div className="p-8 text-center text-gray-500">Loading rules...</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 text-left text-xs border-b border-gray-700">
                <th className="p-3 w-12">On</th>
                <th className="p-3">Name</th>
                <th className="p-3">Type</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Window</th>
                <th className="p-3">Category</th>
                <th className="p-3">Source</th>
                <th className="p-3 w-32">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((rule, idx) => (
                <tr
                  key={rule.id || `rule-${idx}`}
                  className="border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer"
                  onClick={() => setDetailRule(rule)}
                  title="Show rule details"
                >
                  <td className="p-3" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() =>
                        toggleMutation.mutate({
                          id: rule.id,
                          enabled: !rule.enabled,
                        })
                      }
                      className={`w-8 h-4 rounded-full transition relative ${
                        rule.enabled ? "bg-green-600" : "bg-gray-600"
                      }`}
                    >
                      <span
                        className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-transform ${
                          rule.enabled ? "left-4" : "left-0.5"
                        }`}
                      />
                    </button>
                  </td>
                  <td className="p-3">
                    <p className="text-gray-300">{ruleName(rule)}</p>
                    <p className="text-gray-500 text-xs mt-0.5 truncate max-w-md">
                      {rule.description}
                    </p>
                  </td>
                  <td className="p-3">
                    <span className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs">
                      {ruleTypeLabels[rule.type] || rule.type || "—"}
                    </span>
                  </td>
                  <td className="p-3">
                    {typeof rule.severity === "number" ? (
                      <>
                        <span
                          className={`font-medium ${severityColor(rule.severity)}`}
                        >
                          {severityClass(rule.severity)}
                        </span>
                        <span className="text-gray-500 text-xs ml-1">
                          ({rule.severity})
                        </span>
                      </>
                    ) : (
                      <span className="text-gray-500">—</span>
                    )}
                  </td>
                  <td className="p-3 text-gray-400 text-xs whitespace-nowrap">
                    {ruleWindow(rule)}
                  </td>
                  <td className="p-3 text-gray-400 text-xs">
                    {rule.category || "—"}
                  </td>
                  <td className="p-3">
                    <span
                      className={`text-xs ${
                        rule.source === "custom"
                          ? "text-blue-400"
                          : "text-gray-500"
                      }`}
                    >
                      {rule.source || "builtin"}
                    </span>
                  </td>
                  <td className="p-3" onClick={(e) => e.stopPropagation()}>
                    <div className="flex gap-1">
                      <button
                        onClick={() => testMutation.mutate(rule.id)}
                        className="px-2 py-1 bg-gray-700 text-gray-300 text-xs rounded hover:bg-gray-600"
                      >
                        Test
                      </button>
                      {rule.source === "custom" && (
                        <>
                          <button
                            onClick={() => {
                              setEditingRule(rule);
                              setShowEditor(true);
                            }}
                            className="px-2 py-1 bg-gray-700 text-gray-300 text-xs rounded hover:bg-gray-600"
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => {
                              if (
                                confirm(
                                  `Delete rule "${ruleName(rule)}"?`,
                                )
                              )
                                deleteMutation.mutate(rule.id);
                            }}
                            className="px-2 py-1 bg-red-900/50 text-red-400 text-xs rounded hover:bg-red-900"
                          >
                            Del
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td
                    colSpan={8}
                    className="p-8 text-center text-gray-500"
                  >
                    No rules found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Rule detail modal (click a row) */}
      {detailRule && (
        <RuleDetail rule={detailRule} onClose={() => setDetailRule(null)} />
      )}

      {/* Test result modal */}
      {testResults && testingId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-96 max-h-[80vh] overflow-y-auto">
            <h3 className="text-white font-semibold mb-3">Rule Test Result</h3>
            <pre className="text-gray-300 text-xs bg-gray-900 rounded p-3 overflow-x-auto">
              {JSON.stringify(testResults, null, 2)}
            </pre>
            <button
              onClick={() => {
                setTestResults(null);
                setTestingId(null);
              }}
              className="mt-4 w-full px-4 py-2 bg-gray-700 text-gray-300 rounded hover:bg-gray-600 text-sm"
            >
              Close
            </button>
          </div>
        </div>
      )}

      {/* Rule editor modal */}
      {showEditor && (
        <RuleEditor
          rule={editingRule}
          onClose={() => {
            setShowEditor(false);
            setEditingRule(null);
          }}
          onSaved={() => {
            setShowEditor(false);
            setEditingRule(null);
            queryClient.invalidateQueries({ queryKey: ["rules"] });
          }}
        />
      )}
    </div>
  );
};

// --- Rule Detail ---

/** Read-only view of a rule: the summary fields, then the full definition. */
export const RuleDetail: React.FC<{ rule: Rule; onClose: () => void }> = ({
  rule,
  onClose,
}) => {
  const fields: [string, string][] = [
    ["ID", rule.id || "—"],
    ["Type", ruleTypeLabels[rule.type] || rule.type || "—"],
    [
      "Severity",
      typeof rule.severity === "number"
        ? `${severityClass(rule.severity)} (${rule.severity})`
        : "—",
    ],
    ["Window", ruleWindow(rule)],
    ["Group by", rule.group_by?.length ? rule.group_by.join(", ") : "—"],
    ["Category", rule.category || "—"],
    ["Source", rule.source || "builtin"],
    ["Enabled", rule.enabled ? "yes" : "no"],
  ];
  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div
        className="bg-gray-800 rounded-lg p-6 w-[40rem] max-h-[85vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="text-white font-semibold">{ruleName(rule)}</h3>
        {rule.description && (
          <p className="text-gray-400 text-sm mt-1">{rule.description}</p>
        )}
        <dl className="grid grid-cols-3 gap-x-4 gap-y-1 text-sm mt-4">
          {fields.map(([label, value]) => (
            <React.Fragment key={label}>
              <dt className="text-gray-500">{label}</dt>
              <dd className="col-span-2 text-gray-300">{value}</dd>
            </React.Fragment>
          ))}
        </dl>
        <pre className="text-gray-300 text-xs bg-gray-900 rounded p-3 mt-4 overflow-x-auto">
          {JSON.stringify(rule, null, 2)}
        </pre>
        <button
          onClick={onClose}
          className="mt-4 w-full px-4 py-2 bg-gray-700 text-gray-300 rounded hover:bg-gray-600 text-sm"
        >
          Close
        </button>
      </div>
    </div>
  );
};

// --- Rule Editor ---

const RuleEditor: React.FC<{
  rule: Rule | null;
  onClose: () => void;
  onSaved: () => void;
}> = ({ rule, onClose, onSaved }) => {
  const isNew = !rule;
  const [json, setJson] = useState(
    rule
      ? JSON.stringify(rule, null, 2)
      : JSON.stringify(
          {
            id: "",
            name: "",
            description: "",
            type: "threshold",
            enabled: true,
            severity: 5,
            category: "",
            conditions: { match: [] },
            window: "5m",
            threshold: { count: 10 },
          },
          null,
          2,
        ),
  );
  const [error, setError] = useState("");

  const saveMutation = useMutation({
    mutationFn: async () => {
      const parsed = JSON.parse(json);
      if (isNew) {
        return createRule(parsed);
      } else {
        return updateRule(rule!.id, parsed);
      }
    },
    onSuccess: () => onSaved(),
    onError: (err: Error) => setError(err.message),
  });

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-[640px] max-h-[85vh] flex flex-col">
        <h3 className="text-white font-semibold mb-3">
          {isNew ? "Create Rule" : "Edit Rule"}
        </h3>
        {error && (
          <div className="mb-3 px-3 py-2 bg-red-900/40 border border-red-700 rounded text-red-400 text-sm">
            {error}
          </div>
        )}
        <textarea
          value={json}
          onChange={(e) => {
            setJson(e.target.value);
            setError("");
          }}
          className="flex-1 min-h-[300px] bg-gray-900 text-gray-300 text-xs font-mono px-4 py-3 rounded border border-gray-700 focus:border-blue-500 focus:outline-none resize-none"
          spellCheck={false}
        />
        <div className="flex justify-end gap-2 mt-4">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-gray-700 text-gray-300 text-sm rounded hover:bg-gray-600"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              try {
                JSON.parse(json);
                saveMutation.mutate();
              } catch (e) {
                setError("Invalid JSON");
              }
            }}
            disabled={saveMutation.isPending}
            className="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 disabled:opacity-50"
          >
            {saveMutation.isPending ? "Saving..." : "Save Rule"}
          </button>
        </div>
      </div>
    </div>
  );
};

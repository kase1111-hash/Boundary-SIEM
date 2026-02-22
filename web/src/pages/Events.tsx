import React, { useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { searchEvents, aggregate } from "../services/api";
import type { SearchResult } from "../types/api";

// --- Saved searches (localStorage) ---
function getSavedSearches(): { name: string; query: string }[] {
  try {
    return JSON.parse(localStorage.getItem("saved_searches") || "[]");
  } catch {
    return [];
  }
}

function saveSearch(name: string, query: string) {
  const searches = getSavedSearches().filter((s) => s.name !== name);
  searches.unshift({ name, query });
  localStorage.setItem("saved_searches", JSON.stringify(searches.slice(0, 20)));
}

// --- Field names for autocomplete ---
const KNOWN_FIELDS = [
  "action",
  "outcome",
  "severity",
  "target",
  "source.product",
  "source.vendor",
  "source.ip",
  "actor.name",
  "actor.id",
  "actor.ip",
  "tenant",
  "raw",
  "metadata.",
];

// --- EventRow ---
const EventRow: React.FC<{
  event: SearchResult;
  expanded: boolean;
  onToggle: () => void;
}> = ({ event, expanded, onToggle }) => (
  <>
    <tr
      className="border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer"
      onClick={onToggle}
    >
      <td className="p-3 text-gray-500 text-xs whitespace-nowrap">
        {new Date(event.timestamp).toLocaleString()}
      </td>
      <td className="p-3 text-gray-300 text-sm">{event.action}</td>
      <td className="p-3 text-gray-400 text-xs">{event.outcome}</td>
      <td className="p-3 text-gray-400 text-xs">{event.source_product}</td>
      <td className="p-3 text-gray-400 text-xs">{event.actor_name || "—"}</td>
      <td className="p-3 text-gray-400 text-xs">{event.target || "—"}</td>
      <td className="p-3 text-gray-400 text-xs">{event.severity}</td>
    </tr>
    {expanded && (
      <tr className="bg-gray-800/50">
        <td colSpan={7} className="p-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-gray-500 text-xs mb-1">Event ID</p>
              <p className="text-gray-300 font-mono text-xs">
                {event.event_id}
              </p>
            </div>
            <div>
              <p className="text-gray-500 text-xs mb-1">Source Vendor</p>
              <p className="text-gray-300">{event.source_vendor}</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs mb-1">Source IP</p>
              <p className="text-gray-300">{event.source_ip || "—"}</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs mb-1">Actor IP</p>
              <p className="text-gray-300">{event.actor_ip || "—"}</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs mb-1">Actor ID</p>
              <p className="text-gray-300">{event.actor_id || "—"}</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs mb-1">Tenant</p>
              <p className="text-gray-300">{event.tenant_id}</p>
            </div>
            {event.metadata && Object.keys(event.metadata).length > 0 && (
              <div className="col-span-2">
                <p className="text-gray-500 text-xs mb-1">Metadata</p>
                <pre className="text-gray-300 text-xs bg-gray-900 rounded p-2 overflow-x-auto">
                  {JSON.stringify(event.metadata, null, 2)}
                </pre>
              </div>
            )}
            {event.raw && (
              <div className="col-span-2">
                <p className="text-gray-500 text-xs mb-1">Raw Event</p>
                <pre className="text-gray-300 text-xs bg-gray-900 rounded p-2 overflow-x-auto whitespace-pre-wrap">
                  {event.raw}
                </pre>
              </div>
            )}
          </div>
        </td>
      </tr>
    )}
  </>
);

export const EventsPage: React.FC = () => {
  const [queryStr, setQueryStr] = useState("");
  const [submittedQuery, setSubmittedQuery] = useState("");
  const [page, setPage] = useState(0);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [showSaved, setShowSaved] = useState(false);
  const [saveName, setSaveName] = useState("");
  const [showSuggestions, setShowSuggestions] = useState(false);
  const limit = 50;

  const handleSearch = useCallback(
    (q?: string) => {
      setSubmittedQuery(q ?? queryStr);
      setPage(0);
      setExpandedId(null);
    },
    [queryStr],
  );

  const { data, isLoading, isFetching, isError, refetch } = useQuery({
    queryKey: ["search", submittedQuery, page],
    queryFn: () =>
      searchEvents({
        query: submittedQuery,
        limit,
        offset: page * limit,
      }),
    enabled: submittedQuery !== "",
  });

  const { data: histogram } = useQuery({
    queryKey: ["histogram", submittedQuery],
    queryFn: () =>
      aggregate({
        query: submittedQuery || undefined,
        field: "timestamp",
        type: "histogram",
        interval: "1h",
      }),
    enabled: submittedQuery !== "",
  });

  const histogramData = (histogram?.buckets || []).map((b) => ({
    time:
      typeof b.key === "string"
        ? new Date(b.key).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
          })
        : String(b.key),
    count: b.count,
  }));

  const savedSearches = getSavedSearches();

  // Simple field suggestions
  const cursorWord = queryStr.split(/\s+/).pop() || "";
  const suggestions = showSuggestions
    ? KNOWN_FIELDS.filter(
        (f) => cursorWord && f.startsWith(cursorWord.toLowerCase()),
      )
    : [];

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold text-white">Event Search</h2>

      {/* Search bar */}
      <div className="relative">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <input
              type="text"
              value={queryStr}
              onChange={(e) => {
                setQueryStr(e.target.value);
                setShowSuggestions(true);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  handleSearch();
                  setShowSuggestions(false);
                }
                if (e.key === "Escape") setShowSuggestions(false);
              }}
              onFocus={() => setShowSuggestions(true)}
              onBlur={() => setTimeout(() => setShowSuggestions(false), 200)}
              placeholder='Search events... (e.g. action="login" AND severity>5)'
              className="w-full bg-gray-800 text-white text-sm px-4 py-2.5 rounded-lg border border-gray-700 focus:border-blue-500 focus:outline-none font-mono"
            />
            {suggestions.length > 0 && (
              <div className="absolute top-full left-0 right-0 mt-1 bg-gray-800 border border-gray-700 rounded-lg shadow-lg z-10">
                {suggestions.map((field) => (
                  <button
                    key={field}
                    onMouseDown={(e) => {
                      e.preventDefault();
                      const words = queryStr.split(/\s+/);
                      words[words.length - 1] = field;
                      setQueryStr(words.join(" "));
                      setShowSuggestions(false);
                    }}
                    className="w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-700 font-mono"
                  >
                    {field}
                  </button>
                ))}
              </div>
            )}
          </div>
          <button
            onClick={() => handleSearch()}
            className="px-6 py-2.5 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700"
          >
            Search
          </button>
          <button
            onClick={() => setShowSaved(!showSaved)}
            className="px-3 py-2.5 bg-gray-800 text-gray-400 text-sm rounded-lg border border-gray-700 hover:bg-gray-700"
            title="Saved searches"
          >
            Saved
          </button>
        </div>

        {/* Saved searches dropdown */}
        {showSaved && (
          <div className="absolute right-0 top-full mt-1 w-80 bg-gray-800 border border-gray-700 rounded-lg shadow-lg z-10 p-3">
            <div className="flex gap-2 mb-3">
              <input
                type="text"
                value={saveName}
                onChange={(e) => setSaveName(e.target.value)}
                placeholder="Save current query as..."
                className="flex-1 bg-gray-700 text-white text-xs px-2 py-1 rounded border border-gray-600 focus:outline-none"
              />
              <button
                onClick={() => {
                  if (saveName && queryStr) {
                    saveSearch(saveName, queryStr);
                    setSaveName("");
                  }
                }}
                disabled={!saveName || !queryStr}
                className="px-2 py-1 bg-blue-600 text-white text-xs rounded disabled:opacity-50"
              >
                Save
              </button>
            </div>
            {savedSearches.length > 0 ? (
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {savedSearches.map((s) => (
                  <button
                    key={s.name}
                    onClick={() => {
                      setQueryStr(s.query);
                      handleSearch(s.query);
                      setShowSaved(false);
                    }}
                    className="w-full text-left px-2 py-1.5 rounded hover:bg-gray-700 text-sm"
                  >
                    <p className="text-gray-300">{s.name}</p>
                    <p className="text-gray-500 text-xs font-mono truncate">
                      {s.query}
                    </p>
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-gray-500 text-xs">No saved searches</p>
            )}
          </div>
        )}
      </div>

      {/* Time histogram */}
      {histogramData.length > 0 && (
        <div className="bg-gray-800 rounded-lg p-4">
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={histogramData}>
              <XAxis
                dataKey="time"
                tick={{ fill: "#9ca3af", fontSize: 10 }}
                axisLine={{ stroke: "#374151" }}
              />
              <YAxis
                tick={{ fill: "#9ca3af", fontSize: 10 }}
                axisLine={{ stroke: "#374151" }}
                width={40}
              />
              <Tooltip
                contentStyle={{
                  background: "#1f2937",
                  border: "1px solid #374151",
                  borderRadius: 6,
                }}
                labelStyle={{ color: "#d1d5db" }}
              />
              <Bar dataKey="count" fill="#3b82f6" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Results info */}
      {data && (
        <div className="flex justify-between items-center text-sm">
          <span className="text-gray-400">
            {data.total_count.toLocaleString()} results
            {data.took_ms > 0 && (
              <span className="text-gray-500 ml-2">({data.took_ms}ms)</span>
            )}
          </span>
          {isFetching && (
            <span className="text-gray-500 text-xs">Refreshing...</span>
          )}
        </div>
      )}

      {/* Results table */}
      {isError ? (
        <div className="bg-gray-800 rounded-lg p-8 text-center">
          <p className="text-red-400 mb-2">Search failed</p>
          <button
            onClick={() => refetch()}
            className="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-500"
          >
            Retry
          </button>
        </div>
      ) : isLoading ? (
        <div className="bg-gray-800 rounded-lg p-8 text-center text-gray-500">
          Searching...
        </div>
      ) : submittedQuery === "" ? (
        <div className="bg-gray-800 rounded-lg p-12 text-center text-gray-500">
          <p className="text-lg mb-2">Enter a search query</p>
          <p className="text-sm">
            Examples: <code className="text-gray-400">action="login"</code>,{" "}
            <code className="text-gray-400">severity&gt;5 AND outcome="failure"</code>,{" "}
            <code className="text-gray-400">actor.name~"admin*"</code>
          </p>
        </div>
      ) : data?.results && data.results.length > 0 ? (
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 text-left text-xs border-b border-gray-700">
                <th className="p-3">Time</th>
                <th className="p-3">Action</th>
                <th className="p-3">Outcome</th>
                <th className="p-3">Source</th>
                <th className="p-3">Actor</th>
                <th className="p-3">Target</th>
                <th className="p-3">Sev</th>
              </tr>
            </thead>
            <tbody>
              {data.results.map((event) => (
                <EventRow
                  key={event.event_id}
                  event={event}
                  expanded={expandedId === event.event_id}
                  onToggle={() =>
                    setExpandedId(
                      expandedId === event.event_id ? null : event.event_id,
                    )
                  }
                />
              ))}
            </tbody>
          </table>

          {/* Pagination */}
          {data.total_count > limit && (
            <div className="flex justify-between items-center px-4 py-3 border-t border-gray-700">
              <span className="text-gray-500 text-xs">
                Page {page + 1} of {Math.ceil(data.total_count / limit)}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="px-3 py-1 bg-gray-700 text-gray-300 text-sm rounded disabled:opacity-50"
                >
                  Prev
                </button>
                <button
                  onClick={() => setPage((p) => p + 1)}
                  disabled={(page + 1) * limit >= data.total_count}
                  className="px-3 py-1 bg-gray-700 text-gray-300 text-sm rounded disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="bg-gray-800 rounded-lg p-8 text-center text-gray-500">
          No results found
        </div>
      )}
    </div>
  );
};

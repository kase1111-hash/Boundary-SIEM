import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams, useNavigate, Link } from "react-router-dom";
import {
  listAlerts,
  getAlert,
  acknowledgeAlert,
  resolveAlert,
  addAlertNote,
  assignAlert,
} from "../services/api";
import type { AlertStatus, Severity } from "../types/api";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";

// --- AlertList ---

export const AlertListPage: React.FC = () => {
  const [statusFilter, setStatusFilter] = useState<AlertStatus | "">("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "">("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const queryClient = useQueryClient();
  const limit = 25;

  const { data, isLoading } = useQuery({
    queryKey: ["alerts", statusFilter, severityFilter, page],
    queryFn: () =>
      listAlerts({
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
        limit,
        offset: page * limit,
      }),
    refetchInterval: 15_000,
  });

  const bulkAck = useMutation({
    mutationFn: async () => {
      await Promise.all(
        Array.from(selected).map((id) => acknowledgeAlert(id, "operator")),
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      setSelected(new Set());
    },
  });

  const bulkResolve = useMutation({
    mutationFn: async () => {
      await Promise.all(
        Array.from(selected).map((id) => resolveAlert(id, "operator")),
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      setSelected(new Set());
    },
  });

  const toggleSelect = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (!data?.alerts) return;
    if (selected.size === data.alerts.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(data.alerts.map((a) => a.id)));
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-semibold text-white">Alerts</h2>
        <div className="flex gap-2">
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value as AlertStatus | "");
              setPage(0);
            }}
            className="bg-gray-800 text-gray-300 text-sm rounded px-3 py-1.5 border border-gray-700"
          >
            <option value="">All Statuses</option>
            <option value="new">New</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
          </select>
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value as Severity | "");
              setPage(0);
            }}
            className="bg-gray-800 text-gray-300 text-sm rounded px-3 py-1.5 border border-gray-700"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      {/* Bulk actions */}
      {selected.size > 0 && (
        <div className="bg-gray-800 rounded-lg px-4 py-2 flex items-center gap-3">
          <span className="text-gray-300 text-sm">
            {selected.size} selected
          </span>
          <button
            onClick={() => bulkAck.mutate()}
            disabled={bulkAck.isPending}
            className="px-3 py-1 bg-yellow-600 text-white text-sm rounded hover:bg-yellow-700 disabled:opacity-50"
          >
            Acknowledge
          </button>
          <button
            onClick={() => bulkResolve.mutate()}
            disabled={bulkResolve.isPending}
            className="px-3 py-1 bg-green-600 text-white text-sm rounded hover:bg-green-700 disabled:opacity-50"
          >
            Resolve
          </button>
        </div>
      )}

      {/* Alert table */}
      <div className="bg-gray-800 rounded-lg overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500">Loading alerts...</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 text-left text-xs border-b border-gray-700">
                <th className="p-3 w-8">
                  <input
                    type="checkbox"
                    checked={
                      data?.alerts
                        ? selected.size === data.alerts.length &&
                          data.alerts.length > 0
                        : false
                    }
                    onChange={toggleAll}
                    className="rounded bg-gray-700 border-gray-600"
                  />
                </th>
                <th className="p-3">Severity</th>
                <th className="p-3">Title</th>
                <th className="p-3">Rule</th>
                <th className="p-3">Status</th>
                <th className="p-3">Events</th>
                <th className="p-3">Assigned</th>
                <th className="p-3">Created</th>
              </tr>
            </thead>
            <tbody>
              {data?.alerts?.map((alert) => (
                <tr
                  key={alert.id}
                  className="border-b border-gray-700/50 hover:bg-gray-700/30"
                >
                  <td className="p-3">
                    <input
                      type="checkbox"
                      checked={selected.has(alert.id)}
                      onChange={() => toggleSelect(alert.id)}
                      className="rounded bg-gray-700 border-gray-600"
                    />
                  </td>
                  <td className="p-3">
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="p-3 text-gray-300">
                    <Link
                      to={`/alerts/${alert.id}`}
                      className="hover:text-white"
                    >
                      {alert.title}
                    </Link>
                  </td>
                  <td className="p-3 text-gray-400 text-xs">
                    {alert.rule_name}
                  </td>
                  <td className="p-3">
                    <StatusBadge status={alert.status} />
                  </td>
                  <td className="p-3 text-gray-400">{alert.event_count}</td>
                  <td className="p-3 text-gray-400">
                    {alert.assigned_to || "—"}
                  </td>
                  <td className="p-3 text-gray-500 text-xs whitespace-nowrap">
                    {new Date(alert.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
              {(!data?.alerts || data.alerts.length === 0) && (
                <tr>
                  <td
                    colSpan={8}
                    className="p-8 text-center text-gray-500"
                  >
                    No alerts found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {data && data.total > limit && (
          <div className="flex justify-between items-center px-4 py-3 border-t border-gray-700">
            <span className="text-gray-500 text-xs">
              Showing {page * limit + 1}–
              {Math.min((page + 1) * limit, data.total)} of {data.total}
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
                disabled={(page + 1) * limit >= data.total}
                className="px-3 py-1 bg-gray-700 text-gray-300 text-sm rounded disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// --- AlertDetail ---

export const AlertDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [noteContent, setNoteContent] = useState("");
  const [assignee, setAssignee] = useState("");

  const { data: alert, isLoading } = useQuery({
    queryKey: ["alert", id],
    queryFn: () => getAlert(id!),
    enabled: !!id,
  });

  const ackMutation = useMutation({
    mutationFn: () => acknowledgeAlert(id!, "operator"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert", id] });
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
  });

  const resolveMutation = useMutation({
    mutationFn: () => resolveAlert(id!, "operator"),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert", id] });
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
  });

  const noteMutation = useMutation({
    mutationFn: () => addAlertNote(id!, "operator", noteContent),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert", id] });
      setNoteContent("");
    },
  });

  const assignMutation = useMutation({
    mutationFn: () => assignAlert(id!, assignee),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["alert", id] });
      setAssignee("");
    },
  });

  if (isLoading) {
    return (
      <div className="text-gray-500 text-center py-12">Loading alert...</div>
    );
  }
  if (!alert) {
    return (
      <div className="text-gray-500 text-center py-12">Alert not found</div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center gap-3">
        <button
          onClick={() => navigate("/alerts")}
          className="text-gray-400 hover:text-white text-sm"
        >
          &larr; Alerts
        </button>
      </div>

      {/* Header */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex justify-between items-start">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <SeverityBadge severity={alert.severity} />
              <StatusBadge status={alert.status} />
            </div>
            <h2 className="text-xl font-semibold text-white">{alert.title}</h2>
            <p className="text-gray-400 text-sm mt-1">{alert.description}</p>
          </div>
          <div className="flex gap-2">
            {alert.status === "new" && (
              <button
                onClick={() => ackMutation.mutate()}
                disabled={ackMutation.isPending}
                className="px-4 py-2 bg-yellow-600 text-white text-sm rounded hover:bg-yellow-700 disabled:opacity-50"
              >
                Acknowledge
              </button>
            )}
            {alert.status !== "resolved" && (
              <button
                onClick={() => resolveMutation.mutate()}
                disabled={resolveMutation.isPending}
                className="px-4 py-2 bg-green-600 text-white text-sm rounded hover:bg-green-700 disabled:opacity-50"
              >
                Resolve
              </button>
            )}
          </div>
        </div>

        <div className="grid grid-cols-4 gap-4 mt-4 pt-4 border-t border-gray-700">
          <div>
            <p className="text-gray-500 text-xs">Rule</p>
            <p className="text-gray-300 text-sm">{alert.rule_name}</p>
          </div>
          <div>
            <p className="text-gray-500 text-xs">Events</p>
            <p className="text-gray-300 text-sm">{alert.event_count}</p>
          </div>
          <div>
            <p className="text-gray-500 text-xs">Assigned To</p>
            <p className="text-gray-300 text-sm">
              {alert.assigned_to || "Unassigned"}
            </p>
          </div>
          <div>
            <p className="text-gray-500 text-xs">Created</p>
            <p className="text-gray-300 text-sm">
              {new Date(alert.created_at).toLocaleString()}
            </p>
          </div>
        </div>

        {alert.mitre && (
          <div className="mt-3 pt-3 border-t border-gray-700">
            <p className="text-gray-500 text-xs mb-1">MITRE ATT&CK</p>
            <p className="text-gray-300 text-sm">
              {alert.mitre.tactic_name} &mdash; {alert.mitre.technique_name} (
              {alert.mitre.technique_id})
            </p>
          </div>
        )}
      </div>

      {/* Assign */}
      <div className="bg-gray-800 rounded-lg p-4">
        <h3 className="text-white text-sm font-semibold mb-2">Assign</h3>
        <div className="flex gap-2">
          <input
            type="text"
            value={assignee}
            onChange={(e) => setAssignee(e.target.value)}
            placeholder="Username"
            className="flex-1 bg-gray-700 text-white text-sm px-3 py-1.5 rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
          />
          <button
            onClick={() => assignMutation.mutate()}
            disabled={!assignee || assignMutation.isPending}
            className="px-4 py-1.5 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 disabled:opacity-50"
          >
            Assign
          </button>
        </div>
      </div>

      {/* Notes */}
      <div className="bg-gray-800 rounded-lg p-4">
        <h3 className="text-white text-sm font-semibold mb-3">Notes</h3>
        {alert.notes && alert.notes.length > 0 ? (
          <div className="space-y-3 mb-4">
            {alert.notes.map((note) => (
              <div
                key={note.id}
                className="border-l-2 border-gray-600 pl-3 py-1"
              >
                <div className="flex justify-between">
                  <span className="text-blue-400 text-xs font-medium">
                    {note.author}
                  </span>
                  <span className="text-gray-500 text-xs">
                    {new Date(note.created_at).toLocaleString()}
                  </span>
                </div>
                <p className="text-gray-300 text-sm mt-1">{note.content}</p>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-gray-500 text-sm mb-3">No notes yet</p>
        )}
        <div className="flex gap-2">
          <input
            type="text"
            value={noteContent}
            onChange={(e) => setNoteContent(e.target.value)}
            placeholder="Add a note..."
            className="flex-1 bg-gray-700 text-white text-sm px-3 py-1.5 rounded border border-gray-600 focus:border-blue-500 focus:outline-none"
            onKeyDown={(e) => {
              if (e.key === "Enter" && noteContent) noteMutation.mutate();
            }}
          />
          <button
            onClick={() => noteMutation.mutate()}
            disabled={!noteContent || noteMutation.isPending}
            className="px-4 py-1.5 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 disabled:opacity-50"
          >
            Add
          </button>
        </div>
      </div>

      {/* Tags & metadata */}
      {alert.tags && alert.tags.length > 0 && (
        <div className="bg-gray-800 rounded-lg p-4">
          <h3 className="text-white text-sm font-semibold mb-2">Tags</h3>
          <div className="flex flex-wrap gap-2">
            {alert.tags.map((tag) => (
              <span
                key={tag}
                className="px-2 py-0.5 bg-gray-700 text-gray-300 rounded text-xs"
              >
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

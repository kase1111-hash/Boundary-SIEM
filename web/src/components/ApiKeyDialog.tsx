import React, { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  API_KEY_HEADER,
  clearApiKey,
  getAnalystName,
  getApiKey,
  setAnalystName,
  setApiKey,
  subscribeAuth,
} from "../services/auth";

/**
 * Header control for the API key plus the prompt shown whenever the server
 * answers 401 (or the live socket closes with 4401).
 */
export const ApiKeyControl: React.FC = () => {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState<string | null>(null);
  const [value, setValue] = useState("");
  const [analyst, setAnalyst] = useState(getAnalystName);
  const [remember, setRemember] = useState(false);
  const [hasKey, setHasKey] = useState(() => getApiKey() !== null);

  useEffect(
    () =>
      subscribeAuth((event) => {
        setHasKey(getApiKey() !== null);
        if (event.type === "required") {
          setReason(event.reason);
          setOpen(true);
        }
      }),
    [],
  );

  const close = () => {
    setOpen(false);
    setValue("");
  };

  // Escape closes the dialog, like the other modals.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        setValue("");
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  const save = (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) return;
    setAnalystName(analyst, remember);
    setApiKey(value, remember);
    close();
    setReason(null);
    // Retry everything that failed without (or with the old) key
    queryClient.invalidateQueries();
  };

  const signOut = () => {
    clearApiKey();
    setAnalyst("");
    setReason(null);
    // Drop cached data; active queries refetch and prompt on 401
    queryClient.resetQueries();
  };

  return (
    <>
      <div className="flex items-center gap-2">
        <button
          onClick={() => setOpen(true)}
          className="px-2 py-1 text-xs rounded border border-gray-700 text-gray-300 hover:bg-gray-800"
        >
          {hasKey ? "API key set" : "Set API key"}
        </button>
        {hasKey && (
          <button
            onClick={signOut}
            className="px-2 py-1 text-xs rounded text-gray-500 hover:text-gray-300"
          >
            Sign out
          </button>
        )}
      </div>

      {open && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <form
            onSubmit={save}
            role="dialog"
            aria-modal="true"
            aria-labelledby="api-key-title"
            className="bg-gray-800 rounded-lg p-6 w-96 space-y-4"
          >
            <h3 id="api-key-title" className="text-white font-semibold">
              API key required
            </h3>
            {reason && (
              <div className="px-3 py-2 bg-red-900/40 border border-red-700 rounded text-red-400 text-sm">
                {reason}
              </div>
            )}
            <p className="text-gray-400 text-sm">
              This server requires an API key (sent in the{" "}
              <code className="text-gray-300">{API_KEY_HEADER}</code> header).
              Ask your administrator for one of the keys configured under{" "}
              <code className="text-gray-300">auth.api_keys</code>.
            </p>
            <input
              type="password"
              autoFocus
              autoComplete="off"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="API key"
              aria-label="API key"
              className="w-full bg-gray-900 text-white text-sm px-3 py-2 rounded border border-gray-700 focus:border-blue-500 focus:outline-none font-mono"
            />
            <input
              type="text"
              autoComplete="name"
              value={analyst}
              onChange={(e) => setAnalyst(e.target.value)}
              placeholder="Your name (optional)"
              aria-label="Your name"
              className="w-full bg-gray-900 text-white text-sm px-3 py-2 rounded border border-gray-700 focus:border-blue-500 focus:outline-none"
            />
            <p className="text-gray-500 text-xs">
              Alerts you acknowledge, resolve or annotate record this name
              with the API key you used.
            </p>
            <label className="flex items-center gap-2 text-gray-400 text-sm">
              <input
                type="checkbox"
                checked={remember}
                onChange={(e) => setRemember(e.target.checked)}
                className="rounded bg-gray-700 border-gray-600"
              />
              Remember on this device
            </label>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={close}
                className="px-4 py-2 bg-gray-700 text-gray-300 text-sm rounded hover:bg-gray-600"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={!value.trim()}
                className="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 disabled:opacity-50"
              >
                Save
              </button>
            </div>
          </form>
        </div>
      )}
    </>
  );
};

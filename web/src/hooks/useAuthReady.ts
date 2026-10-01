import { useEffect, useState } from "react";
import { authRequired } from "../services/api";
import { getApiKey, handleUnauthorized, subscribeAuth } from "../services/auth";

/** Reason shown in the API key prompt when the dashboard opens without one. */
export const KEY_NEEDED_REASON = "This server requires an API key";

/**
 * Whether the dashboard may request data: an API key is known, or the
 * server does not require one (auth_required on the public /health). While
 * that is being checked nothing is requested, and when a key is required
 * the API key prompt opens. (Without a key, the first load used to send
 * /v1/stats, /v1/alerts and /v1/alerts/stats and log their three 401s.)
 *
 * If /health cannot tell (an older server, or it failed), requests go out
 * and a 401 opens the prompt, as before.
 */
export function useAuthReady(): boolean {
  const [hasKey, setHasKey] = useState(() => getApiKey() !== null);
  // undefined: not checked yet; null: /health could not tell
  const [required, setRequired] = useState<boolean | null | undefined>(
    undefined,
  );

  useEffect(() => subscribeAuth(() => setHasKey(getApiKey() !== null)), []);

  // Checked once: later, a rejected key opens the prompt itself (with the
  // server's reason) and signing out shows the gate.
  useEffect(() => {
    let cancelled = false;
    authRequired().then((r) => {
      if (cancelled) return;
      setRequired(r);
      if (r === true && getApiKey() === null) {
        handleUnauthorized(null, KEY_NEEDED_REASON);
      }
    });
    return () => {
      cancelled = true;
    };
  }, []);

  return hasKey || (required !== undefined && required !== true);
}

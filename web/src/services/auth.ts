// API key handling for the dashboard.
//
// siem-ingest (internal/ingest/middleware.go) authenticates every route except
// /health and /metrics with a static API key read from the header configured
// as auth.api_key_header (default "X-API-Key"). Browsers cannot hold that key
// in a cookie, so the operator enters it once and it is kept in
// sessionStorage (this tab only) or, if they choose, localStorage.

/** Header the API key is sent in. Override with VITE_API_KEY_HEADER at build time. */
export const API_KEY_HEADER: string =
  import.meta.env.VITE_API_KEY_HEADER || "X-API-Key";

const STORAGE_KEY = "boundary-siem.apiKey";

export type AuthEvent =
  | { type: "changed" }
  | { type: "required"; reason: string };

type Listener = (event: AuthEvent) => void;

const listeners = new Set<Listener>();

// Fallback when Web Storage is unavailable (private mode, blocked cookies).
let memoryKey: string | null = null;

type StorageKind = "sessionStorage" | "localStorage";

function storage(kind: StorageKind): Storage | undefined {
  try {
    return (globalThis as Record<string, unknown>)[kind] as Storage | undefined;
  } catch {
    return undefined;
  }
}

function readStored(kind: StorageKind): string | null {
  try {
    return storage(kind)?.getItem(STORAGE_KEY) ?? null;
  } catch {
    return null;
  }
}

function removeStored(): void {
  for (const kind of ["sessionStorage", "localStorage"] as const) {
    try {
      storage(kind)?.removeItem(STORAGE_KEY);
    } catch {
      // storage blocked: nothing stored there
    }
  }
}

function emit(event: AuthEvent): void {
  for (const listener of Array.from(listeners)) {
    listener(event);
  }
}

/** Returns the API key to send, or null when none has been entered. */
export function getApiKey(): string | null {
  return (
    readStored("sessionStorage") || readStored("localStorage") || memoryKey
  );
}

/**
 * Stores the API key. With remember=false it lives only in this tab
 * (sessionStorage); with remember=true it survives restarts (localStorage).
 */
export function setApiKey(key: string, remember = false): void {
  const trimmed = key.trim();
  removeStored();
  memoryKey = trimmed || null;
  if (trimmed) {
    try {
      storage(remember ? "localStorage" : "sessionStorage")?.setItem(
        STORAGE_KEY,
        trimmed,
      );
    } catch {
      // storage blocked: keep the in-memory copy only
    }
  }
  emit({ type: "changed" });
}

/** Forgets the API key (sign out). */
export function clearApiKey(): void {
  removeStored();
  memoryKey = null;
  emit({ type: "changed" });
}

/**
 * Called when the server rejected a request made with usedKey. The stored
 * key is dropped only if it is still the one that was rejected, and
 * listeners are told to prompt for a key. A rejection of an older key (a
 * request that was in flight while the user entered a new one) is stale: it
 * neither erases the new key nor reopens the prompt.
 */
export function handleUnauthorized(
  usedKey: string | null,
  reason = "Authentication required",
): void {
  const current = getApiKey();
  if (current !== null && current !== usedKey) {
    return;
  }
  if (current !== null) {
    removeStored();
    memoryKey = null;
  }
  emit({ type: "required", reason });
}

/** Subscribes to key changes and auth prompts. Returns an unsubscribe function. */
export function subscribeAuth(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

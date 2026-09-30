import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryStorage, jsonResponse } from "../test-utils";
import {
  ApiError,
  deleteRule,
  describeError,
  getEventStats,
  listAlerts,
  listRules,
} from "./api";
import {
  API_KEY_HEADER,
  clearApiKey,
  getApiKey,
  setApiKey,
  subscribeAuth,
  type AuthEvent,
} from "./auth";

// Regression tests for R08: the dashboard never sent an API key, so every
// call against an auth-enabled siem-ingest returned 401.

let session: MemoryStorage;
let local: MemoryStorage;
let fetchMock: ReturnType<typeof vi.fn>;

function sentHeaders(call = 0): Record<string, string> {
  const init = fetchMock.mock.calls[call][1] as RequestInit;
  return init.headers as Record<string, string>;
}

beforeEach(() => {
  session = new MemoryStorage();
  local = new MemoryStorage();
  vi.stubGlobal("sessionStorage", session);
  vi.stubGlobal("localStorage", local);
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  clearApiKey();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("API key header", () => {
  it("uses the header siem-ingest checks by default", () => {
    expect(API_KEY_HEADER).toBe("X-API-Key");
  });

  const calls: [string, () => Promise<unknown>][] = [
    ["listAlerts", () => listAlerts({ limit: 5 })],
    ["getEventStats", () => getEventStats()],
    ["listRules", () => listRules()],
  ];

  it.each(calls)("%s sends the stored key", async (_name, call) => {
    setApiKey("sk_live_123");
    fetchMock.mockResolvedValue(jsonResponse(200, { alerts: [], rules: [] }));

    await call();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(sentHeaders()[API_KEY_HEADER]).toBe("sk_live_123");
  });

  it("sends no key header when no key was entered", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { alerts: [], total: 0 }));

    await listAlerts();

    expect(sentHeaders()).not.toHaveProperty(API_KEY_HEADER);
  });

  it("keeps the key per tab by default and across restarts when remembered", () => {
    setApiKey("tab-key");
    expect(session.getItem("boundary-siem.apiKey")).toBe("tab-key");
    expect(local.getItem("boundary-siem.apiKey")).toBeNull();

    setApiKey("kept-key", true);
    expect(local.getItem("boundary-siem.apiKey")).toBe("kept-key");
    expect(session.getItem("boundary-siem.apiKey")).toBeNull();
    expect(getApiKey()).toBe("kept-key");
  });

  it("works when Web Storage is unavailable", async () => {
    vi.stubGlobal("sessionStorage", undefined);
    vi.stubGlobal("localStorage", undefined);
    setApiKey("mem-key");
    fetchMock.mockResolvedValue(jsonResponse(200, { alerts: [], total: 0 }));

    await listAlerts();

    expect(sentHeaders()[API_KEY_HEADER]).toBe("mem-key");
  });
});

describe("401 handling", () => {
  it("clears the rejected key and asks for a new one", async () => {
    setApiKey("revoked");
    const events: AuthEvent[] = [];
    const unsubscribe = subscribeAuth((e) => events.push(e));
    fetchMock.mockResolvedValue(
      jsonResponse(401, { success: false, error: "invalid API key" }),
    );

    const err = await listAlerts().catch((e: unknown) => e);

    unsubscribe();
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(401);
    expect((err as ApiError).message).toBe("invalid API key");
    expect(getApiKey()).toBeNull();
    expect(events).toContainEqual({ type: "required", reason: "invalid API key" });
  });

  it("prompts when no key has been entered yet", async () => {
    const events: AuthEvent[] = [];
    const unsubscribe = subscribeAuth((e) => events.push(e));
    fetchMock.mockResolvedValue(
      jsonResponse(401, { success: false, error: "missing API key" }),
    );

    await expect(listRules()).rejects.toBeInstanceOf(ApiError);

    unsubscribe();
    expect(events).toContainEqual({ type: "required", reason: "missing API key" });
  });

  it("does not erase a key entered while an old request was in flight", async () => {
    setApiKey("old-key");
    let respond: (r: Response) => void = () => {};
    fetchMock.mockReturnValue(new Promise<Response>((r) => (respond = r)));

    const pending = listAlerts().catch(() => undefined);
    setApiKey("new-key");
    respond(jsonResponse(401, { error: "invalid API key" }));
    await pending;

    expect(getApiKey()).toBe("new-key");
  });

  it("does not treat other errors as authentication failures", async () => {
    setApiKey("good-key");
    fetchMock.mockResolvedValue(jsonResponse(500, { error: "boom" }));

    await expect(listAlerts()).rejects.toMatchObject({ status: 500 });
    expect(getApiKey()).toBe("good-key");
  });
});

describe("responses", () => {
  it("accepts an empty 204 body", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    await expect(deleteRule("r1")).resolves.toBeUndefined();
  });
});

describe("describeError", () => {
  it("explains 401 as an authentication problem", () => {
    expect(describeError(new ApiError(401, "missing API key"))).toMatch(
      /API key/,
    );
  });

  it("passes other messages through", () => {
    expect(describeError(new ApiError(500, "search execution failed"))).toBe(
      "search execution failed",
    );
    expect(describeError(new Error("network down"))).toBe("network down");
  });
});

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryStorage, jsonResponse } from "../test-utils";
import {
  ApiError,
  acknowledgeAlert,
  addAlertNote,
  authRequired,
  describeError,
  resolveAlert,
  searchEvents,
  shouldRetry,
} from "./api";
import { clearApiKey, getAnalystName, setAnalystName, setApiKey } from "./auth";

// E2E round 2 (dashboard): the search error banner showed only "invalid
// query" (the server's details were dropped), every 4xx was retried so each
// invalid search was sent twice, and alert actions were sent as the fixed
// user "operator".

let fetchMock: ReturnType<typeof vi.fn>;

function sentBody(call = 0): unknown {
  const init = fetchMock.mock.calls[call][1] as RequestInit;
  return JSON.parse(init.body as string);
}

beforeEach(() => {
  vi.stubGlobal("sessionStorage", new MemoryStorage());
  vi.stubGlobal("localStorage", new MemoryStorage());
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  clearApiKey();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("error details", () => {
  it("keeps the server's details and shows them", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(400, {
        error: "invalid query",
        code: "invalid_query",
        details: 'unknown field "foo"',
      }),
    );

    const err = await searchEvents({ query: "foo:bar" }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).details).toBe('unknown field "foo"');
    expect(describeError(err)).toBe('invalid query: unknown field "foo"');
  });

  it("shows the message alone without details", () => {
    expect(describeError(new ApiError(500, "search execution failed"))).toBe(
      "search execution failed",
    );
  });
});

describe("shouldRetry", () => {
  it.each([400, 401, 403, 404, 409, 422])("does not retry %i", (status) => {
    expect(shouldRetry(0, new ApiError(status, "no"))).toBe(false);
  });

  it.each([408, 429, 500, 502, 503])("retries %i once", (status) => {
    expect(shouldRetry(0, new ApiError(status, "later"))).toBe(true);
    expect(shouldRetry(1, new ApiError(status, "later"))).toBe(false);
  });

  it("retries a network failure once", () => {
    expect(shouldRetry(0, new TypeError("Failed to fetch"))).toBe(true);
    expect(shouldRetry(1, new TypeError("Failed to fetch"))).toBe(false);
  });
});

describe("alert actions", () => {
  beforeEach(() => {
    setApiKey("k");
    fetchMock.mockImplementation(async () => jsonResponse(200, { status: "ok" }));
  });

  it("send the analyst name entered with the key", async () => {
    setAnalystName("alice");
    await acknowledgeAlert("a1");
    await resolveAlert("a1");
    await addAlertNote("a1", "checked");
    expect(sentBody(0)).toEqual({ user: "alice" });
    expect(sentBody(1)).toEqual({ user: "alice" });
    expect(sentBody(2)).toEqual({ author: "alice", content: "checked" });
  });

  it("leave the user to the server (the API key) without a name", async () => {
    await acknowledgeAlert("a1");
    await resolveAlert("a1");
    await addAlertNote("a1", "checked");
    expect(sentBody(0)).toEqual({});
    expect(sentBody(1)).toEqual({});
    expect(sentBody(2)).toEqual({ content: "checked" });
    expect(JSON.stringify(fetchMock.mock.calls)).not.toContain("operator");
  });
});

describe("analyst name", () => {
  it("is kept with the key and forgotten on sign out", () => {
    expect(getAnalystName()).toBe("");
    setAnalystName("  Alice  ");
    expect(getAnalystName()).toBe("Alice");
    clearApiKey();
    expect(getAnalystName()).toBe("");
  });
});

describe("authRequired", () => {
  it("reads auth_required from /health", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { status: "healthy", auth_required: true }));
    await expect(authRequired()).resolves.toBe(true);
    expect(fetchMock.mock.calls[0][0]).toBe("/health");

    fetchMock.mockResolvedValueOnce(jsonResponse(200, { auth_required: false }));
    await expect(authRequired()).resolves.toBe(false);
  });

  it("is unknown when /health does not tell", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { status: "healthy" }));
    await expect(authRequired()).resolves.toBeNull();
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    await expect(authRequired()).resolves.toBeNull();
    fetchMock.mockResolvedValueOnce(jsonResponse(503, {}));
    await expect(authRequired()).resolves.toBeNull();
  });
});

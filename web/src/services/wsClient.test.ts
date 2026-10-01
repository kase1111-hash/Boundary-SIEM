import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  EventSocket,
  WS_AUTH_FAILED,
  type EventSocketOptions,
  type WSStatus,
} from "./wsClient";

// Regression tests for R14 (client side): the UI must authenticate the
// /ws/events socket with {"type":"auth","api_key":...} as its first message
// (browsers cannot set headers on a WebSocket), treat the socket as live
// only after {"type":"auth_ok"}, and stop reconnecting on close code 4401.

class FakeWebSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;
  static instances: FakeWebSocket[] = [];

  readyState = FakeWebSocket.CONNECTING;
  sent: string[] = [];
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;

  constructor(public url: string) {
    FakeWebSocket.instances.push(this);
  }

  send(data: string) {
    if (this.readyState !== FakeWebSocket.OPEN) {
      throw new Error("send on a socket that is not open");
    }
    this.sent.push(data);
  }

  close(code = 1000, reason = "") {
    if (this.readyState === FakeWebSocket.CLOSED) return;
    this.readyState = FakeWebSocket.CLOSED;
    this.onclose?.({ code, reason } as CloseEvent);
  }

  // --- test controls ---
  serverOpen() {
    this.readyState = FakeWebSocket.OPEN;
    this.onopen?.({} as Event);
  }

  serverSend(msg: unknown) {
    this.onmessage?.({ data: JSON.stringify(msg) } as MessageEvent);
  }

  serverClose(code: number, reason = "") {
    this.readyState = FakeWebSocket.CLOSED;
    this.onclose?.({ code, reason } as CloseEvent);
  }

  sentJSON(): unknown[] {
    return this.sent.map((s) => JSON.parse(s));
  }
}

const latest = () => FakeWebSocket.instances[FakeWebSocket.instances.length - 1];

let statuses: WSStatus[];
let messages: unknown[];
let unauthorized: string[];
let apiKey: string | null;

function makeSocket(overrides: Partial<EventSocketOptions> = {}) {
  return new EventSocket({
    url: "ws://siem.test/ws/events",
    getApiKey: () => apiKey,
    onStatus: (s) => statuses.push(s),
    onMessage: (m) => messages.push(m),
    onUnauthorized: (r) => unauthorized.push(r),
    reconnectInterval: 1000,
    maxReconnectInterval: 8000,
    heartbeatInterval: 30000,
    authTimeout: 5000,
    WebSocketImpl: FakeWebSocket as unknown as typeof WebSocket,
    ...overrides,
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  FakeWebSocket.instances = [];
  statuses = [];
  messages = [];
  unauthorized = [];
  apiKey = "sk_ws_key";
});

afterEach(() => {
  vi.useRealTimers();
});

describe("EventSocket authentication handshake", () => {
  it("sends the auth message first and is live only after auth_ok", () => {
    const sock = makeSocket();
    sock.start();
    const ws = latest();
    expect(ws.url).toBe("ws://siem.test/ws/events");

    sock.send({ type: "subscribe", topics: ["alerts"] }); // queued
    ws.serverOpen();

    expect(ws.sentJSON()).toEqual([{ type: "auth", api_key: "sk_ws_key" }]);
    expect(sock.status).toBe("connecting");

    ws.serverSend({ type: "auth_ok" });

    expect(sock.status).toBe("connected");
    expect(ws.sentJSON()).toEqual([
      { type: "auth", api_key: "sk_ws_key" },
      { type: "subscribe", topics: ["alerts"] },
    ]);
    sock.stop();
  });

  it("sends an empty key when none was entered (auth-disabled servers accept it)", () => {
    apiKey = null;
    const sock = makeSocket();
    sock.start();
    latest().serverOpen();
    expect(latest().sentJSON()[0]).toEqual({ type: "auth", api_key: "" });
    sock.stop();
  });

  it("ignores data frames before auth_ok and swallows pong", () => {
    const sock = makeSocket();
    sock.start();
    const ws = latest();
    ws.serverOpen();
    ws.serverSend({ type: "alert", data: { id: "early" } });
    expect(messages).toEqual([]);

    ws.serverSend({ type: "auth_ok" });
    ws.serverSend({ type: "pong" });
    ws.serverSend({ type: "alert", data: { id: "a1" } });

    expect(messages).toEqual([{ type: "alert", data: { id: "a1" } }]);
    sock.stop();
  });

  it("stops reconnecting and reports unauthorized on close code 4401", () => {
    const sock = makeSocket();
    sock.start();
    const ws = latest();
    ws.serverOpen();
    ws.serverClose(WS_AUTH_FAILED, "invalid API key");

    expect(sock.status).toBe("unauthorized");
    expect(unauthorized).toEqual(["invalid API key"]);

    vi.advanceTimersByTime(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);

    // A new key reconnects immediately
    apiKey = "sk_new";
    sock.reconnectNow();
    expect(FakeWebSocket.instances).toHaveLength(2);
    latest().serverOpen();
    expect(latest().sentJSON()[0]).toEqual({ type: "auth", api_key: "sk_new" });
    sock.stop();
  });

  it("gives up on a server that never answers the auth message", () => {
    const sock = makeSocket();
    sock.start();
    latest().serverOpen();

    vi.advanceTimersByTime(5000);

    expect(sock.status).toBe("disconnected");
    vi.advanceTimersByTime(1000);
    expect(FakeWebSocket.instances).toHaveLength(2);
    sock.stop();
  });
});

describe("EventSocket reconnects", () => {
  it("reconnects with exponential backoff after other closes", () => {
    const sock = makeSocket();
    sock.start();

    latest().serverClose(1006);
    expect(sock.status).toBe("disconnected");
    vi.advanceTimersByTime(999);
    expect(FakeWebSocket.instances).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(FakeWebSocket.instances).toHaveLength(2);

    latest().serverClose(1006);
    vi.advanceTimersByTime(1999);
    expect(FakeWebSocket.instances).toHaveLength(2);
    vi.advanceTimersByTime(1);
    expect(FakeWebSocket.instances).toHaveLength(3);

    // A successful handshake resets the backoff
    latest().serverOpen();
    latest().serverSend({ type: "auth_ok" });
    latest().serverClose(1001);
    vi.advanceTimersByTime(1000);
    expect(FakeWebSocket.instances).toHaveLength(4);
    sock.stop();
  });

  it("sends heartbeats only while authenticated", () => {
    const sock = makeSocket();
    sock.start();
    const ws = latest();
    ws.serverOpen();
    ws.serverSend({ type: "auth_ok" });

    vi.advanceTimersByTime(30_000);
    expect(ws.sentJSON()).toContainEqual({ type: "ping" });
    sock.stop();
  });

  it("does not reconnect after stop()", () => {
    const sock = makeSocket();
    sock.start();
    latest().serverOpen();
    sock.stop();
    vi.advanceTimersByTime(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(sock.status).toBe("disconnected");
  });
});

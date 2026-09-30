// Live event stream client for /ws/events.
//
// Browsers cannot set headers on a WebSocket, so the socket authenticates
// in-band:
//   client -> {"type":"auth","api_key":"<key or empty>"}   (first message)
//   server -> {"type":"auth_ok"}                           (then data frames)
//   server closes with code 4401 when the key is missing or invalid.
// After auth_ok the client sends {"type":"ping"} every heartbeatInterval and
// the server answers {"type":"pong"}. Data frames are {"type":..., "data":...}.

export type WSStatus =
  | "connecting"
  | "connected"
  | "disconnected"
  | "unauthorized";

/** Close code the server uses when authentication fails. */
export const WS_AUTH_FAILED = 4401;

export interface EventSocketOptions {
  url: string;
  getApiKey: () => string | null;
  onStatus?: (status: WSStatus) => void;
  onMessage?: (data: unknown) => void;
  /** Called with the server's reason when it closes with WS_AUTH_FAILED. */
  onUnauthorized?: (reason: string) => void;
  reconnectInterval?: number;
  maxReconnectInterval?: number;
  heartbeatInterval?: number;
  /** How long to wait for auth_ok before giving up on a connection. */
  authTimeout?: number;
  /** Injected for tests. */
  WebSocketImpl?: typeof WebSocket;
}

const MAX_QUEUE = 100;
const OPEN = 1;

export class EventSocket {
  status: WSStatus = "disconnected";

  private ws: WebSocket | null = null;
  private authenticated = false;
  private stopped = true;
  private retries = 0;
  private queue: string[] = [];
  private reconnectTimer?: ReturnType<typeof setTimeout>;
  private authTimer?: ReturnType<typeof setTimeout>;
  private heartbeatTimer?: ReturnType<typeof setInterval>;

  private readonly reconnectInterval: number;
  private readonly maxReconnectInterval: number;
  private readonly heartbeatInterval: number;
  private readonly authTimeout: number;

  constructor(private readonly opts: EventSocketOptions) {
    this.reconnectInterval = opts.reconnectInterval ?? 2000;
    this.maxReconnectInterval = opts.maxReconnectInterval ?? 30000;
    this.heartbeatInterval = opts.heartbeatInterval ?? 30000;
    this.authTimeout = opts.authTimeout ?? 10000;
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.teardown();
    this.setStatus("disconnected");
  }

  /** Drops the current connection and connects again now (e.g. new API key). */
  reconnectNow(): void {
    if (this.stopped) return;
    this.teardown();
    this.retries = 0;
    this.connect();
  }

  /** Sends data once authenticated; queues it (bounded) until then. */
  send(data: unknown): void {
    const msg = JSON.stringify(data);
    if (this.authenticated && this.ws?.readyState === OPEN) {
      this.ws.send(msg);
    } else if (this.queue.length < MAX_QUEUE) {
      this.queue.push(msg);
    }
  }

  private setStatus(status: WSStatus): void {
    if (this.status === status) return;
    this.status = status;
    this.opts.onStatus?.(status);
  }

  private connect(): void {
    const Impl = this.opts.WebSocketImpl ?? WebSocket;
    let ws: WebSocket;
    try {
      ws = new Impl(this.opts.url);
    } catch {
      this.setStatus("disconnected");
      this.scheduleReconnect();
      return;
    }
    this.ws = ws;
    this.authenticated = false;
    this.setStatus("connecting");

    ws.onopen = () => {
      ws.send(
        JSON.stringify({ type: "auth", api_key: this.opts.getApiKey() ?? "" }),
      );
      this.authTimer = setTimeout(() => {
        if (!this.authenticated) ws.close();
      }, this.authTimeout);
    };

    ws.onmessage = (event: MessageEvent) => {
      let data: unknown;
      try {
        data = JSON.parse(event.data);
      } catch {
        return; // non-JSON frames are not part of the protocol
      }
      const type = (data as { type?: unknown } | null)?.type;
      if (!this.authenticated) {
        if (type === "auth_ok") this.onAuthenticated(ws);
        return;
      }
      if (type === "pong") return;
      this.opts.onMessage?.(data);
    };

    ws.onclose = (event: CloseEvent) => {
      if (this.ws !== ws) return; // superseded connection
      this.clearTimers();
      this.ws = null;
      this.authenticated = false;
      if (this.stopped) return;
      if (event.code === WS_AUTH_FAILED) {
        // Retrying with the same key cannot succeed; wait for reconnectNow()
        this.setStatus("unauthorized");
        this.opts.onUnauthorized?.(
          event.reason || "WebSocket authentication failed",
        );
        return;
      }
      this.setStatus("disconnected");
      this.scheduleReconnect();
    };

    ws.onerror = () => {
      ws.close();
    };
  }

  private onAuthenticated(ws: WebSocket): void {
    this.authenticated = true;
    this.retries = 0;
    if (this.authTimer) clearTimeout(this.authTimer);
    this.authTimer = undefined;
    this.setStatus("connected");
    while (this.queue.length > 0 && ws.readyState === OPEN) {
      ws.send(this.queue.shift() as string);
    }
    this.heartbeatTimer = setInterval(() => {
      if (ws.readyState === OPEN) ws.send(JSON.stringify({ type: "ping" }));
    }, this.heartbeatInterval);
  }

  private scheduleReconnect(): void {
    const delay = Math.min(
      this.reconnectInterval * Math.pow(2, this.retries),
      this.maxReconnectInterval,
    );
    this.retries++;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = undefined;
      if (!this.stopped) this.connect();
    }, delay);
  }

  private clearTimers(): void {
    if (this.authTimer) clearTimeout(this.authTimer);
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.authTimer = undefined;
    this.heartbeatTimer = undefined;
  }

  private teardown(): void {
    this.clearTimers();
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = undefined;
    const ws = this.ws;
    this.ws = null;
    this.authenticated = false;
    if (ws) {
      ws.onclose = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.close();
    }
  }
}

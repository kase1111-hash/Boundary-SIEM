import { useEffect, useRef, useState, useCallback } from "react";

export type WSStatus = "connecting" | "connected" | "disconnected";

interface UseWebSocketOptions {
  url?: string;
  onMessage?: (data: unknown) => void;
  reconnectInterval?: number;
  maxReconnectInterval?: number;
  heartbeatInterval?: number;
  enabled?: boolean;
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const {
    onMessage,
    reconnectInterval = 2000,
    maxReconnectInterval = 30000,
    heartbeatInterval = 30000,
    enabled = true,
  } = options;

  const [status, setStatus] = useState<WSStatus>("disconnected");
  const [lastMessage, setLastMessage] = useState<unknown>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const retriesRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout>>();
  const heartbeatRef = useRef<ReturnType<typeof setInterval>>();
  const queueRef = useRef<string[]>([]);

  const getUrl = useCallback(() => {
    if (options.url) return options.url;
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${window.location.host}/ws/events`;
  }, [options.url]);

  const flushQueue = useCallback((ws: WebSocket) => {
    while (queueRef.current.length > 0 && ws.readyState === WebSocket.OPEN) {
      const msg = queueRef.current.shift()!;
      ws.send(msg);
    }
  }, []);

  const startHeartbeat = useCallback(
    (ws: WebSocket) => {
      if (heartbeatRef.current) clearInterval(heartbeatRef.current);
      heartbeatRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "ping" }));
        }
      }, heartbeatInterval);
    },
    [heartbeatInterval],
  );

  const stopHeartbeat = useCallback(() => {
    if (heartbeatRef.current) {
      clearInterval(heartbeatRef.current);
      heartbeatRef.current = undefined;
    }
  }, []);

  const connect = useCallback(() => {
    if (!enabled) return;

    try {
      const ws = new WebSocket(getUrl());
      wsRef.current = ws;
      setStatus("connecting");

      ws.onopen = () => {
        setStatus("connected");
        retriesRef.current = 0;
        flushQueue(ws);
        startHeartbeat(ws);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data?.type === "pong") return;
          setLastMessage(data);
          onMessage?.(data);
        } catch {
          // Non-JSON message
          setLastMessage(event.data);
        }
      };

      ws.onclose = () => {
        setStatus("disconnected");
        wsRef.current = null;
        stopHeartbeat();

        // Exponential backoff reconnect
        const delay = Math.min(
          reconnectInterval * Math.pow(2, retriesRef.current),
          maxReconnectInterval,
        );
        retriesRef.current++;
        timerRef.current = setTimeout(connect, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {
      setStatus("disconnected");
    }
  }, [
    enabled,
    getUrl,
    onMessage,
    reconnectInterval,
    maxReconnectInterval,
    flushQueue,
    startHeartbeat,
    stopHeartbeat,
  ]);

  useEffect(() => {
    connect();
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      stopHeartbeat();
      if (wsRef.current) {
        wsRef.current.onclose = null; // prevent reconnect on cleanup
        wsRef.current.close();
      }
    };
  }, [connect, stopHeartbeat]);

  const send = useCallback((data: unknown) => {
    const msg = JSON.stringify(data);
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(msg);
    } else {
      // Queue messages while disconnected (cap at 100 to avoid unbounded growth)
      if (queueRef.current.length < 100) {
        queueRef.current.push(msg);
      }
    }
  }, []);

  return { status, lastMessage, send };
}

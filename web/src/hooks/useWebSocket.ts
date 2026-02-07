import { useEffect, useRef, useState, useCallback } from "react";

export type WSStatus = "connecting" | "connected" | "disconnected";

interface UseWebSocketOptions {
  url?: string;
  onMessage?: (data: unknown) => void;
  reconnectInterval?: number;
  maxReconnectInterval?: number;
  enabled?: boolean;
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const {
    onMessage,
    reconnectInterval = 2000,
    maxReconnectInterval = 30000,
    enabled = true,
  } = options;

  const [status, setStatus] = useState<WSStatus>("disconnected");
  const [lastMessage, setLastMessage] = useState<unknown>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const retriesRef = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout>>();

  const getUrl = useCallback(() => {
    if (options.url) return options.url;
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${window.location.host}/ws/events`;
  }, [options.url]);

  const connect = useCallback(() => {
    if (!enabled) return;

    try {
      const ws = new WebSocket(getUrl());
      wsRef.current = ws;
      setStatus("connecting");

      ws.onopen = () => {
        setStatus("connected");
        retriesRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
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
  }, [enabled, getUrl, onMessage, reconnectInterval, maxReconnectInterval]);

  useEffect(() => {
    connect();
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      if (wsRef.current) {
        wsRef.current.onclose = null; // prevent reconnect on cleanup
        wsRef.current.close();
      }
    };
  }, [connect]);

  const send = useCallback((data: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  return { status, lastMessage, send };
}
